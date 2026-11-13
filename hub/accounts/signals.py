"""Sign-in and credential changes go to the audit log (rule 7)."""

import re
import time

from allauth.account import signals as account_signals
from allauth.mfa import signals as mfa_signals
from allauth.mfa.models import Authenticator
from allauth.socialaccount import signals as social_signals
from django.contrib.auth.signals import user_logged_out, user_login_failed
from django.core.exceptions import PermissionDenied
from django.db.models.signals import post_save, pre_delete, pre_save
from django.dispatch import receiver

from hub.accounts.mfa import ENROLLED_IN_SESSION_KEY, SECOND_FACTORS, authentication_methods
from hub.accounts.models import User
from hub.audit import services as audit
from hub.audit.models import AuditEvent

_EMAIL_SHAPE = re.compile(r"^[^@\s]{1,64}@[^@\s]{1,255}$")


@receiver(account_signals.user_logged_in)
def _signed_in(request, user, **kwargs):
    audit.record(
        "auth.signed_in",
        request=request,
        actor=user,
        organisation=None,
        data={"methods": authentication_methods(request)},
    )


@receiver(user_logged_out)
def _signed_out(request, user, **kwargs):
    if user is not None:
        audit.record("auth.signed_out", request=request, actor=user, organisation=None)


@receiver(user_login_failed)
def _sign_in_failed(credentials, request=None, **kwargs):
    # People sometimes type a password into the email field. Keep the attempt only if it reads
    # as an email address; never store anything else that was typed.
    attempted = str(credentials.get("email") or credentials.get("username") or "").strip()
    if not _EMAIL_SHAPE.match(attempted):
        attempted = "(not an email address)"
    audit.record(
        "auth.sign_in_failed",
        request=request,
        actor=None,
        actor_kind=AuditEvent.ActorKind.SYSTEM,
        organisation=None,
        target_label=attempted[:254],
    )


def _revoke_app_sessions(user) -> None:
    """A changed password or a removed factor ends every app sign-in of the login, so that
    recovering an account also throws out whoever else was using it."""
    from hub.organisations.services import revoke_tokens

    revoke_tokens(user=user)


def _password_event(action):
    def handler(request, user, **kwargs):
        _revoke_app_sessions(user)
        audit.record(action, request=request, actor=user, organisation=None)

    return handler


_password_changed = _password_event("auth.password_changed")
_password_set = _password_event("auth.password_set")
_password_reset = _password_event("auth.password_reset")
account_signals.password_changed.connect(_password_changed)
account_signals.password_set.connect(_password_set)
account_signals.password_reset.connect(_password_reset)


@receiver(account_signals.email_changed)
def _email_changed(request, user, from_email_address, to_email_address, **kwargs):
    audit.record(
        "auth.email_changed",
        request=request,
        actor=user,
        organisation=None,
        data={"from": getattr(from_email_address, "email", ""), "to": getattr(to_email_address, "email", "")},
    )


@receiver(mfa_signals.authenticator_added)
def _mfa_added(request, user, authenticator, **kwargs):
    if authenticator.type in SECOND_FACTORS and request is not None:
        # Activating a factor proves possession of it, so this session has passed MFA. (Adding a
        # further factor already needed a recent check: AccountPolicyMiddleware.)
        request.session[ENROLLED_IN_SESSION_KEY] = time.time()
    audit.record("auth.mfa_added", request=request, actor=user, organisation=None, data={"type": authenticator.type})


@receiver(mfa_signals.authenticator_removed)
def _mfa_removed(request, user, authenticator, **kwargs):
    if authenticator.type in SECOND_FACTORS:
        _revoke_app_sessions(user)
    audit.record("auth.mfa_removed", request=request, actor=user, organisation=None, data={"type": authenticator.type})


@receiver(mfa_signals.authenticator_reset)
def _mfa_reset(request, user, authenticator, **kwargs):
    if authenticator.type in SECOND_FACTORS:
        _revoke_app_sessions(user)
    audit.record("auth.mfa_reset", request=request, actor=user, organisation=None, data={"type": authenticator.type})


@receiver(social_signals.social_account_added)
def _social_added(request, sociallogin, **kwargs):
    audit.record(
        "auth.sso_connected",
        request=request,
        actor=sociallogin.user,
        organisation=None,
        data={"provider": sociallogin.account.provider},
    )


@receiver(social_signals.social_account_removed)
def _social_removed(request, socialaccount, **kwargs):
    audit.record(
        "auth.sso_disconnected",
        request=request,
        actor=socialaccount.user,
        organisation=None,
        data={"provider": socialaccount.provider},
    )


# --- the last second factor ---------------------------------------------------------------------


@receiver(pre_delete, sender=Authenticator)
def _keep_the_last_factor(sender, instance, origin=None, **kwargs):
    """A role that requires MFA keeps at least one authenticator app or passkey.

    allauth asks the adapter before removing an authenticator app but not before removing a
    passkey, so the rule is enforced here, where every removal passes. Only a direct removal is
    judged: deleting the login itself takes its factors with it.
    """
    from hub.organisations.services import user_requires_mfa

    if origin is not instance or instance.type not in SECOND_FACTORS:
        return
    others = Authenticator.objects.filter(user_id=instance.user_id, type__in=SECOND_FACTORS).exclude(pk=instance.pk)
    if not others.exists() and user_requires_mfa(instance.user):
        raise PermissionDenied("Your role requires two-step sign-in. Add another method before removing this one.")


# --- privileges of Pulsar's own staff -----------------------------------------------------------

_PRIVILEGE_FIELDS = ("is_active", "is_staff", "is_superuser", "is_platform_operator")


@receiver(pre_save, sender=User)
def _remember_privileges(sender, instance, **kwargs):
    previous = None
    if not instance._state.adding:
        previous = User.objects.filter(pk=instance.pk).values(*_PRIVILEGE_FIELDS).first()
    instance._privileges_before = previous


@receiver(post_save, sender=User)
def _audit_privilege_changes(sender, instance, created, **kwargs):
    """Granting or removing operator, staff or superuser rights, or deactivating a login, is
    audited however it is done: the admin, a command or a shell."""
    before = getattr(instance, "_privileges_before", None) or dict.fromkeys(_PRIVILEGE_FIELDS, False)
    if created:
        before["is_active"] = True
    changes = {
        field: {"from": before[field], "to": getattr(instance, field)}
        for field in _PRIVILEGE_FIELDS
        if before[field] != getattr(instance, field)
    }
    if not changes:
        return
    from allauth.core import context

    request = context.request
    audit.record(
        "account.privileges_changed",
        request=request,
        actor=getattr(request, "user", None) if request is not None and request.user.is_authenticated else None,
        organisation=None,
        target=instance,
        target_label=instance.email,
        data=changes,
    )
