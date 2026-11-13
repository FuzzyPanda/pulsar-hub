"""Sign-in and credential changes go to the audit log (rule 7)."""

import time

from allauth.account import signals as account_signals
from allauth.mfa import signals as mfa_signals
from allauth.socialaccount import signals as social_signals
from django.contrib.auth.signals import user_logged_out, user_login_failed
from django.dispatch import receiver

from hub.accounts.mfa import ENROLLED_IN_SESSION_KEY, SECOND_FACTORS, authentication_methods
from hub.audit import services as audit
from hub.audit.models import AuditEvent


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
    attempted = str(credentials.get("email") or credentials.get("username") or "")[:254]
    audit.record(
        "auth.sign_in_failed",
        request=request,
        actor=None,
        actor_kind=AuditEvent.ActorKind.SYSTEM,
        organisation=None,
        target_label=attempted,
    )


def _account_event(action):
    def handler(request, user, **kwargs):
        audit.record(action, request=request, actor=user, organisation=None)

    return handler


_password_changed = _account_event("auth.password_changed")
_password_set = _account_event("auth.password_set")
_password_reset = _account_event("auth.password_reset")
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
        # Activating a factor proves possession of it, so this session has passed MFA.
        request.session[ENROLLED_IN_SESSION_KEY] = time.time()
    audit.record("auth.mfa_added", request=request, actor=user, organisation=None, data={"type": authenticator.type})


@receiver(mfa_signals.authenticator_removed)
def _mfa_removed(request, user, authenticator, **kwargs):
    audit.record("auth.mfa_removed", request=request, actor=user, organisation=None, data={"type": authenticator.type})


@receiver(mfa_signals.authenticator_reset)
def _mfa_reset(request, user, authenticator, **kwargs):
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
