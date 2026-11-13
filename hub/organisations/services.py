"""Everything that changes an organisation or who belongs to it.

Views, API endpoints and management commands call these functions; none of them writes these
models directly. Each function checks who is asking, makes the change in one transaction and
writes the audit event (rule 7).
"""

import logging
from datetime import timedelta

from django.conf import settings
from django.core.exceptions import PermissionDenied, ValidationError
from django.core.mail import send_mail
from django.db import connection, transaction
from django.template.loader import render_to_string
from django.urls import reverse
from django.utils import timezone
from django.utils.text import slugify

from hub.audit import services as audit
from hub.audit.models import AuditEvent
from hub.organisations.context import organisation_context, require_organisation
from hub.organisations.models import (
    IdentityProvider,
    Invitation,
    Membership,
    OperatorAccess,
    Organisation,
    Role,
    hash_token,
)

logger = logging.getLogger("hub.organisations")

RESERVED_SLUGS = frozenset(
    {"admin", "api", "accounts", "oauth", "operator", "static", "new", "org", "invitations", "healthz", "readyz"}
)


class Actor:
    """Who is asking, inside the current organisation: a member, or a Pulsar operator on a visit."""

    def __init__(self, user, membership: Membership | None = None, operator_access: OperatorAccess | None = None):
        self.user = user
        self.membership = membership
        self.operator_access = operator_access

    @classmethod
    def from_request(cls, request) -> "Actor":
        return cls(request.user, getattr(request, "membership", None), getattr(request, "operator_access", None))

    @property
    def is_operator(self) -> bool:
        return self.operator_access is not None and self.operator_access.is_active

    @property
    def role(self) -> Role | None:
        """A visiting operator acts as an Admin: enough to help, not enough to own."""
        if self.membership is not None and self.membership.is_active:
            return self.membership.role_enum
        if self.is_operator:
            return Role.ADMIN
        return None

    def has_role(self, minimum: Role) -> bool:
        role = self.role
        return role is not None and role.at_least(minimum)

    def require(self, minimum: Role) -> None:
        if not self.has_role(minimum):
            raise PermissionDenied(f"This needs the {Role(minimum).label} role.")


def _audit(actor: Actor, action: str, *, request=None, **kwargs):
    """Record an event by `actor`, whether or not there is a request to read the user from."""
    kind = (
        AuditEvent.ActorKind.OPERATOR if actor.is_operator and actor.membership is None else AuditEvent.ActorKind.USER
    )
    return audit.record(action, request=request, actor=actor.user, actor_kind=kind, **kwargs)


# --- Lookups that run before an organisation is known ---------------------------------------------


def memberships_for_user(user):
    """Every active membership of one login, across organisations, for the organisation switcher."""
    return (
        Membership.all_organisations.filter(  # unscoped: a user's own memberships, to choose an organisation
            user=user, is_active=True
        )
        .exclude(organisation__status=Organisation.Status.DELETING)
        .select_related("organisation")
        .order_by("organisation__name")
    )


def resolve_access(user, organisation: Organisation) -> tuple[Membership | None, OperatorAccess | None]:
    """How `user` may enter `organisation`: as a member, as a visiting operator, or not at all."""
    membership = (
        Membership.all_organisations.filter(  # unscoped: the caller's own membership in the organisation asked for
            organisation=organisation, user=user, is_active=True
        )
        .select_related("organisation")
        .first()
    )
    if membership is not None:
        return membership, None
    if user.is_platform_operator:
        now = timezone.now()
        access = (
            OperatorAccess.all_organisations.filter(  # unscoped: the caller's own operator visit
                organisation=organisation, operator=user, ended_at__isnull=True, starts_at__lte=now, expires_at__gt=now
            )
            .select_related("organisation")
            .first()
        )
        if access is not None:
            return None, access
    return None, None


def find_pending_invitation(token: str) -> Invitation | None:
    if not token:
        return None
    invitation = (
        Invitation.all_organisations.filter(  # unscoped: looked up by its secret token; the bearer has no organisation yet
            token_hash=hash_token(token)
        )
        .select_related("organisation")
        .first()
    )
    if invitation is None or not invitation.is_pending or not invitation.organisation.is_active:
        return None
    return invitation


def identity_providers_for(organisation: Organisation) -> list[IdentityProvider]:
    # unscoped: one named organisation's own rows
    return list(IdentityProvider.all_organisations.filter(organisation=organisation))


def sign_in_providers_for(organisation: Organisation) -> list[dict]:
    """The Microsoft and Google sign-in buttons to show for an organisation.

    One entry per provider, and only for providers Pulsar has an application registration for
    (MICROSOFT_CLIENT_ID, GOOGLE_CLIENT_ID). An organisation can list a directory before the
    registration exists; that must show as "not available yet", never as an error page.
    """
    configured = settings.SOCIALACCOUNT_PROVIDERS
    seen, buttons = set(), []
    for idp in identity_providers_for(organisation):
        if idp.provider in configured and idp.provider not in seen:
            seen.add(idp.provider)
            buttons.append({"provider": idp.provider, "label": idp.get_provider_display()})
    return buttons


def user_requires_mfa(user) -> bool:
    """True if any of the user's memberships needs MFA, or the user is Pulsar staff."""
    if user.is_platform_operator or user.is_staff:
        return True
    return any(m.mfa_required for m in memberships_for_user(user))


# --- Organisation lifecycle (Pulsar operators) ----------------------------------------------------


def _require_operator(user) -> None:
    if not (user and user.is_authenticated and user.is_active and user.is_platform_operator):
        raise PermissionDenied("Only a Pulsar operator can do this.")


def unique_slug(name: str) -> str:
    base = slugify(name)[:50] or "organisation"
    if base in RESERVED_SLUGS:
        base = f"{base}-org"
    slug, n = base, 2
    while Organisation.objects.filter(slug=slug).exists():
        slug, n = f"{base}-{n}", n + 1
    return slug


@transaction.atomic
def provision_organisation(*, name: str, owner_email: str, operator, slug: str = "", request=None):
    """Create an organisation and invite its first Owner. Returns (organisation, invitation, token)."""
    _require_operator(operator)
    name = name.strip()
    if not name:
        raise ValidationError("An organisation needs a name.")
    slug = slugify(slug) if slug else unique_slug(name)
    if slug in RESERVED_SLUGS or Organisation.objects.filter(slug=slug).exists():
        raise ValidationError("That address is taken.")
    organisation = Organisation.objects.create(name=name, slug=slug)
    with organisation_context(organisation):
        audit.record(
            "organisation.provisioned",
            request=request,
            actor=operator,
            actor_kind=AuditEvent.ActorKind.OPERATOR,
            target=organisation,
            target_label=name,
        )
        invitation, token = _create_invitation(
            email=owner_email, role=Role.OWNER, invited_by=operator, request=request, actor_kind="operator"
        )
    return organisation, invitation, token


@transaction.atomic
def suspend_organisation(organisation: Organisation, *, operator, reason: str, request=None) -> None:
    """Stop members using an organisation without removing anything. Gateways are not affected:
    a suspended organisation's doors keep working from their last synced state (rule 4)."""
    _require_operator(operator)
    organisation.status = Organisation.Status.SUSPENDED
    organisation.suspended_at = timezone.now()
    organisation.suspended_reason = reason[:255]
    organisation.save(update_fields=["status", "suspended_at", "suspended_reason", "updated_at"])
    revoke_tokens(organisation=organisation)
    audit.record(
        "organisation.suspended",
        request=request,
        actor=operator,
        actor_kind=AuditEvent.ActorKind.OPERATOR,
        organisation=organisation,
        target=organisation,
        data={"reason": reason[:255]},
    )


@transaction.atomic
def reactivate_organisation(organisation: Organisation, *, operator, request=None) -> None:
    _require_operator(operator)
    organisation.status = Organisation.Status.ACTIVE
    organisation.suspended_at = None
    organisation.suspended_reason = ""
    organisation.save(update_fields=["status", "suspended_at", "suspended_reason", "updated_at"])
    audit.record(
        "organisation.reactivated",
        request=request,
        actor=operator,
        actor_kind=AuditEvent.ActorKind.OPERATOR,
        organisation=organisation,
        target=organisation,
    )


# Never exported: values that would let the reader act as someone.
_EXPORT_EXCLUDED_FIELDS = frozenset({"token_hash", "password", "secret", "token"})


def _scoped_models():
    from django.apps import apps

    from hub.organisations.scoping import OrganisationScopedModel

    models = [m for m in apps.get_models() if issubclass(m, OrganisationScopedModel)]
    return sorted(models, key=lambda m: m._meta.label)


def export_organisation(organisation: Organisation, *, actor_user, request=None) -> dict:
    """Everything the hub holds for one organisation, as plain data.

    Walks every organisation-scoped model, so a model added in a later phase is exported without
    anyone remembering to add it here.
    """
    data: dict = {
        "format": "pulsar-hub-export/1",
        "exported_at": timezone.now().isoformat(),
        "organisation": {
            "org_ref": str(organisation.pk),
            "name": organisation.name,
            "slug": organisation.slug,
            "status": organisation.status,
            "staff_mfa_required": organisation.staff_mfa_required,
            "sso_required": organisation.sso_required,
            "created_at": organisation.created_at.isoformat(),
        },
        "records": {},
    }

    def rows(queryset, model):
        fields = [f for f in model._meta.concrete_fields if f.name not in _EXPORT_EXCLUDED_FIELDS]
        out = []
        for obj in queryset.iterator():
            row = {}
            for field in fields:
                value = field.value_from_object(obj)
                row[field.attname] = (
                    value if isinstance(value, (bool, int, float, dict, list, type(None))) else str(value)
                )
            out.append(row)
        return out

    for model in _scoped_models():
        # unscoped: export of one named organisation
        queryset = model.all_organisations.filter(organisation=organisation)
        data["records"][model._meta.label] = rows(queryset, model)
    # unscoped: export of one named organisation
    members = Membership.all_organisations.filter(organisation=organisation)
    data["records"]["accounts.User"] = [
        {"id": str(m.user_id), "email": m.user.email, "name": m.user.name} for m in members.select_related("user")
    ]
    # unscoped: export of one named organisation
    events = AuditEvent.all_organisations.filter(organisation=organisation)
    data["records"]["audit.AuditEvent"] = rows(events, AuditEvent)
    with organisation_context(organisation):
        audit.record("organisation.exported", request=request, actor=actor_user, target=organisation)
    return data


def delete_organisation(organisation: Organisation, *, operator, confirm_slug: str, request=None) -> None:
    """Remove an organisation and every row that belongs to it. This cannot be undone.

    The organisation's own audit rows go with it; one platform-level event remains to say that the
    deletion happened, when, and who did it.
    """
    _require_operator(operator)
    if confirm_slug != organisation.slug:
        raise ValidationError("Type the organisation's address to confirm.")
    org_ref, name, slug = str(organisation.pk), organisation.name, organisation.slug
    with transaction.atomic():
        Organisation.objects.filter(pk=organisation.pk).update(status=Organisation.Status.DELETING)
        with connection.cursor() as cursor:  # unscoped: lets this transaction remove the organisation's audit rows
            cursor.execute("SET LOCAL hub.audit_purge = 'on'")
        # Cascades through every foreign key to the organisation, tokens included.
        Organisation.objects.filter(pk=organisation.pk).delete()
        with connection.cursor() as cursor:  # unscoped: closes the audit purge window
            cursor.execute("SET LOCAL hub.audit_purge = 'off'")
        audit.record(
            "organisation.deleted",
            request=request,
            actor=operator,
            actor_kind=AuditEvent.ActorKind.OPERATOR,
            organisation=None,
            target_label=name,
            data={"org_ref": org_ref, "slug": slug},
        )
    logger.warning("organisation deleted", extra={"deleted_org_ref": org_ref})


# --- Operator visits ------------------------------------------------------------------------------


@transaction.atomic
def open_operator_access(organisation: Organisation, *, operator, reason: str, hours: int | None = None, request=None):
    _require_operator(operator)
    reason = (reason or "").strip()
    if len(reason) < 5:
        raise ValidationError("Give a reason for the visit; the organisation will see it.")
    hours = max(1, min(hours or settings.OPERATOR_ACCESS_MAX_HOURS, settings.OPERATOR_ACCESS_MAX_HOURS))
    with organisation_context(organisation):
        now = timezone.now()
        access = OperatorAccess.objects.create(
            operator=operator, reason=reason[:255], starts_at=now, expires_at=now + timedelta(hours=hours)
        )
        audit.record(
            "operator.access_opened",
            request=request,
            actor=operator,
            actor_kind=AuditEvent.ActorKind.OPERATOR,
            target=access,
            data={"reason": access.reason, "expires_at": access.expires_at.isoformat()},
        )
    return access


@transaction.atomic
def end_operator_access(access: OperatorAccess, *, ended_by, request=None) -> None:
    """End a visit early. The operator can, and so can an Owner of the organisation."""
    organisation = require_organisation()
    if access.organisation_id != organisation.pk:
        raise PermissionDenied
    if access.ended_at is not None:
        return
    access.ended_at = timezone.now()
    access.ended_by = ended_by
    access.save(update_fields=["ended_at", "ended_by"])
    audit.record("operator.access_ended", request=request, actor=ended_by, target=access)


# --- Members and invitations (inside the current organisation) ------------------------------------


def _may_grant(actor: Actor, role: Role) -> bool:
    """Admins manage Managers and Staff. Only an Owner makes Admins and Owners. Operators make none."""
    if actor.membership is not None and actor.membership.has_role(Role.OWNER):
        return True
    if actor.has_role(Role.ADMIN):
        return role in (Role.MANAGER, Role.STAFF)
    return False


def _create_invitation(*, email: str, role: Role, invited_by, request, actor_kind: str | None = None):
    organisation = require_organisation()
    email = email.strip().lower()
    if not email or "@" not in email:
        raise ValidationError("Enter an email address.")
    if Membership.objects.filter(user__email__iexact=email, is_active=True).exists():
        raise ValidationError("That person is already a member.")
    now = timezone.now()
    Invitation.objects.filter(email=email, accepted_at__isnull=True, revoked_at__isnull=True).update(revoked_at=now)
    token = Invitation.new_token()
    invitation = Invitation.objects.create(
        email=email,
        role=role,
        token_hash=hash_token(token),
        invited_by=invited_by,
        expires_at=Invitation.default_expiry(),
    )
    audit.record(
        "member.invited",
        request=request,
        actor=invited_by,
        actor_kind=actor_kind,
        target=invitation,
        target_label=email,
        data={"role": role},
    )
    link = settings.HUB_BASE_URL + reverse("invitation_accept", kwargs={"token": token})
    context = {
        "organisation": organisation,
        "role": Role(role).label,
        "link": link,
        "invited_by": invited_by,
        "expires_at": invitation.expires_at,
        "product_name": settings.PRODUCT_NAME,
    }
    send_mail(
        subject=f"[{settings.PRODUCT_NAME}] You have been invited to {organisation.name}",
        message=render_to_string("organisations/email/invitation.txt", context),
        from_email=None,
        recipient_list=[email],
    )
    return invitation, token


@transaction.atomic
def invite_member(*, actor: Actor, email: str, role: str, request=None):
    role = Role(role)
    if not _may_grant(actor, role):
        raise PermissionDenied("You cannot invite someone with that role.")
    return _create_invitation(email=email, role=role, invited_by=actor.user, request=request)


@transaction.atomic
def revoke_invitation(invitation: Invitation, *, actor: Actor, request=None) -> None:
    actor.require(Role.ADMIN)
    if not _may_grant(actor, Role(invitation.role)):
        raise PermissionDenied("You cannot revoke that invitation.")
    if invitation.accepted_at is None and invitation.revoked_at is None:
        invitation.revoked_at = timezone.now()
        invitation.save(update_fields=["revoked_at"])
        _audit(actor, "member.invitation_revoked", request=request, target=invitation, target_label=invitation.email)


@transaction.atomic
def accept_invitation(invitation: Invitation, *, user, request=None) -> Membership:
    """Turn an invitation into a membership. The login's email must be the invited address."""
    if not invitation.is_pending or not invitation.organisation.is_active:
        raise ValidationError("This invitation is no longer valid.")
    if user.email.lower() != invitation.email.lower():
        raise PermissionDenied("This invitation was sent to a different email address.")
    with organisation_context(invitation.organisation):
        locked = Invitation.objects.select_for_update().get(pk=invitation.pk)
        if not locked.is_pending:
            raise ValidationError("This invitation is no longer valid.")
        membership, created = Membership.objects.get_or_create(user=user, defaults={"role": locked.role})
        if not created:
            # A returning member: restore access with the invited role, never silently upgrade an
            # active one.
            if membership.is_active:
                raise ValidationError("You are already a member of this organisation.")
            membership.is_active = True
            membership.role = locked.role
            membership.save(update_fields=["is_active", "role", "updated_at"])
        locked.accepted_at = timezone.now()
        locked.accepted_by = user
        locked.save(update_fields=["accepted_at", "accepted_by"])
        audit.record(
            "member.joined",
            request=request,
            actor=user,
            target=membership,
            target_label=user.email,
            data={"role": membership.role},
        )
    return membership


def _active_owner_count() -> int:
    return Membership.objects.filter(role=Role.OWNER, is_active=True).count()


@transaction.atomic
def change_role(membership: Membership, *, actor: Actor, new_role: str, request=None) -> None:
    new_role = Role(new_role)
    old_role = membership.role_enum
    if membership.user_id == actor.user.pk:
        raise PermissionDenied("You cannot change your own role.")
    if not (_may_grant(actor, new_role) and _may_grant(actor, old_role)):
        raise PermissionDenied("You cannot make that change.")
    if old_role == new_role:
        return
    # Lock the organisation's owners so two demotions cannot race past the last-owner rule.
    list(Membership.objects.select_for_update().filter(role=Role.OWNER, is_active=True))
    if old_role == Role.OWNER and _active_owner_count() <= 1:
        raise ValidationError("An organisation must keep at least one Owner.")
    membership.role = new_role
    membership.save(update_fields=["role", "updated_at"])
    # Tokens carry the role as a claim; make clients fetch fresh ones.
    revoke_tokens(organisation=membership.organisation, user=membership.user)
    _audit(
        actor,
        "member.role_changed",
        request=request,
        target=membership,
        target_label=membership.user.email,
        data={"from": old_role, "to": new_role},
    )


@transaction.atomic
def remove_member(membership: Membership, *, actor: Actor, request=None) -> None:
    """End someone's access to this organisation. The login itself is untouched."""
    is_self = membership.user_id == actor.user.pk
    if not is_self and not _may_grant(actor, membership.role_enum):
        raise PermissionDenied("You cannot remove that member.")
    list(Membership.objects.select_for_update().filter(role=Role.OWNER, is_active=True))
    if membership.role_enum == Role.OWNER and membership.is_active and _active_owner_count() <= 1:
        raise ValidationError("An organisation must keep at least one Owner.")
    if not membership.is_active:
        return
    membership.is_active = False
    membership.save(update_fields=["is_active", "updated_at"])
    revoke_tokens(organisation=membership.organisation, user=membership.user)
    _audit(
        actor,
        "member.left" if is_self else "member.removed",
        request=request,
        target=membership,
        target_label=membership.user.email,
        data={"role": membership.role},
    )


@transaction.atomic
def update_security_settings(*, actor: Actor, staff_mfa_required: bool, sso_required: bool, request=None) -> None:
    if actor.membership is None or not actor.membership.has_role(Role.OWNER):
        raise PermissionDenied("Only an Owner can change sign-in rules.")
    organisation = require_organisation()
    if sso_required and not IdentityProvider.objects.exists():
        raise ValidationError("Add an identity provider before requiring single sign-on.")
    changes = {}
    for field, value in (("staff_mfa_required", staff_mfa_required), ("sso_required", sso_required)):
        if getattr(organisation, field) != value:
            changes[field] = {"from": getattr(organisation, field), "to": value}
            setattr(organisation, field, value)
    if changes:
        organisation.save(update_fields=[*changes, "updated_at"])
        _audit(actor, "organisation.security_changed", request=request, target=organisation, data=changes)


@transaction.atomic
def rename_organisation(*, actor: Actor, name: str, request=None) -> None:
    actor.require(Role.ADMIN)
    organisation = require_organisation()
    name = name.strip()
    if not name:
        raise ValidationError("An organisation needs a name.")
    if name != organisation.name:
        old = organisation.name
        organisation.name = name[:200]
        organisation.save(update_fields=["name", "updated_at"])
        _audit(actor, "organisation.renamed", request=request, target=organisation, data={"from": old, "to": name})


@transaction.atomic
def add_identity_provider(*, actor: Actor, provider: str, tenant: str, request=None) -> IdentityProvider:
    if actor.membership is None or not actor.membership.has_role(Role.OWNER):
        raise PermissionDenied("Only an Owner can change sign-in rules.")
    provider = IdentityProvider.Provider(provider)
    tenant = (tenant or "").strip().lower()
    if not tenant:
        raise ValidationError("Enter the tenant id or domain.")
    idp, created = IdentityProvider.objects.get_or_create(provider=provider, tenant=tenant)
    if created:
        _audit(
            actor,
            "organisation.identity_provider_added",
            request=request,
            target=idp,
            data={"provider": provider, "tenant": tenant},
        )
    return idp


@transaction.atomic
def remove_identity_provider(idp: IdentityProvider, *, actor: Actor, request=None) -> None:
    if actor.membership is None or not actor.membership.has_role(Role.OWNER):
        raise PermissionDenied("Only an Owner can change sign-in rules.")
    organisation = require_organisation()
    if organisation.sso_required and IdentityProvider.objects.count() <= 1:
        raise ValidationError("Turn off required single sign-on before removing the last identity provider.")
    data = {"provider": idp.provider, "tenant": idp.tenant}
    pk = idp.pk
    idp.delete()
    _audit(actor, "organisation.identity_provider_removed", request=request, target_label=str(pk), data=data)


# --- Tokens ---------------------------------------------------------------------------------------


def revoke_tokens(*, organisation: Organisation, user=None) -> None:
    """Delete OAuth tokens bound to an organisation, for one user or for everyone."""
    from hub.accounts.models import AccessToken, Grant, RefreshToken

    for model in (RefreshToken, AccessToken, Grant):
        queryset = model.objects.filter(organisation=organisation)
        if user is not None:
            queryset = queryset.filter(user=user)
        queryset.delete()
