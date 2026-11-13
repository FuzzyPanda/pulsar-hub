"""Organisations, who belongs to them, and how Pulsar's own staff are let in."""

import hashlib
import secrets
import uuid
from datetime import timedelta

from django.conf import settings
from django.db import models
from django.utils import timezone

from hub.organisations.scoping import OrganisationManager, OrganisationScopedModel


class Organisation(models.Model):
    """One client business. `id` is the `org_ref` of docs/CONTRACTS.md."""

    class Status(models.TextChoices):
        ACTIVE = "active", "Active"
        SUSPENDED = "suspended", "Suspended"
        DELETING = "deleting", "Being deleted"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=200)
    slug = models.SlugField(max_length=63, unique=True, help_text="Used in console addresses: /org/<slug>/")
    status = models.CharField(max_length=16, choices=Status.choices, default=Status.ACTIVE)
    suspended_at = models.DateTimeField(null=True, blank=True)
    suspended_reason = models.CharField(max_length=255, blank=True)

    # Decision D6: MFA is always required for Owner, Admin and Manager. For Staff each
    # organisation chooses; the default is off.
    staff_mfa_required = models.BooleanField(default=False)
    # When set, members must sign in through one of the organisation's identity providers, so an
    # account disabled in the client's directory can no longer get in.
    sso_required = models.BooleanField(default=False)

    # Decision D3: one product owns people and sites for an organisation, never both. An
    # organisation that rosters keeps them in Pulsar Rostering, which sends the hub a copy; the hub
    # then refuses edits of its own. Access groups are always the hub's.
    class DirectorySource(models.TextChoices):
        HUB = "hub", "Pulsar Hub"
        ROSTERING = "rostering", "Pulsar Rostering"

    directory_source = models.CharField(max_length=16, choices=DirectorySource.choices, default=DirectorySource.HUB)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["name"]

    def __str__(self) -> str:
        return self.name

    @property
    def org_ref(self) -> uuid.UUID:
        return self.id

    @property
    def is_active(self) -> bool:
        return self.status == self.Status.ACTIVE


class Role(models.TextChoices):
    OWNER = "owner", "Owner"
    ADMIN = "admin", "Admin"
    MANAGER = "manager", "Manager"
    STAFF = "staff", "Staff"

    @property
    def rank(self) -> int:
        return _ROLE_RANK[self.value]

    def at_least(self, other: "Role | str") -> bool:
        return self.rank >= Role(other).rank


_ROLE_RANK = {"staff": 10, "manager": 20, "admin": 30, "owner": 40}
# Roles that must always have MFA (PLAN H1, decision D6).
MFA_REQUIRED_ROLES = frozenset({Role.OWNER, Role.ADMIN, Role.MANAGER})


class Membership(OrganisationScopedModel):
    """A login's place in one organisation. One login can hold memberships in several."""

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="memberships")
    role = models.CharField(max_length=16, choices=Role.choices, default=Role.STAFF)
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(fields=["organisation", "user"], name="organisations_membership_unique"),
        ]
        ordering = ["created_at"]

    def __str__(self) -> str:
        return f"{self.user_id} {self.role}"

    @property
    def role_enum(self) -> Role:
        return Role(self.role)

    def has_role(self, minimum: Role | str) -> bool:
        return self.is_active and self.role_enum.at_least(minimum)

    @property
    def mfa_required(self) -> bool:
        return self.role_enum in MFA_REQUIRED_ROLES or self.organisation.staff_mfa_required


def hash_token(token: str) -> str:
    """Invitation links and similar bearer values are stored only as a SHA-256 digest.

    The tokens are 256 bits of randomness, so a plain digest is enough; there is nothing to
    brute-force and a lookup by digest stays a single indexed query.
    """
    return hashlib.sha256(token.encode()).hexdigest()


class Invitation(OrganisationScopedModel):
    """An emailed link that lets one address join one organisation with one role."""

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    email = models.EmailField()
    role = models.CharField(max_length=16, choices=Role.choices, default=Role.STAFF)
    token_hash = models.CharField(max_length=64, unique=True, editable=False)
    invited_by = models.ForeignKey(settings.AUTH_USER_MODEL, null=True, on_delete=models.SET_NULL, related_name="+")
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()
    accepted_at = models.DateTimeField(null=True, blank=True)
    accepted_by = models.ForeignKey(settings.AUTH_USER_MODEL, null=True, on_delete=models.SET_NULL, related_name="+")
    revoked_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ["-created_at"]

    def __str__(self) -> str:
        return f"invitation {self.id}"

    @staticmethod
    def new_token() -> str:
        return secrets.token_urlsafe(32)

    @staticmethod
    def default_expiry():
        return timezone.now() + timedelta(days=settings.INVITATION_EXPIRY_DAYS)

    @property
    def is_pending(self) -> bool:
        return self.accepted_at is None and self.revoked_at is None and self.expires_at > timezone.now()


class IdentityProvider(OrganisationScopedModel):
    """A directory whose users may sign in to this organisation with Microsoft or Google.

    This row holds no secret. Pulsar's own application registration (in the environment) does the
    OAuth exchange; this row only says which Entra tenant or Google Workspace domain belongs to
    the organisation. It never creates a membership: people still join by invitation.
    """

    class Provider(models.TextChoices):
        MICROSOFT = "microsoft", "Microsoft Entra"
        GOOGLE = "google", "Google Workspace"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    provider = models.CharField(max_length=16, choices=Provider.choices)
    # Microsoft: the Entra tenant id (a GUID). Google: the Workspace primary domain (the `hd` claim).
    tenant = models.CharField(max_length=255)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["organisation", "provider", "tenant"], name="organisations_identityprovider_unique"
            ),
        ]

    def __str__(self) -> str:
        return f"{self.provider}:{self.tenant}"

    def save(self, *args, **kwargs):
        self.tenant = (self.tenant or "").strip().lower()
        super().save(*args, **kwargs)


class OperatorAccessManager(OrganisationManager):
    def active(self):
        now = timezone.now()
        return self.get_queryset().filter(ended_at__isnull=True, starts_at__lte=now, expires_at__gt=now)


class OperatorAccess(OrganisationScopedModel):
    """A time-limited, audited visit to an organisation by one of Pulsar's own staff.

    Being a platform operator opens no organisation by itself. An operator opens a visit with a
    reason; it lasts at most OPERATOR_ACCESS_MAX_HOURS, shows in the organisation's audit log, and
    can be ended early by the operator or by the organisation's owner.
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    operator = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="+")
    reason = models.CharField(max_length=255)
    starts_at = models.DateTimeField(default=timezone.now)
    expires_at = models.DateTimeField()
    ended_at = models.DateTimeField(null=True, blank=True)
    ended_by = models.ForeignKey(settings.AUTH_USER_MODEL, null=True, on_delete=models.SET_NULL, related_name="+")

    objects = OperatorAccessManager()

    class Meta:
        ordering = ["-starts_at"]

    def __str__(self) -> str:
        return f"operator access {self.id}"

    @property
    def is_active(self) -> bool:
        now = timezone.now()
        return self.ended_at is None and self.starts_at <= now < self.expires_at
