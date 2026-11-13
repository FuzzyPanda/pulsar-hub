"""The audit log (CLAUDE.md rule 7).

Append-only, at three levels:

* this model and its managers refuse to update or delete;
* a database trigger (migration 0002) refuses every UPDATE, and every DELETE outside the purge
  function below, so code that goes around the ORM is refused too;
* in production the application connects as a role that holds only INSERT and SELECT on this
  table (`manage.py grant_app_role`), so not even raw SQL from a compromised web process can
  rewrite or selectively remove events, or switch the trigger off.

The one way rows leave is `hub_purge_organisation_audit(org)`, a database function that removes
every event of an organisation that is being deleted. `delete_organisation` calls it and leaves a
platform-level record that the deletion happened.

Neither foreign key lets Django touch this table when something else is deleted: the organisation
must be purged first, and a deleted login simply leaves its id and `actor_label` behind.
"""

import uuid

from django.conf import settings
from django.db import models

from hub.organisations.context import require_organisation


class AuditQuerySet(models.QuerySet):
    def update(self, **kwargs):
        raise TypeError("Audit events are append-only.")

    def delete(self):
        raise TypeError("Audit events are append-only.")

    def bulk_update(self, *args, **kwargs):
        raise TypeError("Audit events are append-only.")


class OrganisationAuditManager(models.Manager.from_queryset(AuditQuerySet)):
    """Events of the current organisation only. Fails closed when there is none."""

    def get_queryset(self):
        return super().get_queryset().filter(organisation_id=require_organisation().pk)


class AllAuditManager(models.Manager.from_queryset(AuditQuerySet)):
    """Events of every organisation, and account-level and platform events."""

    use_in_migrations = False


class AuditEvent(models.Model):
    class ActorKind(models.TextChoices):
        USER = "user", "User"
        OPERATOR = "operator", "Pulsar operator"
        SYSTEM = "system", "System"
        SERVICE = "service", "Service token"
        GATEWAY = "gateway", "Gateway"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    occurred_at = models.DateTimeField(auto_now_add=True, db_index=True)
    # Null for account-level events (sign-in, password and MFA changes) and for platform events.
    organisation = models.ForeignKey(
        "organisations.Organisation", null=True, blank=True, on_delete=models.DO_NOTHING, related_name="+"
    )
    action = models.CharField(max_length=64, db_index=True)
    actor = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        blank=True,
        on_delete=models.DO_NOTHING,
        db_constraint=False,
        related_name="+",
    )
    actor_kind = models.CharField(max_length=16, choices=ActorKind.choices, default=ActorKind.USER)
    # Kept beside the foreign key so the record still reads after the account is gone.
    actor_label = models.CharField(max_length=254, blank=True)
    target_type = models.CharField(max_length=64, blank=True)
    target_ref = models.CharField(max_length=64, blank=True)
    target_label = models.CharField(max_length=254, blank=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.CharField(max_length=255, blank=True)
    request_id = models.CharField(max_length=64, blank=True)
    # Small, non-sensitive detail: old and new role, a reason, an expiry. Never a secret, a token,
    # a card number, or anything named in rule 11.
    data = models.JSONField(default=dict, blank=True)

    objects = OrganisationAuditManager()
    all_organisations = AllAuditManager()

    class Meta:
        default_manager_name = "objects"
        ordering = ["-occurred_at", "-id"]
        indexes = [models.Index(fields=["organisation", "-occurred_at"])]

    def __str__(self) -> str:
        return f"{self.occurred_at:%Y-%m-%dT%H:%M:%SZ} {self.action}"

    def save(self, *args, **kwargs):
        if not self._state.adding:
            raise TypeError("Audit events are append-only.")
        super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        raise TypeError("Audit events are append-only.")
