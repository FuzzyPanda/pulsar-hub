"""The audit log (CLAUDE.md rule 7).

Append-only. The model refuses updates and deletes, and a database trigger (migration 0002)
refuses them too, so a bug or a shell session cannot quietly rewrite history. The single
exception is deleting a whole organisation, which removes that organisation's rows inside one
transaction that sets `hub.audit_purge` and leaves a platform-level record of the deletion.
"""

import uuid

from django.conf import settings
from django.db import models

from hub.organisations.scoping import AllOrganisationsManager, OrganisationManager


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
        "organisations.Organisation", null=True, blank=True, on_delete=models.CASCADE, related_name="+"
    )
    action = models.CharField(max_length=64, db_index=True)
    actor = models.ForeignKey(
        settings.AUTH_USER_MODEL, null=True, blank=True, on_delete=models.SET_NULL, related_name="+"
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

    objects = OrganisationManager()
    all_organisations = AllOrganisationsManager()

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
