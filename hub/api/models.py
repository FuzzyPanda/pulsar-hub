"""Service tokens: how another system (Pulsar Rostering) calls the hub for one organisation."""

import secrets
import uuid

from django.conf import settings
from django.contrib.postgres.fields import ArrayField
from django.db import models

from hub.organisations.scoping import OrganisationManager, OrganisationScopedModel


class Scope(models.TextChoices):
    DIRECTORY_READ = "directory:read", "Read people and sites"
    DIRECTORY_WRITE = "directory:write", "Send people and sites (Pulsar Rostering)"
    EVENTS_READ = "events:read", "Read door and attendance events"


def new_service_token() -> str:
    return "hubsvc_" + secrets.token_urlsafe(40)


class ServiceTokenManager(OrganisationManager):
    def live(self):
        return self.get_queryset().filter(revoked_at__isnull=True)


class ServiceToken(OrganisationScopedModel):
    """A bearer token for one organisation with a fixed list of scopes. Stored only as a digest;
    the token itself is shown once, when it is created."""

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=100)
    token_hash = models.CharField(max_length=64, unique=True, editable=False)
    scopes = ArrayField(models.CharField(max_length=32, choices=Scope.choices), default=list)
    created_by = models.ForeignKey(settings.AUTH_USER_MODEL, null=True, on_delete=models.SET_NULL, related_name="+")
    created_at = models.DateTimeField(auto_now_add=True)
    last_used_at = models.DateTimeField(null=True, blank=True)
    revoked_at = models.DateTimeField(null=True, blank=True)

    objects = ServiceTokenManager()

    class Meta:
        ordering = ["-created_at"]

    def __str__(self) -> str:
        return self.name

    @property
    def is_live(self) -> bool:
        return self.revoked_at is None

    def has_scope(self, scope: str) -> bool:
        return scope in self.scopes
