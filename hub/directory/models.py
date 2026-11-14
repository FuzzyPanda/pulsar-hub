"""People and sites: the two records every Pulsar product shares.

`Person.id` is the `person_ref` and `Site.id` the `site_ref` of docs/CONTRACTS.md. Where an
organisation's people and sites come from Pulsar Rostering, the ids are the ones Rostering minted,
so the same person has one id in every product.

Rule 11 lives here by omission: a person is a name, a work email and a status. Pay, bank details,
dates of birth, licences and home addresses are never stored in the hub, so they can never leave it.
"""

import uuid
import zoneinfo

from django.conf import settings
from django.core.exceptions import ValidationError
from django.db import models

from hub.organisations.scoping import OrganisationScopedModel


def validate_timezone(value: str) -> None:
    try:
        zoneinfo.ZoneInfo(value)
    except (KeyError, ValueError) as exc:
        raise ValidationError("Choose a time zone such as Australia/Melbourne.") from exc


class Site(OrganisationScopedModel):
    """A place with doors: a clinic, a depot, an office."""

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=200)
    address = models.CharField(max_length=300, blank=True)
    # For display only (rule 8): every stored and transmitted time is UTC.
    timezone = models.CharField(max_length=64, default="Australia/Melbourne", validators=[validate_timezone])
    is_active = models.BooleanField(default=True)
    # A site whose doors are run by another system (a PerfectGym site, rule 10). It gets sign-in
    # and rostering; it cannot be paired with a gateway and has no access features.
    access_managed_elsewhere = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["name"]

    def __str__(self) -> str:
        return self.name

    @property
    def site_ref(self) -> uuid.UUID:
        return self.id


class Person(OrganisationScopedModel):
    """A staff member or contractor. Not a login: a person may have one, and most never will."""

    class Status(models.TextChoices):
        ACTIVE = "active", "Active"
        ENDED = "ended", "Ended"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=200)
    work_email = models.EmailField(blank=True)
    status = models.CharField(max_length=16, choices=Status.choices, default=Status.ACTIVE)
    ended_at = models.DateTimeField(null=True, blank=True)
    # The person's current job positions ("Guard", "Supervisor"), as Pulsar Rostering last sent
    # them: plain names, sorted, no duplicates. Not a credential and not one of rule 11's fields.
    # An access group can name positions; holding one puts the person in that group
    # (hub.access.services.sync_position_memberships).
    positions = models.JSONField(default=list, blank=True)
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL, null=True, blank=True, on_delete=models.SET_NULL, related_name="+"
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["name"]

    def __str__(self) -> str:
        return self.name

    @property
    def person_ref(self) -> uuid.UUID:
        return self.id

    @property
    def is_active(self) -> bool:
        return self.status == self.Status.ACTIVE
