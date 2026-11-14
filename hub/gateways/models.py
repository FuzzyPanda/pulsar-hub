"""Pulsar Access Control gateways: pairing, what each has applied, and what each reports.

A gateway always dials out (rule 3). The hub holds nothing that lets it reach a site, and it
never receives a card number, a PIN or a credential hash (rule 2). The remote console
(`hub.console`) runs down a connection the gateway itself opened.
"""

import secrets
import uuid

from django.conf import settings
from django.db import models
from django.utils import timezone

from hub.organisations.scoping import OrganisationManager, OrganisationScopedModel

# Easy to read aloud and type on a gateway's setup screen: no 0/O, 1/I/L.
_CODE_ALPHABET = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"


def new_pairing_code() -> str:
    """Twelve characters in three groups, about 59 bits. Valid for minutes and usable once."""
    raw = "".join(secrets.choice(_CODE_ALPHABET) for _ in range(12))
    return f"{raw[0:4]}-{raw[4:8]}-{raw[8:12]}"


def normalise_pairing_code(code: str) -> str:
    raw = "".join(ch for ch in (code or "").upper() if ch.isalnum())
    return f"{raw[0:4]}-{raw[4:8]}-{raw[8:12]}" if len(raw) == 12 else ""


def new_gateway_credential() -> str:
    return "hubgw_" + secrets.token_urlsafe(40)


class PairingCode(OrganisationScopedModel):
    """A one-time code an organisation admin creates for a site and an installer types into the gateway."""

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    site = models.ForeignKey("directory.Site", on_delete=models.CASCADE, related_name="pairing_codes")
    code_hash = models.CharField(max_length=64, unique=True, editable=False)
    created_by = models.ForeignKey(settings.AUTH_USER_MODEL, null=True, on_delete=models.SET_NULL, related_name="+")
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()
    used_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ["-created_at"]

    def __str__(self) -> str:
        return f"pairing code {self.id}"

    @property
    def is_usable(self) -> bool:
        return self.used_at is None and self.expires_at > timezone.now()


class GatewayManager(OrganisationManager):
    def live(self):
        return self.get_queryset().filter(revoked_at__isnull=True)


class Gateway(OrganisationScopedModel):
    """One paired gateway. Its credential is bound to one organisation and one site, stored only as a digest."""

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    site = models.ForeignKey("directory.Site", on_delete=models.CASCADE, related_name="gateways")
    name = models.CharField(max_length=100, blank=True)
    credential_hash = models.CharField(max_length=64, unique=True, editable=False)
    paired_at = models.DateTimeField(auto_now_add=True)
    paired_by_code = models.ForeignKey(PairingCode, null=True, on_delete=models.SET_NULL, related_name="+")
    revoked_at = models.DateTimeField(null=True, blank=True)
    revoked_by = models.ForeignKey(settings.AUTH_USER_MODEL, null=True, on_delete=models.SET_NULL, related_name="+")

    # The remote-console tunnel: a connection the gateway opened to the hub's relay and keeps open
    # (rule 3 as amended: the gateway dials, the hub answers down that connection). These are what
    # the relay last reported, written by `hub.console.services`; none of it is a setting.
    tunnel_connected = models.BooleanField(default=False)
    tunnel_changed_at = models.DateTimeField(null=True, blank=True)
    tunnel_seen_at = models.DateTimeField(null=True, blank=True)
    # The protocol version last agreed. Blank until this gateway has opened a tunnel at all.
    tunnel_protocol = models.CharField(max_length=32, blank=True)
    # The relay's name for the connection that is open now. A report that an earlier connection
    # closed, arriving late, is recognised by it and ignored.
    tunnel_id = models.CharField(max_length=32, blank=True)
    # Whether the gateway says its remote console is switched on. Set on the gateway, by someone
    # on site, and off unless they did: the hub can read it and cannot change it.
    console_enabled = models.BooleanField(default=False)

    # What the gateway last told us.
    last_seen_at = models.DateTimeField(null=True, blank=True)
    software_version = models.CharField(max_length=64, blank=True)
    applied_version = models.CharField(max_length=64, blank=True)
    applied_at = models.DateTimeField(null=True, blank=True)
    apply_failures = models.JSONField(default=list, blank=True)
    state = models.JSONField(default=dict, blank=True)
    state_reported_at = models.DateTimeField(null=True, blank=True)

    objects = GatewayManager()

    class Meta:
        ordering = ["paired_at"]
        constraints = [
            # A site has at most one live gateway. Pairing a new one means revoking the old.
            models.UniqueConstraint(
                fields=["site"], condition=models.Q(revoked_at__isnull=True), name="gateways_one_live_gateway_per_site"
            ),
        ]

    def __str__(self) -> str:
        return self.name or f"gateway {self.id}"

    @property
    def is_live(self) -> bool:
        return self.revoked_at is None

    def is_in_contact(self, *, now=None) -> bool:
        if self.last_seen_at is None:
            return False
        limit = timezone.timedelta(seconds=settings.GATEWAY_OUT_OF_CONTACT_SECONDS)
        return (now or timezone.now()) - self.last_seen_at < limit


class GatewayEvent(OrganisationScopedModel):
    """Something a gateway reported: a clock-in at a door, access applied, a door forced.

    `event_id` is the id the gateway gave the event and is the idempotency key (rule 9): the same
    event received twice is stored once. `id` only orders events for readers that follow the
    stream with a cursor.
    """

    id = models.BigAutoField(primary_key=True)
    event_id = models.UUIDField(editable=False)
    type = models.CharField(max_length=48, db_index=True)
    occurred_at = models.DateTimeField()
    received_at = models.DateTimeField(auto_now_add=True)
    site = models.ForeignKey("directory.Site", on_delete=models.CASCADE, related_name="events")
    gateway = models.ForeignKey(Gateway, null=True, on_delete=models.SET_NULL, related_name="events")
    person = models.ForeignKey(
        "directory.Person", null=True, blank=True, on_delete=models.SET_NULL, related_name="events"
    )
    data = models.JSONField(default=dict, blank=True)

    class Meta:
        ordering = ["-occurred_at", "-id"]
        constraints = [
            models.UniqueConstraint(fields=["organisation", "event_id"], name="gateways_event_id_unique"),
        ]
        indexes = [models.Index(fields=["organisation", "site", "-occurred_at"])]

    def __str__(self) -> str:
        return f"{self.type} {self.event_id}"
