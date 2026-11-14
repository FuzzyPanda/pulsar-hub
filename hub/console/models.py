"""Remote console sessions: one person, one gateway, one browser, for a short time.

The owner decided on 2026-11-14 that a gateway's own web console may be reached through the hub
(CLAUDE.md rule 3 as amended; `docs/DECISIONS.md` D7). The gateway still dials out: it keeps a
tunnel open to the hub's relay, and the relay carries a signed-in person's requests down it. A row
here is the hub's record of one such session, and nothing is relayed without a live one.

No secret is stored: the hand-off token, the browser's console cookie and the hub browser session
it was opened from are each kept only as a SHA-256 digest.
"""

import uuid

from django.conf import settings
from django.db import models
from django.utils import timezone

from hub.organisations.models import Role
from hub.organisations.scoping import OrganisationManager, OrganisationScopedModel


class ConsoleSessionManager(OrganisationManager):
    def live(self):
        """Started (or about to be) and not yet over. Expiry is by the clock, whether or not
        anything has got round to recording it."""
        return self.get_queryset().filter(ended_at__isnull=True, expires_at__gt=timezone.now())


class ConsoleSession(OrganisationScopedModel):
    class EndReason(models.TextChoices):
        EXPIRED = "expired", "It reached its time limit"
        USER = "user", "Ended by the person using it"
        ADMIN = "admin", "Ended from the hub by an Owner or Admin"
        REPLACED = "replaced", "The same person opened a new session"
        GATEWAY_REVOKED = "gateway_revoked", "The gateway was revoked"
        TUNNEL_DROPPED = "tunnel_dropped", "The gateway's connection dropped"
        GATEWAY_ENDED = "gateway_ended", "Ended on the gateway"
        GATEWAY_REFUSED = "gateway_refused", "The gateway did not accept it"
        MEMBERSHIP_CHANGED = "membership_changed", "The person's membership or role changed"
        SIGNED_OUT = "signed_out", "The person signed out of the hub"
        HUB_SESSION_ENDED = "hub_session_ended", "The hub sign-in it was opened from ended"
        ORGANISATION_CLOSED = "organisation_closed", "The organisation or site was closed"
        NOT_OPENED = "not_opened", "The browser never opened it"
        RELAY_RESTARTED = "relay_restarted", "The hub's relay restarted"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    gateway = models.ForeignKey("gateways.Gateway", on_delete=models.CASCADE, related_name="console_sessions")
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="+")
    # The role the person held when the session started. A session never outlives a change to it.
    role = models.CharField(max_length=16, choices=Role.choices)
    # The console origin this session is served on; its cookie means nothing anywhere else.
    origin = models.CharField(max_length=300)

    created_at = models.DateTimeField(auto_now_add=True)
    # Set when the gateway has accepted the session. Until then nothing can be relayed.
    started_at = models.DateTimeField(null=True, blank=True)
    expires_at = models.DateTimeField()
    extended_count = models.PositiveSmallIntegerField(default=0)
    ended_at = models.DateTimeField(null=True, blank=True)
    end_reason = models.CharField(max_length=32, choices=EndReason.choices, blank=True)
    ended_by = models.ForeignKey(settings.AUTH_USER_MODEL, null=True, on_delete=models.SET_NULL, related_name="+")

    # The single-use hand-off from the hub's origin to the console origin.
    token_hash = models.CharField(max_length=64, unique=True, editable=False)
    handoff_expires_at = models.DateTimeField()
    handoff_used_at = models.DateTimeField(null=True, blank=True)
    # What binds the session to one browser: its cookie on the console origin (set at hand-off),
    # and the hub sign-in it was opened from.
    cookie_hash = models.CharField(max_length=64, blank=True, editable=False)
    browser_hash = models.CharField(max_length=64, editable=False)
    client_ip = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.CharField(max_length=255, blank=True)

    objects = ConsoleSessionManager()

    class Meta:
        ordering = ["-created_at"]
        indexes = [models.Index(fields=["organisation", "gateway", "ended_at"])]

    def __str__(self) -> str:
        return f"console session {self.id}"

    @property
    def is_live(self) -> bool:
        return self.ended_at is None and self.expires_at > timezone.now()
