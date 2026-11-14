"""Pairing gateways and taking in what they report.

The rules that shape this file (CLAUDE.md): a gateway always dials out; the hub being down never
stops a door; everything inbound is idempotent; and the hub never receives a card number, a PIN
or a credential hash. The last is enforced, not assumed: event and state payloads are checked
against fixed lists of allowed keys, and anything else is refused.
"""

import hashlib
import hmac
import re
import uuid
from datetime import timedelta

from django.conf import settings
from django.core.exceptions import PermissionDenied, ValidationError
from django.db import IntegrityError, transaction
from django.utils import timezone
from django.utils.dateparse import parse_datetime

from hub.audit import services as audit
from hub.audit.models import AuditEvent
from hub.directory.models import Person, Site
from hub.gateways.models import (
    Gateway,
    GatewayEvent,
    PairingCode,
    new_gateway_credential,
    new_pairing_code,
    normalise_pairing_code,
)
from hub.organisations.context import organisation_context, require_organisation
from hub.organisations.models import Role, hash_token
from hub.organisations.services import Actor, _audit

# --- pairing --------------------------------------------------------------------------------------


@transaction.atomic
def create_pairing_code(site: Site, *, actor: Actor, request=None) -> tuple[PairingCode, str]:
    """Make a one-time code for `site`. Returns the row and the code; the code is shown once."""
    actor.require_member(Role.ADMIN)
    if site.access_managed_elsewhere:
        raise ValidationError("This site's doors are managed by another system, so it cannot be paired.")
    if not site.is_active:
        raise ValidationError("This site is not active.")
    # One outstanding code per site: making a new one cancels the last.
    PairingCode.objects.filter(site=site, used_at__isnull=True).update(expires_at=timezone.now())
    code = new_pairing_code()
    pairing = PairingCode.objects.create(
        site=site,
        code_hash=hash_token(code),
        created_by=actor.user,
        expires_at=timezone.now() + timedelta(minutes=settings.PAIRING_CODE_MINUTES),
    )
    _audit(actor, "gateway.pairing_code_created", request=request, target=site, target_label=site.name)
    return pairing, code


def pair_gateway(*, code: str, name: str = "", software_version: str = "", request=None) -> tuple[Gateway, str]:
    """Exchange a one-time code for a long-lived credential bound to one organisation and one site.

    Called by the gateway itself, before any organisation is known. Every way of failing gives the
    same answer, so the endpoint says nothing about which codes exist.
    """
    refusal = PermissionDenied("That pairing code is not valid.")
    code = normalise_pairing_code(code)
    if not code:
        raise refusal
    pairing = (
        PairingCode.all_organisations.filter(code_hash=hash_token(code))  # unscoped: looked up by its secret code
        .select_related("organisation", "site")
        .first()
    )
    if pairing is None or not pairing.organisation.is_active:
        raise refusal
    with organisation_context(pairing.organisation), transaction.atomic():
        pairing = PairingCode.objects.select_for_update().select_related("site").get(pk=pairing.pk)
        site = pairing.site
        if not pairing.is_usable or site.access_managed_elsewhere or not site.is_active:
            raise refusal
        now = timezone.now()
        # A site has one live gateway. Pairing a replacement revokes the one before it.
        for old in Gateway.objects.live().filter(site=site):
            old.revoked_at = now
            old.save(update_fields=["revoked_at"])
            _close_remote_console(old, request=request)
            audit.record(
                "gateway.revoked",
                request=request,
                actor=None,
                actor_kind=AuditEvent.ActorKind.GATEWAY,
                target=old,
                target_label=site.name,
                data={"reason": "replaced by a newly paired gateway"},
            )
        credential = new_gateway_credential()
        gateway = Gateway.objects.create(
            site=site,
            name=(name or "").strip()[:100],
            software_version=(software_version or "").strip()[:64],
            credential_hash=hash_token(credential),
            paired_by_code=pairing,
            last_seen_at=now,
        )
        pairing.used_at = now
        pairing.save(update_fields=["used_at"])
        audit.record(
            "gateway.paired",
            request=request,
            actor=None,
            actor_kind=AuditEvent.ActorKind.GATEWAY,
            target=gateway,
            target_label=site.name,
            data={"name": gateway.name, "code_created_by": getattr(pairing.created_by, "email", "")},
        )
    return gateway, credential


def find_gateway(credential: str) -> Gateway | None:
    """The live gateway that holds `credential`, or None."""
    if not credential or not credential.startswith("hubgw_"):
        return None
    gateway = (
        Gateway.all_organisations.filter(  # unscoped: looked up by its secret credential
            credential_hash=hash_token(credential), revoked_at__isnull=True
        )
        .select_related("organisation", "site")
        .first()
    )
    if gateway is None or not gateway.organisation.is_active or not gateway.site.is_active:
        return None
    return gateway


@transaction.atomic
def revoke_gateway(gateway: Gateway, *, actor: Actor, request=None) -> None:
    """Stop accepting a gateway. It keeps its last synced people and follows its own fail policy;
    nothing about its doors changes because the hub stopped listening (rule 4)."""
    actor.require_member(Role.ADMIN)
    if gateway.revoked_at is None:
        gateway.revoked_at, gateway.revoked_by = timezone.now(), actor.user
        gateway.save(update_fields=["revoked_at", "revoked_by"])
        _audit(actor, "gateway.revoked", request=request, target=gateway, target_label=gateway.site.name)
        _close_remote_console(gateway, request=request, ended_by=actor.user)


def _close_remote_console(gateway: Gateway, *, request=None, ended_by=None) -> None:
    """A revoked gateway's remote console sessions end and its tunnel is closed, at once."""
    from hub.console import services as console

    console.gateway_revoked(gateway, request=request, ended_by=ended_by)


def touch(gateway: Gateway, *, software_version: str = "") -> None:
    """Note that the gateway called. Written at most twice a minute; a poll is otherwise read-only."""
    now = timezone.now()
    fields = {}
    if gateway.last_seen_at is None or now - gateway.last_seen_at > timedelta(seconds=30):
        fields["last_seen_at"] = now
    if software_version and software_version[:64] != gateway.software_version:
        fields["software_version"] = software_version[:64]
    if fields:
        Gateway.objects.filter(pk=gateway.pk).update(**fields)
        for key, value in fields.items():
            setattr(gateway, key, value)


# --- acknowledgement ------------------------------------------------------------------------------


@transaction.atomic
def record_ack(gateway: Gateway, *, version: str, failures: list) -> None:
    """The gateway has applied `version`. Per-person failures are kept so the console can show them."""
    version = str(version or "")[:64]
    if not re.fullmatch(r"[0-9a-f]{8,64}", version):
        raise ValidationError("version is not a version this hub issued.")
    cleaned = []
    for item in (failures or [])[:500]:
        if not isinstance(item, dict):
            raise ValidationError("failures must be a list of objects.")
        try:
            ref = str(uuid.UUID(str(item.get("person_ref"))))
        except (ValueError, TypeError) as exc:
            raise ValidationError("A failure names something that is not a person_ref.") from exc
        cleaned.append({"person_ref": ref, "reason": str(item.get("reason") or "")[:200]})
    changed = gateway.applied_version != version or gateway.apply_failures != cleaned
    gateway.applied_version, gateway.applied_at, gateway.apply_failures = version, timezone.now(), cleaned
    gateway.save(update_fields=["applied_version", "applied_at", "apply_failures"])
    if changed:
        audit.record(
            "access.applied",
            actor=None,
            actor_kind=AuditEvent.ActorKind.GATEWAY,
            target=gateway,
            target_label=gateway.site.name,
            data={"version": version, "failures": len(cleaned)},
        )


# --- events ---------------------------------------------------------------------------------------

# Every event type the hub accepts, and the only keys its `data` may carry. Nothing here can hold
# a card number, a PIN or a credential hash, and a key that is not listed is refused (rule 2).
_DOOR = {"door": 100, "door_ref": 64}
EVENT_DATA_KEYS: dict[str, dict[str, int]] = {
    "attendance.clock_in": {**_DOOR},
    "attendance.clock_out": {**_DOOR},
    "access.applied": {"version": 64},
    "access.revoked": {"version": 64},
    "door.forced": {**_DOOR},
    "door.held_open": {**_DOOR, "seconds": 0},
    "gateway.health": {"status": 32, "detail": 200},
}
PERSON_REQUIRED = {"attendance.clock_in", "attendance.clock_out"}
MAX_EVENTS_PER_BATCH = 500
MAX_CLOCK_SKEW = timedelta(minutes=5)


def verify_signature(*, credential: str, body: bytes, header: str) -> bool:
    """`X-Hub-Signature: sha256=<hex>` is HMAC-SHA256 of the raw body, keyed with the pairing
    credential. The hub keeps only a digest of the credential, so it checks the signature with
    the credential presented on this same request."""
    if not header or not header.startswith("sha256="):
        return False
    expected = hmac.new(credential.encode(), body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, header[len("sha256=") :].strip().lower())


def _clean_data(event_type: str, data) -> dict:
    allowed = EVENT_DATA_KEYS[event_type]
    if data is None:
        return {}
    if not isinstance(data, dict):
        raise ValidationError("data must be an object")
    cleaned = {}
    for key, value in data.items():
        if key not in allowed:
            raise ValidationError(f"data.{key} is not accepted for {event_type}")
        limit = allowed[key]
        if limit == 0:
            if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= 10_000_000:
                raise ValidationError(f"data.{key} must be a whole number")
            cleaned[key] = value
        else:
            if not isinstance(value, str):
                raise ValidationError(f"data.{key} must be text")
            cleaned[key] = value[:limit]
    return cleaned


def ingest_events(gateway: Gateway, events: list) -> dict:
    """Store a batch of events from `gateway`. Returns counts and the events it refused.

    One bad event does not sink the batch: each is judged alone, so a gateway that queued events
    while the hub was unreachable can always drain its queue. An event already held (same id) is a
    duplicate and changes nothing.
    """
    organisation = require_organisation()
    if not isinstance(events, list):
        raise ValidationError("events must be a list.")
    if len(events) > MAX_EVENTS_PER_BATCH:
        raise ValidationError(f"At most {MAX_EVENTS_PER_BATCH} events in one batch.")
    now = timezone.now()
    accepted, duplicates, rejected = 0, 0, []
    refs = set()
    for event in events:
        if isinstance(event, dict) and event.get("person_ref"):
            try:
                refs.add(uuid.UUID(str(event["person_ref"])))
            except (ValueError, TypeError):
                pass
    people = {p.pk: p for p in Person.objects.filter(pk__in=refs)}

    for event in events:
        event_id = event.get("id") if isinstance(event, dict) else None
        try:
            if not isinstance(event, dict):
                raise ValidationError("not an object")
            try:
                event_uuid = uuid.UUID(str(event_id))
            except (ValueError, TypeError) as exc:
                raise ValidationError("id is not a UUID") from exc
            event_type = event.get("type")
            if event_type not in EVENT_DATA_KEYS:
                raise ValidationError("unknown type")
            # The envelope must name the organisation and site this gateway is paired to.
            if str(event.get("org_ref")) != str(organisation.pk) or str(event.get("site_ref")) != str(gateway.site_id):
                raise ValidationError("org_ref or site_ref does not match this gateway's pairing")
            occurred_at = parse_datetime(str(event.get("occurred_at") or ""))
            if occurred_at is None or occurred_at.tzinfo is None:
                raise ValidationError("occurred_at must be RFC 3339 with a time zone")
            if occurred_at - now > MAX_CLOCK_SKEW:
                raise ValidationError("occurred_at is in the future")
            person = None
            if event.get("person_ref"):
                try:
                    person = people.get(uuid.UUID(str(event["person_ref"])))
                except (ValueError, TypeError):
                    person = None
                if person is None:
                    raise ValidationError("person_ref is not a person of this organisation")
            elif event_type in PERSON_REQUIRED:
                raise ValidationError("person_ref is required for this type")
            data = _clean_data(event_type, event.get("data"))
            try:
                with transaction.atomic():
                    GatewayEvent.objects.create(
                        event_id=event_uuid,
                        type=event_type,
                        occurred_at=occurred_at,
                        site=gateway.site,
                        gateway=gateway,
                        person=person,
                        data=data,
                    )
                accepted += 1
            except IntegrityError:
                duplicates += 1
        except ValidationError as exc:
            rejected.append({"id": str(event_id) if event_id is not None else None, "reason": "; ".join(exc.messages)})
    return {"accepted": accepted, "duplicates": duplicates, "rejected": rejected}


# --- state snapshot (phase H4) --------------------------------------------------------------------

DOOR_STATES = {"locked", "unlocked", "open", "held_open", "forced", "fault", "lockdown", "unknown"}


@transaction.atomic
def record_state(gateway: Gateway, payload: dict) -> None:
    """The gateway's latest picture of its doors and itself. Replaces the one before; never history."""
    if not isinstance(payload, dict):
        raise ValidationError("The state must be an object.")
    doors = payload.get("doors") or []
    if not isinstance(doors, list) or len(doors) > 500:
        raise ValidationError("doors must be a list of at most 500 doors.")
    cleaned_doors = []
    for door in doors:
        if not isinstance(door, dict) or set(door) - {"door_ref", "name", "state", "mode"}:
            raise ValidationError("A door may carry only door_ref, name, state and mode.")
        state = str(door.get("state") or "unknown")
        if state not in DOOR_STATES:
            raise ValidationError(f"Door state must be one of: {', '.join(sorted(DOOR_STATES))}.")
        cleaned_doors.append(
            {
                "door_ref": str(door.get("door_ref") or "")[:64],
                "name": str(door.get("name") or "")[:100],
                "state": state,
                "mode": str(door.get("mode") or "")[:32],
            }
        )
    health = payload.get("health") or {}
    if not isinstance(health, dict) or set(health) - {"status", "detail", "queued_events"}:
        raise ValidationError("health may carry only status, detail and queued_events.")
    queued = health.get("queued_events", 0)
    if isinstance(queued, bool) or not isinstance(queued, int) or queued < 0:
        raise ValidationError("health.queued_events must be a whole number.")
    gateway.state = {
        "doors": cleaned_doors,
        "health": {
            "status": str(health.get("status") or "")[:32],
            "detail": str(health.get("detail") or "")[:200],
            "queued_events": queued,
        },
    }
    gateway.state_reported_at = timezone.now()
    gateway.save(update_fields=["state", "state_reported_at"])


# --- read side for the console --------------------------------------------------------------------


def people_on_site(site: Site, *, hours: int = 18) -> list[dict]:
    """Who is on site: each person whose latest clock event here, within `hours`, was a clock-in."""
    since = timezone.now() - timedelta(hours=hours)
    latest: dict = {}
    events = GatewayEvent.objects.filter(
        site=site, type__in=PERSON_REQUIRED, occurred_at__gte=since, person__isnull=False
    ).select_related("person")
    for event in events.order_by("occurred_at", "id"):
        latest[event.person_id] = event
    return [
        {"person": event.person, "since": event.occurred_at, "door": event.data.get("door", "")}
        for event in sorted(latest.values(), key=lambda e: e.occurred_at)
        if event.type == "attendance.clock_in"
    ]
