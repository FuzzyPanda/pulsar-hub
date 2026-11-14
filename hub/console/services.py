"""Everything that decides or changes anything about the remote console.

The relay (`relay/`) holds the tunnels and carries the bytes; it decides nothing. Each question it
has is answered here, each thing it reports is recorded here, and every start, end, refusal and
extension of a session is written to the audit log here (rule 7).

Who may open a session: an active member who is an Owner or an Admin of the gateway's
organisation, in a browser session that has just passed a step-up check. Never a Pulsar operator
on a visit, never a Manager or Staff. What a session may reach is not decided here at all: the
hub sends a gateway a method, a path and headers, and the gateway alone chooses what on its side
receives them (`docs/CONTRACTS.md`, "Remote console").
"""

import logging
import secrets
import uuid
from datetime import timedelta

from allauth.usersessions.models import UserSession
from django.conf import settings
from django.contrib.sessions.models import Session
from django.core.cache import cache
from django.core.exceptions import PermissionDenied, ValidationError
from django.db import transaction
from django.urls import reverse
from django.utils import timezone

from hub.audit import services as audit
from hub.audit.models import AuditEvent
from hub.console import relay_client
from hub.console.models import ConsoleSession
from hub.gateways.models import Gateway
from hub.organisations.context import organisation_context, require_organisation
from hub.organisations.models import Membership, Role, hash_token
from hub.organisations.services import Actor
from hub.products.addresses import browser_host

logger = logging.getLogger("hub.console")

# A fixed, small number: a console is for one person at a time, with room for a colleague.
MAX_SESSIONS_PER_GATEWAY = 3
# How long the browser has to carry the hand-off token from the hub's origin to the console's.
HANDOFF_SECONDS = 60
# The relay reports each open tunnel every ten seconds. Silence for this long means the relay is
# gone, and a tunnel nobody vouches for is shown as not connected.
TUNNEL_STALE_SECONDS = 45
CONSOLE_ROLES = (Role.OWNER, Role.ADMIN)
# Opening a session makes a web worker wait for the gateway's answer (five seconds at most, by
# the contract). The workers are few and synchronous, so that wait is rationed: so many Opens a
# minute per person and per gateway, a minute's rest for a gateway that did not answer, and only
# this many Opens waiting at once on the whole hub.
OPENS_PER_MINUTE_PER_USER = 10
OPENS_PER_MINUTE_PER_GATEWAY = 20
OPENS_WAITING_AT_ONCE = 1
SILENT_GATEWAY_REST_SECONDS = 60
OPEN_WAIT_SECONDS = 8.0

EndReason = ConsoleSession.EndReason

# --- the state of a gateway's remote console, in the words the pages show -------------------------

NOT_SET_UP = "not_set_up"
AVAILABLE = "available"
SWITCHED_OFF = "switched_off"
NOT_CONNECTED = "not_connected"
TOO_OLD = "too_old"

STATE_WORDS = {
    AVAILABLE: ("Available", "The gateway is connected and its remote console is switched on."),
    SWITCHED_OFF: (
        "Switched off on the gateway",
        "The gateway is connected, but its remote console is switched off. It can only be switched on at the "
        "gateway itself, by someone on site.",
    ),
    NOT_CONNECTED: (
        "Gateway not connected",
        "The gateway does not have a connection open to the hub just now. Doors are not affected.",
    ),
    TOO_OLD: (
        "Gateway software too old",
        "This gateway has never opened a remote-console connection to the hub. Its software needs to be updated "
        "before its console can be opened from here.",
    ),
    NOT_SET_UP: ("Not set up on this hub", "The remote console has not been set up on this hub."),
}


def configured() -> bool:
    return bool(settings.CONSOLE_ORIGIN_TEMPLATE and settings.RELAY_INTERNAL_SECRET)


def tunnel_is_open(gateway: Gateway, *, now=None) -> bool:
    if not gateway.tunnel_connected or gateway.tunnel_seen_at is None:
        return False
    return (now or timezone.now()) - gateway.tunnel_seen_at < timedelta(seconds=TUNNEL_STALE_SECONDS)


def console_state(gateway: Gateway) -> str:
    if not configured():
        return NOT_SET_UP
    if tunnel_is_open(gateway):
        return AVAILABLE if gateway.console_enabled else SWITCHED_OFF
    # A gateway that has never agreed a protocol version with this hub cannot do so by waiting.
    return NOT_CONNECTED if gateway.tunnel_protocol else TOO_OLD


def describe(gateway: Gateway) -> dict:
    state = console_state(gateway)
    label, detail = STATE_WORDS[state]
    return {"state": state, "label": label, "detail": detail}


def console_origin(gateway: Gateway, *, host: str) -> str:
    """The origin a gateway's console is served on. `{gateway}` gives each gateway its own;
    `{host}` (bench only) is the host name the browser used to reach the hub."""
    return settings.CONSOLE_ORIGIN_TEMPLATE.replace("{gateway}", gateway.pk.hex).replace("{host}", host)


def _utc(value) -> str:
    return value.strftime("%Y-%m-%dT%H:%M:%SZ")


# --- audit ----------------------------------------------------------------------------------------


def _record(action: str, *, gateway: Gateway, user, request=None, session=None, system: bool = False, **data):
    """One audit event about a console session: always with the person, the gateway, the site and
    the browser's address, whoever or whatever caused it."""
    client_ip = (session.client_ip if session is not None else None) or audit.client_ip(request) or ""
    detail = {
        "gateway": str(gateway.pk),
        "gateway_name": gateway.name,
        "site": str(gateway.site_id),
        "site_name": gateway.site.name,
        "user": getattr(user, "email", "") or "",
        "client_ip": str(client_ip),
        **({"session": str(session.pk)} if session is not None else {}),
        **{key: value for key, value in data.items() if value not in (None, "")},
    }
    kwargs = {"actor": None, "actor_kind": AuditEvent.ActorKind.SYSTEM} if system or request is None else {}
    return audit.record(
        action, request=request, target=session or gateway, target_label=gateway.site.name, data=detail, **kwargs
    )


def record_refusal(*, gateway: Gateway, request, reason: str) -> None:
    _record("console.session_refused", gateway=gateway, user=request.user, request=request, reason=reason)


# --- opening, extending and ending, by a person ---------------------------------------------------


def _counted(key: str, limit: int, *, seconds: int = 60) -> bool:
    """Count one more of `key` in this window. False when that is over `limit`."""
    cache.add(key, 0, seconds)
    try:
        return cache.incr(key) <= limit
    except ValueError:  # it expired between the two calls
        cache.set(key, 1, seconds)
        return True


def _take_waiting_place() -> str:
    """One of the few places for an Open that is waiting on a gateway. "" when all are taken."""
    for place in range(OPENS_WAITING_AT_ONCE):
        key = f"console-open-waiting:{place}"
        if cache.add(key, 1, int(OPEN_WAIT_SECONDS) + 2):
            return key
    return ""


def _hub_origin(request) -> str:
    """The origin of the hub as this browser reached it: what its hand-off POST will name."""
    return f"{request.scheme}://{request.get_host()}".lower()


def _browser_hash(request) -> str:
    key = getattr(request.session, "session_key", None)
    return hash_token(key) if key else ""


def open_session(gateway: Gateway, *, actor: Actor, request) -> tuple[ConsoleSession, str]:
    """Start a console session for the person asking, and return it with its hand-off token.

    The token is returned once, is never stored, and is good for one use within a minute. The
    session exists only once the gateway itself has accepted it.
    """
    require_organisation()
    user = actor.user

    def refuse(reason: str, message: str, kind=ValidationError):
        _record("console.session_refused", gateway=gateway, user=user, request=request, reason=reason)
        return kind(message)

    if not actor.is_member_with(Role.ADMIN):
        if actor.is_operator:
            raise refuse("operator", "An operator visit cannot open a gateway's console.", PermissionDenied)
        raise refuse("role", "Only an Owner or an Admin can open a gateway's console.", PermissionDenied)
    if not gateway.is_live:
        raise refuse("gateway_revoked", "This gateway has been revoked.")
    state = console_state(gateway)
    if state != AVAILABLE:
        raise refuse(state, STATE_WORDS[state][1])
    browser = _browser_hash(request)
    if not browser:
        raise refuse("no_browser_session", "Sign in again to open the console.")
    if cache.get(f"console-open-silent:{gateway.pk}"):
        raise refuse("gateway_resting", "The gateway did not answer a moment ago. Try again in a minute.")
    within_limits = _counted(f"console-open-user:{user.pk}", OPENS_PER_MINUTE_PER_USER)
    within_limits = _counted(f"console-open-gateway:{gateway.pk}", OPENS_PER_MINUTE_PER_GATEWAY) and within_limits
    if not within_limits:
        raise refuse("rate_limited", "Too many attempts to open this console. Wait a minute and try again.")

    now = timezone.now()
    token = secrets.token_urlsafe(32)
    full = False
    with transaction.atomic():
        Gateway.objects.select_for_update().get(pk=gateway.pk)  # one opener at a time per gateway
        others = ConsoleSession.objects.live().filter(gateway=gateway).exclude(user=user).count()
        if others >= MAX_SESSIONS_PER_GATEWAY:
            full = True
        else:
            # One session per person per gateway: opening again replaces the one before.
            for earlier in ConsoleSession.objects.live().filter(gateway=gateway, user=user):
                _end(earlier, EndReason.REPLACED, request=request, ended_by=user)
            if ConsoleSession.objects.live().filter(gateway=gateway).count() >= MAX_SESSIONS_PER_GATEWAY:
                full = True
            else:
                session = ConsoleSession.objects.create(
                    gateway=gateway,
                    user=user,
                    role=actor.membership.role,
                    origin=console_origin(gateway, host=browser_host(request)),
                    hub_origin=_hub_origin(request),
                    expires_at=now + timedelta(minutes=settings.CONSOLE_SESSION_MINUTES),
                    token_hash=hash_token(token),
                    handoff_expires_at=now + timedelta(seconds=HANDOFF_SECONDS),
                    browser_hash=browser,
                    client_ip=audit.client_ip(request),
                    user_agent=request.META.get("HTTP_USER_AGENT", "")[:255],
                )
    if full:
        raise refuse(
            "too_many",
            f"This gateway already has {MAX_SESSIONS_PER_GATEWAY} remote console sessions open. End one first.",
        )

    # Outside any transaction: the gateway is asked, through the relay, and may say no.
    frame = {
        "session": str(session.pk),
        "user": {"id": str(user.pk), "email": user.email, "name": user.name, "role": session.role},
        "started_at": _utc(now),
        "expires_at": _utc(session.expires_at),
        "console_origin": session.origin,
        "client_ip": str(session.client_ip or ""),
    }
    return_url = request.build_absolute_uri(
        reverse("site_detail", kwargs={"org_slug": session.organisation.slug, "site_id": gateway.site_id})
    )
    place = _take_waiting_place()
    if not place:
        accepted, reason = False, "hub_busy"
    else:
        try:
            accepted, reason = relay_client.start_session(
                gateway_id=str(gateway.pk), frame=frame, return_url=return_url
            )
        finally:
            cache.delete(place)
    if reason == "gateway_silent":
        cache.set(f"console-open-silent:{gateway.pk}", 1, SILENT_GATEWAY_REST_SECONDS)
    if not accepted:
        ConsoleSession.objects.filter(pk=session.pk, ended_at__isnull=True).update(
            ended_at=timezone.now(), end_reason=EndReason.GATEWAY_REFUSED
        )
        words = {
            "disabled": "The remote console is switched off on the gateway.",
            "busy": "The gateway has no room for another remote session just now.",
            "not_connected": "The gateway is not connected just now.",
            "relay_unreachable": "The hub's relay could not be reached. Try again in a moment.",
            "gateway_silent": "The gateway did not answer. Try again in a minute.",
            "hub_busy": "Another remote console is being opened just now. Try again in a few seconds.",
        }.get(reason, "The gateway did not accept the session.")
        raise refuse(reason, words)
    started = ConsoleSession.objects.filter(pk=session.pk, ended_at__isnull=True).update(started_at=now)
    if not started:  # ended in the moment between (the gateway was revoked, the person removed)
        relay_client.end_session(str(session.pk), "hub")
        raise refuse("ended_while_starting", "The session could not be started. Try again.")
    session.started_at = now
    _record(
        "console.session_started",
        gateway=gateway,
        user=user,
        request=request,
        session=session,
        role=session.role,
        expires_at=_utc(session.expires_at),
    )
    return session, token


def extend_session(session: ConsoleSession, *, actor: Actor, request) -> None:
    """Give a session another full term. Only the person it belongs to, after a fresh step-up
    (the view requires it), and only while it is still running."""
    gateway = session.gateway

    def refuse(reason: str, message: str, kind=ValidationError):
        _record(
            "console.session_refused", gateway=gateway, user=actor.user, request=request, session=session, reason=reason
        )
        return kind(message)

    if session.user_id != actor.user.pk or not actor.is_member_with(Role.ADMIN):
        raise refuse("extend_not_yours", "Only the person using a session can extend it.", PermissionDenied)
    if not session.is_live or session.started_at is None or _invalid_reason(session):
        raise refuse("over", "That session is already over. Open the console again.")
    expires_at = timezone.now() + timedelta(minutes=settings.CONSOLE_SESSION_MINUTES)
    with transaction.atomic():
        updated = ConsoleSession.objects.filter(pk=session.pk, ended_at__isnull=True).update(
            expires_at=expires_at, extended_count=session.extended_count + 1
        )
        if not updated:
            raise ValidationError("That session is already over. Open the console again.")
        session.expires_at = expires_at
        _record(
            "console.session_extended",
            gateway=gateway,
            user=actor.user,
            request=request,
            session=session,
            expires_at=_utc(expires_at),
        )
        transaction.on_commit(lambda: relay_client.extend_session(str(session.pk), _utc(expires_at)))


@transaction.atomic
def end_session(session: ConsoleSession, *, actor: Actor, request) -> None:
    """End a session from the hub: the person using it, or any Owner or Admin."""
    own = session.user_id == actor.user.pk and actor.membership is not None
    if not own:
        actor.require_member(Role.ADMIN)
    _end(session, EndReason.USER if own else EndReason.ADMIN, request=request, ended_by=actor.user)


# --- ending, whatever the cause -------------------------------------------------------------------


def _end(session: ConsoleSession, reason: str, *, request=None, ended_by=None, notify: bool = True) -> bool:
    """Mark one session over, once, and say so in the audit log. Needs its organisation current."""
    updated = ConsoleSession.objects.filter(pk=session.pk, ended_at__isnull=True).update(
        ended_at=timezone.now(), end_reason=reason, ended_by=ended_by
    )
    if not updated:
        return False
    session.ended_at, session.end_reason = timezone.now(), reason
    _record(
        "console.session_ended",
        gateway=session.gateway,
        user=session.user,
        request=request,
        session=session,
        reason=str(reason),
        ended_by=getattr(ended_by, "email", ""),
    )
    if notify:
        session_id = str(session.pk)
        transaction.on_commit(lambda: relay_client.end_session(session_id, str(reason)))
    return True


def _open_sessions():
    """Every session of the current organisation that has not been marked over."""
    return ConsoleSession.objects.filter(ended_at__isnull=True).select_related("gateway__site", "user", "organisation")


def end_for_gateway(gateway: Gateway, reason: str, *, request=None, ended_by=None, notify: bool = True) -> int:
    return sum(
        _end(session, reason, request=request, ended_by=ended_by, notify=notify)
        for session in _open_sessions().filter(gateway=gateway)
    )


def end_for_member(user, reason: str = EndReason.MEMBERSHIP_CHANGED, *, request=None, ended_by=None) -> int:
    """The person's role changed or they left: their sessions in this organisation end now."""
    return sum(
        _end(session, reason, request=request, ended_by=ended_by) for session in _open_sessions().filter(user=user)
    )


def end_for_browser(session_key: str, reason: str = EndReason.SIGNED_OUT, *, request=None) -> int:
    """The hub sign-in a session was opened from is over, so the session is too."""
    if not session_key:
        return 0
    ended = 0
    # unscoped: found by the digest of the caller's own browser session, across their organisations
    rows = ConsoleSession.all_organisations.filter(browser_hash=hash_token(session_key), ended_at__isnull=True)
    for session in rows.select_related("gateway__site", "user", "organisation"):
        with organisation_context(session.organisation):
            ended += _end(session, reason, request=request, ended_by=session.user)
    return ended


def gateway_revoked(gateway: Gateway, *, request=None, ended_by=None) -> None:
    """Called when a gateway is revoked: its sessions end and its tunnel is closed at once."""
    end_for_gateway(gateway, EndReason.GATEWAY_REVOKED, request=request, ended_by=ended_by, notify=False)
    Gateway.objects.filter(pk=gateway.pk).update(tunnel_connected=False, tunnel_changed_at=timezone.now())
    gateway_id = str(gateway.pk)
    transaction.on_commit(lambda: relay_client.close_gateway(gateway_id))


def _hub_sign_in_is_alive(session: ConsoleSession) -> bool:
    keys = [
        key
        for key in UserSession.objects.filter(user_id=session.user_id).values_list("session_key", flat=True)
        if hash_token(key) == session.browser_hash
    ]
    return bool(keys) and Session.objects.filter(session_key__in=keys, expire_date__gt=timezone.now()).exists()


def _invalid_reason(session: ConsoleSession) -> str:
    """Why a session that has not been ended must be, or "" if it may go on. Needs its organisation
    current. This is the whole rule; the relay asks it of every session every few seconds."""
    now = timezone.now()
    gateway = session.gateway
    if session.expires_at <= now:
        return EndReason.EXPIRED
    if gateway.revoked_at is not None:
        return EndReason.GATEWAY_REVOKED
    if not session.organisation.is_active or not gateway.site.is_active:
        return EndReason.ORGANISATION_CLOSED
    membership = Membership.objects.filter(user_id=session.user_id, is_active=True).first()
    if (
        not session.user.is_active
        or membership is None
        or membership.role != session.role
        or membership.role_enum not in CONSOLE_ROLES
    ):
        return EndReason.MEMBERSHIP_CHANGED
    if session.handoff_used_at is None and session.handoff_expires_at <= now:
        return EndReason.NOT_OPENED
    if not _hub_sign_in_is_alive(session):
        return EndReason.HUB_SESSION_ENDED
    return ""


def sweep() -> int:
    """End every session, in every organisation, that should no longer be running. The relay's
    heartbeat does this every few seconds; the worker runs it too, so that a session's end is
    recorded even while the relay is down."""
    ended = 0
    # unscoped: platform housekeeping over every organisation's open sessions
    rows = ConsoleSession.all_organisations.filter(ended_at__isnull=True)
    for session in rows.select_related("gateway__site", "user", "organisation"):
        with organisation_context(session.organisation):
            reason = _invalid_reason(session)
            if reason:
                ended += _end(session, reason)
    return ended


# --- what the relay asks and reports (hub/console/internal.py) ------------------------------------


def _is_uuid(value) -> bool:
    try:
        uuid.UUID(str(value))
    except (ValueError, TypeError):
        return False
    return True


def _gateway_by_id(gateway_id) -> Gateway | None:
    if not _is_uuid(gateway_id):
        return None
    # unscoped: the relay names a gateway it authenticated by credential; its organisation follows from the row
    return Gateway.all_organisations.select_related("organisation", "site").filter(pk=gateway_id).first()


def _may_tunnel(gateway: Gateway) -> bool:
    return gateway.revoked_at is None and gateway.organisation.is_active and gateway.site.is_active


def relay_started(instance: str) -> None:
    """A relay has just started, so no tunnel is open and every session is over."""
    # unscoped: platform event; every organisation's tunnels and sessions are affected alike
    for gateway in Gateway.all_organisations.filter(tunnel_connected=True).select_related("organisation", "site"):
        with organisation_context(gateway.organisation), transaction.atomic():
            Gateway.objects.filter(pk=gateway.pk).update(tunnel_connected=False, tunnel_changed_at=timezone.now())
    # unscoped: as above
    rows = ConsoleSession.all_organisations.filter(ended_at__isnull=True)
    for session in rows.select_related("gateway__site", "user", "organisation"):
        with organisation_context(session.organisation):
            _end(session, EndReason.RELAY_RESTARTED, notify=False)
    logger.info("relay %s started; tunnels and sessions cleared", instance)


def authorize_tunnel(credential: str) -> dict | None:
    """The gateway a credential belongs to, for the relay to bind a tunnel to; None if not accepted.
    The same check as every other gateway call (`gateways.services.find_gateway`)."""
    from hub.gateways import services as gateways

    gateway = gateways.find_gateway(credential)
    if gateway is None:
        return None
    with organisation_context(gateway.organisation):
        gateways.touch(gateway)
    return {
        "gateway_id": str(gateway.pk),
        "org_ref": str(gateway.organisation_id),
        "site_ref": str(gateway.site_id),
    }


def tunnel_refused(gateway_id, offered: str) -> None:
    """The gateway offered no protocol version this hub speaks."""
    gateway = _gateway_by_id(gateway_id)
    if gateway is None:
        return
    with organisation_context(gateway.organisation):
        Gateway.objects.filter(pk=gateway.pk).update(tunnel_protocol="", tunnel_connected=False)
    logger.warning("gateway %s offered no console protocol this hub speaks: %s", gateway.pk, offered[:120])


def tunnel_opened(
    gateway_id, *, protocol: str, software_version: str, console_enabled: bool, tunnel_id: str = ""
) -> bool:
    gateway = _gateway_by_id(gateway_id)
    if gateway is None or not _may_tunnel(gateway):
        return False
    now = timezone.now()
    with organisation_context(gateway.organisation), transaction.atomic():
        # A new tunnel replaces the one before, and the sessions that were on that one are over.
        end_for_gateway(gateway, EndReason.TUNNEL_DROPPED, notify=False)
        fields = {
            "tunnel_connected": True,
            "tunnel_changed_at": now,
            "tunnel_seen_at": now,
            "tunnel_protocol": protocol[:32],
            "tunnel_id": tunnel_id[:32],
        }
        if software_version and software_version[:64] != gateway.software_version:
            fields["software_version"] = software_version[:64]
        Gateway.objects.filter(pk=gateway.pk).update(**fields)
        _set_console_enabled(gateway, console_enabled)
    return True


def _set_console_enabled(gateway: Gateway, enabled: bool) -> None:
    """Record what the gateway says about its own switch. The hub cannot set it; it only hears."""
    if gateway.console_enabled == enabled:
        return
    Gateway.objects.filter(pk=gateway.pk).update(console_enabled=enabled)
    gateway.console_enabled = enabled
    audit.record(
        "gateway.remote_console_switched",
        actor=None,
        actor_kind=AuditEvent.ActorKind.GATEWAY,
        target=gateway,
        target_label=gateway.site.name,
        data={"enabled": enabled},
    )
    if not enabled:
        end_for_gateway(gateway, EndReason.GATEWAY_ENDED)


def tunnel_closed(gateway_id, tunnel_id: str = "") -> None:
    """A tunnel has closed. The report names the connection: one that arrives after the gateway
    has already opened another is about the old connection, and changes nothing."""
    gateway = _gateway_by_id(gateway_id)
    if gateway is None:
        return
    if tunnel_id and gateway.tunnel_id and tunnel_id != gateway.tunnel_id:
        return
    with organisation_context(gateway.organisation), transaction.atomic():
        Gateway.objects.filter(pk=gateway.pk).update(tunnel_connected=False, tunnel_changed_at=timezone.now())
        end_for_gateway(gateway, EndReason.TUNNEL_DROPPED, notify=False)


def console_switched(gateway_id, enabled: bool) -> None:
    gateway = _gateway_by_id(gateway_id)
    if gateway is None:
        return
    with organisation_context(gateway.organisation), transaction.atomic():
        _set_console_enabled(gateway, enabled)


# What the relay may say ended a session. Anything else it reports is recorded as the gateway's doing.
_RELAY_END_REASONS = {
    "expired": EndReason.EXPIRED,
    "user": EndReason.USER,
    "gateway_ended": EndReason.GATEWAY_ENDED,
    "tunnel_dropped": EndReason.TUNNEL_DROPPED,
}


def _session_by_id(session_id) -> ConsoleSession | None:
    if not _is_uuid(session_id):
        return None
    # unscoped: the relay names a session the hub gave it; its organisation follows from the row
    rows = ConsoleSession.all_organisations.select_related("gateway__site", "user", "organisation")
    return rows.filter(pk=session_id).first()


def session_ended_by_relay(session_id, reason: str) -> None:
    session = _session_by_id(session_id)
    if session is None:
        return
    with organisation_context(session.organisation), transaction.atomic():
        ended_by = session.user if reason == "user" else None
        _end(session, _RELAY_END_REASONS.get(reason, EndReason.GATEWAY_ENDED), ended_by=ended_by, notify=False)


def redeem_handoff(token: str, origin: str, hub_origin: str = "") -> dict | None:
    """Exchange a hand-off token for the browser's console cookie. Once, within a minute, on the
    session's own console origin, posted from a page of the hub origin the session was opened on,
    and only while the session is otherwise still valid."""
    if not token:
        return None
    # unscoped: looked up by its secret token; the bearer's organisation follows from the row
    found = ConsoleSession.all_organisations.filter(token_hash=hash_token(token)).first()
    if found is None:
        return None
    with organisation_context(found.organisation), transaction.atomic():
        session = (
            ConsoleSession.objects.select_for_update(of=("self",))
            .select_related("gateway__site", "user", "organisation")
            .get(pk=found.pk)
        )
        now = timezone.now()
        problem = ""
        if session.handoff_used_at is not None:
            problem = "handoff_reused"
        elif session.handoff_expires_at <= now:
            problem = "handoff_expired"
        elif session.ended_at is not None or session.started_at is None:
            problem = "over"
        elif session.origin.lower() != (origin or "").lower():
            problem = "handoff_wrong_origin"
        elif session.hub_origin and session.hub_origin != (hub_origin or "").lower():
            # Posted from somewhere that is not the hub: the token is not spent, and not honoured.
            problem = "handoff_not_from_hub"
        elif _invalid_reason(session):
            problem = "over"
        if problem:
            _record(
                "console.session_refused",
                gateway=session.gateway,
                user=session.user,
                session=session,
                system=True,
                reason=problem,
            )
            return None
        cookie_secret = secrets.token_urlsafe(32)
        session.handoff_used_at = now
        session.cookie_hash = hash_token(cookie_secret)
        session.save(update_fields=["handoff_used_at", "cookie_hash"])
    return {"session": str(session.pk), "cookie_secret": cookie_secret}


def heartbeat(gateways: list, session_ids: list) -> dict:
    """The relay says which tunnels and sessions it holds; the hub says which must go.

    This is where a change the hub could not push (the relay was briefly unreachable, a person was
    deactivated, an organisation was suspended) still takes effect within seconds, and where a
    tunnel or a session the relay no longer holds is recorded as gone.
    """
    now = timezone.now()
    held, tunnel_ids = {}, {}
    for item in gateways if isinstance(gateways, list) else []:
        if isinstance(item, dict) and item.get("id"):
            held[str(item["id"])] = item.get("console_enabled") is True
            tunnel_ids[str(item["id"])] = str(item.get("tunnel") or "")[:32]
    close: list[str] = []
    seen: set[str] = set()
    # unscoped: the relay's own list of tunnels, each authenticated by its gateway's credential
    rows = Gateway.all_organisations.filter(pk__in=[value for value in held if _is_uuid(value)])
    for gateway in rows.select_related("organisation", "site"):
        seen.add(str(gateway.pk))
        if not _may_tunnel(gateway):
            close.append(str(gateway.pk))
            continue
        with organisation_context(gateway.organisation), transaction.atomic():
            fields = {"tunnel_seen_at": now}
            if not gateway.tunnel_connected:
                fields.update(tunnel_connected=True, tunnel_changed_at=now)
            if tunnel_ids.get(str(gateway.pk)) and tunnel_ids[str(gateway.pk)] != gateway.tunnel_id:
                fields["tunnel_id"] = tunnel_ids[str(gateway.pk)]  # the relay holds the tunnels; its word stands
            Gateway.objects.filter(pk=gateway.pk).update(**fields)
            _set_console_enabled(gateway, held[str(gateway.pk)])
    close.extend(gateway_id for gateway_id in held if gateway_id not in seen)

    # Tunnels the hub believes are open that the relay does not hold: they have dropped.
    # unscoped: platform reconciliation of every organisation's tunnel state
    stale = Gateway.all_organisations.filter(tunnel_connected=True).exclude(pk__in=list(seen))
    for gateway in stale.select_related("organisation", "site"):
        with organisation_context(gateway.organisation), transaction.atomic():
            Gateway.objects.filter(pk=gateway.pk).update(tunnel_connected=False, tunnel_changed_at=now)
            end_for_gateway(gateway, EndReason.TUNNEL_DROPPED, notify=False)

    held_sessions = {str(value) for value in session_ids} if isinstance(session_ids, list) else set()
    # unscoped: platform reconciliation of every organisation's open sessions
    rows = ConsoleSession.all_organisations.filter(ended_at__isnull=True)
    for session in rows.select_related("gateway__site", "user", "organisation"):
        with organisation_context(session.organisation), transaction.atomic():
            reason = _invalid_reason(session)
            lost = session.started_at is not None and now - session.started_at > timedelta(seconds=30)
            if not reason and str(session.pk) not in held_sessions and lost:
                reason = EndReason.RELAY_RESTARTED  # the relay holds no such session any more
            if reason:
                _end(session, reason, notify=False)
    end = []
    for session_id in held_sessions:
        session = _session_by_id(session_id)
        if session is None or session.ended_at is not None:
            end.append({"id": session_id, "reason": session.end_reason if session is not None else "unknown"})
    return {"close": close, "end": end}


# --- read side for the pages ----------------------------------------------------------------------


def live_sessions(gateway: Gateway) -> list[ConsoleSession]:
    return list(ConsoleSession.objects.live().filter(gateway=gateway, started_at__isnull=False).select_related("user"))
