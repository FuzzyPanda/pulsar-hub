"""The remote console, on the hub's side: who may open a session, what ends one, what the relay is
told and what it may ask, and what is written to the audit log.

The relay is not running here. `relay` (below) stands in for the web service's calls to it and
records them; `tests/relay/` tests the relay itself and `tests/test_console_e2e.py` runs both
together.
"""

import json
import re
import time
from datetime import timedelta

import pytest
from django.conf import settings as django_settings
from django.contrib.sessions.models import Session
from django.core.exceptions import PermissionDenied, ValidationError
from django.core.management import call_command, get_commands
from django.urls import NoReverseMatch, reverse
from django.utils import timezone

from hub.audit.models import AuditEvent
from hub.console import relay_client, services
from hub.console.models import ConsoleSession
from hub.gateways import services as gateway_services
from hub.gateways.models import Gateway
from hub.organisations import services as org_services
from hub.organisations.context import organisation_context
from hub.organisations.models import Organisation, hash_token
from hub.organisations.services import Actor
from tests import factories as f
from tests.test_auth import secret_of, totp_code

pytestmark = pytest.mark.django_db

SECRET = "test-only-relay-secret-0123456789abcdef"
End = ConsoleSession.EndReason


class RelayStub:
    """Stands in for the relay's control port: records what the web service asked of it."""

    def __init__(self):
        self.calls: list[tuple[str, dict]] = []
        self.start_answer: dict | None = {"ok": True}

    def __call__(self, action, payload, *, timeout=3.0):
        self.calls.append((action, payload))
        return self.start_answer if action == "session/start" else {"ok": True}

    def actions(self) -> list[str]:
        return [action for action, _ in self.calls]

    def last(self, action: str) -> dict:
        return [payload for name, payload in self.calls if name == action][-1]


@pytest.fixture
def relay(monkeypatch):
    stub = RelayStub()
    monkeypatch.setattr(relay_client, "call", stub)
    return stub


@pytest.fixture
def commit(django_capture_on_commit_callbacks):
    """Run a block as a committed transaction, so that what is deferred to commit happens."""
    return lambda: django_capture_on_commit_callbacks(execute=True)


def actor(world, role):
    return Actor(world.user(role), world.memberships[role])


def events(world, action) -> list[AuditEvent]:
    rows = AuditEvent.all_organisations.filter(organisation=world.organisation, action=action)
    return list(rows.order_by("occurred_at"))


def open_url(world):
    return reverse("console_open", kwargs={"org_slug": world.organisation.slug, "gateway_id": world.gateway.pk})


def live(world) -> list[ConsoleSession]:
    with organisation_context(world.organisation):
        return list(ConsoleSession.objects.live().select_related("user"))


def open_as(client, world, role="owner", **extra):
    """Sign in with a fresh second factor and open the console. Returns (response, token or None)."""
    f.sign_in(client, world.user(role), mfa=True)
    response = client.post(open_url(world), **extra)
    match = re.search(r'name="token" value="([^"]+)"', response.content.decode())
    return response, match.group(1) if match else None


def internal(client, name, payload, *, secret=SECRET, **extra):
    headers = {"HTTP_AUTHORIZATION": f"Bearer {secret}"} if secret is not None else {}
    return client.post(
        f"/internal/relay/{name}", json.dumps(payload), content_type="application/json", **headers, **extra
    )


@pytest.fixture
def world(world_a):
    f.open_console_tunnel(world_a.gateway)
    return world_a


# --- the state of a gateway's remote console ------------------------------------------------------


def test_the_state_is_told_in_words(world_a, settings):
    gateway = world_a.gateway
    assert services.describe(gateway)["label"] == "Gateway software too old"  # it has never opened a tunnel
    f.open_console_tunnel(gateway, enabled=False)
    assert services.describe(gateway)["label"] == "Switched off on the gateway"
    f.open_console_tunnel(gateway)
    assert services.describe(gateway) == {
        "state": "available",
        "label": "Available",
        "detail": "The gateway is connected and its remote console is switched on.",
    }
    # The relay has stopped vouching for the tunnel (it reports every ten seconds).
    with organisation_context(world_a.organisation):
        Gateway.objects.filter(pk=gateway.pk).update(tunnel_seen_at=timezone.now() - timedelta(seconds=90))
    gateway.refresh_from_db()
    assert services.describe(gateway)["label"] == "Gateway not connected"
    services.tunnel_refused(gateway.pk, "pulsar-console.v0")  # it offered a version this hub does not speak
    gateway.refresh_from_db()
    assert services.describe(gateway)["label"] == "Gateway software too old"
    settings.CONSOLE_ORIGIN_TEMPLATE = ""
    assert services.describe(gateway)["label"] == "Not set up on this hub"


def test_the_hub_only_hears_whether_the_console_is_switched_on(world):
    """The switch is on the gateway. Nothing in the hub sets it: no route, no service an actor can call."""
    assert world.gateway.console_enabled
    services.console_switched(world.gateway.pk, False)
    world.gateway.refresh_from_db()
    assert not world.gateway.console_enabled
    switched = events(world, "gateway.remote_console_switched")
    assert [e.data for e in switched] == [{"enabled": True}, {"enabled": False}]  # each as the gateway reported it
    assert all(e.actor_kind == AuditEvent.ActorKind.GATEWAY and e.actor is None for e in switched)
    for name in ("console_enable", "console_switch", "gateway_console_address", "console_enabled"):
        with pytest.raises(NoReverseMatch):
            reverse(name, kwargs={"org_slug": "x", "gateway_id": world.gateway.pk})


def test_the_console_address_link_is_gone(world_a):
    assert not hasattr(Gateway, "console_address")
    assert "set_console_address" not in get_commands()
    assert not hasattr(gateway_services, "set_console_address")
    assert not events(world_a, "gateway.console_address_changed")


# --- opening a session ----------------------------------------------------------------------------


def test_an_owner_opens_a_session_after_a_step_up(client, world, relay):
    response, token = open_as(client, world, REMOTE_ADDR="198.51.100.7", HTTP_USER_AGENT="Firefox")
    assert response.status_code == 200
    body = response.content.decode()
    origin = f"https://{world.gateway.pk.hex}.console.test"
    # The page posts the one-time token to the console origin: it is never in an address.
    assert f'<form id="console-handoff" method="post" action="{origin}/__hub__/handoff"' in body
    assert response["Cache-Control"] == "no-store" and response["Referrer-Policy"] == "no-referrer"
    assert token and len(token) >= 43 and token not in response.headers.get("Location", "")

    (session,) = live(world)
    assert session.user == world.owner and session.role == "owner" and session.origin == origin
    assert session.started_at is not None and session.handoff_used_at is None and session.cookie_hash == ""
    lifetime = session.expires_at - session.started_at
    assert timedelta(minutes=14, seconds=50) < lifetime <= timedelta(minutes=15)
    assert timedelta(seconds=50) < session.handoff_expires_at - session.started_at <= timedelta(seconds=60)
    assert str(session.client_ip) == "198.51.100.7" and session.user_agent == "Firefox"
    # Only digests are stored: of the token, and of the hub sign-in the session is bound to.
    assert session.token_hash == hash_token(token) and token not in str(vars(session))
    assert session.browser_hash == hash_token(client.session.session_key)
    assert client.session.session_key not in str(vars(session))

    # The gateway was told, through the relay, who the session is for and until when.
    sent = relay.last("session/start")
    assert sent["gateway_id"] == str(world.gateway.pk)
    assert sent["frame"] == {
        "session": str(session.pk),
        "user": {"id": str(world.owner.pk), "email": world.owner.email, "name": world.owner.name, "role": "owner"},
        "started_at": session.started_at.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "expires_at": session.expires_at.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "console_origin": origin,
        "client_ip": "198.51.100.7",
    }
    assert sent["return_url"].endswith(f"/org/{world.organisation.slug}/sites/{world.site.pk}/")

    (event,) = events(world, "console.session_started")
    assert event.actor == world.owner and str(event.ip_address) == "198.51.100.7"
    assert event.target_ref == str(session.pk) and event.target_label == world.site.name
    assert event.data == {
        "gateway": str(world.gateway.pk),
        "gateway_name": world.gateway.name,
        "site": str(world.site.pk),
        "site_name": world.site.name,
        "user": world.owner.email,
        "client_ip": "198.51.100.7",
        "session": str(session.pk),
        "role": "owner",
        "expires_at": session.expires_at.strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    # The token is in no audit event, of any kind.
    assert token not in json.dumps(list(AuditEvent.all_organisations.values("data", "target_label", "target_ref")))


def test_an_admin_may_open_one_and_a_manager_staff_or_visiting_operator_may_not(client, world, relay):
    response, token = open_as(client, world, "admin")
    assert response.status_code == 200 and token and [s.role for s in live(world)] == ["admin"]

    for role in ("manager", "staff"):
        response, token = open_as(client, world, role)
        assert response.status_code == 403 and token is None
    f.sign_in(client, world.operator_access.operator, mfa=True)
    assert client.post(open_url(world)).status_code == 403
    assert [s.role for s in live(world)] == ["admin"] and relay.actions().count("session/start") == 1

    refusals = events(world, "console.session_refused")
    assert [(e.actor_label, e.data["reason"]) for e in refusals] == [
        (world.manager.email, "role"),
        (world.staff.email, "role"),
        (world.operator_access.operator.email, "operator"),
    ]
    assert refusals[-1].actor_kind == AuditEvent.ActorKind.OPERATOR
    assert all(e.data["gateway"] == str(world.gateway.pk) and e.data["site_name"] == world.site.name for e in refusals)

    # The service refuses them too, whatever calls it.
    with organisation_context(world.organisation):
        for who in (actor(world, "manager"), Actor(world.operator_access.operator, None, world.operator_access)):
            with pytest.raises(PermissionDenied):
                services.open_session(world.gateway, actor=who, request=None)


def test_opening_needs_a_fresh_authenticator_check(client, world, relay, settings):
    owner = world.owner
    f.sign_in(client, owner, mfa=True)
    session = client.session
    records = session["account_authentication_methods"]
    for record in records:
        record["at"] = time.time() - settings.MFA_STEP_UP_MAX_AGE - 60  # signed in a while ago
    session["account_authentication_methods"] = records
    session.save()

    response = client.post(open_url(world))
    assert response.status_code == 302 and response["Location"].startswith(reverse("mfa_reauthenticate"))
    assert not live(world) and not relay.calls

    # The right code finishes the same request: the hand-off page, and a session for this sign-in.
    done = client.post(response["Location"], {"code": totp_code(secret_of(owner))}, REMOTE_ADDR="198.51.100.7")
    assert done.status_code == 200 and b'id="console-handoff"' in done.content
    (opened,) = live(world)
    assert opened.user == owner and opened.browser_hash == hash_token(client.session.session_key)
    with organisation_context(world.organisation):
        assert not services._invalid_reason(opened)  # the step-up did not move the hub sign-in to a new key


@pytest.mark.parametrize(
    ("prepare", "reason", "words"),
    [
        (lambda g: Gateway.objects.filter(pk=g.pk).update(console_enabled=False), "switched_off", "switched off"),
        (
            lambda g: Gateway.objects.filter(pk=g.pk).update(tunnel_connected=False),
            "not_connected",
            "does not have a connection",
        ),
        (
            lambda g: Gateway.objects.filter(pk=g.pk).update(tunnel_connected=False, tunnel_protocol=""),
            "too_old",
            "software needs to be updated",
        ),
    ],
)
def test_a_console_that_is_not_available_cannot_be_opened(client, world, relay, prepare, reason, words):
    with organisation_context(world.organisation):
        prepare(world.gateway)
    response, token = open_as(client, world)
    assert response.status_code == 302 and token is None
    assert words in client.get(response["Location"]).content.decode()
    assert not live(world) and not relay.calls
    assert [e.data["reason"] for e in events(world, "console.session_refused")] == [reason]


@pytest.mark.parametrize(
    ("answer", "reason"),
    [
        ({"ok": False, "reason": "disabled"}, "disabled"),
        ({"ok": False, "reason": "busy"}, "busy"),
        ({"ok": False, "reason": "gateway_silent"}, "gateway_silent"),
        ({"ok": False, "reason": "not_connected"}, "not_connected"),
        (None, "relay_unreachable"),
    ],
)
def test_the_gateway_has_the_last_word_on_whether_a_session_starts(client, world, relay, answer, reason):
    relay.start_answer = answer
    response, token = open_as(client, world)
    assert response.status_code == 302 and token is None
    assert not live(world)
    with organisation_context(world.organisation):
        refused = ConsoleSession.objects.exclude(pk=world.console_session.pk).get()
    assert refused.started_at is None and refused.end_reason == End.GATEWAY_REFUSED
    assert [e.data["reason"] for e in events(world, "console.session_refused")] == [reason]
    assert not events(world, "console.session_started")


def test_a_gateway_has_room_for_three_sessions_and_one_per_person(client, world, relay):
    with organisation_context(world.organisation):
        others = [
            f.ConsoleSessionFactory(organisation=world.organisation, gateway=world.gateway, user=f.UserFactory())
            for _ in range(services.MAX_SESSIONS_PER_GATEWAY)
        ]
    response, token = open_as(client, world)
    assert response.status_code == 302 and token is None
    assert "already has 3 remote console sessions open" in client.get(response["Location"]).content.decode()
    assert [e.data["reason"] for e in events(world, "console.session_refused")] == ["too_many"]
    assert len(live(world)) == 3

    with organisation_context(world.organisation):
        ConsoleSession.objects.filter(pk=others[0].pk).update(ended_at=timezone.now(), end_reason=End.USER)
    _, first = open_as(client, world)
    assert first and len(live(world)) == 3
    # The same person opening again replaces their session; it does not take a second place.
    _, second = open_as(client, world)
    assert second and second != first and len(live(world)) == 3
    mine = [s for s in live(world) if s.user == world.owner]
    assert len(mine) == 1 and mine[0].token_hash == hash_token(second)
    replaced = [e for e in events(world, "console.session_ended") if e.data["reason"] == "replaced"]
    assert len(replaced) == 1


def test_a_revoked_gateway_cannot_be_opened(client, world, relay):
    with organisation_context(world.organisation):
        gateway_services.revoke_gateway(world.gateway, actor=actor(world, "admin"))
        with pytest.raises(ValidationError):
            services.open_session(world.gateway, actor=actor(world, "owner"), request=None)
    assert [e.data["reason"] for e in events(world, "console.session_refused")] == ["gateway_revoked"]


# --- the hand-off ---------------------------------------------------------------------------------


def test_the_hand_off_token_is_redeemed_once_for_the_browsers_cookie(client, world, relay):
    _, token = open_as(client, world)
    (session,) = live(world)
    answer = internal(client, "handoff/redeem", {"token": token, "origin": session.origin})
    assert answer.status_code == 200 and answer["Cache-Control"] == "no-store"
    body = answer.json()
    assert body["session"] == str(session.pk) and len(body["cookie_secret"]) >= 43
    session.refresh_from_db()
    assert session.handoff_used_at is not None and session.cookie_hash == hash_token(body["cookie_secret"])
    assert body["cookie_secret"] not in str(vars(session))

    # A second presentation of the same token gives nothing, and is recorded.
    again = internal(client, "handoff/redeem", {"token": token, "origin": session.origin})
    assert again.status_code == 403 and "cookie_secret" not in again.content.decode()
    assert [e.data["reason"] for e in events(world, "console.session_refused")] == ["handoff_reused"]
    assert internal(client, "handoff/redeem", {"token": "never-issued", "origin": session.origin}).status_code == 403
    assert internal(client, "handoff/redeem", {"origin": session.origin}).status_code == 403


@pytest.mark.parametrize(
    ("spoil", "reason"),
    [
        (lambda s: ConsoleSession.objects.filter(pk=s.pk).update(handoff_expires_at=timezone.now()), "handoff_expired"),
        (lambda s: ConsoleSession.objects.filter(pk=s.pk).update(ended_at=timezone.now(), end_reason="admin"), "over"),
        (lambda s: ConsoleSession.objects.filter(pk=s.pk).update(expires_at=timezone.now()), "over"),
        (
            lambda s: ConsoleSession.objects.filter(pk=s.pk).update(origin="https://other.console.test"),
            "handoff_wrong_origin",
        ),
    ],
)
def test_a_hand_off_is_refused_when_late_over_or_on_the_wrong_origin(client, world, relay, spoil, reason):
    _, token = open_as(client, world)
    (session,) = live(world)
    with organisation_context(world.organisation):
        spoil(session)
    answer = internal(
        client, "handoff/redeem", {"token": token, "origin": f"https://{world.gateway.pk.hex}.console.test"}
    )
    assert answer.status_code == 403
    assert [e.data["reason"] for e in events(world, "console.session_refused")] == [reason]
    session.refresh_from_db()
    assert session.cookie_hash == "" and session.handoff_used_at is None


# --- extending and ending -------------------------------------------------------------------------


def session_url(name, world, session):
    return reverse(name, kwargs={"org_slug": world.organisation.slug, "session_id": session.pk})


def test_only_the_person_using_a_session_extends_it(client, world, relay, commit):
    open_as(client, world)
    (session,) = live(world)
    with organisation_context(world.organisation):
        ConsoleSession.objects.filter(pk=session.pk).update(expires_at=timezone.now() + timedelta(minutes=2))
    with commit():
        assert client.post(session_url("console_extend", world, session)).status_code == 302
    session.refresh_from_db()
    assert session.extended_count == 1
    assert timedelta(minutes=14) < session.expires_at - timezone.now() <= timedelta(minutes=15)
    assert relay.last("session/extend") == {
        "session": str(session.pk),
        "expires_at": session.expires_at.strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    (event,) = events(world, "console.session_extended")
    assert event.actor == world.owner and event.data["expires_at"] == relay.last("session/extend")["expires_at"]

    # Another Admin cannot extend it for them; a Manager cannot reach the route at all.
    f.sign_in(client, world.admin, mfa=True)
    assert client.post(session_url("console_extend", world, session)).status_code == 403
    f.sign_in(client, world.manager, mfa=True)
    assert client.post(session_url("console_extend", world, session)).status_code == 403
    assert [e.data["reason"] for e in events(world, "console.session_refused")] == ["extend_not_yours", "role"]
    session.refresh_from_db()
    assert session.extended_count == 1


def test_a_session_that_is_over_cannot_be_extended(client, world, relay):
    open_as(client, world)
    (session,) = live(world)
    with organisation_context(world.organisation):
        ConsoleSession.objects.filter(pk=session.pk).update(expires_at=timezone.now() - timedelta(seconds=1))
    assert client.post(session_url("console_extend", world, session)).status_code == 302
    session.refresh_from_db()
    assert session.extended_count == 0 and session.expires_at < timezone.now()
    assert [e.data["reason"] for e in events(world, "console.session_refused")] == ["over"]
    assert "session/extend" not in relay.actions()


def test_the_person_or_any_owner_or_admin_ends_a_session_from_the_hub(client, world, relay, commit):
    open_as(client, world, "admin")
    (session,) = live(world)
    # A Manager sees the site page but cannot end a session.
    f.sign_in(client, world.manager, mfa=True)
    assert client.post(session_url("console_end", world, session)).status_code == 403
    assert live(world)
    # The Owner ends the Admin's session.
    f.sign_in(client, world.owner, mfa=True)
    with commit():
        assert client.post(session_url("console_end", world, session), REMOTE_ADDR="198.51.100.8").status_code == 302
    session.refresh_from_db()
    assert session.ended_at is not None and session.end_reason == End.ADMIN and session.ended_by == world.owner
    assert relay.last("session/end") == {"session": str(session.pk), "reason": "admin"}
    (event,) = [e for e in events(world, "console.session_ended") if e.data["session"] == str(session.pk)]
    assert event.actor == world.owner and event.data["reason"] == "admin" and event.data["user"] == world.admin.email
    assert event.data["ended_by"] == world.owner.email and str(event.ip_address) == "198.51.100.8"

    # The person using one ends their own.
    open_as(client, world, "admin")
    (mine,) = live(world)
    with commit():
        client.post(session_url("console_end", world, mine))
    mine.refresh_from_db()
    assert mine.end_reason == End.USER
    # Ending twice changes nothing and records nothing more.
    before = len(events(world, "console.session_ended"))
    client.post(session_url("console_end", world, mine))
    assert len(events(world, "console.session_ended")) == before


def test_the_site_page_lists_open_sessions_with_end_and_extend(client, world, relay):
    open_as(client, world, "admin")
    (session,) = live(world)
    page_url = reverse("site_detail", kwargs={"org_slug": world.organisation.slug, "site_id": world.site.pk})
    body = client.get(page_url).content.decode()
    assert "Open remote console sessions" in body and world.admin.name in body
    assert session_url("console_end", world, session) in body and session_url("console_extend", world, session) in body
    # Another Admin or Owner can end it and cannot extend it.
    f.sign_in(client, world.owner, mfa=True)
    body = client.get(page_url).content.decode()
    assert session_url("console_end", world, session) in body
    assert session_url("console_extend", world, session) not in body
    # A Manager is not shown who has a session open.
    f.sign_in(client, world.manager, mfa=True)
    body = client.get(page_url).content.decode()
    assert "Open remote console sessions" not in body and session_url("console_end", world, session) not in body


# --- what ends a session without anyone asking ----------------------------------------------------


def started_session(client, world, relay, role="owner") -> ConsoleSession:
    _, token = open_as(client, world, role)
    (session,) = [s for s in live(world) if s.user == world.user(role)]
    internal(client, "handoff/redeem", {"token": token, "origin": session.origin})
    session.refresh_from_db()
    return session


def reason_of(session) -> str:
    session.refresh_from_db()
    return session.end_reason


def test_revoking_the_gateway_ends_its_sessions_and_closes_its_tunnel(client, world, relay, commit):
    session = started_session(client, world, relay)
    f.sign_in(client, world.admin, mfa=True)
    url = reverse("gateway_revoke", kwargs={"org_slug": world.organisation.slug, "gateway_id": world.gateway.pk})
    with commit():
        assert client.post(url).status_code == 302
    assert reason_of(session) == End.GATEWAY_REVOKED
    assert relay.last("gateway/close") == {"gateway_id": str(world.gateway.pk)}
    world.gateway.refresh_from_db()
    assert not world.gateway.tunnel_connected and world.gateway.revoked_at is not None
    ended = [e for e in events(world, "console.session_ended") if e.data["session"] == str(session.pk)]
    assert ended[0].data["reason"] == "gateway_revoked" and ended[0].data["user"] == world.owner.email
    # Its credential no longer opens a tunnel.
    assert internal(client, "tunnel/authorize", {"credential": world.gateway_credential}).status_code == 401
    assert not services.tunnel_opened(
        world.gateway.pk, protocol="pulsar-console.v1", software_version="", console_enabled=True
    )


def test_pairing_a_replacement_gateway_ends_the_old_ones_sessions(client, world, relay, commit):
    session = started_session(client, world, relay)
    with organisation_context(world.organisation):
        _, code = gateway_services.create_pairing_code(world.site, actor=actor(world, "admin"))
    with commit():
        gateway_services.pair_gateway(code=code, name="Replacement")
    assert reason_of(session) == End.GATEWAY_REVOKED and relay.last("gateway/close")["gateway_id"] == str(
        world.gateway.pk
    )


def test_a_change_of_role_or_leaving_ends_that_persons_sessions(client, world, relay, commit):
    mine = started_session(client, world, relay, "admin")
    owners = started_session(client, world, relay, "owner")
    with organisation_context(world.organisation), commit():
        org_services.change_role(world.memberships["admin"], actor=actor(world, "owner"), new_role="manager")
    assert reason_of(mine) == End.MEMBERSHIP_CHANGED and relay.last("session/end")["session"] == str(mine.pk)
    assert owners.pk in [s.pk for s in live(world)]  # nobody else's session is touched

    again = f.ConsoleSessionFactory(organisation=world.organisation, gateway=world.gateway, user=world.manager)
    with organisation_context(world.organisation), commit():
        org_services.remove_member(world.memberships["manager"], actor=actor(world, "owner"))
    assert reason_of(again) == End.MEMBERSHIP_CHANGED


def test_signing_out_of_the_hub_ends_the_sessions_opened_from_that_sign_in(client, world, relay, commit):
    session = started_session(client, world, relay)
    elsewhere = f.ConsoleSessionFactory(organisation=world.organisation, gateway=world.gateway, user=world.admin)
    with commit():
        client.post(reverse("account_logout"))
    assert reason_of(session) == End.SIGNED_OUT and relay.last("session/end")["reason"] == "signed_out"
    assert reason_of(elsewhere) == ""  # a different sign-in


def beat(client, world, sessions=(), gateways=None):
    held = [{"id": str(world.gateway.pk), "console_enabled": True}] if gateways is None else gateways
    answer = internal(client, "heartbeat", {"instance": "r1", "gateways": held, "sessions": [str(s) for s in sessions]})
    assert answer.status_code == 200
    return answer.json()


@pytest.mark.parametrize(
    ("happens", "reason"),
    [
        (lambda w, s: ConsoleSession.objects.filter(pk=s.pk).update(expires_at=timezone.now()), End.EXPIRED),
        (lambda w, s: Session.objects.all().delete(), End.HUB_SESSION_ENDED),
        (lambda w, s: type(w.owner).objects.filter(pk=w.owner.pk).update(is_active=False), End.MEMBERSHIP_CHANGED),
        (
            lambda w, s: Organisation.objects.filter(pk=w.organisation.pk).update(status=Organisation.Status.SUSPENDED),
            End.ORGANISATION_CLOSED,
        ),
        (lambda w, s: type(w.site).objects.filter(pk=w.site.pk).update(is_active=False), End.ORGANISATION_CLOSED),
        (lambda w, s: Gateway.objects.filter(pk=w.gateway.pk).update(revoked_at=timezone.now()), End.GATEWAY_REVOKED),
    ],
)
def test_the_heartbeat_ends_what_is_no_longer_valid(client, world, relay, happens, reason):
    """Whatever the cause and however it was done (a page, a command, a shell), within one
    heartbeat the session is over, the relay is told to drop it and the audit log says why."""
    session = started_session(client, world, relay)
    assert beat(client, world, [session.pk]) == {"close": [], "end": []}
    with organisation_context(world.organisation):
        happens(world, session)
    answer = beat(client, world, [session.pk])
    assert answer["end"] == [{"id": str(session.pk), "reason": str(reason)}]
    assert reason_of(session) == reason
    (event,) = [e for e in events(world, "console.session_ended") if e.data["session"] == str(session.pk)]
    assert event.data["reason"] == reason and event.data["user"] == world.owner.email
    assert event.actor_kind == AuditEvent.ActorKind.SYSTEM and event.data["client_ip"]


def test_a_session_the_browser_never_opened_ends_after_a_minute(client, world, relay):
    open_as(client, world)
    (session,) = live(world)
    with organisation_context(world.organisation):
        ConsoleSession.objects.filter(pk=session.pk).update(handoff_expires_at=timezone.now())
    assert beat(client, world, [session.pk])["end"] == [{"id": str(session.pk), "reason": "not_opened"}]


def test_the_heartbeat_keeps_tunnel_state_true(client, world, world_b, relay):
    session = started_session(client, world, relay)
    # The relay still holds the tunnel: it is marked as seen.
    with organisation_context(world.organisation):
        Gateway.objects.filter(pk=world.gateway.pk).update(tunnel_seen_at=timezone.now() - timedelta(seconds=40))
    beat(client, world, [session.pk])
    world.gateway.refresh_from_db()
    assert services.tunnel_is_open(world.gateway)
    # A gateway the hub does not accept, or does not know, is to be closed.
    f.open_console_tunnel(world_b.gateway)
    with organisation_context(world_b.organisation):
        Gateway.objects.filter(pk=world_b.gateway.pk).update(revoked_at=timezone.now())
    unknown = "00000000-0000-4000-8000-000000000001"
    held = [{"id": str(g), "console_enabled": True} for g in (world.gateway.pk, world_b.gateway.pk, unknown)]
    answer = beat(client, world, [session.pk], gateways=held + [{"id": "not-a-uuid"}])
    assert sorted(answer["close"]) == sorted([str(world_b.gateway.pk), unknown, "not-a-uuid"])
    # The relay no longer lists the tunnel: it has dropped, and its sessions with it.
    answer = beat(client, world, [session.pk], gateways=[])
    world.gateway.refresh_from_db()
    assert not world.gateway.tunnel_connected and reason_of(session) == End.TUNNEL_DROPPED
    assert answer["end"] == [{"id": str(session.pk), "reason": "tunnel_dropped"}]
    assert services.describe(world.gateway)["label"] == "Gateway not connected"


def test_a_session_the_relay_no_longer_holds_is_over(client, world, relay):
    session = started_session(client, world, relay)
    with organisation_context(world.organisation):
        ConsoleSession.objects.filter(pk=session.pk).update(started_at=timezone.now() - timedelta(minutes=1))
    assert beat(client, world, []) == {"close": [], "end": []}
    assert reason_of(session) == End.RELAY_RESTARTED


def test_a_relay_that_restarts_has_no_tunnels_and_no_sessions(client, world, relay):
    session = started_session(client, world, relay)
    assert internal(client, "started", {"instance": "r2"}).status_code == 200
    world.gateway.refresh_from_db()
    assert not world.gateway.tunnel_connected and reason_of(session) == End.RELAY_RESTARTED
    assert services.describe(world.gateway)["label"] == "Gateway not connected"


def test_what_the_relay_reports_is_recorded(client, world, relay):
    session = started_session(client, world, relay)
    assert (
        internal(client, "event", {"event": "session.ended", "session": str(session.pk), "reason": "user"}).status_code
        == 200
    )
    assert reason_of(session) == End.USER
    second = started_session(client, world, relay)
    internal(client, "event", {"event": "console.switched", "gateway_id": str(world.gateway.pk), "enabled": False})
    assert reason_of(second) == End.GATEWAY_ENDED
    world.gateway.refresh_from_db()
    assert not world.gateway.console_enabled and services.describe(world.gateway)["state"] == "switched_off"
    f.open_console_tunnel(world.gateway)
    third = started_session(client, world, relay)
    internal(client, "event", {"event": "tunnel.closed", "gateway_id": str(world.gateway.pk)})
    assert reason_of(third) == End.TUNNEL_DROPPED
    # A reason the relay may not give is recorded as the gateway's doing; nonsense is refused.
    f.open_console_tunnel(world.gateway)
    fourth = started_session(client, world, relay)
    internal(client, "event", {"event": "session.ended", "session": str(fourth.pk), "reason": "admin"})
    assert reason_of(fourth) == End.GATEWAY_ENDED
    assert internal(client, "event", {"event": "make.me.owner"}).status_code == 400
    assert internal(client, "event", {"event": "session.ended", "session": "not-a-uuid"}).status_code == 200


def test_the_worker_sweeps_up_while_the_relay_is_down(client, world, relay):
    session = started_session(client, world, relay)
    with organisation_context(world.organisation):
        ConsoleSession.objects.filter(pk=session.pk).update(expires_at=timezone.now())
    call_command("sweep_console_sessions", stdout=open("/dev/null", "w"))  # noqa: SIM115
    assert reason_of(session) == End.EXPIRED


# --- the internal channel -------------------------------------------------------------------------

INTERNAL_CALLS = [
    ("started", {"instance": "x"}),
    ("tunnel/authorize", {"credential": "hubgw_x"}),
    ("tunnel/refused", {"gateway_id": "x", "offered": ""}),
    ("tunnel/opened", {"gateway_id": "x"}),
    ("handoff/redeem", {"token": "x", "origin": "x"}),
    ("event", {"event": "tunnel.closed", "gateway_id": "x"}),
    ("heartbeat", {"gateways": [], "sessions": []}),
]


@pytest.mark.parametrize(("name", "payload"), INTERNAL_CALLS)
def test_the_internal_channel_answers_only_to_the_shared_secret(client, world, name, payload):
    before = AuditEvent.all_organisations.count()
    for secret in (None, "", "wrong", SECRET[:-1], SECRET + "x"):
        assert internal(client, name, payload, secret=secret).status_code == 404
    # The right secret, but through a proxy (Caddy adds these to everything it forwards).
    assert internal(client, name, payload, HTTP_X_FORWARDED_FOR="203.0.113.5").status_code == 404
    assert internal(client, name, payload, HTTP_X_FORWARDED_PROTO="https").status_code == 404
    # Not a POST.
    assert client.get(f"/internal/relay/{name}", HTTP_AUTHORIZATION=f"Bearer {SECRET}").status_code == 404
    # A signed-in Owner's browser is nobody here.
    f.sign_in(client, world.owner, mfa=True)
    assert (
        client.post(f"/internal/relay/{name}", json.dumps(payload), content_type="application/json").status_code == 404
    )
    world.gateway.refresh_from_db()
    assert world.gateway.tunnel_connected and AuditEvent.all_organisations.count() == before


def test_the_internal_channel_is_off_when_no_secret_is_set(client, world, settings):
    settings.RELAY_INTERNAL_SECRET = ""
    assert internal(client, "heartbeat", {"gateways": [], "sessions": []}, secret="").status_code == 404
    assert internal(client, "heartbeat", {"gateways": [], "sessions": []}).status_code == 404


def test_every_internal_route_is_relay_only():
    from django.urls import get_resolver

    from tests.isolation.test_routes import all_routes

    names = [(pattern, name) for pattern, name in all_routes() if pattern.startswith("internal/")]
    assert len(names) == len(INTERNAL_CALLS)
    for pattern, _name in names:
        assert getattr(get_resolver().resolve("/" + pattern).func, "relay_only", False), pattern


def test_a_tunnel_is_bound_to_the_gateway_its_credential_belongs_to(client, world_a, world_b):
    for world in (world_a, world_b):
        answer = internal(client, "tunnel/authorize", {"credential": world.gateway_credential})
        assert answer.status_code == 200
        assert answer.json() == {
            "gateway_id": str(world.gateway.pk),
            "org_ref": str(world.organisation.pk),
            "site_ref": str(world.site.pk),
        }
    for bad in ("", "hubgw_unknown", world_a.gateway_credential + "x", world_a.service_token_value):
        assert internal(client, "tunnel/authorize", {"credential": bad}).status_code == 401
    # A suspended organisation's gateway keeps its doors and loses its tunnel.
    Organisation.objects.filter(pk=world_b.organisation.pk).update(status=Organisation.Status.SUSPENDED)
    assert internal(client, "tunnel/authorize", {"credential": world_b.gateway_credential}).status_code == 401


def test_one_organisations_session_cannot_be_redeemed_or_ended_through_another(client, world, world_b, relay):
    """The relay names a session by a secret token or by an id the hub gave it. Neither lets a
    call reach across: each acts on that one row, inside that row's organisation."""
    _, token = open_as(client, world)
    (session,) = live(world)
    b_origin = f"https://{world_b.gateway.pk.hex}.console.test"
    assert internal(client, "handoff/redeem", {"token": token, "origin": b_origin}).status_code == 403
    internal(client, "event", {"event": "tunnel.closed", "gateway_id": str(world_b.gateway.pk)})
    assert [s.pk for s in live(world)] == [session.pk]


# --- settings and export --------------------------------------------------------------------------


def test_the_session_lifetime_has_a_hard_maximum():
    import os
    import subprocess
    import sys

    def start(minutes: str):
        env = {**os.environ, "CONSOLE_SESSION_MINUTES": minutes, "DJANGO_SETTINGS_MODULE": "hub.test_settings"}
        return subprocess.run([sys.executable, "-c", "import django; django.setup()"], env=env, capture_output=True)  # noqa: S603

    assert start("60").returncode == 0
    for refused in ("61", "0", "600"):
        result = start(refused)
        assert result.returncode != 0 and b"CONSOLE_SESSION_MINUTES must be between 1 and 60" in result.stderr
    assert django_settings.CONSOLE_SESSION_MINUTES == 15


def test_an_export_holds_no_console_secret(client, world, relay):
    session = started_session(client, world, relay)
    data = org_services.export_organisation(world.organisation, actor_user=world.owner)
    rows = data["records"]["console.ConsoleSession"]
    assert len(rows) == 2 and str(session.pk) in str(rows)
    text = json.dumps(data, default=str)
    for digest in (session.token_hash, session.cookie_hash, session.browser_hash):
        assert digest and digest not in text
    assert "cookie_hash" not in text and "browser_hash" not in text and "token_hash" not in text
