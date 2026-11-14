"""The remote console end to end: the real web service, the real relay and a fake gateway.

Everything else tests one side with the other stood in for. Here a person signs in to the hub,
opens a gateway's console and uses it, and each thing that must end a session is done for real and
seen to take effect in the relay and on the gateway: the two halves of the internal channel, the
audit log on both sides, and the origin the console is served on (one per gateway, as in
production).
"""

import asyncio
import hashlib
import http.client
import re
import threading
import time
from urllib.parse import urlencode

import aiohttp
import pytest
from aiohttp import web
from django.contrib.sessions.models import Session
from django.test import Client
from django.urls import reverse

from hub.audit.models import AuditEvent
from hub.console.models import ConsoleSession
from hub.gateways.models import Gateway
from hub.organisations import services as org_services
from hub.organisations.context import organisation_context
from hub.organisations.services import Actor
from relay.config import RelayConfig
from relay.hubapi import HubApi
from relay.server import Relay
from tests import factories as f
from tools.fake_gateway import FakeGateway, big_digest

pytestmark = pytest.mark.django_db(transaction=True)

SECRET = "test-only-relay-secret-0123456789abcdef"


class Stack:
    """The relay and a fake gateway on an event loop of their own, so the test itself can stay
    ordinary synchronous code: the Django test client for the hub, http.client for the browser."""

    def __init__(self, hub_url: str):
        self.hub_url = hub_url
        self.loop = asyncio.new_event_loop()
        self.thread = threading.Thread(target=self.loop.run_forever, daemon=True)
        self.thread.start()
        self.relay: Relay | None = None
        self.ports: dict[str, int] = {}
        self.gateways: list[FakeGateway] = []
        self._cleanup: list = []

    def run(self, coroutine, timeout: float = 30):
        return asyncio.run_coroutine_threadsafe(coroutine, self.loop).result(timeout)

    def start(self) -> None:
        async def start():
            http_session = aiohttp.ClientSession()
            self._cleanup.append(http_session.close)
            config = RelayConfig(
                internal_secret=SECRET,
                hub_url=self.hub_url,
                hub_host="localhost",
                origin_template="https://{gateway}.console.test",
                allow_plain_http=False,
                num_proxies=1,
                heartbeat_seconds=0.3,
            )
            self.relay = Relay(config, HubApi(config, http_session))
            for name, app in (
                ("tunnel", self.relay.tunnel_app()),
                ("console", self.relay.console_app()),
                ("control", self.relay.control_app()),
            ):
                runner = web.AppRunner(app, access_log=None, handler_cancellation=True, shutdown_timeout=1.0)
                await runner.setup()
                site = web.TCPSite(runner, "127.0.0.1", 0)
                await site.start()
                self.ports[name] = site._server.sockets[0].getsockname()[1]
                self._cleanup.append(runner.cleanup)
            await self.relay.start()

        self.run(start())
        self.wait(lambda: self.relay.ready)

    def gateway(self, credential: str, **options) -> FakeGateway:
        async def connect():
            gateway = FakeGateway(f"http://127.0.0.1:{self.ports['tunnel']}", credential, **options)
            gateway.extra_headers = {"X-Forwarded-Proto": "https", "X-Forwarded-For": "192.0.2.50"}  # as Caddy would
            self.gateways.append(gateway)
            await gateway.connect()
            return gateway

        return self.run(connect())

    def wait(self, condition, seconds: float = 10.0) -> None:
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            if condition():
                return
            time.sleep(0.02)
        raise AssertionError("the condition never became true")

    def stop(self) -> None:
        async def stop():
            for gateway in self.gateways:
                await gateway.stop()
            await self.relay.stop()
            for cleanup in reversed(self._cleanup):
                await cleanup()

        self.run(stop())
        self.loop.call_soon_threadsafe(self.loop.stop)
        self.thread.join(5)


class ConsoleBrowser:
    """A browser on one gateway's console origin, as Caddy would present it to the relay."""

    def __init__(self, stack: Stack, origin: str, client_ip: str = "198.51.100.7"):
        self.port = stack.ports["console"]
        self.origin = origin
        self.host = origin.removeprefix("https://")
        self.client_ip = client_ip
        self.cookie = ""

    def request(self, method: str, path: str, body: bytes | None = None, headers: dict | None = None):
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=30)
        sent = {"Host": self.host, "X-Forwarded-Proto": "https", "X-Forwarded-For": self.client_ip, **(headers or {})}
        if self.cookie:
            sent["Cookie"] = self.cookie
        if method != "GET":
            sent.setdefault("Origin", self.origin)
        connection.request(method, path, body=body, headers=sent)
        response = connection.getresponse()
        data = response.read()
        connection.close()
        set_cookie = response.getheader("Set-Cookie")
        if set_cookie:
            self.cookie = "" if "max-age=0" in set_cookie.lower() else set_cookie.split(";", 1)[0]
        return response, data

    def get(self, path: str, **kwargs):
        return self.request("GET", path, **kwargs)

    def hand_off(self, token: str):
        body = urlencode({"token": token}).encode()
        headers = {"Content-Type": "application/x-www-form-urlencoded", "Origin": "https://hub.test"}
        return self.request("POST", "/__hub__/handoff", body=body, headers=headers)


@pytest.fixture
def stack(live_server, settings, world_a):
    stack = Stack(live_server.url)
    stack.start()
    settings.RELAY_CONTROL_URL = f"http://127.0.0.1:{stack.ports['control']}"
    try:
        yield stack
    finally:
        stack.stop()


def audit(world, action) -> list[AuditEvent]:
    rows = AuditEvent.all_organisations.filter(organisation=world.organisation, action=action)
    return list(rows.order_by("occurred_at"))


def gateway_row(world) -> Gateway:
    with organisation_context(world.organisation):
        return Gateway.objects.get(pk=world.gateway.pk)


def session_row(world, **filters) -> ConsoleSession:
    with organisation_context(world.organisation):
        return ConsoleSession.objects.exclude(pk=world.console_session.pk).select_related("user").get(**filters)


def open_console(client, stack, world, role="owner") -> tuple[ConsoleBrowser, ConsoleSession]:
    """Sign in, open the console from the hub and carry the hand-off to the console origin."""
    f.sign_in(client, world.user(role), mfa=True)
    url = reverse("console_open", kwargs={"org_slug": world.organisation.slug, "gateway_id": world.gateway.pk})
    page = client.post(url, REMOTE_ADDR="198.51.100.7")
    assert page.status_code == 200, page.content.decode()[:500]
    html = page.content.decode()
    action = re.search(r'id="console-handoff" method="post" action="([^"]+)"', html).group(1)
    token = re.search(r'name="token" value="([^"]+)"', html).group(1)
    origin = action.removesuffix("/__hub__/handoff")
    browser = ConsoleBrowser(stack, origin)
    response, _ = browser.hand_off(token)
    assert response.status == 200 and browser.cookie.startswith("__Host-pulsar_console=")
    return browser, session_row(world, user=world.user(role), ended_at__isnull=True)


def test_a_person_opens_a_gateways_console_through_the_hub_and_uses_it(client, stack, world_a):
    world = world_a
    assert gateway_row(world).tunnel_protocol == ""  # never connected: "gateway software too old"
    gateway = stack.gateway(world.gateway_credential)
    row = gateway_row(world)
    assert row.tunnel_connected and row.console_enabled and row.tunnel_protocol == "pulsar-console.v1"
    assert row.software_version == "fake-1.0"
    assert gateway.welcome["org_ref"] == str(world.organisation.pk) and gateway.welcome["site_ref"] == str(
        world.site.pk
    )

    browser, session = open_console(client, stack, world)
    assert browser.origin == f"https://{world.gateway.pk.hex}.console.test"

    # The console, through the hub: a page, a form with CSRF, a redirect, an upload, a big download.
    response, body = browser.get("/")
    assert response.status == 302 and response.getheader("Location") == "/ui/"
    response, body = browser.get("/ui/")
    html = body.decode()
    assert response.status == 200 and f"Remote session for: {world.owner.email} (owner)" in html
    assert response.getheader("Set-Cookie") is None
    token = html.split('name="csrfmiddlewaretoken" value="')[1].split('"')[0]
    form = urlencode({"csrfmiddlewaretoken": token, "note": "checked the back door"}).encode()
    response, _ = browser.request(
        "POST", "/ui/note", body=form, headers={"Content-Type": "application/x-www-form-urlencoded"}
    )
    assert response.status == 303 and response.getheader("Location") == "/ui/?saved=1"
    assert gateway.console.notes == ["checked the back door"]
    payload = bytes(range(256)) * 4096 * 3  # 3 MiB
    boundary = "----hubrelay"
    multipart = (
        (
            f'--{boundary}\r\nContent-Disposition: form-data; name="csrfmiddlewaretoken"\r\n\r\n{token}\r\n'
            f'--{boundary}\r\nContent-Disposition: form-data; name="file"; filename="plan.bin"\r\n'
            "Content-Type: application/octet-stream\r\n\r\n"
        ).encode()
        + payload
        + f"\r\n--{boundary}--\r\n".encode()
    )
    response, body = browser.request(
        "POST", "/ui/upload", body=multipart, headers={"Content-Type": f"multipart/form-data; boundary={boundary}"}
    )
    assert response.status == 200 and hashlib.sha256(payload).hexdigest() in body.decode()
    response, body = browser.get("/ui/big?mb=10")
    assert response.status == 200 and hashlib.sha256(body).hexdigest() == big_digest(10)

    # What the gateway was told, and what it recorded of its own.
    started = [e for e in gateway.audit if e["event"] == "session.started"][-1]
    assert started["session"] == str(session.pk) and started["user"] == world.owner.email
    assert started["user_id"] == str(world.owner.pk) and started["role"] == "owner"
    assert started["client_ip"] == "198.51.100.7"
    requests = [e for e in gateway.audit if e["event"] == "request"]
    assert {e["user"] for e in requests} == {world.owner.email} and len(requests) >= 5
    seen = gateway.console.seen[-1]["headers"]
    lowered = {name.lower(): value for name, value in seen.items()}
    assert lowered["x-forwarded-for"] == "198.51.100.7" and lowered["x-forwarded-proto"] == "https"
    assert lowered["x-hub-console-session"] == str(session.pk)

    # And the hub's own audit log.
    (event,) = audit(world, "console.session_started")
    assert event.actor == world.owner and event.data["gateway"] == str(world.gateway.pk)
    assert event.data["site_name"] == world.site.name and event.data["client_ip"] == "198.51.100.7"

    # The page lists the session; ending it there stops the console at once.
    site_url = reverse("site_detail", kwargs={"org_slug": world.organisation.slug, "site_id": world.site.pk})
    assert "Open remote console sessions" in client.get(site_url).content.decode()
    end_url = reverse("console_end", kwargs={"org_slug": world.organisation.slug, "session_id": session.pk})
    assert client.post(end_url).status_code == 302
    response, body = browser.get("/ui/")
    assert response.status == 401 and "has ended" in body.decode()
    stack.wait(lambda: any(e["event"] == "session.ended" for e in gateway.audit))
    ended = [e for e in gateway.audit if e["event"] == "session.ended"][-1]
    assert ended["reason"] == "user" and ended["user"] == world.owner.email
    assert audit(world, "console.session_ended")[-1].data["reason"] == "user"


def test_each_thing_that_must_end_a_session_does(client, stack, world_a):
    world = world_a
    gateway = stack.gateway(world.gateway_credential)

    def ends_with(reason: str, browser: ConsoleBrowser, session: ConsoleSession) -> None:
        stack.wait(lambda: browser.get("/ui/")[0].status == 401)

        def recorded() -> bool:
            session.refresh_from_db()
            return bool(session.end_reason)

        stack.wait(recorded)
        assert session.end_reason == reason, session.end_reason
        stack.wait(
            lambda: any(e["event"] == "session.ended" and e["session"] == str(session.pk) for e in gateway.audit)
        )
        assert audit(world, "console.session_ended")[-1].data["reason"] == reason

    # Its time limit.
    browser, session = open_console(client, stack, world)
    assert browser.get("/ui/")[0].status == 200
    with organisation_context(world.organisation):
        ConsoleSession.objects.filter(pk=session.pk).update(expires_at=session.started_at)
    ends_with("expired", browser, session)

    # The person's role changing.
    browser, session = open_console(client, stack, world, "admin")
    with organisation_context(world.organisation):
        owner = Actor(world.owner, world.memberships["owner"])
        org_services.change_role(world.memberships["admin"], actor=owner, new_role="manager")
    ends_with("membership_changed", browser, session)
    with organisation_context(world.organisation):
        org_services.change_role(world.memberships["admin"], actor=owner, new_role="admin")

    # Signing out of the hub.
    browser, session = open_console(client, stack, world)
    assert client.post(reverse("account_logout")).status_code == 302
    ends_with("signed_out", browser, session)

    # The hub sign-in ending some other way (revoked from the sessions list, or expired).
    browser, session = open_console(client, stack, world)
    Session.objects.all().delete()
    ends_with("hub_session_ended", browser, session)

    # The gateway switching its remote console off, on site.
    browser, session = open_console(client, stack, world)
    stack.run(gateway.set_console_enabled(False))
    ends_with("gateway_ended", browser, session)
    stack.wait(lambda: not gateway_row(world).console_enabled)
    f.sign_in(client, world.owner, mfa=True)
    url = reverse("console_open", kwargs={"org_slug": world.organisation.slug, "gateway_id": world.gateway.pk})
    assert client.post(url).status_code == 302  # refused: switched off on the gateway
    assert audit(world, "console.session_refused")[-1].data["reason"] == "switched_off"
    stack.run(gateway.set_console_enabled(True))
    stack.wait(lambda: gateway_row(world).console_enabled)

    # The tunnel dropping.
    browser, session = open_console(client, stack, world)
    stack.run(gateway.disconnect())
    stack.wait(lambda: not gateway_row(world).tunnel_connected)
    session.refresh_from_db()
    assert session.end_reason == "tunnel_dropped" and browser.get("/ui/")[0].status == 401
    assert [e for e in gateway.audit if e["event"] == "session.ended"][-1]["reason"] == "tunnel_closed"


def test_revoking_a_gateway_mid_session_closes_everything_at_once(client, stack, world_a):
    world = world_a
    gateway = stack.gateway(world.gateway_credential)
    browser, session = open_console(client, stack, world)
    assert browser.get("/ui/")[0].status == 200
    f.sign_in(client, world.admin, mfa=True)
    url = reverse("gateway_revoke", kwargs={"org_slug": world.organisation.slug, "gateway_id": world.gateway.pk})
    assert client.post(url).status_code == 302
    # By the time the hub has answered, the tunnel is closed and the console is gone.
    stack.wait(lambda: gateway.closed.is_set(), seconds=3)
    assert gateway.close_code == 4003
    assert browser.get("/ui/")[0].status == 401
    session.refresh_from_db()
    assert session.end_reason == "gateway_revoked"
    assert not gateway_row(world).tunnel_connected
    # The credential opens no new tunnel.
    with pytest.raises(aiohttp.WSServerHandshakeError) as refused:
        stack.run(gateway.connect())
    assert refused.value.status == 401


def test_two_organisations_consoles_never_meet(client, stack, world_a, world_b):
    gateway_a = stack.gateway(world_a.gateway_credential)
    gateway_b = stack.gateway(world_b.gateway_credential)
    browser_a, session_a = open_console(client, stack, world_a)
    browser_a.get("/ui/cookie?set=only_a:AAAA")
    # A second browser: signing in as someone else in the first would end A's sign-in, and with it A's session.
    browser_b, session_b = open_console(Client(), stack, world_b)
    assert browser_a.origin != browser_b.origin
    # Each console answers on its own origin, to its own session, with its own cookies.
    assert world_a.owner.email in browser_a.get("/ui/")[1].decode()
    assert world_b.owner.email in browser_b.get("/ui/")[1].decode()
    assert "AAAA" not in browser_b.get("/ui/cookie")[1].decode()
    assert not [r for r in gateway_b.console.seen if "AAAA" in str(r)]
    # A's cookie on B's origin, and B's on A's, open nothing.
    stray = ConsoleBrowser(stack, browser_b.origin)
    stray.cookie = browser_a.cookie
    assert stray.get("/ui/")[0].status == 401
    stray = ConsoleBrowser(stack, browser_a.origin)
    stray.cookie = browser_b.cookie
    assert stray.get("/ui/")[0].status == 401
    # An Owner of A cannot open, see or end anything of B's from the hub.
    f.sign_in(client, world_a.owner, mfa=True)
    slug_a = world_a.organisation.slug
    assert (
        client.post(reverse("console_open", kwargs={"org_slug": slug_a, "gateway_id": world_b.gateway.pk})).status_code
        == 404
    )
    assert (
        client.post(reverse("console_end", kwargs={"org_slug": slug_a, "session_id": session_b.pk})).status_code == 404
    )
    assert browser_b.get("/ui/")[0].status == 200
    assert gateway_a.audit and all(world_b.owner.email not in str(e) for e in gateway_a.audit)
