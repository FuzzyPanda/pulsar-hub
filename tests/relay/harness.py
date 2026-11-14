"""A relay, a stand-in for the hub's web service, fake gateways and a browser, all on loopback.

`Bench` runs the real relay (`relay.server.Relay`) on three ephemeral ports. `StubHub` answers
its questions from memory, so these tests need no database; `tests/test_console_e2e.py` runs the
same relay against the real web service instead.
"""

import asyncio
import functools
import json
import secrets
from datetime import UTC, datetime, timedelta

import aiohttp
from aiohttp import web

from relay.config import RelayConfig
from relay.hubapi import HubUnavailable
from relay.server import Relay
from tools.fake_gateway import FakeGateway

SECRET = "test-only-relay-secret-0123456789abcdef"
HUB_ORIGIN = "https://hub.test"  # where the hub's own pages are, as far as these tests go


def async_test(test):
    """Run a coroutine test to completion, with a ceiling so a hang fails instead of stalling CI."""

    @functools.wraps(test)
    def wrapper(*args, **kwargs):
        async def bounded():
            return await asyncio.wait_for(test(*args, **kwargs), 60)

        return asyncio.run(bounded())

    return wrapper


class StubHub:
    """What `relay.hubapi.HubApi` is to the relay, answered from memory."""

    def __init__(self):
        self.credentials: dict[str, dict] = {}
        self.handoffs: dict[str, dict] = {}
        self.calls: list[tuple] = []
        self.events: list[dict] = []
        self.heartbeat_answer: dict = {"close": [], "end": []}
        self.down = False
        self.refuse_open = False
        self.tunnel_ids: dict[str, str] = {}
        self.event_delay = 0.0

    def _check(self):
        if self.down:
            raise HubUnavailable("stub hub is down")

    def add_gateway(self, name: str = "a") -> tuple[str, str]:
        gateway_id = f"00000000-0000-4000-8000-{secrets.token_hex(6)}"
        credential = f"hubgw_{name}_{secrets.token_urlsafe(24)}"
        self.credentials[credential] = {"gateway_id": gateway_id, "org_ref": f"org-{name}", "site_ref": f"site-{name}"}
        return gateway_id, credential

    async def started(self, instance):
        self._check()
        self.calls.append(("started", instance))

    async def authorize_tunnel(self, credential):
        self._check()
        self.calls.append(("authorize",))
        return self.credentials.get(credential)

    async def tunnel_refused(self, gateway_id, offered):
        self._check()
        self.calls.append(("refused", gateway_id, offered))

    async def tunnel_opened(self, instance, gateway_id, *, tunnel_id, protocol, software_version, enabled):
        self._check()
        self.calls.append(("opened", gateway_id, protocol, software_version, enabled))
        self.tunnel_ids[gateway_id] = tunnel_id
        return not self.refuse_open

    async def redeem_handoff(self, token, origin, hub_origin):
        self._check()
        self.calls.append(("redeem", origin, hub_origin))
        answer = self.handoffs.get(token)
        if answer is None or answer["origin"] != origin or hub_origin != HUB_ORIGIN:
            return None  # as the web service does: refused, and the token not spent
        del self.handoffs[token]  # single use
        return {"session": answer["session"], "cookie_secret": answer["cookie_secret"]}

    async def event(self, payload):
        self._check()
        if self.event_delay:
            await asyncio.sleep(self.event_delay)
        self.events.append(payload)

    async def heartbeat(self, instance, gateways, sessions):
        self._check()
        self.calls.append(("heartbeat", gateways, sessions))
        return self.heartbeat_answer


class Bench:
    def __init__(self, **config):
        self.hub = StubHub()
        self._config = config
        self.relay: Relay | None = None
        self._runners: list[web.AppRunner] = []
        self.ports: dict[str, int] = {}
        self.gateways: list[FakeGateway] = []
        self.raw_gateways: list = []
        self.browsers: list = []
        self._http: aiohttp.ClientSession | None = None

    async def __aenter__(self) -> "Bench":
        defaults = {
            "internal_secret": SECRET,
            "hub_url": "http://hub.invalid",
            "hub_host": "hub.test",
            "origin_template": "http://{host}:8081",
            "allow_plain_http": True,
            "num_proxies": 0,
            "heartbeat_seconds": 3600.0,  # tests call `relay.beat()` themselves
        }
        self.relay = Relay(RelayConfig(**{**defaults, **self._config}), self.hub)
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
            self._runners.append(runner)
        await self.relay.start()
        for _ in range(200):
            if self.relay.ready:
                break
            await asyncio.sleep(0.01)
        self._http = aiohttp.ClientSession()
        return self

    async def __aexit__(self, *exc) -> None:
        for browser in self.browsers:
            await browser.close()
        for gateway in [*self.gateways, *self.raw_gateways]:
            await gateway.stop()
        await self._http.close()
        await self.relay.stop()
        for runner in self._runners:
            await runner.cleanup()

    # --- addresses --------------------------------------------------------------------------------

    @property
    def tunnel_base(self) -> str:
        return f"http://127.0.0.1:{self.ports['tunnel']}"

    @property
    def console_base(self) -> str:
        return f"http://127.0.0.1:{self.ports['console']}"

    @property
    def console_origin(self) -> str:
        """The origin a browser talking straight to the console port is on (the bench's shared one)."""
        return self.console_base

    # --- a gateway --------------------------------------------------------------------------------

    async def gateway(self, name: str = "a", *, connect: bool = True, **options) -> FakeGateway:
        gateway_id, credential = self.hub.add_gateway(name)
        gateway = FakeGateway(self.tunnel_base, credential, **options)
        gateway.gateway_id = gateway_id
        self.gateways.append(gateway)
        if connect:
            await gateway.connect()
        return gateway

    # --- what the web service would do ------------------------------------------------------------

    async def control(self, action: str, payload: dict, *, secret: str = SECRET) -> tuple[int, dict]:
        url = f"http://127.0.0.1:{self.ports['control']}/control/{action}"
        async with self._http.post(url, json=payload, headers={"Authorization": f"Bearer {secret}"}) as response:
            return response.status, await response.json()

    def frame(self, gateway: FakeGateway, *, origin: str | None = None, minutes: float = 15, email="owner@a.test"):
        now = datetime.now(UTC)
        return {
            "session": f"11111111-1111-4111-8111-{secrets.token_hex(6)}",
            "user": {
                "id": "22222222-2222-4222-8222-222222222222",
                "email": email,
                "name": "Olive Owner",
                "role": "owner",
            },
            "started_at": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "expires_at": (now + timedelta(minutes=minutes)).isoformat().replace("+00:00", "Z"),
            "console_origin": origin or self.console_origin,
            "client_ip": "203.0.113.9",
        }

    async def start_session(self, gateway: FakeGateway, **kwargs) -> tuple[dict, dict]:
        """Start a session as the web service does. Returns (the relay's answer, the frame sent)."""
        frame = self.frame(gateway, **kwargs)
        _, answer = await self.control(
            "session/start", {"gateway_id": gateway.gateway_id, "frame": frame, "return_url": "https://hub.test/back"}
        )
        return answer, frame

    def issue_handoff(self, frame: dict) -> str:
        token = secrets.token_urlsafe(32)
        self.hub.handoffs[token] = {
            "session": frame["session"],
            "cookie_secret": secrets.token_urlsafe(32),
            "origin": frame["console_origin"],
        }
        return token

    async def browser(self, gateway: FakeGateway, *, headers: dict | None = None, **kwargs) -> "Browser":
        """A browser with an open console session on `gateway`."""
        answer, frame = await self.start_session(gateway, **kwargs)
        assert answer == {"ok": True}, answer
        browser = Browser(self, frame, headers=headers)
        response = await browser.hand_off(self.issue_handoff(frame))
        assert response.status == 200, response.status
        return browser


class Browser:
    """Enough of a browser for one host: it keeps the cookies it is given, sends them all back,
    and sends `Origin` with anything that is not a plain read. `headers` are sent with every
    request (a test that plays Caddy in front of a production console sets Host and
    X-Forwarded-Proto there)."""

    def __init__(self, bench: Bench, frame: dict, *, headers: dict | None = None):
        self.bench = bench
        self.frame = frame
        self.session_id = frame["session"]
        self.origin = frame["console_origin"]
        self.extra_headers = headers or {}
        self.cookies: dict[str, str] = {}
        self.set_cookie_headers: list[str] = []  # every Set-Cookie it was ever sent, verbatim
        self.http = aiohttp.ClientSession(cookie_jar=aiohttp.DummyCookieJar(), auto_decompress=False)
        bench.browsers.append(self)

    async def close(self) -> None:
        await self.http.close()

    async def hand_off(self, token: str) -> aiohttp.ClientResponse:
        response = await self.request("POST", "/__hub__/handoff", data={"token": token}, origin=HUB_ORIGIN)
        await response.read()
        return response

    async def request(self, method: str, path: str, *, origin: str | None = None, headers=None, **kwargs):
        sent = {**self.extra_headers, **(headers or {})}
        if method not in ("GET", "HEAD") and "Origin" not in sent:
            sent["Origin"] = origin or self.origin
        if self.cookies and "Cookie" not in sent:
            sent["Cookie"] = "; ".join(f"{name}={value}" for name, value in self.cookies.items())
        response = await self.http.request(
            method, self.bench.console_base + path, headers=sent, allow_redirects=False, **kwargs
        )
        for header in response.headers.getall("Set-Cookie", []):
            self.set_cookie_headers.append(header)
            name, _, value = header.split(";", 1)[0].partition("=")
            if value and "max-age=0" not in header.lower():
                self.cookies[name.strip()] = value.strip()
            else:
                self.cookies.pop(name.strip(), None)
        return response

    async def get(self, path: str, **kwargs):
        return await self.request("GET", path, **kwargs)

    async def post(self, path: str, **kwargs):
        return await self.request("POST", path, **kwargs)


class RawGateway:
    """A gateway that does exactly what a test tells it to, right or wrong: it says hello, accepts
    every session, and hands each `req` frame to `behave(gateway, frame)`."""

    def __init__(self, bench: Bench, name: str = "raw", *, behave=None, headers: dict | None = None):
        self.bench = bench
        self.gateway_id, self.credential = bench.hub.add_gateway(name)
        self.behave = behave
        self.headers = headers or {}
        self.requests: list[dict] = []
        self.frames: list[dict] = []
        self.welcome: dict | None = None
        self.ws: aiohttp.ClientWebSocketResponse | None = None
        self._http = aiohttp.ClientSession()
        self._task: asyncio.Task | None = None
        self.closed = asyncio.Event()

    async def connect(self, *, enabled: bool = True) -> "RawGateway":
        self.ws = await self._http.ws_connect(
            self.bench.tunnel_base + "/api/v1/gateways/tunnel",
            headers={"Authorization": f"Bearer {self.credential}", **self.headers},
            protocols=("pulsar-console.v1",),
            max_msg_size=4 * 1024 * 1024,
        )
        await self.send("hello", console_enabled=enabled)
        self.welcome = json.loads((await self.ws.receive(timeout=5)).data)
        self._task = asyncio.create_task(self._serve())
        self.bench.raw_gateways.append(self)
        return self

    async def send(self, frame_type: str, **fields) -> None:
        await self.ws.send_str(json.dumps({"t": frame_type, **fields}))

    async def data(self, stream_id: int, chunk: bytes) -> None:
        await self.ws.send_bytes(stream_id.to_bytes(4, "big") + chunk)

    async def _serve(self) -> None:
        try:
            async for message in self.ws:
                if message.type != aiohttp.WSMsgType.TEXT:
                    continue
                frame = json.loads(message.data)
                self.frames.append(frame)
                if frame["t"] == "session.start":
                    await self.send("session.ack", session=frame["session"], ok=True)
                elif frame["t"] == "req":
                    self.requests.append(frame)
                    if self.behave is not None:
                        asyncio.ensure_future(self._behave(frame))
        finally:
            self.closed.set()

    async def _behave(self, frame: dict) -> None:
        try:
            await self.behave(self, frame)
        except (ConnectionError, aiohttp.ClientError):
            pass  # the relay closed the tunnel on it, which is often the point

    @property
    def close_code(self) -> int | None:
        return self.ws.close_code

    async def stop(self) -> None:
        if self.ws is not None and not self.ws.closed:
            await self.ws.close()
        if self._task is not None:
            await asyncio.gather(self._task, return_exceptions=True)
        await self._http.close()
