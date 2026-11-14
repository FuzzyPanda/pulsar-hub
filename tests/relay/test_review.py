"""Regression tests for the faults an independent security review found in the relay
(2026-11-15). Each of the first two was confirmed by running an exploit against the relay; the
test fails on the code as it was and passes on the fix.
"""

import asyncio
import json
import logging

import aiohttp
import pytest
from aiohttp import web

from relay import protocol
from relay.config import RelayConfig
from relay.hubapi import HubApi, HubUnavailable
from relay.outbox import Outbox
from tests.relay.harness import HUB_ORIGIN, SECRET, Bench, Browser, RawGateway, async_test
from tests.relay.test_relay import settle

FORGED = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 27\r\n\r\n<script>ATTACKER()</script>"


def cookie_header(browser: Browser) -> str:
    return "; ".join(f"{name}={value}" for name, value in browser.cookies.items())


async def raw_exchange(bench: Bench, browser: Browser, request_line: str, *, seconds: float = 1.5) -> bytes:
    """One request on a raw connection, as a reverse proxy holds one to the relay. Returns every
    byte that comes back until the relay closes the connection or `seconds` pass."""
    reader, writer = await asyncio.open_connection("127.0.0.1", bench.ports["console"])
    host = bench.console_origin.removeprefix("http://")
    writer.write(f"{request_line} HTTP/1.1\r\nHost: {host}\r\nCookie: {cookie_header(browser)}\r\n\r\n".encode())
    await writer.drain()
    received = b""
    try:
        async with asyncio.timeout(seconds):
            while chunk := await reader.read(65536):
                received += chunk
            received += b"<EOF>"
    except TimeoutError:
        received += b"<STILL OPEN>"
    except ConnectionError:
        received += b"<EOF>"  # cut, not closed politely: still the end
    writer.close()
    return received


# --- 1. critical: bytes after a response that has no body ----------------------------------------


@pytest.mark.parametrize(
    ("request_line", "status"),
    [("GET /ui/", 304), ("GET /ui/", 204), ("HEAD /ui/", 200), ("HEAD /ui/", 404)],
)
@async_test
async def test_a_gateway_cannot_put_bytes_after_a_response_that_has_no_body(request_line, status):
    """A 304, a 204 and any answer to HEAD have no body. A gateway that says one has, and then
    sends "body" frames, was having those bytes written to the browser's connection after the
    response was over: on a connection a reverse proxy reuses, the next request's answer, on
    another organisation's console. Now it is a protocol error and the tunnel goes."""
    release = asyncio.Event()

    async def hostile(gateway, frame):
        await gateway.send("res", s=frame["s"], status=status, headers=[], body=True)
        await release.wait()
        await gateway.data(frame["s"], FORGED)
        await gateway.send("res.end", s=frame["s"])

    async with Bench() as bench:
        gateway = await RawGateway(bench, behave=hostile).connect()
        browser = await bench.browser(gateway)
        exchange = asyncio.create_task(raw_exchange(bench, browser, request_line))
        await asyncio.wait_for(gateway.closed.wait(), 5)  # at the `res` frame, before any data
        assert gateway.close_code == protocol.CLOSE_PROTOCOL
        release.set()
        received = await exchange
        assert b"ATTACKER" not in received
        # One response, the relay's own (502, or 401 once the dead tunnel has taken the session
        # with it), and nothing after it.
        assert received.startswith((b"HTTP/1.1 502 ", b"HTTP/1.1 401 "))
        assert received.count(b"HTTP/1.1 ") == 1
        assert not bench.relay.tunnels and not bench.relay.sessions


@async_test
async def test_a_bodiless_response_is_passed_on_without_a_body_and_the_tunnel_stays():
    """The honest form of the same answers still works."""

    async def honest(gateway, frame):
        status = 304 if "cached" in frame["path"] else 204 if "empty" in frame["path"] else 200
        headers = [["etag", '"v1"'], ["content-length", "5"]] if frame["method"] == "HEAD" else [["etag", '"v1"']]
        await gateway.send("res", s=frame["s"], status=status, headers=headers, body=False)

    async with Bench() as bench:
        gateway = await RawGateway(bench, behave=honest).connect()
        browser = await bench.browser(gateway)
        for path, status in (("/ui/cached", 304), ("/ui/empty", 204)):
            response = await browser.get(path)
            assert response.status == status and await response.read() == b""
        head = await browser.request("HEAD", "/ui/page")
        assert head.status == 200 and head.headers["Content-Length"] == "5" and await head.read() == b""
        assert not gateway.closed.is_set()


@pytest.mark.parametrize("status", [100, 101, 103, 199, 600, 0, -1, "200", None, True, 204.0])
@async_test
async def test_a_status_that_is_not_a_final_one_ends_the_tunnel(status):
    """An interim response (1xx) would also leave the real one to be read as the next answer."""

    async def hostile(gateway, frame):
        await gateway.send("res", s=frame["s"], status=status, headers=[], body=False)

    async with Bench() as bench:
        gateway = await RawGateway(bench, behave=hostile).connect()
        browser = await bench.browser(gateway)
        response = await browser.get("/ui/")
        assert response.status in (502, 401)  # 401 once the dead tunnel has taken the session with it
        await asyncio.wait_for(gateway.closed.wait(), 5)
        assert gateway.close_code == protocol.CLOSE_PROTOCOL


@pytest.mark.parametrize(("declared", "sent"), [(100, 10), (100, 0), (10, 100)])
@async_test
async def test_a_body_that_does_not_match_its_declared_length_leaves_no_usable_connection(declared, sent):
    """A gateway that promises more than it sends leaves the connection waiting for the rest; one
    that sends more than it promised has bytes left over. Either way, whatever the proxy in front
    sent down that connection next would be answered with the gateway's bytes. The connection is
    cut instead, and never carries more than was declared."""

    async def hostile(gateway, frame):
        await gateway.send("res", s=frame["s"], status=200, headers=[["content-length", str(declared)]], body=True)
        if sent:
            await gateway.data(frame["s"], b"x" * sent)
        await gateway.send("res.end", s=frame["s"])

    async with Bench() as bench:
        gateway = await RawGateway(bench, behave=hostile).connect()
        browser = await bench.browser(gateway)
        received = await raw_exchange(bench, browser, "GET /ui/")
        head, _, body = received.partition(b"\r\n\r\n")
        assert received.endswith(b"<EOF>"), "the connection was left open"
        assert b"connection: close" in head.lower()
        assert len(body.removesuffix(b"<EOF>")) <= min(declared, sent)
        assert not gateway.closed.is_set()  # a bad length is the stream's problem, not the tunnel's


@async_test
async def test_no_connection_that_carried_a_gateways_response_is_used_again():
    """How a proxied response is framed comes from the gateway, so each goes out on a connection
    that is then closed. The relay's own pages, which it frames itself, may keep theirs."""
    async with Bench() as bench:
        gateway = await bench.gateway("a")
        browser = await bench.browser(gateway)
        for path in ("/ui/", "/ui/big?mb=1", "/ui/echo", "/"):
            received = await raw_exchange(bench, browser, f"GET {path}", seconds=5)
            assert received.endswith(b"<EOF>"), path
            assert b"connection: close" in received.partition(b"\r\n\r\n")[0].lower(), path
            assert received.count(b"HTTP/1.1 ") == 1
        # Its own page for a request with no session keeps the connection, as any server would.
        stranger = Browser(bench, browser.frame)
        stranger.cookies = {"pulsar_console": "nobody"}
        assert (await raw_exchange(bench, stranger, "GET /ui/", seconds=0.5)).endswith(b"<STILL OPEN>")


@async_test
async def test_a_length_that_is_not_plain_digits_and_a_header_that_cannot_be_written_do_no_harm():
    async def odd(gateway, frame):
        headers = [["content-length", "²"], ["x-ok", "fine"], ["x-broken", "caf\udce9"]]
        await gateway.send("res", s=frame["s"], status=200, headers=headers, body=True)
        await gateway.data(frame["s"], b"hello")
        await gateway.send("res.end", s=frame["s"])

    async with Bench() as bench:
        gateway = await RawGateway(bench, behave=odd).connect()
        browser = await bench.browser(gateway)
        response = await browser.get("/ui/")
        assert response.status == 200 and await response.read() == b"hello"
        assert response.headers["X-Ok"] == "fine" and "X-Broken" not in response.headers
        assert not bench.relay.tunnels[gateway.gateway_id].streams


# --- 2. medium: a flood of `console` frames --------------------------------------------------------


@async_test
async def test_console_frames_faster_than_the_contract_allows_end_the_tunnel():
    async with Bench() as bench:
        victim = await bench.gateway("victim")
        victims_browser = await bench.browser(victim)
        gateway = await RawGateway(bench, "flood").connect(enabled=False)
        warnings: list[logging.LogRecord] = []
        handler = logging.Handler()
        handler.emit = warnings.append
        logging.getLogger("relay").addHandler(handler)
        try:
            for n in range(2000):
                try:
                    await gateway.send("console", enabled=n % 2 == 0)
                except (ConnectionError, aiohttp.ClientError):
                    break
            await asyncio.wait_for(gateway.closed.wait(), 5)
            assert gateway.close_code == protocol.CLOSE_PROTOCOL
            await bench.control("session/end", {"session": victims_browser.session_id, "reason": "user"})
            await victim.disconnect()
            await settle(lambda: any(e["event"] == "tunnel.closed" for e in bench.hub.events))
        finally:
            logging.getLogger("relay").removeHandler(handler)
        # The hub heard of one change at most from the flood, and of the other gateway's tunnel at once.
        switched = [e for e in bench.hub.events if e["event"] == "console.switched"]
        assert len(switched) <= 1
        assert len([r for r in warnings if r.levelno >= logging.ERROR]) == 0
        assert len(bench.relay.outbox) == 0


@async_test
async def test_a_console_frame_is_accepted_again_after_the_interval_and_must_be_a_boolean():
    original, protocol.CONSOLE_FRAME_SECONDS = protocol.CONSOLE_FRAME_SECONDS, 0.3
    try:
        async with Bench() as bench:
            gateway = await RawGateway(bench).connect(enabled=False)
            tunnel = bench.relay.tunnels[gateway.gateway_id]
            await gateway.send("console", enabled=True)
            await settle(lambda: tunnel.console_enabled)
            await asyncio.sleep(0.35)
            await gateway.send("console", enabled=False)
            await settle(lambda: not tunnel.console_enabled)
            assert not gateway.closed.is_set()
            await asyncio.sleep(0.35)
            await gateway.send("console", enabled="yes")
            await asyncio.wait_for(gateway.closed.wait(), 5)
            assert gateway.close_code == protocol.CLOSE_PROTOCOL
    finally:
        protocol.CONSOLE_FRAME_SECONDS = original


class SlowHub:
    def __init__(self, delay=0.005):
        self.events, self.delay, self.down = [], delay, False

    async def event(self, payload):
        await asyncio.sleep(self.delay)
        if self.down:
            raise HubUnavailable("down")
        self.events.append(payload)


@async_test
async def test_the_outbox_keeps_the_latest_state_per_gateway_and_starves_nobody():
    """What the exploit did to the old queue: 20,000 switch changes from one gateway, then another
    organisation's event. The old queue dropped 19,000 with an error line each and delivered the
    rest in order, the other organisation's last."""
    hub = SlowHub()
    outbox = Outbox(hub, "relay-1", console_burst=3, console_seconds=0.5)
    task = asyncio.create_task(outbox.run())
    try:
        for n in range(20000):
            outbox.console_switched("noisy", n % 2 == 0)
        outbox.session_ended("victims-session", "user")
        outbox.tunnel_closed("victim", "t1", "tunnel_dropped")
        assert len(outbox) <= 3  # one slot each, however much was said
        await asyncio.sleep(0.2)
        delivered = [e["event"] for e in hub.events]
        assert "session.ended" in delivered and "tunnel.closed" in delivered
        assert delivered.count("console.switched") <= 3
        # Still alternating: the hub hears a few changes, then the latest once the time has passed.
        for n in range(1000):
            outbox.console_switched("noisy", n % 2 == 0)
        outbox.console_switched("noisy", True)
        await asyncio.sleep(1.2)
        switched = [e for e in hub.events if e["event"] == "console.switched"]
        assert len(switched) <= 7 and switched[-1]["enabled"] is True
        assert outbox.told_state("noisy", False) is True and len(outbox) == 0
    finally:
        task.cancel()


@async_test
async def test_the_outbox_replaces_what_is_waiting_and_logs_at_most_once_a_minute():
    hub = SlowHub()
    hub.down = True
    outbox = Outbox(hub, "relay-1", capacity=4)
    records: list[logging.LogRecord] = []
    handler = logging.Handler()
    handler.emit = records.append
    logging.getLogger("relay.outbox").addHandler(handler)
    task = asyncio.create_task(outbox.run())
    try:
        for n in range(500):
            outbox.session_ended(f"session-{n}", "user")  # far more than it keeps
            outbox.tunnel_closed("gateway-a", f"tunnel-{n}", "tunnel_dropped")
        await asyncio.sleep(0.1)
        assert len(outbox) == 4
        assert len(records) == 1 and records[0].levelno == logging.WARNING
        hub.down = False
    finally:
        task.cancel()
        logging.getLogger("relay.outbox").removeHandler(handler)
    # The slot for a gateway's tunnel holds the latest connection it was told about.
    assert outbox._slots[("tunnel.closed", "gateway-a")]["tunnel"] == "tunnel-499"


@async_test
async def test_a_gateway_that_reconnects_with_its_switch_flipped_does_not_flood_the_hub():
    """The switch state also travels in `hello`. Reconnecting with it changed, over and over, is
    paced by the same rule: the hub is given what it already has until the pace allows."""
    outbox = Outbox(SlowHub(), "relay-1", console_burst=2, console_seconds=60)
    told = [outbox.state_at_open("g", n % 2 == 0) for n in range(51)]
    changes = sum(1 for before, after in zip(told, told[1:], strict=False) if before != after)
    assert changes <= 2 and len(outbox) == 1  # the latest is waiting for its turn


# --- 3. low: only the cookie name that belongs to the scheme --------------------------------------


@async_test
async def test_over_https_only_the_host_prefixed_cookie_is_a_console_cookie():
    """A sibling console origin can set a plain `pulsar_console` cookie for the whole console
    domain. It used to count as a second console cookie, and two meant "no session": a way to
    lock someone out of their console, or to slip them into another."""
    async with Bench(allow_plain_http=False, origin_template="https://{gateway}.console.test") as bench:
        gateway = await bench.gateway("a", connect=False)
        gateway.extra_headers = {"X-Forwarded-Proto": "https"}
        await gateway.connect()
        host = f"{gateway.gateway_id.replace('-', '')}.console.test"
        as_caddy = {"Host": host, "X-Forwarded-Proto": "https"}
        browser = await bench.browser(gateway, origin=f"https://{host}", headers=as_caddy)
        real = browser.cookies["__Host-pulsar_console"]
        tossed = {"Cookie": f"pulsar_console=from-a-sibling; __Host-pulsar_console={real}"}
        assert (await browser.get("/ui/", headers=tossed)).status == 200
        # The real secret under the plain name is not a session either.
        assert (await browser.get("/ui/", headers={"Cookie": f"pulsar_console={real}"})).status == 401
        # Two of the real name is still nobody.
        doubled = {"Cookie": f"__Host-pulsar_console=x; __Host-pulsar_console={real}"}
        assert (await browser.get("/ui/", headers=doubled)).status == 401


# --- 4. low: the hand-off comes from the hub's own page -------------------------------------------


@async_test
async def test_a_hand_off_is_accepted_only_from_the_hubs_origin():
    async with Bench() as bench:
        gateway = await bench.gateway("a")
        _, frame = await bench.start_session(gateway)
        token = bench.issue_handoff(frame)
        before = len(bench.hub.calls)
        absent = Browser(bench, frame)
        response = await absent.http.post(bench.console_base + "/__hub__/handoff", data={"token": token})
        assert response.status == 403 and len(bench.hub.calls) == before  # no Origin: the hub is not even asked
        for origin in ("https://evil.example", bench.console_origin, "null"):
            stranger = Browser(bench, frame)
            response = await stranger.request("POST", "/__hub__/handoff", data={"token": token}, origin=origin)
            assert response.status == 403 and not stranger.cookies, origin
        # None of that spent the token: the person's own hand-off still works.
        owner = Browser(bench, frame)
        assert (await owner.hand_off(token)).status == 200
        assert bench.hub.calls[-1] == ("redeem", bench.console_origin, HUB_ORIGIN)
        assert (await owner.get("/ui/")).status == 200


@async_test
async def test_a_hand_off_body_is_read_whole_or_not_at_all():
    async with Bench() as bench:
        gateway = await bench.gateway("a")
        _, frame = await bench.start_session(gateway)
        token = bench.issue_handoff(frame)
        body = f"token={token}".encode()
        reader, writer = await asyncio.open_connection("127.0.0.1", bench.ports["console"])
        host = bench.console_origin.removeprefix("http://")
        head = (
            f"POST /__hub__/handoff HTTP/1.1\r\nHost: {host}\r\nOrigin: {HUB_ORIGIN}\r\n"
            f"Content-Type: application/x-www-form-urlencoded\r\nContent-Length: {len(body)}\r\n\r\n"
        )
        writer.write(head.encode() + body[:10])  # the body arrives in two pieces
        await writer.drain()
        await asyncio.sleep(0.2)
        writer.write(body[10:])
        await writer.drain()
        status_line = await asyncio.wait_for(reader.readline(), 5)
        writer.close()
        assert status_line.split()[1] == b"200"


# --- 5. low: Refresh with a quoted address ----------------------------------------------------------


@pytest.mark.parametrize(
    ("sent", "kept"),
    [
        ('0; "//evil.example/x"', "0; url=/x"),
        ("0; '//evil.example/x'", "0; url=/x"),
        ('0; url="https://evil.example/x"', "0; url=/x"),
        ("0;url='//evil.example/x'", "0; url=/x"),
        ('0; URL = "//evil.example/x"', "0; url=/x"),
        ('3; "/ui/next"', "3; url=/ui/next"),
        ("5", "5"),
        ('5; ""', "5"),
        ("0; //evil.example/x", "0; url=/x"),
        ("x; //evil.example", "0; url=/"),
    ],
)
def test_a_refresh_address_is_confined_however_it_is_quoted(sent, kept):
    out, _ = protocol.response_headers_for_browser([["Refresh", sent]], shared_origin=False)
    value = dict(out)["Refresh"]
    assert value == kept
    assert '"' not in value and "'" not in value and "//" not in value


# --- 6. low: only the hub's own 401 means "not accepted" -------------------------------------------


async def hub_answering(status: int, body=None):
    async def handler(request):
        return web.json_response(body if body is not None else {}, status=status)

    app = web.Application()
    app.router.add_route("*", "/{tail:.*}", handler)
    runner = web.AppRunner(app, access_log=None)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 0)
    await site.start()
    port = site._server.sockets[0].getsockname()[1]
    config = RelayConfig(
        internal_secret=SECRET, hub_url=f"http://127.0.0.1:{port}", hub_host="hub.test", origin_template="x"
    )
    return runner, config


@pytest.mark.parametrize("status", [400, 403, 404, 409, 429, 301, 302, 500, 502, 503])
@async_test
async def test_only_an_explicit_401_says_a_credential_is_not_accepted(status):
    """A gateway told 401 stops until someone pairs it again. A rate limit, a proxy's error page
    or a redirect from something between the relay and the web service must never read as that."""
    runner, config = await hub_answering(status)
    try:
        async with aiohttp.ClientSession() as http:
            api = HubApi(config, http)
            with pytest.raises(HubUnavailable):
                await api.authorize_tunnel("hubgw_x")
            with pytest.raises(HubUnavailable):
                await api.started("relay-1")
            with pytest.raises(HubUnavailable):
                await api.heartbeat("relay-1", [], [])
            with pytest.raises(HubUnavailable):
                await api.event({"event": "tunnel.closed"})
            if status != 403:
                with pytest.raises(HubUnavailable):
                    await api.redeem_handoff("t", "o", "h")
            if status != 409:
                with pytest.raises(HubUnavailable):
                    await api.tunnel_opened("r", "g", tunnel_id="t", protocol="p", software_version="", enabled=True)
    finally:
        await runner.cleanup()


@async_test
async def test_the_hubs_real_answers_are_read_as_what_they_are():
    for status, check in (
        (401, lambda api: api.authorize_tunnel("hubgw_x")),
        (403, lambda api: api.redeem_handoff("t", "o", "h")),
    ):
        runner, config = await hub_answering(status)
        try:
            async with aiohttp.ClientSession() as http:
                assert await check(HubApi(config, http)) is None
        finally:
            await runner.cleanup()
    runner, config = await hub_answering(409)
    try:
        async with aiohttp.ClientSession() as http:
            api = HubApi(config, http)
            opened = await api.tunnel_opened("r", "g", tunnel_id="t", protocol="p", software_version="", enabled=True)
            assert opened is False
    finally:
        await runner.cleanup()
    runner, config = await hub_answering(200, {"gateway_id": "g"})
    try:
        async with aiohttp.ClientSession() as http:
            api = HubApi(config, http)
            assert await api.authorize_tunnel("hubgw_x") == {"gateway_id": "g"}
            await api.started("relay-1")
    finally:
        await runner.cleanup()


@async_test
async def test_a_gateway_is_told_try_later_when_the_hub_gives_a_strange_answer():
    """End to end through the relay: the web service answering 429 to the credential check
    reaches the gateway as 503, not as the 401 that would unpair it."""
    runner, config = await hub_answering(429)
    try:
        async with aiohttp.ClientSession() as http:
            async with Bench() as bench:
                bench.relay.hub = HubApi(config, http)  # the real client, against a hub that says 429
                with pytest.raises(aiohttp.WSServerHandshakeError) as refused:
                    await http.ws_connect(
                        bench.tunnel_base + "/api/v1/gateways/tunnel",
                        headers={"Authorization": "Bearer hubgw_anything"},
                        protocols=("pulsar-console.v1",),
                    )
                assert refused.value.status == 503
    finally:
        await runner.cleanup()


# --- 7. low: checks made before a wait are made again after it ------------------------------------


@async_test
async def test_a_request_that_waited_for_a_stream_is_checked_again_before_it_is_sent():
    async with Bench(session_streams=1, slot_seconds=5, response_seconds=30) as bench:
        gateway = await bench.gateway("a")
        browser = await bench.browser(gateway)
        holding = asyncio.create_task(browser.get("/ui/slow"))
        await settle(lambda: len(bench.relay.tunnels[gateway.gateway_id].streams) == 1)
        waiting = asyncio.create_task(browser.get("/ui/echo?after-the-wait"))
        await asyncio.sleep(0.2)
        # While it waits, the session is ended from the hub. That frees the stream it was waiting for.
        await bench.control("session/end", {"session": browser.session_id, "reason": "admin"})
        response = await asyncio.wait_for(waiting, 5)
        assert response.status == 401
        assert not [r for r in gateway.console.seen if "after-the-wait" in r["path"]]
        assert not [e for e in gateway.audit if e["event"] == "request.refused"]  # it was never sent at all
        await asyncio.gather(holding, return_exceptions=True)


@async_test
async def test_when_the_hub_goes_stale_what_is_in_flight_stops_too():
    async with Bench(response_seconds=30) as bench:
        gateway = await bench.gateway("a")
        browser = await bench.browser(gateway)
        in_flight = asyncio.create_task(browser.get("/ui/slow"))
        download = await browser.get("/ui/big?mb=50")
        await download.content.read(100_000)
        tunnel = bench.relay.tunnels[gateway.gateway_id]
        await settle(lambda: len(tunnel.streams) == 2)
        bench.hub.down = True
        await bench.relay.beat()
        assert len(tunnel.streams) == 2  # one missed heartbeat is not staleness
        bench.relay.hub_seen_at -= 1_000_000  # long past every allowance
        await bench.relay.beat()
        assert not tunnel.streams
        assert (await asyncio.wait_for(in_flight, 5)).status == 502
        with pytest.raises((aiohttp.ClientError, asyncio.IncompleteReadError)):
            await download.read()
        await settle(lambda: not gateway._streams)  # the gateway was told to stop both
        assert not gateway.closed.is_set()  # the tunnel itself is left alone


# --- 8. low: the limit is on the frame as it goes on the wire --------------------------------------


@async_test
async def test_headers_that_make_the_frame_too_large_once_encoded_are_refused():
    async with Bench() as bench:
        gateway = await bench.gateway("a")
        browser = await bench.browser(gateway)
        # 36,000 characters: inside the header limit as characters, 216,000 bytes once escaped.
        headers = {f"X-Note-{n}": "é" * 3600 for n in range(10)}
        before = len(gateway.console.seen)
        response = await browser.get("/ui/echo", headers=headers)
        assert response.status == 431
        assert len(gateway.console.seen) == before and not gateway.closed.is_set()
        modest = await browser.get("/ui/echo", headers={"X-Note": "é" * 3600})
        assert modest.status == 200
        seen = {name.lower(): value for name, value in gateway.console.seen[-1]["headers"].items()}
        assert seen["x-note"] == "é" * 3600


# --- notes ------------------------------------------------------------------------------------------


def test_a_header_name_with_an_underscore_is_never_passed_on():
    sent = protocol.request_headers_for_gateway(
        [
            ("X_Forwarded_For", "10.0.0.1"),
            ("x_hub_console_session", "someone-elses"),
            ("X_Pulsar_Mtls_Verified", "1"),
            ("X_Real_IP", "10.0.0.1"),
            ("Accept", "text/html"),
        ],
        cookie_header="",
        client_ip="203.0.113.9",
        origin="https://a.console.test",
        session_id="sess-1",
        content_length=None,
    )
    names = [name for name, _ in sent]
    assert not [name for name in names if "_" in name]
    assert dict(sent)["x-forwarded-for"] == "203.0.113.9" and dict(sent)["x-hub-console-session"] == "sess-1"


@async_test
async def test_a_path_with_a_backslash_is_not_sent_to_a_gateway():
    async with Bench() as bench:
        gateway = await bench.gateway("a")
        browser = await bench.browser(gateway)
        before = len(gateway.console.seen)
        for target in ("/\\evil.example/x", "/ui/..\\..\\x"):
            received = await raw_exchange(bench, browser, f"GET {target}")
            assert received.split()[1] in (b"400", b"404"), target
        assert len(gateway.console.seen) == before


def test_the_console_domain_may_not_be_the_hubs_host_under_it_or_over_it():
    from relay.config import ConfigError, check_origin_template

    good = "https://{gateway}.console.example.net"
    check_origin_template(good, allow_plain_http=False, hub_base_url="https://hub.example.com")
    for template, hub in (
        ("https://{gateway}.hub.example.com", "https://hub.example.com"),  # the hub's own host
        ("https://{gateway}.console.hub.example.com", "https://hub.example.com"),  # under it
        ("https://{gateway}.example.com", "https://hub.example.com"),  # over it
        ("https://{gateway}.HUB.example.com", "https://hub.example.com:8443"),
    ):
        with pytest.raises(ConfigError):
            check_origin_template(template, allow_plain_http=False, hub_base_url=hub)
    # The plain-HTTP lab mode is for a hub that is itself plain HTTP.
    check_origin_template("http://{host}:8081", allow_plain_http=True, hub_base_url="http://192.168.1.143")
    with pytest.raises(ConfigError):
        check_origin_template("http://{host}:8081", allow_plain_http=True, hub_base_url="https://hub.example.com")
    with pytest.raises(ConfigError):
        check_origin_template(good, allow_plain_http=True, hub_base_url="https://hub.example.com")


@async_test
async def test_a_late_report_names_the_tunnel_it_is_about():
    """Finding 9: `tunnel.closed` and `tunnel/opened` carry the relay's id for the connection, so
    the web service can tell a late report about an old connection from one about the current."""
    async with Bench() as bench:
        first = await bench.gateway("a")
        first_id = bench.hub.tunnel_ids[first.gateway_id]
        assert first_id == bench.relay.tunnels[first.gateway_id].id
        await first.disconnect()
        await settle(lambda: any(e["event"] == "tunnel.closed" for e in bench.hub.events))
        closed = [e for e in bench.hub.events if e["event"] == "tunnel.closed"][-1]
        assert closed["tunnel"] == first_id and closed["gateway_id"] == first.gateway_id
        await first.connect()
        assert bench.hub.tunnel_ids[first.gateway_id] != first_id
        await bench.relay.beat()
        beat = [c for c in bench.hub.calls if c[0] == "heartbeat"][-1]
        assert beat[1] == [
            {"id": first.gateway_id, "tunnel": bench.hub.tunnel_ids[first.gateway_id], "console_enabled": True}
        ]
        assert json.dumps(beat)  # plain data, as it goes to the web service
