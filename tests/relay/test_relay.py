"""The relay itself, with a fake gateway on one side and a browser on the other.

Each test names the invariant it demonstrates (A to E in the pull request that added the remote
console). The hub's web service is a stand-in here (`harness.StubHub`); the same relay is run
against the real one in `tests/test_console_e2e.py`.
"""

import asyncio
import hashlib
import json

import aiohttp
import pytest

from relay import protocol
from tests.relay.harness import SECRET, Bench, Browser, async_test
from tools.fake_gateway import big_digest


async def settle(condition, *, seconds: float = 5.0):
    """Wait for something another task is about to do."""
    for _ in range(int(seconds / 0.01)):
        if condition():
            return
        await asyncio.sleep(0.01)
    raise AssertionError("the condition never became true")


async def connect_raw(bench: Bench, credential: str, **kwargs):
    http = aiohttp.ClientSession()
    try:
        headers = {"Authorization": f"Bearer {credential}", **kwargs.pop("headers", {})}
        return http, await http.ws_connect(
            bench.tunnel_base + "/api/v1/gateways/tunnel",
            headers=headers,
            protocols=kwargs.pop("protocols", ("pulsar-console.v1",)),
            **kwargs,
        )
    except Exception:
        await http.close()
        raise


async def refused_status(bench: Bench, credential: str, **kwargs) -> tuple[int, dict]:
    with pytest.raises(aiohttp.WSServerHandshakeError) as caught:
        await connect_raw(bench, credential, **kwargs)
    return caught.value.status, dict(caught.value.headers or {})


# --- A. the tunnel --------------------------------------------------------------------------------


@async_test
async def test_a_gateway_opens_a_tunnel_with_its_credential_and_the_hub_learns_its_state():
    async with Bench() as bench:
        gateway = await bench.gateway("a", console_enabled=False)
        assert gateway.welcome["gateway_id"] == gateway.gateway_id
        assert gateway.welcome["org_ref"] == "org-a" and gateway.welcome["site_ref"] == "site-a"
        assert gateway.welcome["limits"] == {
            "max_streams": 32,
            "window": 262144,
            "max_data": 65536,
            "max_text_frame": 131072,
            "max_header_bytes": 65536,
            "max_request_body": 16 * 1024 * 1024,
        }
        assert ("opened", gateway.gateway_id, "pulsar-console.v1", "fake-1.0", False) in bench.hub.calls
        # The switch is on the gateway. When someone there turns it on, the hub is told.
        await gateway.set_console_enabled(True)
        await settle(lambda: bench.hub.events)
        assert bench.hub.events[-1]["event"] == "console.switched" and bench.hub.events[-1]["enabled"] is True
        assert bench.relay.tunnels[gateway.gateway_id].console_enabled


@async_test
async def test_a_credential_the_hub_does_not_accept_opens_nothing():
    async with Bench() as bench:
        _, good = bench.hub.add_gateway("a")
        for bad in ("hubgw_wrong", good + "x", "not-a-gateway-credential", ""):
            status, _ = await refused_status(bench, bad)
            assert status == 401, bad
        assert not bench.relay.tunnels
        # No Authorization header at all.
        async with aiohttp.ClientSession() as http:
            with pytest.raises(aiohttp.WSServerHandshakeError) as caught:
                await http.ws_connect(bench.tunnel_base + "/api/v1/gateways/tunnel", protocols=("pulsar-console.v1",))
            assert caught.value.status == 401


@async_test
async def test_a_tunnel_needs_tls_unless_the_lab_flag_is_on():
    template = "https://{gateway}.console.test"
    async with Bench(allow_plain_http=False, origin_template=template) as bench:
        _, credential = bench.hub.add_gateway("a")
        status, _ = await refused_status(bench, credential)  # plain HTTP, as it reached Caddy
        assert status == 403
        http, ws = await connect_raw(bench, credential, headers={"X-Forwarded-Proto": "https"})
        await ws.close()
        await http.close()
    async with Bench(allow_plain_http=True) as bench:  # the bench: INSECURE_COOKIES is on
        gateway = await bench.gateway("a")
        assert gateway.welcome is not None


@async_test
async def test_a_browser_cannot_open_a_tunnel():
    async with Bench() as bench:
        _, credential = bench.hub.add_gateway("a")
        status, _ = await refused_status(bench, credential, headers={"Origin": "https://evil.example"})
        assert status == 403


@async_test
async def test_a_version_the_hub_does_not_speak_is_refused_before_any_frame():
    async with Bench() as bench:
        gateway_id, credential = bench.hub.add_gateway("a")
        async with aiohttp.ClientSession() as http:
            async with http.get(
                bench.tunnel_base + "/api/v1/gateways/tunnel",
                headers={
                    "Authorization": f"Bearer {credential}",
                    "Upgrade": "websocket",
                    "Connection": "Upgrade",
                    "Sec-WebSocket-Version": "13",
                    "Sec-WebSocket-Key": "dGhlIHNhbXBsZSBub25jZQ==",
                    "Sec-WebSocket-Protocol": "pulsar-console.v0, pulsar-console.v7",
                },
            ) as response:
                assert response.status == 426
                assert (await response.json())["supported"] == ["pulsar-console.v1"]
        assert ("refused", gateway_id, "pulsar-console.v0, pulsar-console.v7") in bench.hub.calls
        assert not bench.relay.tunnels


@async_test
async def test_a_hub_that_cannot_be_asked_says_try_later_and_never_not_accepted():
    """A 401 tells a gateway its pairing is over. The relay must not say that just because the web
    service is restarting."""
    async with Bench() as bench:
        _, credential = bench.hub.add_gateway("a")
        bench.hub.down = True
        status, headers = await refused_status(bench, credential)
        assert status == 503 and headers.get("Retry-After")


@async_test
async def test_a_gateway_that_never_says_hello_is_dropped():
    async with Bench() as bench:
        _, credential = bench.hub.add_gateway("a")
        original, protocol.HELLO_SECONDS = protocol.HELLO_SECONDS, 0.2
        try:
            http, ws = await connect_raw(bench, credential)
            message = await ws.receive(timeout=5)
            assert message.type in (aiohttp.WSMsgType.CLOSE, aiohttp.WSMsgType.CLOSING, aiohttp.WSMsgType.CLOSED)
            assert ws.close_code == protocol.CLOSE_PROTOCOL
            await http.close()
            # Anything but hello as the first frame is the same mistake.
            http, ws = await connect_raw(bench, credential)
            await ws.send_str(json.dumps({"t": "res", "s": 1, "status": 200}))
            await ws.receive(timeout=5)
            assert ws.close_code == protocol.CLOSE_PROTOCOL
            await http.close()
        finally:
            protocol.HELLO_SECONDS = original
        assert not bench.relay.tunnels


@async_test
async def test_revoking_a_gateway_closes_its_tunnel_and_its_sessions_at_once():
    async with Bench() as bench:
        gateway = await bench.gateway("a")
        browser = await bench.browser(gateway)
        assert (await browser.get("/ui/")).status == 200
        status, answer = await bench.control("gateway/close", {"gateway_id": gateway.gateway_id})
        assert (status, answer) == (200, {"ok": True})
        await asyncio.wait_for(gateway.closed.wait(), 5)
        assert gateway.close_code == protocol.CLOSE_REVOKED
        assert not bench.relay.tunnels and not bench.relay.sessions
        assert (await browser.get("/ui/")).status == 401
        # The gateway heard why, before the tunnel went: its own audit log has the reason.
        ended = [e for e in gateway.audit if e["event"] == "session.ended"]
        assert [e["reason"] for e in ended] == ["gateway_revoked"]
        # And it cannot come back: the hub no longer accepts the credential.
        bench.hub.credentials.clear()
        with pytest.raises(aiohttp.WSServerHandshakeError) as caught:
            await gateway.connect()
        assert caught.value.status == 401


@async_test
async def test_the_heartbeat_closes_what_the_hub_no_longer_accepts():
    """The backstop for a push that did not arrive: within one heartbeat the hub's answer closes
    the tunnel of a revoked gateway and ends a session that is no longer valid."""
    async with Bench() as bench:
        kept, dropped = await bench.gateway("a"), await bench.gateway("b")
        browser = await bench.browser(kept)
        bench.hub.heartbeat_answer = {
            "close": [dropped.gateway_id],
            "end": [{"id": browser.session_id, "reason": "membership_changed"}],
        }
        await bench.relay.beat()
        await asyncio.wait_for(dropped.closed.wait(), 5)
        assert dropped.close_code == protocol.CLOSE_REVOKED
        assert list(bench.relay.tunnels) == [kept.gateway_id]
        assert (await browser.get("/ui/")).status == 401
        await settle(lambda: any(e["event"] == "session.ended" for e in kept.audit))
        ended = [e for e in kept.audit if e["event"] == "session.ended"][-1]
        assert ended["reason"] == "membership_changed" and ended["user"] == "owner@a.test"
        # What the relay told the hub it holds.
        call = [c for c in bench.hub.calls if c[0] == "heartbeat"][-1]
        assert {g["id"] for g in call[1]} == {kept.gateway_id, dropped.gateway_id} and call[2] == [browser.session_id]


@async_test
async def test_a_second_tunnel_from_the_same_gateway_replaces_the_first():
    async with Bench() as bench:
        first = await bench.gateway("a")
        browser = await bench.browser(first)
        second = type(first)(bench.tunnel_base, first.credential)
        bench.gateways.append(second)
        await second.connect()
        await asyncio.wait_for(first.closed.wait(), 5)
        assert first.close_code == protocol.CLOSE_REPLACED
        assert len(bench.relay.tunnels) == 1
        # Sessions do not move from one connection to the next.
        assert (await browser.get("/ui/")).status == 401


@async_test
async def test_a_dropped_tunnel_ends_its_sessions_and_the_hub_is_told():
    async with Bench() as bench:
        gateway = await bench.gateway("a")
        browser = await bench.browser(gateway)
        await gateway.disconnect()
        await settle(lambda: not bench.relay.tunnels)
        assert not bench.relay.sessions
        assert (await browser.get("/ui/")).status == 401
        await settle(lambda: any(e["event"] == "tunnel.closed" for e in bench.hub.events))
        assert [e for e in gateway.audit if e["event"] == "session.ended"][-1]["reason"] == "tunnel_closed"


@async_test
async def test_a_frame_the_hub_does_not_know_is_ignored_and_a_malformed_one_ends_the_tunnel():
    async with Bench() as bench:
        _, credential = bench.hub.add_gateway("a")
        http, ws = await connect_raw(bench, credential)
        await ws.send_str(json.dumps({"t": "hello", "console_enabled": True}))
        assert json.loads((await ws.receive(timeout=5)).data)["t"] == "welcome"
        await ws.send_str(json.dumps({"t": "something.from.the.future", "x": 1}))
        await ws.send_str(json.dumps({"t": "res", "s": 999, "status": 200}))  # a stream that is not open
        await ws.send_bytes(b"\x00\x00\x03\xe7data")  # likewise
        await asyncio.sleep(0.1)
        assert not ws.closed and len(bench.relay.tunnels) == 1
        await ws.send_str("this is not json")
        await ws.receive(timeout=5)
        assert ws.close_code == protocol.CLOSE_PROTOCOL
        await http.close()


# --- B. sessions ----------------------------------------------------------------------------------


@async_test
async def test_a_session_exists_only_once_the_gateway_has_accepted_it():
    async with Bench() as bench:
        gateway = await bench.gateway("a")
        answer, frame = await bench.start_session(gateway)
        assert answer == {"ok": True}
        started = [e for e in gateway.audit if e["event"] == "session.started"][-1]
        # The gateway is told who the session is for, from where and until when.
        assert started["user"] == "owner@a.test" and started["role"] == "owner"
        assert started["user_id"] == frame["user"]["id"] and started["client_ip"] == "203.0.113.9"
        assert started["expires_at"] == frame["expires_at"]

        gateway.refuse_sessions = "busy"
        answer, frame = await bench.start_session(gateway)
        assert answer == {"ok": False, "reason": "busy"} and frame["session"] not in bench.relay.sessions

        # The switch is on the gateway: off there means no session, whatever the hub asks.
        gateway.refuse_sessions = ""
        await gateway.set_console_enabled(False)
        await settle(lambda: not bench.relay.tunnels[gateway.gateway_id].console_enabled)
        answer, _ = await bench.start_session(gateway)
        assert answer == {"ok": False, "reason": "disabled"}

        _, answer = await bench.control("session/start", {"gateway_id": "no-such-gateway", "frame": frame})
        assert answer == {"ok": False, "reason": "not_connected"}


@async_test
async def test_switching_the_console_off_on_the_gateway_ends_its_sessions():
    async with Bench() as bench:
        gateway = await bench.gateway("a")
        browser = await bench.browser(gateway)
        await gateway.set_console_enabled(False)
        await settle(lambda: not bench.relay.sessions)
        assert (await browser.get("/ui/")).status == 401
        await settle(lambda: any(e["event"] == "session.ended" for e in bench.hub.events))
        assert [e for e in bench.hub.events if e["event"] == "session.ended"][-1]["reason"] == "gateway_ended"


@async_test
async def test_the_hand_off_token_works_once_and_only_on_its_own_origin():
    async with Bench() as bench:
        gateway = await bench.gateway("a")
        answer, frame = await bench.start_session(gateway)
        token = bench.issue_handoff(frame)
        browser = Browser(bench, frame)
        # Without the hand-off there is no session cookie and nothing is relayed.
        assert (await browser.get("/ui/")).status == 401
        response = await browser.hand_off(token)
        assert response.status == 200 and response.headers["Cache-Control"] == "no-store"
        assert (await browser.get("/ui/")).status == 200
        # A second use, by anyone, is refused, and gives no cookie.
        thief = Browser(bench, frame)
        assert (await thief.hand_off(token)).status == 403 and not thief.cookies
        assert (await thief.get("/ui/")).status == 401
        # Junk never reaches the hub at all.
        before = len(bench.hub.calls)
        assert (await thief.hand_off("short")).status == 403
        assert (await thief.hand_off("x" * 5000)).status == 403
        assert len(bench.hub.calls) == before


@async_test
async def test_the_console_cookie_is_httponly_strict_host_only_and_a_digest_on_the_server():
    async with Bench() as bench:
        gateway = await bench.gateway("a")
        browser = await bench.browser(gateway)
        (header,) = browser.set_cookie_headers
        attributes = [part.strip().lower() for part in header.split(";")[1:]]
        assert header.startswith("pulsar_console=")
        assert sorted(attributes) == ["httponly", "path=/", "samesite=strict"]  # no Domain: host-only
        secret = browser.cookies["pulsar_console"]
        held = bench.relay.sessions[browser.session_id]
        assert held.cookie_digest == hashlib.sha256(secret.encode()).hexdigest() and secret not in repr(held)


@async_test
async def test_in_production_the_cookie_is_host_prefixed_and_secure_and_tied_to_one_gateways_origin():
    template = "https://{gateway}.console.test"
    async with Bench(allow_plain_http=False, origin_template=template) as bench:
        gateways = []
        for name in ("a", "b"):
            gateway = await bench.gateway(name, connect=False)
            gateway.extra_headers = {"X-Forwarded-Proto": "https"}  # Caddy terminated TLS in front of the relay
            await gateway.connect()
            gateways.append(gateway)
        a, b = gateways
        host_a = f"{a.gateway_id.replace('-', '')}.console.test"
        host_b = f"{b.gateway_id.replace('-', '')}.console.test"
        as_caddy = {"Host": host_a, "X-Forwarded-Proto": "https"}
        browser = await bench.browser(a, origin=f"https://{host_a}", headers=as_caddy)
        (header,) = browser.set_cookie_headers
        assert header.startswith("__Host-pulsar_console=")
        attributes = sorted(part.strip().lower() for part in header.split(";")[1:])
        assert attributes == ["httponly", "path=/", "samesite=strict", "secure"]  # no Domain: host-only
        page = await browser.get("/ui/")
        assert page.status == 200 and page.headers["Cache-Control"] != "no-store"  # its own origin: may cache
        # The same cookie presented on another gateway's origin opens nothing there.
        assert (await browser.get("/ui/", headers={"Host": host_b, "X-Forwarded-Proto": "https"})).status == 401
        # Nor does anything work over plain HTTP.
        assert (await browser.get("/ui/", headers={"Host": host_a, "X-Forwarded-Proto": "http"})).status == 403
        # A session opened for B's origin cannot be handed off on A's.
        answer, frame = await bench.start_session(b, origin=f"https://{host_b}")
        stray = Browser(bench, frame, headers=as_caddy)
        assert (await stray.hand_off(bench.issue_handoff(frame))).status == 403 and not stray.cookies


@async_test
async def test_two_cookies_with_the_relays_name_are_treated_as_none():
    """Something on the same host planted a second cookie to shadow the real one."""
    async with Bench() as bench:
        gateway = await bench.gateway("a")
        browser = await bench.browser(gateway)
        real = browser.cookies["pulsar_console"]
        doubled = {"Cookie": f"pulsar_console=attackers-value; pulsar_console={real}"}
        assert (await browser.get("/ui/", headers=doubled)).status == 401
        assert (await browser.get("/ui/")).status == 200


@async_test
async def test_a_session_ends_at_its_time_limit_and_can_be_extended_before_it():
    async with Bench() as bench:
        gateway = await bench.gateway("a")
        browser = await bench.browser(gateway, minutes=0.02)  # 1.2 seconds
        assert (await browser.get("/ui/")).status == 200
        later = bench.frame(gateway, minutes=15)["expires_at"]
        _, answer = await bench.control("session/extend", {"session": browser.session_id, "expires_at": later})
        assert answer == {"ok": True}
        await settle(lambda: any(e["event"] == "session.extended" for e in gateway.audit))
        await asyncio.sleep(1.4)
        assert (await browser.get("/ui/")).status == 200  # extended, so still running

        short = await bench.browser(gateway, minutes=0.02, email="admin@a.test")
        await asyncio.sleep(1.4)
        # Past its time the cookie opens nothing, whether or not anything has swept it up yet,
        # and the page that says so still knows the way back to the hub.
        late = await short.get("/ui/")
        assert late.status == 401 and "https://hub.test/back" in await late.text()
        await bench.relay.beat()
        assert short.session_id not in bench.relay.sessions
        await settle(
            lambda: any(e["event"] == "session.ended" and e["session"] == short.session_id for e in gateway.audit)
        )
        ended = [e for e in gateway.audit if e["event"] == "session.ended" and e["session"] == short.session_id]
        assert ended and ended[0]["reason"] == "expired" and ended[0]["user"] == "admin@a.test"
        await settle(lambda: any(e.get("session") == short.session_id for e in bench.hub.events))
        told = [e for e in bench.hub.events if e.get("session") == short.session_id][-1]
        assert told["event"] == "session.ended" and told["reason"] == "expired"


@async_test
async def test_ending_a_session_from_the_hub_or_from_the_console_stops_it_at_once():
    async with Bench() as bench:
        gateway = await bench.gateway("a")
        browser = await bench.browser(gateway)
        _, answer = await bench.control("session/end", {"session": browser.session_id, "reason": "admin"})
        assert answer == {"ok": True}
        response = await browser.get("/ui/")
        assert response.status == 401 and "has ended" in await response.text()
        assert "https://hub.test/back" in await (await browser.get("/__hub__/ended")).text()
        assert [e for e in gateway.audit if e["event"] == "session.ended"][-1]["reason"] == "admin"
        # A page that was polling is sent to the "ended" page rather than left to fail quietly.
        polled = await browser.get("/ui/tick", headers={"HX-Request": "true"})
        assert polled.status == 401 and polled.headers["HX-Redirect"] == "/__hub__/ended"

        mine = await bench.browser(gateway)
        ended = await mine.post("/__hub__/end")
        assert ended.status == 200 and "max-age=0" in mine.set_cookie_headers[-1].lower()
        assert (await mine.get("/ui/")).status == 401
        await settle(lambda: any(e.get("session") == mine.session_id for e in bench.hub.events))
        assert [e for e in bench.hub.events if e.get("session") == mine.session_id][-1]["reason"] == "user"
        # Another site cannot end someone's session for them.
        third = await bench.browser(gateway)
        await third.post("/__hub__/end", origin="https://evil.example")
        assert (await third.get("/ui/")).status == 200


@async_test
async def test_a_gateway_refuses_a_request_for_a_session_it_was_not_told_about():
    """The gateway's own check, which a real gateway must make too: the hub's word that a request
    belongs to a session is not enough if the gateway never accepted that session."""
    async with Bench() as bench:
        gateway = await bench.gateway("a")
        browser = await bench.browser(gateway)
        gateway.sessions.clear()  # as if the gateway had ended it locally
        assert (await browser.get("/ui/")).status == 502
        assert gateway.audit[-1]["event"] == "request.refused"
        assert not [r for r in gateway.console.seen if r["path"] == "/ui/"]


# --- C. origin isolation and cookies --------------------------------------------------------------


@async_test
async def test_a_gateways_cookies_stay_in_the_relay_and_the_hubs_cookies_stay_out_of_the_gateway():
    async with Bench() as bench:
        gateway = await bench.gateway("a")
        browser = await bench.browser(gateway)
        # On a bench the console shares a host name with the hub, so the browser sends the hub's
        # cookies here too. None of them may travel on.
        browser.cookies.update({"sessionid": "THE-HUBS-SESSION", "csrftoken": "THE-HUBS-CSRF", "messages": "hub"})
        page = await browser.get("/ui/", headers={"Authorization": "Bearer THE-HUBS-TOKEN"})
        assert page.status == 200 and "Set-Cookie" not in page.headers
        first = gateway.console.seen[-1]["headers"]
        assert "Cookie" not in first and "Authorization" not in first
        # The console set its own session and CSRF cookies. The browser never saw them...
        assert set(browser.cookies) == {"pulsar_console", "sessionid", "csrftoken", "messages"}
        assert browser.cookies["sessionid"] == "THE-HUBS-SESSION"
        assert all(h.startswith("pulsar_console=") for h in browser.set_cookie_headers)
        # ...and the next request carries them, from the jar, and nothing of the hub's or the relay's.
        echoed = await (await browser.get("/ui/echo")).json()
        cookie = echoed["headers"]["Cookie"]
        assert "sessionid=" in cookie and "csrftoken=" in cookie
        for foreign in (
            "THE-HUBS-SESSION",
            "THE-HUBS-CSRF",
            "messages",
            "pulsar_console",
            browser.cookies["pulsar_console"],
        ):
            assert foreign not in json.dumps(echoed)


@async_test
async def test_one_gateways_cookies_are_never_sent_to_another_gateway_or_another_session():
    async with Bench() as bench:
        a, b = await bench.gateway("a"), await bench.gateway("b")
        on_a = await bench.browser(a)
        await on_a.get("/ui/cookie?set=secret_of_a:AAAA")
        assert (await (await on_a.get("/ui/cookie")).json())["cookies"]["secret_of_a"] == "AAAA"
        # The same browser, on the same bench origin, opens gateway B. B sees nothing A set.
        on_b = await bench.browser(b, email="owner@a.test")
        on_b.cookies.update({k: v for k, v in on_a.cookies.items() if k != "pulsar_console"})
        seen_by_b = (await (await on_b.get("/ui/cookie")).json())["cookies"]
        assert "secret_of_a" not in seen_by_b and "AAAA" not in json.dumps(b.console.seen)
        # A second person on gateway A does not inherit the first person's console cookies either.
        colleague = await bench.browser(a, email="admin@a.test")
        assert "secret_of_a" not in (await (await colleague.get("/ui/cookie")).json())["cookies"]
        # And when a session ends its jar is gone with it.
        await bench.control("session/end", {"session": on_a.session_id, "reason": "user"})
        again = await bench.browser(a)
        assert "secret_of_a" not in (await (await again.get("/ui/cookie")).json())["cookies"]


@async_test
async def test_a_hostile_console_cannot_plant_anything_on_the_origin():
    async with Bench() as bench:
        gateway = await bench.gateway("a")
        browser = await bench.browser(gateway)
        response = await browser.get("/ui/hostile")
        assert response.status == 200
        for header in (
            "Set-Cookie",
            "Strict-Transport-Security",
            "Clear-Site-Data",
            "Service-Worker-Allowed",
            "Alt-Svc",
        ):
            assert header not in response.headers, header
        assert response.headers["Cache-Control"] == "no-store"  # the bench origin is shared: nothing is cached
        assert response.headers["Refresh"] == "0; url=/x" and response.headers["HX-Redirect"] == "/hx"
        assert response.headers["Referrer-Policy"] == "same-origin"
        assert response.headers["Cross-Origin-Resource-Policy"] == "same-origin"
        assert response.headers["Server"] == "pulsar-hub"  # neither the console's server nor the relay's library
        # A service worker would outlive the session; its script is never served.
        worker = await browser.get("/static/app.js", headers={"Service-Worker": "script"})
        assert worker.status == 403
        # A redirect that tries to leave the console is kept on it.
        away = await browser.get("/ui/elsewhere")
        assert away.status == 302 and away.headers["Location"] == "/landing?x=1"


@async_test
async def test_a_request_from_another_site_is_refused_before_it_reaches_the_gateway():
    async with Bench() as bench:
        gateway = await bench.gateway("a")
        browser = await bench.browser(gateway)
        before = len(gateway.console.seen)
        for origin in (
            "https://evil.example",
            "https://hub.test",
            "null",
            bench.console_origin.replace("127.0.0.1", "localhost"),
        ):
            response = await browser.post("/ui/echo-any", origin=origin, data={"x": "1"})
            assert response.status == 403, origin
        assert len(gateway.console.seen) == before
        assert (await browser.post("/ui/echo-any", data={"x": "1"})).status == 200


@async_test
async def test_only_a_path_on_the_console_is_ever_sent_to_a_gateway():
    """A request line that names another host, or begins with two slashes, goes nowhere. The
    gateway makes the same check, and it is the gateway that decides what a path reaches."""
    async with Bench() as bench:
        gateway = await bench.gateway("a")
        browser = await bench.browser(gateway)
        cookie = "; ".join(f"{name}={value}" for name, value in browser.cookies.items())
        before = len(gateway.console.seen)
        for target in ("//evil.example/ui/", "http://169.254.169.254/latest/", "evil.example:22"):
            reader, writer = await asyncio.open_connection("127.0.0.1", bench.ports["console"])
            host = bench.console_origin.removeprefix("http://")
            writer.write(
                f"GET {target} HTTP/1.1\r\nHost: {host}\r\nCookie: {cookie}\r\nConnection: close\r\n\r\n".encode()
            )
            await writer.drain()
            status_line = (await reader.readline()).decode()
            writer.close()
            assert status_line.split()[1] in ("400", "404"), (target, status_line)
        assert len(gateway.console.seen) == before
        assert (await browser.get("/ui/")).status == 200


@async_test
async def test_the_relays_own_paths_are_never_sent_to_a_gateway():
    async with Bench() as bench:
        gateway = await bench.gateway("a")
        browser = await bench.browser(gateway)
        for path in ("/__hub__/", "/__hub__/anything", "/__hub__/handoff", "/%5F%5Fhub__/x"):
            assert (await browser.get(path)).status in (404, 405), path
        assert not [r for r in gateway.console.seen if "hub__" in r["path"]]


# --- D. proxy correctness and limits --------------------------------------------------------------


@async_test
async def test_a_form_post_with_csrf_and_its_redirect_work_through_the_relay():
    async with Bench() as bench:
        gateway = await bench.gateway("a")
        browser = await bench.browser(gateway)
        page = await browser.get("/")
        assert page.status == 302 and page.headers["Location"] == "/ui/"
        html = await (await browser.get("/ui/")).text()
        assert "Remote session for: owner@a.test (owner)" in html  # attributed on the gateway's side
        token = html.split('name="csrfmiddlewaretoken" value="')[1].split('"')[0]
        saved = await browser.post("/ui/note", data={"csrfmiddlewaretoken": token, "note": "locked up at six"})
        # The console answered with an absolute address on its own local origin. The browser is
        # sent to the same path on the console origin instead.
        assert saved.status == 303 and saved.headers["Location"] == "/ui/?saved=1"
        assert gateway.console.notes == ["locked up at six"]
        posted = [r for r in gateway.console.seen if r["path"] == "/ui/note"][-1]["headers"]
        posted = {name.title(): value for name, value in posted.items()}
        # The gateway rewrote Origin to its own; the forwarding headers came down the tunnel.
        assert posted["Origin"] == gateway.console.local_origin
        assert posted["X-Forwarded-For"] == "127.0.0.1" and posted["X-Forwarded-Proto"] == "http"
        assert posted["X-Forwarded-Host"] == bench.console_origin.removeprefix("http://")
        assert posted["X-Hub-Console-Session"] == browser.session_id
        assert "Saved." in await (await browser.get("/ui/?saved=1")).text()
        # A wrong token is the console's own refusal, passed through as it is.
        assert (await browser.post("/ui/note", data={"csrfmiddlewaretoken": "wrong", "note": "x"})).status == 403


@async_test
async def test_every_method_the_console_uses_is_carried_and_others_are_not():
    async with Bench() as bench:
        gateway = await bench.gateway("a")
        browser = await bench.browser(gateway)
        for method in ("GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"):
            response = await browser.request(method, "/ui/echo-any?m=" + method)
            assert response.status == 200, method
            assert (await response.json())["method"] == method
        head = await browser.request("HEAD", "/ui/echo-any")
        assert head.status == 200 and await head.read() == b""
        assert (await browser.request("TRACE", "/ui/echo-any")).status == 405
        upgrade = await browser.get("/ui/echo", headers={"Connection": "Upgrade", "Upgrade": "websocket"})
        assert upgrade.status == 501
        assert (await browser.get("/no/such/page")).status == 404


@async_test
async def test_an_upload_arrives_whole_and_one_over_the_cap_is_refused():
    async with Bench(max_request_body=6 * 1024 * 1024) as bench:
        gateway = await bench.gateway("a")
        browser = await bench.browser(gateway)
        html = await (await browser.get("/ui/")).text()
        token = html.split('name="csrfmiddlewaretoken" value="')[1].split('"')[0]
        payload = bytes(range(256)) * 4096 * 5  # 5 MiB, many windows' worth
        form = aiohttp.FormData()
        form.add_field("csrfmiddlewaretoken", token)
        form.add_field("file", payload, filename="firmware.bin", content_type="application/octet-stream")
        result = await (await browser.post("/ui/upload", data=form)).json()
        assert result == {"name": "firmware.bin", "size": len(payload), "sha256": hashlib.sha256(payload).hexdigest()}
        # Over the cap: refused by its declared size, before a byte is sent on.
        before = len(gateway.console.seen)
        form = aiohttp.FormData()
        form.add_field("csrfmiddlewaretoken", token)
        form.add_field("file", b"x" * (7 * 1024 * 1024), filename="too-big.bin")
        assert (await browser.post("/ui/upload", data=form)).status == 413
        assert len(gateway.console.seen) == before


@async_test
async def test_a_large_download_streams_through_with_bounded_memory():
    async with Bench() as bench:
        gateway = await bench.gateway("a")
        browser = await bench.browser(gateway)
        tunnel = bench.relay.tunnels[gateway.gateway_id]
        response = await browser.get("/ui/big?mb=20")
        assert response.status == 200 and response.headers["Content-Length"] == str(20 * 1024 * 1024)
        digest, received, most_held = hashlib.sha256(), 0, 0
        async for chunk in response.content.iter_chunked(64 * 1024):
            digest.update(chunk)
            received += len(chunk)
            for stream in tunnel.streams.values():
                most_held = max(most_held, stream.unacknowledged)
            if received % (4 * 1024 * 1024) < 64 * 1024:
                await asyncio.sleep(0.05)  # a browser that reads in bursts
        assert received == 20 * 1024 * 1024 and digest.hexdigest() == big_digest(20)
        # The relay never held more of the body than one window, however fast the gateway sent.
        assert 0 < most_held <= protocol.WINDOW
        assert not tunnel.streams


@async_test
async def test_a_gateway_that_ignores_the_window_loses_its_tunnel():
    """Back-pressure is the gateway's duty too. One that sends more than it was given credit for
    is cut off rather than buffered without limit."""
    async with Bench() as bench:
        gateway = await bench.gateway("a", connect=False)
        gateway.ignore_window = True
        await gateway.connect()
        browser = await bench.browser(gateway)
        response = await browser.get("/ui/big?mb=20")
        await asyncio.sleep(0.5)  # the browser reads nothing; the gateway keeps sending
        await asyncio.wait_for(gateway.closed.wait(), 10)
        assert gateway.close_code == protocol.CLOSE_PROTOCOL
        with pytest.raises((aiohttp.ClientError, asyncio.IncompleteReadError)):
            await response.read()


@async_test
async def test_many_requests_at_once_share_the_tunnel_without_mixing():
    async with Bench() as bench:
        gateway = await bench.gateway("a")
        browser = await bench.browser(gateway)

        async def fetch(n: int):
            if n % 5 == 0:
                response = await browser.get("/ui/big?mb=1")
                return n, hashlib.sha256(await response.read()).hexdigest() == big_digest(1)
            response = await browser.get(f"/ui/echo?n={n}")
            return n, (await response.json())["path"] == f"/ui/echo?n={n}"

        results = await asyncio.gather(*(fetch(n) for n in range(40)))
        assert all(ok for _, ok in results) and len(results) == 40
        assert not bench.relay.tunnels[gateway.gateway_id].streams


@async_test
async def test_one_session_cannot_take_every_stream_and_a_full_tunnel_says_busy():
    async with Bench(session_streams=2, slot_seconds=0.3, response_seconds=5) as bench:
        gateway = await bench.gateway("a")
        browser = await bench.browser(gateway)
        colleague = await bench.browser(gateway, email="admin@a.test")
        held = [asyncio.create_task(browser.get("/ui/slow")) for _ in range(2)]
        await settle(lambda: len(bench.relay.tunnels[gateway.gateway_id].streams) == 2)
        # The third request of the same session waits for a slot, then is told to try again.
        busy = await browser.get("/ui/echo")
        assert busy.status == 503 and busy.headers["Retry-After"]
        # Someone else's session on the same gateway is not held up by it.
        assert (await colleague.get("/ui/echo")).status == 200
        for task in held:
            task.cancel()
        await asyncio.gather(*held, return_exceptions=True)
        await settle(lambda: not bench.relay.tunnels[gateway.gateway_id].streams)
        assert (await browser.get("/ui/echo")).status == 200


@async_test
async def test_a_gateway_that_does_not_answer_times_out_and_is_told_to_stop():
    async with Bench(response_seconds=0.4) as bench:
        gateway = await bench.gateway("a")
        browser = await bench.browser(gateway)
        response = await browser.get("/ui/slow")
        assert response.status == 504
        tunnel = bench.relay.tunnels[gateway.gateway_id]
        await settle(lambda: not tunnel.streams and not gateway._streams)  # the gateway got the reset
        assert (await browser.get("/ui/echo")).status == 200  # and the tunnel is fine


@async_test
async def test_a_browser_that_goes_away_frees_its_stream_on_both_sides():
    async with Bench() as bench:
        gateway = await bench.gateway("a")
        browser = await bench.browser(gateway)
        tunnel = bench.relay.tunnels[gateway.gateway_id]
        response = await browser.get("/ui/big?mb=50")
        await response.content.read(100_000)
        response.close()  # the tab was closed in the middle of a download
        await settle(lambda: not tunnel.streams and not gateway._streams)
        assert (await browser.get("/ui/echo")).status == 200


@async_test
async def test_a_response_with_too_many_headers_is_not_passed_on():
    async with Bench() as bench:
        gateway = await bench.gateway("a")
        browser = await bench.browser(gateway)
        assert (await browser.get("/ui/many-headers?n=20")).status == 200
        assert (await browser.get("/ui/many-headers?n=250")).status == 502
        assert (await browser.get("/ui/echo")).status == 200  # the tunnel is unharmed


# --- E. the internal channel and failing closed ---------------------------------------------------


@async_test
async def test_the_control_port_answers_only_to_the_shared_secret():
    async with Bench() as bench:
        gateway = await bench.gateway("a")
        browser = await bench.browser(gateway)
        for secret in ("", "wrong", SECRET[:-1], SECRET + "x"):
            status, _ = await bench.control("session/end", {"session": browser.session_id}, secret=secret)
            assert status == 404
            status, _ = await bench.control("gateway/close", {"gateway_id": gateway.gateway_id}, secret=secret)
            assert status == 404
        assert (await browser.get("/ui/")).status == 200 and bench.relay.tunnels
        # The control and tunnel addresses do not exist on the console listener, where browsers are.
        async with aiohttp.ClientSession() as http:
            for path in ("/control/session/end", "/control/health", "/api/v1/gateways/tunnel", "/tls-ask"):
                async with http.post(
                    bench.console_base + path, json={}, headers={"Authorization": f"Bearer {SECRET}"}
                ) as response:
                    assert response.status == 401, path  # just a console request with no session


@async_test
async def test_when_the_hub_cannot_be_asked_nothing_is_relayed():
    """The relay cannot know that a session was ended or a person removed while the web service is
    out of reach, so after a few missed heartbeats it stops relaying until the hub answers again."""
    async with Bench(heartbeat_seconds=0.1) as bench:
        gateway = await bench.gateway("a")
        browser = await bench.browser(gateway)
        assert (await browser.get("/ui/")).status == 200
        bench.hub.down = True
        bench.relay.hub_seen_at -= 60  # as if the heartbeat had been failing for a minute
        refused = await browser.get("/ui/")
        assert refused.status == 503 and refused.headers["Retry-After"]
        # A hand-off is not honoured either.
        answer, frame = await bench.start_session(gateway, email="admin@a.test")
        assert (await Browser(bench, frame).hand_off(bench.issue_handoff(frame))).status == 403
        bench.hub.down = False
        await settle(lambda: bench.relay.hub_is_fresh)
        assert (await browser.get("/ui/")).status == 200
        # The gateway's tunnel was never touched: the hub being unwell is not the gateway's problem.
        assert not gateway.closed.is_set()


@async_test
async def test_caddy_is_told_yes_only_for_a_connected_gateways_host_name():
    async with Bench() as bench:
        gateway = await bench.gateway("a")
        label = gateway.gateway_id.replace("-", "")
        async with aiohttp.ClientSession() as http:
            base = f"http://127.0.0.1:{bench.ports['control']}/tls-ask?domain="
            async with http.get(base + f"{label}.console.example.net") as response:
                assert response.status == 200
            for name in ("0000.console.example.net", "console.example.net", "", "hub.example.com"):
                async with http.get(base + name) as response:
                    assert response.status == 404, name
            await gateway.disconnect()
            await settle(lambda: not bench.relay.tunnels)
            async with http.get(base + f"{label}.console.example.net") as response:
                assert response.status == 404
