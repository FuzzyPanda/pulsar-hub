"""Conformance checks for a gateway's side of the remote-console tunnel (`pulsar-console.v1`).

This plays the HUB. Point a gateway at it and it runs through the contract in
`docs/CONTRACTS.md`, "Remote console", saying PASS, FAIL or SKIP for each rule it can observe
from the hub's end of the tunnel. It needs aiohttp and nothing else from this repository, so it
can be copied next to a gateway build.

    python tools/console_conformance.py --listen 127.0.0.1:8900

Then give the gateway `http://127.0.0.1:8900` as its hub address (plain HTTP needs the gateway's
own lab flag, HUB_LINK_ALLOW_INSECURE_HTTP=true) and pair it with any code: this tool accepts every
pairing code, hands out the credential shown at start, and answers the gateway's ordinary polling
calls with an empty site, so an unmodified gateway build can be tested end to end.

  --path /ui/            a page of the console that answers 200 to a GET without signing in
                         (default /healthz)
  --large-path PATH      a GET that returns more than 300 kB, to check flow control on responses
  --slow                 also run the checks that take a minute or more (expiry, back-off)
  --check-revocation     finish by closing with 4003 and checking the gateway does not come back.
                         A real gateway will mark itself revoked, as it must: pair it again after.

What it cannot see is listed at the end as things to check by hand on the gateway.
"""

import argparse
import asyncio
import json
import secrets
import struct
import sys
import time
import uuid
from datetime import UTC, datetime, timedelta

import aiohttp
from aiohttp import web

SUBPROTOCOL = "pulsar-console.v1"
WINDOW = 256 * 1024
MAX_DATA = 64 * 1024
LIMITS = {
    "max_streams": 32,
    "window": WINDOW,
    "max_data": MAX_DATA,
    "max_text_frame": 128 * 1024,
    "max_header_bytes": 64 * 1024,
    "max_request_body": 16 * 1024 * 1024,
}
BY_HAND = """
Check by hand on the gateway (the hub cannot see these):
  [ ] every request from the tunnel goes to the console's one fixed local address, whatever the
      frame says; nothing in a frame can name a host, a port or another service
  [ ] Host is set by the gateway; Origin and Referer are rewritten from `console_origin` to the
      console's local origin, so the console's own CSRF check passes for a form posted remotely
  [ ] X-Forwarded-*, X-Hub-* and client-certificate headers are trusted only from the tunnel and
      are stripped from every request that reaches the console any other way
  [ ] the remote console is OFF until someone switches it on at the gateway, and the hub cannot
      switch it on
  [ ] session start, end (with the reason) and each action taken in a session are in the gateway's
      own audit log with the hub user's id, email and role
  [ ] with the hub unreachable, or this tool stopped, doors behave exactly as before
"""


def now_text(delta: float = 0.0) -> str:
    return (datetime.now(UTC) + timedelta(seconds=delta)).strftime("%Y-%m-%dT%H:%M:%SZ")


class Stream:
    def __init__(self):
        self.head: asyncio.Future = asyncio.get_running_loop().create_future()
        self.done = asyncio.Event()
        self.received = 0
        self.unacknowledged = 0
        self.most_unacknowledged = 0
        self.biggest_frame = 0
        self.reset = ""
        self.send_credit = WINDOW  # request body the hub may still send on this stream
        self.window_grants = 0  # `win` frames the gateway sent for the request body

    @property
    def finished(self) -> bool:
        return self.done.is_set()


class Connection:
    """One tunnel, as the hub holds it."""

    def __init__(self, ws: web.WebSocketResponse, request: web.Request):
        self.ws = ws
        self.upgrade = request
        self.hello: asyncio.Future = asyncio.get_running_loop().create_future()
        self.streams: dict[int, Stream] = {}
        self.acks: dict[str, asyncio.Future] = {}
        self.pongs = asyncio.Queue()
        self.console_frames: list[dict] = []
        self.gateway_ended: list[dict] = []
        self.problems: list[str] = []
        self.closed = asyncio.Event()
        self.auto_grant = True
        self._next = 0

    async def send(self, frame_type: str, **fields) -> None:
        await self.ws.send_str(json.dumps({"t": frame_type, **fields}, separators=(",", ":")))

    async def read(self) -> None:
        try:
            async for message in self.ws:
                if message.type == aiohttp.WSMsgType.TEXT:
                    await self._text(message.data)
                elif message.type == aiohttp.WSMsgType.BINARY:
                    await self._data(message.data)
                elif message.type == aiohttp.WSMsgType.PONG:
                    self.pongs.put_nowait(message.data)
                elif message.type == aiohttp.WSMsgType.PING:
                    await self.ws.pong(message.data)
        finally:
            self.closed.set()
            for stream in self.streams.values():
                stream.done.set()

    async def _text(self, raw: str) -> None:
        try:
            frame = json.loads(raw)
            kind = frame["t"]
        except (ValueError, KeyError, TypeError):
            self.problems.append(f"a text frame that is not a JSON object with t: {raw[:80]!r}")
            return
        if kind == "hello":
            if not self.hello.done():
                self.hello.set_result(frame)
        elif kind == "session.ack":
            future = self.acks.get(str(frame.get("session")))
            if future is not None and not future.done():
                future.set_result(frame)
        elif kind == "session.end":
            self.gateway_ended.append(frame)
        elif kind == "console":
            self.console_frames.append(frame)
        elif kind in ("res", "res.end", "rst", "win"):
            stream = self.streams.get(frame.get("s"))
            if stream is None:
                return
            if kind == "res":
                if stream.head.done():
                    self.problems.append("two res frames for one stream")
                else:
                    stream.head.set_result(frame)
                    if frame.get("body") is not True:
                        stream.done.set()
            elif kind == "res.end":
                stream.done.set()
            elif kind == "rst":
                stream.reset = str(frame.get("reason") or "reset")
                if not stream.head.done():
                    stream.head.set_result(None)
                stream.done.set()
            else:
                grant = frame.get("n")
                if isinstance(grant, bool) or not isinstance(grant, int) or grant <= 0:
                    self.problems.append(f"a win frame whose n is not a positive number: {grant!r}")
                else:
                    stream.window_grants += 1
                    stream.send_credit += grant

    async def _data(self, raw: bytes) -> None:
        if len(raw) <= 4:
            self.problems.append("a data frame with no data")
            return
        (stream_id,) = struct.unpack_from(">I", raw)
        stream = self.streams.get(stream_id)
        if stream is None:
            return
        size = len(raw) - 4
        stream.received += size
        stream.unacknowledged += size
        stream.biggest_frame = max(stream.biggest_frame, size)
        stream.most_unacknowledged = max(stream.most_unacknowledged, stream.unacknowledged)
        if self.auto_grant and stream.unacknowledged >= WINDOW // 2:
            await self.grant(stream_id, stream)

    async def grant(self, stream_id: int, stream: Stream) -> None:
        grant, stream.unacknowledged = stream.unacknowledged, 0
        if grant:
            await self.send("win", s=stream_id, n=grant)

    async def start_session(self, *, lifetime: float = 900, email: str = "conformance@hub.test") -> tuple[str, dict]:
        session = str(uuid.uuid4())
        future = asyncio.get_running_loop().create_future()
        self.acks[session] = future
        await self.send(
            "session.start",
            session=session,
            user={"id": str(uuid.uuid4()), "email": email, "name": "Conformance Check", "role": "owner"},
            started_at=now_text(),
            expires_at=now_text(lifetime),
            console_origin="https://conformance.console.invalid",
            client_ip="192.0.2.1",
        )
        try:
            return session, await asyncio.wait_for(future, 5)
        except TimeoutError:
            return session, {}

    async def request(self, session: str, method: str, path: str, *, body: bytes = b"", wait: float = 30):
        """Send one request. Returns (stream, head frame or None)."""
        self._next += 1
        stream_id, stream = self._next, Stream()
        self.streams[stream_id] = stream
        headers = [
            ["accept", "*/*"],
            ["user-agent", "pulsar-console-conformance"],
            ["x-forwarded-for", "192.0.2.1"],
            ["x-forwarded-proto", "https"],
            ["x-forwarded-host", "conformance.console.invalid"],
            ["x-hub-console-session", session],
        ]
        if body:
            headers += [["content-type", "application/octet-stream"], ["content-length", str(len(body))]]
            headers += [["origin", "https://conformance.console.invalid"]]
        await self.send("req", s=stream_id, session=session, method=method, path=path, headers=headers, body=bool(body))
        if body:
            view, deadline = memoryview(body), time.monotonic() + wait
            while view and not stream.reset and time.monotonic() < deadline:
                if stream.send_credit <= 0:  # wait for the gateway to grant more
                    await asyncio.sleep(0.02)
                    continue
                size = min(len(view), MAX_DATA, stream.send_credit)
                await self.ws.send_bytes(struct.pack(">I", stream_id) + bytes(view[:size]))
                view, stream.send_credit = view[size:], stream.send_credit - size
            if not view:
                await self.send("req.end", s=stream_id)
            elif not stream.reset:
                stream.reset = "no answer"  # the gateway stopped granting credit and never reset
        try:
            head = await asyncio.wait_for(asyncio.shield(stream.head), wait)
        except TimeoutError:
            head = None
            stream.reset = stream.reset or "no answer"
        return stream_id, stream, head


class Conformance:
    def __init__(self, args):
        self.args = args
        self.credential = args.credential or "hubgw_" + secrets.token_urlsafe(40)
        self.gateway_id, self.org_ref, self.site_ref = (str(uuid.uuid4()) for _ in range(3))
        self.connections: asyncio.Queue = asyncio.Queue()
        self.attempts: list[tuple[float, int]] = []  # (when, status) of every tunnel attempt
        self.refuse_with: int | None = None
        self.results: list[tuple[str, str, str]] = []

    # --- the hub's ordinary calls, answered just enough for a gateway to stay paired ---------------

    def app(self) -> web.Application:
        app = web.Application()
        app.router.add_post("/api/v1/gateways/pair", self.pair)
        app.router.add_get("/api/v1/gateways/tunnel", self.tunnel)
        app.router.add_get("/api/v1/sites/{site}/access", self.access)
        app.router.add_post("/api/v1/sites/{site}/access/ack", self.nothing)
        app.router.add_post("/api/v1/sites/{site}/events", self.events)
        app.router.add_post("/api/v1/sites/{site}/state", self.nothing)
        return app

    def _authorised(self, request: web.Request) -> bool:
        return request.headers.get("Authorization", "") == f"Bearer {self.credential}"

    async def pair(self, request):
        return web.json_response(
            {
                "gateway_id": self.gateway_id,
                "credential": self.credential,
                "org_ref": self.org_ref,
                "org_name": "Conformance",
                "site_ref": self.site_ref,
                "site_name": "Conformance bench",
                "site_timezone": "UTC",
                "poll_seconds": 60,
            },
            status=201,
        )

    async def access(self, request):
        if not self._authorised(request):
            return web.json_response({"detail": "This gateway's credential is not accepted."}, status=401)
        version = "c0ffee00c0ffee00c0ffee00c0ffee00"
        if request.query.get("version") == version:
            return web.Response(status=304)
        return web.json_response(
            {
                "org_ref": self.org_ref,
                "site_ref": self.site_ref,
                "version": version,
                "generated_at": now_text(),
                "access_groups": [],
                "people": [],
            }
        )

    async def events(self, request):
        return web.json_response({"accepted": 0, "duplicates": 0, "rejected": []})

    async def nothing(self, request):
        return web.Response(status=204)

    async def tunnel(self, request: web.Request):
        def refuse(status: int, detail: str, **extra):
            self.attempts.append((time.monotonic(), status))
            return web.json_response({"detail": detail, **extra}, status=status)

        if not self._authorised(request):
            return refuse(401, "This gateway's credential is not accepted.")
        if self.refuse_with == 426:
            return refuse(426, "No common protocol version.", supported=[SUBPROTOCOL])
        offered = [p.strip() for p in request.headers.get("Sec-WebSocket-Protocol", "").split(",") if p.strip()]
        if SUBPROTOCOL not in offered:
            self.note(
                "FAIL", "upgrade", f"the gateway offered {offered or 'no subprotocol'}; it must offer {SUBPROTOCOL}"
            )
            return refuse(426, "No common protocol version.", supported=[SUBPROTOCOL])
        ws = web.WebSocketResponse(protocols=(SUBPROTOCOL,), autoping=False, max_msg_size=LIMITS["max_text_frame"])
        await ws.prepare(request)
        self.attempts.append((time.monotonic(), 101))
        connection = Connection(ws, request)
        self.connections.put_nowait(connection)
        await connection.read()
        return ws

    # --- reporting --------------------------------------------------------------------------------

    def note(self, outcome: str, name: str, detail: str = "") -> None:
        self.results.append((outcome, name, detail))
        print(f"{outcome:4}  {name}" + (f" - {detail}" if detail else ""), flush=True)

    def check(self, name: str, passed: bool, detail: str = "", *, fail: str = "") -> bool:
        self.note("PASS" if passed else "FAIL", name, detail if passed else (fail or detail))
        return passed

    async def next_connection(self, timeout: float) -> Connection | None:
        try:
            connection = await asyncio.wait_for(self.connections.get(), timeout)
        except TimeoutError:
            return None
        asyncio.ensure_future(self._welcome(connection))
        return connection

    async def _welcome(self, connection: Connection) -> None:
        try:
            await asyncio.wait_for(asyncio.shield(connection.hello), 10)
        except TimeoutError:
            return
        await connection.send(
            "welcome",
            gateway_id=self.gateway_id,
            org_ref=self.org_ref,
            site_ref=self.site_ref,
            limits=LIMITS,
            ping_seconds=20,
            idle_seconds=60,
        )

    # --- the checks -------------------------------------------------------------------------------

    async def run(self) -> int:
        args = self.args
        print(f"Hub address for the gateway:  http://{args.listen}")
        print(f"Credential (any pairing code is accepted and returns it):  {self.credential}")
        print("Waiting for the gateway to open its tunnel...\n", flush=True)
        connection = await self.next_connection(args.wait)
        if connection is None:
            refused = [status for _, status in self.attempts if status != 101]
            hint = f" (attempts refused: {refused})" if refused else ""
            self.note("FAIL", "upgrade", f"no tunnel was opened within {args.wait:.0f} s{hint}")
            return self.finish()
        request = connection.upgrade
        self.check("upgrade: Authorization bearer credential, subprotocol offered", True)
        self.check(
            "upgrade: no Origin header",
            "Origin" not in request.headers,
            fail="a gateway is not a browser; the hub refuses a tunnel that carries Origin",
        )
        try:
            hello = await asyncio.wait_for(asyncio.shield(connection.hello), 10)
        except TimeoutError:
            self.note("FAIL", "hello within 10 seconds", "no hello frame arrived; the hub closes with 4000")
            return self.finish()
        self.check(
            "hello: console_enabled is a boolean",
            isinstance(hello.get("console_enabled"), bool),
            f"console_enabled={hello.get('console_enabled')!r}, software_version={hello.get('software_version')!r}",
        )
        await asyncio.sleep(0.2)

        await connection.send("x-conformance.unknown", note="a frame type from a later version")
        await connection.ws.ping(b"conformance")
        try:
            await asyncio.wait_for(connection.pongs.get(), 5)
            self.check("keepalive: answers a WebSocket ping", True)
        except TimeoutError:
            self.check("keepalive: answers a WebSocket ping", False, fail="no pong within 5 seconds")
        self.check(
            "an unknown frame type is ignored",
            not connection.closed.is_set(),
            fail="the gateway closed the tunnel on a frame type it did not know",
        )

        if hello.get("console_enabled") is not True:
            _, ack = await connection.start_session()
            self.check(
                "console switched off: session.start is refused with reason disabled",
                ack.get("ok") is False and ack.get("reason") == "disabled",
                fail=f"got {ack or 'no session.ack within 5 seconds'}",
            )
            self.note("SKIP", "everything else", "switch the remote console on at the gateway and run again")
            return self.finish()

        session, ack = await connection.start_session()
        if not self.check("session.start is acknowledged within 5 seconds", ack.get("ok") is True, fail=f"got {ack}"):
            return self.finish()

        _, stream, head = await connection.request(session, "GET", args.path)
        ok = head is not None and isinstance(head.get("status"), int) and 200 <= head["status"] <= 599
        self.check(f"GET {args.path}: a res frame with a final status", ok, f"status {head and head.get('status')}")
        if ok:
            headers = head.get("headers")
            well_formed = isinstance(headers, list) and all(
                isinstance(h, list) and len(h) == 2 and all(isinstance(x, str) for x in h) for h in headers
            )
            self.check("res: headers are a list of [name, value] string pairs", well_formed)
            await asyncio.wait_for(stream.done.wait(), 30)
            self.check("res: the body ends with res.end (or body is false)", stream.finished and not stream.reset)
            self.check(
                f"GET {args.path}: answers 200 (the path given with --path should)",
                head["status"] == 200,
                fail=f"status {head['status']}; give --path a page that needs no sign-in",
            )
            self.check("data frames carry at most 65536 bytes", stream.biggest_frame <= MAX_DATA)

        _, stream, head = await connection.request(str(uuid.uuid4()), "GET", args.path, wait=10)
        refused = head is None or head.get("status", 0) >= 400
        self.check(
            "a request for a session the gateway was not told about is refused",
            refused and stream.reset != "no answer",
            fail=f"answered {head and head.get('status')}" if not refused else "no rst and no res within 10 seconds",
        )

        for path in ("http://169.254.169.254/latest/meta-data/", "//example.invalid/", "example.invalid:22"):
            _, stream, head = await connection.request(session, "GET", path, wait=10)
            refused = head is None or head.get("status", 0) >= 400
            self.check(
                f"a path that is not an origin-form path is refused: {path}",
                refused and stream.reset != "no answer",
                fail=f"answered {head and head.get('status')}: the gateway may have fetched it",
            )

        results = await asyncio.gather(*(connection.request(session, "GET", args.path) for _ in range(8)))
        await asyncio.gather(*(asyncio.wait_for(s.done.wait(), 30) for _, s, _ in results), return_exceptions=True)
        self.check(
            "eight requests at once are each answered",
            all(head is not None and head.get("status") == 200 and s.finished for _, s, head in results),
        )

        body = secrets.token_bytes(WINDOW + 3 * MAX_DATA)
        _, stream, head = await connection.request(session, "POST", args.path, body=body, wait=30)
        self.check(
            "a request body larger than the window is taken to its end (credit is granted) or reset",
            stream.reset not in ("no answer",) and (head is not None or stream.reset),
            f"status {head and head.get('status')}, win frames {stream.window_grants}, reset {stream.reset or 'no'}",
            fail="the gateway neither granted credit nor answered nor reset within 30 seconds",
        )

        if args.large_path:
            connection.auto_grant = False
            stream_id, stream, head = await connection.request(session, "GET", args.large_path)
            await asyncio.sleep(3)  # no credit is given back: a conforming gateway stops at one window
            held = stream.received
            self.check(
                "response flow control: the gateway stops at the window when no credit comes back",
                head is not None and WINDOW - MAX_DATA <= held <= WINDOW,
                f"sent {held} bytes and waited",
                fail=f"sent {held} bytes without credit (the window is {WINDOW}); the hub closes with 4000"
                if held > WINDOW
                else f"sent only {held} bytes: give --large-path something over 300 kB",
            )
            connection.auto_grant = True
            await connection.grant(stream_id, stream)
            try:
                await asyncio.wait_for(stream.done.wait(), 60)
                self.check("response flow control: sending resumes when credit is granted", stream.received > held)
            except TimeoutError:
                self.check("response flow control: sending resumes when credit is granted", False)
        else:
            self.note("SKIP", "response flow control", "give --large-path a GET that returns more than 300 kB")

        stream_id, stream, _ = await connection.request(session, "GET", args.path, wait=0.01)
        await connection.send("rst", s=stream_id, reason="client_closed")
        _, _, head = await connection.request(session, "GET", args.path)
        self.check(
            "after the hub resets a stream the tunnel carries on", head is not None and head.get("status") == 200
        )

        await connection.send("session.extend", session=session, expires_at=now_text(1800))
        _, _, head = await connection.request(session, "GET", args.path)
        self.check("session.extend: the session carries on", head is not None and head.get("status") == 200)
        await connection.send("session.end", session=session, reason="user", ended_at=now_text())
        await asyncio.sleep(0.5)
        _, stream, head = await connection.request(session, "GET", args.path, wait=10)
        self.check(
            "after session.end a request for that session is refused",
            (head is None or head.get("status", 0) >= 400) and stream.reset != "no answer",
            fail=f"answered {head and head.get('status')}",
        )

        if args.slow:
            session, ack = await connection.start_session(lifetime=2)
            await asyncio.sleep(65)
            _, stream, head = await connection.request(session, "GET", args.path, wait=10)
            self.check(
                "a session a minute past its expires_at is refused even with no session.end",
                ack.get("ok") is True and (head is None or head.get("status", 0) >= 400),
                fail=f"answered {head and head.get('status')}",
            )
        else:
            self.note("SKIP", "expiry enforced by the gateway's own clock", "run with --slow (takes 65 seconds)")

        self.check("no malformed frame was seen", not connection.problems, fail="; ".join(connection.problems[:3]))

        # Dropping the tunnel: the gateway comes back, not at once and not never.
        dropped_at = time.monotonic()
        await connection.ws.close(code=1001, message=b"conformance: reconnect expected")
        again = await self.next_connection(20)
        waited = time.monotonic() - dropped_at
        self.check(
            "after the hub drops the tunnel (1001) the gateway reconnects with back-off",
            again is not None and 0.4 <= waited <= 10,
            f"reconnected after {waited:.1f} s",
            fail="no reconnection within 20 seconds" if again is None else f"reconnected after {waited:.2f} s",
        )
        if again is not None and args.slow:
            await asyncio.wait_for(asyncio.shield(again.hello), 10)
            await asyncio.sleep(1)
            mark = time.monotonic()
            await again.ws.close(code=4001, message=b"replaced")
            successor = await self.next_connection(90)
            waited = time.monotonic() - mark
            self.check(
                "after 4001 (replaced) the gateway waits at least 30 seconds",
                successor is not None and waited >= 29,
                f"reconnected after {waited:.0f} s",
                fail="no reconnection within 90 seconds" if successor is None else f"reconnected after {waited:.0f} s",
            )
            again = successor
        if again is not None and args.check_revocation:
            await asyncio.wait_for(asyncio.shield(again.hello), 10)
            await asyncio.sleep(1)
            before = len(self.attempts)
            await again.ws.close(code=4003, message=b"revoked")
            await asyncio.sleep(20)
            self.check(
                "after 4003 (revoked) the gateway does not open another tunnel",
                len(self.attempts) == before,
                fail=f"{len(self.attempts) - before} more attempts in 20 seconds",
            )
        elif again is not None:
            self.note("SKIP", "4003 (revoked) stops the gateway", "run with --check-revocation; it unpairs the gateway")
        return self.finish()

    def finish(self) -> int:
        failed = [name for outcome, name, _ in self.results if outcome == "FAIL"]
        passed = sum(1 for outcome, _, _ in self.results if outcome == "PASS")
        skipped = sum(1 for outcome, _, _ in self.results if outcome == "SKIP")
        print(f"\n{passed} passed, {len(failed)} failed, {skipped} skipped.")
        print(BY_HAND)
        return 1 if failed else 0


async def main_async(args, *, on_listening=None) -> int:
    conformance = Conformance(args)
    runner = web.AppRunner(conformance.app(), access_log=None, shutdown_timeout=1.0)
    await runner.setup()
    host, _, port = args.listen.rpartition(":")
    site = web.TCPSite(runner, host or "127.0.0.1", int(port))
    await site.start()
    args.listen = "{}:{}".format(*site._server.sockets[0].getsockname()[:2])  # the port, if 0 was asked for
    if on_listening is not None:
        on_listening(conformance)
    try:
        return await conformance.run()
    finally:
        await runner.cleanup()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--listen", default="127.0.0.1:8900", help="host:port to listen on as the hub")
    parser.add_argument("--credential", default="", help="the credential to accept (default: a new random one)")
    parser.add_argument("--path", default="/healthz", help="a console page that answers 200 without signing in")
    parser.add_argument("--large-path", default="", help="a GET that returns more than 300 kB")
    parser.add_argument("--wait", type=float, default=120, help="seconds to wait for the gateway to connect")
    parser.add_argument("--slow", action="store_true", help="also run the checks that take a minute or more")
    parser.add_argument("--check-revocation", action="store_true", help="finish by revoking (unpairs the gateway)")
    return asyncio.run(main_async(parser.parse_args()))


if __name__ == "__main__":
    sys.exit(main())
