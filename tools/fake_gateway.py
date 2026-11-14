"""A fake gateway for the remote console: the gateway's half of `pulsar-console.v1`, with a small
console of its own behind it.

It is what the hub's tests use in place of a real Pulsar Access Control gateway, and it can be
run by hand against a hub on a bench:

    python tools/fake_gateway.py --hub http://hub.lan --pair K7QM-2XPA-9RTD
    python tools/fake_gateway.py --hub http://hub.lan --credential-file ./credential

It follows `docs/CONTRACTS.md`, "Remote console", as a real gateway must: it dials out, it sends
every request to one fixed local address that it chose itself (its own console, started here on a
loopback port), it refuses a request for a session it was not told about, and it keeps its own
record of who each session was for. It needs aiohttp and nothing else.
"""

import argparse
import asyncio
import contextlib
import hashlib
import json
import logging
import random
import secrets
import struct
import sys
import time
from datetime import UTC, datetime
from html import escape
from urllib.parse import urlsplit

import aiohttp
from aiohttp import web

SUBPROTOCOL = "pulsar-console.v1"
WINDOW = 256 * 1024
MAX_DATA = 64 * 1024
logger = logging.getLogger("fake_gateway")


def big_bytes(megabytes: int):
    """A body of `megabytes` MiB that is cheap to make and whose digest both ends can work out."""
    block = bytes(range(256)) * 256  # 64 KiB
    for _ in range(megabytes * 16):
        yield block


def big_digest(megabytes: int) -> str:
    digest = hashlib.sha256()
    for block in big_bytes(megabytes):
        digest.update(block)
    return digest.hexdigest()


# --- the fake console: an ordinary small web application --------------------------------------------


class FakeConsole:
    """Stands in for the gateway's own web console. It behaves as Django does where that matters to
    a proxy: a session cookie, a CSRF cookie that must match the form's token, a strict Origin
    check against its own local address, redirects, an upload and a large download."""

    def __init__(self):
        self.notes: list[str] = []
        self.seen: list[dict] = []  # every request it was sent: method, path and headers
        self.local_origin = ""  # set once it is listening
        self.audit: list[dict] = []  # the gateway's own audit record, shown on a page of its console
        self.slow_seconds = 3600.0

    def app(self) -> web.Application:
        app = web.Application(client_max_size=64 * 1024 * 1024, middlewares=[self._record])
        app.router.add_get("/", self.root)
        app.router.add_get("/ui/", self.home)
        app.router.add_post("/ui/note", self.note)
        app.router.add_post("/ui/upload", self.upload)
        app.router.add_get("/ui/big", self.big)
        app.router.add_get("/ui/echo", self.echo)
        app.router.add_route("*", "/ui/echo-any", self.echo)
        app.router.add_get("/ui/tick", self.tick)
        app.router.add_get("/ui/slow", self.slow)
        app.router.add_get("/ui/hostile", self.hostile)
        app.router.add_get("/ui/elsewhere", self.elsewhere)
        app.router.add_get("/ui/many-headers", self.many_headers)
        app.router.add_get("/ui/audit", self.audit_page)
        app.router.add_get("/ui/cookie", self.cookie)
        app.router.add_get("/static/app.js", self.script)
        return app

    @web.middleware
    async def _record(self, request, handler):
        self.seen.append({"method": request.method, "path": request.path_qs, "headers": dict(request.headers)})
        del self.seen[:-500]
        return await handler(request)

    def _tokens(self, request) -> tuple[str, str, bool]:
        session = request.cookies.get("sessionid") or ""
        csrf = request.cookies.get("csrftoken") or ""
        fresh = not (session and csrf)
        return session or secrets.token_hex(16), csrf or secrets.token_hex(16), fresh

    async def root(self, request):
        raise web.HTTPFound("/ui/")

    async def home(self, request):
        session, csrf, fresh = self._tokens(request)
        who = request.headers.get("X-Fake-Gateway-User", "nobody (not through a hub session)")
        notes = "".join(f"<li>{escape(note)}</li>" for note in self.notes) or "<li>No notes yet.</li>"
        html = f"""<!doctype html><html lang="en"><head><meta charset="utf-8"><title>Fake door controller</title>
<meta name="csrf-token" content="{csrf}"><script src="/static/app.js" defer></script></head>
<body><h1>Fake door controller</h1>
<p id="who">Remote session for: {escape(who)}</p>
<p id="saved">{"Saved." if request.query.get("saved") else ""}</p>
<h2>Notes</h2><ul id="notes">{notes}</ul>
<form id="note-form" method="post" action="/ui/note">
  <input type="hidden" name="csrfmiddlewaretoken" value="{csrf}">
  <label>Note <input id="note" name="note"></label> <button id="save" type="submit">Save note</button>
</form>
<h2>Upload</h2>
<form id="upload-form" method="post" action="/ui/upload" enctype="multipart/form-data">
  <input type="hidden" name="csrfmiddlewaretoken" value="{csrf}">
  <input id="file" type="file" name="file"> <button id="send" type="submit">Upload</button>
</form>
<h2>Live</h2><p>Ticks: <span id="tick">0</span></p>
<p><a id="big" href="/ui/big?mb=20">A 20 MB download</a> · <a id="elsewhere" href="/ui/elsewhere">A redirect that tries to leave</a></p>
</body></html>"""
        response = web.Response(text=html, content_type="text/html")
        if fresh:
            response.headers.add("Set-Cookie", f"sessionid={session}; HttpOnly; Path=/; SameSite=Lax")
            response.headers.add("Set-Cookie", f"csrftoken={csrf}; Path=/; SameSite=Lax; Max-Age=31449600")
        return response

    def _check_csrf(self, request, form_token: str) -> None:
        cookie = request.cookies.get("csrftoken", "")
        origin = request.headers.get("Origin")
        if origin is not None and origin != self.local_origin:
            raise web.HTTPForbidden(text=f"CSRF: Origin {origin} is not {self.local_origin}")
        if not cookie or not secrets.compare_digest(cookie, form_token or ""):
            raise web.HTTPForbidden(text="CSRF: the token does not match the cookie")
        if not request.cookies.get("sessionid"):
            raise web.HTTPForbidden(text="no session cookie")

    async def note(self, request):
        form = await request.post()
        self._check_csrf(request, form.get("csrfmiddlewaretoken", ""))
        self.notes.append(str(form.get("note", ""))[:200])
        # An absolute address on the gateway's own local origin, as an application that builds
        # absolute redirects would send. The hub must keep the browser on the console origin.
        raise web.HTTPSeeOther(f"{self.local_origin}/ui/?saved=1")

    async def upload(self, request):
        reader = await request.multipart()
        token, size, digest, name = "", 0, hashlib.sha256(), ""
        async for part in reader:
            if part.name == "csrfmiddlewaretoken":
                token = (await part.read()).decode()
            elif part.name == "file":
                name = part.filename or ""
                while chunk := await part.read_chunk(65536):
                    size += len(chunk)
                    digest.update(chunk)
        self._check_csrf(request, token)
        return web.json_response({"name": name, "size": size, "sha256": digest.hexdigest()})

    async def big(self, request):
        megabytes = max(1, min(int(request.query.get("mb", "20")), 200))
        response = web.StreamResponse(headers={"Content-Type": "application/octet-stream"})
        response.content_length = megabytes * 1024 * 1024
        await response.prepare(request)
        for block in big_bytes(megabytes):
            await response.write(block)
        await response.write_eof()
        return response

    async def echo(self, request):
        body = await request.read()
        return web.json_response(
            {"method": request.method, "path": request.path_qs, "headers": dict(request.headers), "body": len(body)}
        )

    async def tick(self, request):
        return web.Response(text=str(int(time.time())), headers={"Cache-Control": "max-age=3600"})

    async def slow(self, request):
        await asyncio.sleep(self.slow_seconds)
        return web.Response(text="late")

    async def hostile(self, request):
        """Everything a console must not be able to do to the browser's view of the origin."""
        response = web.Response(text="hostile", headers={"Cache-Control": "public, max-age=31536000, immutable"})
        response.headers.add("Set-Cookie", "sessionid=planted; Domain=example.net; Path=/")
        response.headers.add("Set-Cookie", "tracker=1; Path=/; Max-Age=31536000")
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains; preload"
        response.headers["Clear-Site-Data"] = '"cookies"'
        response.headers["Service-Worker-Allowed"] = "/"
        response.headers["Alt-Svc"] = 'h3="evil.example:443"'
        response.headers["Refresh"] = "0; url=https://evil.example/x"
        response.headers["HX-Redirect"] = "https://evil.example/hx"
        return response

    async def audit_page(self, request):
        """The gateway's own record of remote sessions: who, from where, until when, and how each ended."""
        sessions = [entry for entry in self.audit if entry["event"] != "request"]
        requests = sum(1 for entry in self.audit if entry["event"] == "request")
        return web.json_response({"sessions": sessions[-50:], "requests_recorded": requests})

    async def many_headers(self, request):
        response = web.Response(text="too many headers")
        for n in range(int(request.query.get("n", "250"))):
            response.headers[f"X-Pad-{n}"] = "v"
        return response

    async def elsewhere(self, request):
        raise web.HTTPFound("https://evil.example/landing?x=1")

    async def cookie(self, request):
        response = web.json_response({"cookies": dict(request.cookies)})
        if "set" in request.query:
            name, _, value = request.query["set"].partition(":")
            response.headers.add("Set-Cookie", f"{name}={value}; Path=/ui/")
        return response

    async def script(self, request):
        js = """
(function () {
  var n = 0;
  setInterval(function () {
    fetch('/ui/tick', {headers: {'HX-Request': 'true'}}).then(function (r) {
      if (r.ok) { n += 1; document.getElementById('tick').textContent = String(n); }
      var to = r.headers.get('HX-Redirect'); if (to) { location.href = to; }
    });
  }, 1000);
})();
"""
        return web.Response(text=js, content_type="application/javascript")


# --- the tunnel client ------------------------------------------------------------------------------


class _RequestStream:
    def __init__(self):
        self.body: asyncio.Queue = asyncio.Queue()
        self.task: asyncio.Task | None = None
        self.send_credit = WINDOW
        self.credit = asyncio.Event()
        self.to_grant = 0


class FakeGateway:
    """The gateway's half of the tunnel. `console_enabled` is the local opt-in switch."""

    def __init__(
        self, hub_url: str, credential: str, *, console_enabled: bool = True, software_version: str = "fake-1.0"
    ):
        self.hub_url = hub_url.rstrip("/")
        self.credential = credential
        self.console_enabled = console_enabled
        self.software_version = software_version
        self.console = FakeConsole()
        self.sessions: dict[str, dict] = {}
        self.audit: list[dict] = self.console.audit  # the gateway's own record of sessions and requests
        self.welcome: dict | None = None
        self.close_code: int | None = None
        self.refuse_sessions = ""  # a reason to refuse every session with, for tests
        self.ignore_window = False  # misbehave: send body without waiting for credit
        self.subprotocols = (SUBPROTOCOL,)
        self.extra_headers: dict[str, str] = {}  # for tests that stand in for the proxy in front of the hub
        self.connected = asyncio.Event()
        self.closed = asyncio.Event()
        self._ws: aiohttp.ClientWebSocketResponse | None = None
        self._http: aiohttp.ClientSession | None = None
        self._runner: web.AppRunner | None = None
        self._streams: dict[int, _RequestStream] = {}
        self._send_lock = asyncio.Lock()
        self._task: asyncio.Task | None = None

    # --- lifecycle --------------------------------------------------------------------------------

    @property
    def tunnel_url(self) -> str:
        parts = urlsplit(self.hub_url)
        scheme = "wss" if parts.scheme == "https" else "ws"
        return f"{scheme}://{parts.netloc}/api/v1/gateways/tunnel"

    async def start_console(self) -> None:
        if self._runner is not None:
            return
        self._runner = web.AppRunner(
            self.console.app(), access_log=None, handler_cancellation=True, shutdown_timeout=1.0
        )
        await self._runner.setup()
        site = web.TCPSite(self._runner, "127.0.0.1", 0)
        await site.start()
        port = site._server.sockets[0].getsockname()[1]
        # The one place this gateway ever sends a request. Nothing from the hub can change it.
        self.console.local_origin = f"http://127.0.0.1:{port}"
        self._http = aiohttp.ClientSession(auto_decompress=False, cookie_jar=aiohttp.DummyCookieJar())

    async def connect(self) -> None:
        """Open the tunnel and serve it in the background. Raises on a refusal."""
        await self.start_console()
        self.connected.clear()
        self.closed.clear()
        self.close_code = None
        self._ws = await self._http.ws_connect(
            self.tunnel_url,
            headers={
                "Authorization": f"Bearer {self.credential}",
                "X-Gateway-Version": self.software_version,
                **self.extra_headers,
            },
            protocols=self.subprotocols,
            max_msg_size=4 + MAX_DATA + 1024,
            heartbeat=None,
            autoping=True,
        )
        if self._ws.protocol != SUBPROTOCOL:
            await self._ws.close()
            raise RuntimeError("the hub did not agree a protocol version")
        await self._send_json(
            {"t": "hello", "software_version": self.software_version, "console_enabled": self.console_enabled}
        )
        self._task = asyncio.create_task(self._serve())
        # Welcomed, or closed before the welcome (the hub may refuse with a close code at any point).
        waiting = [asyncio.ensure_future(self.connected.wait()), asyncio.ensure_future(self.closed.wait())]
        try:
            done, _ = await asyncio.wait(waiting, timeout=10, return_when=asyncio.FIRST_COMPLETED)
        finally:
            for waiter in waiting:
                waiter.cancel()
        if not done:
            await self.disconnect()
            raise TimeoutError("the hub did not send welcome")

    async def disconnect(self) -> None:
        if self._ws is not None and not self._ws.closed:
            await self._ws.close()
        if self._task is not None:
            await asyncio.gather(self._task, return_exceptions=True)

    async def stop(self) -> None:
        await self.disconnect()
        if self._http is not None:
            await self._http.close()
        if self._runner is not None:
            await self._runner.cleanup()

    async def set_console_enabled(self, enabled: bool) -> None:
        """The local switch. Turning it off ends every session, here first."""
        self.console_enabled = enabled
        if not enabled:
            for session_id in list(self.sessions):
                self._end(session_id, "disabled")
        await self._send_json({"t": "console", "enabled": enabled})

    # --- frames -----------------------------------------------------------------------------------

    async def _send_json(self, frame: dict) -> None:
        async with self._send_lock:
            await self._ws.send_str(json.dumps(frame, separators=(",", ":")))

    async def _send_data(self, stream_id: int, chunk: bytes) -> None:
        async with self._send_lock:
            await self._ws.send_bytes(struct.pack(">I", stream_id) + chunk)

    async def _serve(self) -> None:
        try:
            async for message in self._ws:
                if message.type == aiohttp.WSMsgType.TEXT:
                    await self._on_frame(json.loads(message.data))
                elif message.type == aiohttp.WSMsgType.BINARY:
                    (stream_id,) = struct.unpack_from(">I", message.data)
                    stream = self._streams.get(stream_id)
                    if stream is not None:
                        stream.body.put_nowait(message.data[4:])
        finally:
            self.close_code = self._ws.close_code
            # The tunnel is gone, so every session on it is over, whether or not the hub said so.
            for session_id in list(self.sessions):
                self._end(session_id, "tunnel_closed")
            for stream in self._streams.values():
                if stream.task is not None:
                    stream.task.cancel()
            self._streams.clear()
            self.connected.clear()
            self.closed.set()

    def _record(self, event: str, **detail) -> None:
        self.audit.append({"at": datetime.now(UTC).isoformat(), "event": event, **detail})
        del self.audit[:-2000]
        if event != "request":
            logger.info("audit: %s %s", event, json.dumps(detail, sort_keys=True))

    def _end(self, session_id: str, reason: str) -> None:
        session = self.sessions.pop(session_id, None)
        if session is not None:
            self._record("session.ended", session=session_id, user=session["user"]["email"], reason=reason)

    async def _on_frame(self, frame: dict) -> None:
        kind = frame.get("t")
        if kind == "welcome":
            self.welcome = frame
            self.connected.set()
        elif kind == "session.start":
            session_id = frame["session"]
            reason = self.refuse_sessions or ("" if self.console_enabled else "disabled")
            if reason:
                self._record("session.refused", session=session_id, user=frame["user"]["email"], reason=reason)
                await self._send_json({"t": "session.ack", "session": session_id, "ok": False, "reason": reason})
                return
            self.sessions[session_id] = frame
            self._record(
                "session.started",
                session=session_id,
                user=frame["user"]["email"],
                user_id=frame["user"]["id"],
                role=frame["user"]["role"],
                client_ip=frame.get("client_ip", ""),
                expires_at=frame["expires_at"],
            )
            await self._send_json({"t": "session.ack", "session": session_id, "ok": True})
        elif kind == "session.extend":
            if frame["session"] in self.sessions:
                self.sessions[frame["session"]]["expires_at"] = frame["expires_at"]
                self._record("session.extended", session=frame["session"], expires_at=frame["expires_at"])
        elif kind == "session.end":
            self._end(frame["session"], frame.get("reason", ""))
        elif kind == "req":
            stream = _RequestStream()
            self._streams[frame["s"]] = stream
            stream.task = asyncio.create_task(self._handle(frame, stream))
        elif kind == "req.end":
            stream = self._streams.get(frame["s"])
            if stream is not None:
                stream.body.put_nowait(None)
        elif kind == "win":
            stream = self._streams.get(frame["s"])
            if stream is not None:
                stream.send_credit += frame["n"]
                stream.credit.set()
        elif kind == "rst":
            stream = self._streams.pop(frame["s"], None)
            if stream is not None and stream.task is not None:
                stream.task.cancel()
        # Unknown frame types are ignored.

    # --- one request ------------------------------------------------------------------------------

    def _session_is_live(self, session_id: str) -> bool:
        session = self.sessions.get(session_id)
        if session is None:
            return False
        expires = datetime.fromisoformat(session["expires_at"].replace("Z", "+00:00"))
        return expires > datetime.now(UTC)

    def _local_headers(self, frame: dict, session: dict) -> dict:
        """The hub's headers, turned into a request for the gateway's own console."""
        public = session["console_origin"]
        local = self.console.local_origin
        headers = {}
        for name, value in frame["headers"]:
            lower = name.lower()
            if lower in ("origin",):
                value = local if value == public else "null"
            elif lower == "referer" and value.startswith(public):
                value = local + value[len(public) :]
            elif lower.startswith("x-fake-gateway-"):
                continue  # its own identity headers: only ever written below
            headers[name] = value
        headers["Host"] = urlsplit(local).netloc
        headers["X-Fake-Gateway-User"] = f"{session['user']['email']} ({session['user']['role']})"
        return headers

    async def _body_from_hub(self, stream_id: int, stream: _RequestStream):
        while True:
            chunk = await stream.body.get()
            if chunk is None:
                return
            yield chunk
            stream.to_grant += len(chunk)
            if stream.to_grant >= WINDOW // 2:
                grant, stream.to_grant = stream.to_grant, 0
                await self._send_json({"t": "win", "s": stream_id, "n": grant})

    async def _handle(self, frame: dict, stream: _RequestStream) -> None:
        stream_id = frame["s"]
        try:
            session_id = frame.get("session", "")
            if not self._session_is_live(session_id) or not self.console_enabled:
                self._record("request.refused", session=session_id, path=frame.get("path", ""))
                await self._send_json({"t": "rst", "s": stream_id, "reason": "no_session"})
                return
            session = self.sessions[session_id]
            path = frame["path"]
            if not path.startswith("/") or path.startswith("//"):
                await self._send_json({"t": "rst", "s": stream_id, "reason": "bad_path"})
                return
            self._record(
                "request", session=session_id, user=session["user"]["email"], method=frame["method"], path=path
            )
            body = self._body_from_hub(stream_id, stream) if frame.get("body") else None
            async with self._http.request(
                frame["method"],
                self.console.local_origin + path,  # always its own console; the frame carries no host
                headers=self._local_headers(frame, session),
                data=body,
                allow_redirects=False,
                timeout=aiohttp.ClientTimeout(total=None, sock_read=120),
            ) as response:
                headers = [[name, value] for name, value in response.headers.items()]
                has_body = frame["method"] != "HEAD" and response.status not in (204, 304)
                await self._send_json(
                    {"t": "res", "s": stream_id, "status": response.status, "headers": headers, "body": has_body}
                )
                if has_body:
                    async for chunk in response.content.iter_chunked(MAX_DATA):
                        while not self.ignore_window and stream.send_credit < len(chunk):
                            stream.credit.clear()
                            await stream.credit.wait()
                        stream.send_credit -= len(chunk)
                        await self._send_data(stream_id, chunk)
                    await self._send_json({"t": "res.end", "s": stream_id})
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # whatever went wrong locally, the hub hears "reset"
            logger.warning("request failed locally: %s", exc)
            with contextlib.suppress(Exception):
                await self._send_json({"t": "rst", "s": stream_id, "reason": "local_error"})
        finally:
            self._streams.pop(stream_id, None)

    # --- running by hand --------------------------------------------------------------------------

    async def run_forever(self) -> None:
        """Keep the tunnel open, reconnecting as the contract says: back off, with jitter, and stop
        for good when the hub says the credential is no longer accepted."""
        failures = 0
        while True:
            started = time.monotonic()
            try:
                await self.connect()
                logger.info("tunnel open to %s", self.tunnel_url)
                await self.closed.wait()
                logger.info("tunnel closed (code %s)", self.close_code)
                if self.close_code == 4003:
                    logger.error("the hub no longer accepts this gateway; not reconnecting")
                    return
            except aiohttp.WSServerHandshakeError as exc:
                logger.warning("the hub refused the tunnel: %s", exc.status)
                if exc.status == 401:
                    logger.error("the hub no longer accepts this gateway; not reconnecting")
                    return
            except (TimeoutError, aiohttp.ClientError, OSError) as exc:
                logger.warning("could not connect: %s", exc)
            failures = 0 if time.monotonic() - started > 60 else failures + 1
            delay = min(300, 2 ** max(failures - 1, 0)) * random.uniform(0.5, 1)  # jitter, not a secret
            if self.close_code == 4001:
                delay = max(delay, 30)  # replaced by another instance: never sooner than this
            await asyncio.sleep(delay)


async def pair(hub_url: str, code: str, name: str) -> dict:
    async with aiohttp.ClientSession() as http:
        async with http.post(
            f"{hub_url.rstrip('/')}/api/v1/gateways/pair",
            json={"code": code, "name": name, "software_version": "fake-1.0"},
        ) as response:
            if response.status != 201:
                raise SystemExit(f"pairing refused: {response.status} {await response.text()}")
            return await response.json()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--hub", required=True, help="the hub's address, such as http://hub.lan")
    parser.add_argument("--pair", metavar="CODE", help="pair first with this one-time code")
    parser.add_argument("--credential-file", default="fake-gateway.credential", help="where the credential is kept")
    parser.add_argument("--name", default="Fake gateway")
    parser.add_argument("--console-off", action="store_true", help="start with the remote console switched off")
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

    async def run() -> None:
        if args.pair:
            answer = await pair(args.hub, args.pair, args.name)
            with open(args.credential_file, "w") as handle:
                handle.write(answer["credential"])
            logger.info("paired as gateway %s at site %s", answer["gateway_id"], answer["site_name"])
        with open(args.credential_file) as handle:
            credential = handle.read().strip()
        gateway = FakeGateway(args.hub, credential, console_enabled=not args.console_off)
        try:
            await gateway.run_forever()
        finally:
            await gateway.stop()

    asyncio.run(run())
    return 0


if __name__ == "__main__":
    sys.exit(main())
