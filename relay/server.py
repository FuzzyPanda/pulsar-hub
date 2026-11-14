"""The relay service: three listeners and the state they share.

* the tunnel listener, where gateways connect (Caddy sends it `/api/v1/gateways/tunnel`);
* the console listener, where a browser reaches a gateway's console (Caddy sends it everything on
  the console origins);
* the control listener, where the hub's web service tells the relay what has changed. It is never
  routed by Caddy and every call carries the shared secret.

State is in memory only. If the relay restarts, every tunnel has dropped and so every session is
over; it says so to the hub (`started`) before it accepts anything.
"""

import asyncio
import hashlib
import hmac
import logging
import secrets
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime
from urllib.parse import parse_qs

import aiohttp
from aiohttp import web

from relay import pages, protocol
from relay.config import RelayConfig, gateway_label
from relay.hubapi import HubApi, HubUnavailable
from relay.protocol import CookieJar, ProtocolError
from relay.tunnel import StreamReset, Tunnel, TunnelClosed, read_body

logger = logging.getLogger("relay")

COOKIE_NAME = "pulsar_console"
SECURE_COOKIE_NAME = "__Host-pulsar_console"
HANDOFF_PATH = protocol.RESERVED_PREFIX + "handoff"
END_PATH = protocol.RESERVED_PREFIX + "end"
ENDED_PATH = protocol.RESERVED_PREFIX + "ended"


def _epoch(value: str) -> float:
    return datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


@dataclass
class ConsoleSession:
    """A console session as the relay holds it. The hub's database row is the record; this is the
    working copy, gone when the relay stops."""

    id: str
    gateway_id: str
    origin: str
    expires_at: float
    start_frame: dict
    return_url: str = ""
    cookie_digest: str = ""  # empty until the browser has redeemed its hand-off token
    jar: CookieJar = field(default_factory=CookieJar)
    slots: asyncio.Semaphore | None = None
    ended: bool = False


class RateLimit:
    """At most `limit` events per key per `window` seconds; a bounded table."""

    def __init__(self, limit: int, window: float, *, size: int = 4096):
        self._limit, self._window, self._size = limit, window, size
        self._events: dict[str, list[float]] = {}

    def allow(self, key: str) -> bool:
        now = time.monotonic()
        events = [at for at in self._events.get(key, ()) if now - at < self._window]
        if len(events) >= self._limit:
            self._events[key] = events
            return False
        if key not in self._events and len(self._events) >= self._size:
            self._events.clear()  # under a flood of new keys, forget rather than grow
        events.append(now)
        self._events[key] = events
        return True


class Relay:
    def __init__(self, config: RelayConfig, hub: HubApi):
        self.config = config
        self.hub = hub
        self.instance = secrets.token_hex(8)
        self.tunnels: dict[str, Tunnel] = {}
        self.sessions: dict[str, ConsoleSession] = {}
        self.by_cookie: dict[str, ConsoleSession] = {}
        self.tombstones: dict[str, tuple[float, str]] = {}  # cookie digest -> (when, return address)
        self.hub_seen_at = 0.0  # the last time the hub confirmed what the relay holds
        self.ready = False
        self._events: asyncio.Queue = asyncio.Queue(maxsize=1000)
        self._tasks: list[asyncio.Task] = []
        self._tunnel_attempts = RateLimit(30, 60)
        self._handoff_attempts = RateLimit(20, 60)

    # --- lifecycle --------------------------------------------------------------------------------

    async def start(self) -> None:
        self._tasks = [asyncio.create_task(self._announce_then_beat()), asyncio.create_task(self._send_events())]

    async def stop(self) -> None:
        self.ready = False
        for task in self._tasks:
            task.cancel()
        for tunnel in list(self.tunnels.values()):
            await tunnel.close(protocol.CLOSE_GOING_AWAY, "the hub's relay is restarting")
        await asyncio.gather(*self._tasks, return_exceptions=True)

    async def _announce_then_beat(self) -> None:
        delay = 1.0
        while True:
            try:
                await self.hub.started(self.instance)
                break
            except HubUnavailable as exc:
                logger.warning("waiting for the hub: %s", exc)
                await asyncio.sleep(delay)
                delay = min(delay * 2, 15)
        self.hub_seen_at = time.monotonic()
        self.ready = True
        logger.info("relay %s ready", self.instance)
        while True:
            await asyncio.sleep(self.config.heartbeat_seconds)
            await self.beat()

    async def beat(self) -> None:
        """Tell the hub what the relay holds and act on what it says is no longer valid."""
        now = time.time()
        for session in [s for s in self.sessions.values() if s.expires_at <= now]:
            await self.end_session(session, "expired", tell_hub=True)
        gateways = [{"id": t.gateway_id, "console_enabled": t.console_enabled} for t in self.tunnels.values()]
        try:
            answer = await self.hub.heartbeat(self.instance, gateways, list(self.sessions))
        except HubUnavailable as exc:
            logger.warning("heartbeat failed: %s", exc)
            return
        self.hub_seen_at = time.monotonic()
        for item in answer.get("end", []):
            session = self.sessions.get(str(item.get("id")))
            if session is not None:
                await self.end_session(session, str(item.get("reason") or "hub"), tell_hub=False)
        for gateway_id in answer.get("close", []):
            await self.close_gateway(str(gateway_id), "revoked")
        cutoff = time.monotonic() - 3600
        for digest in [d for d, (at, _) in self.tombstones.items() if at < cutoff]:
            del self.tombstones[digest]

    @property
    def hub_is_fresh(self) -> bool:
        """The hub has confirmed the relay's sessions recently. When it has not, nothing is relayed:
        the relay cannot know that a session was ended or a person removed."""
        return self.ready and time.monotonic() - self.hub_seen_at < self.config.heartbeat_seconds * 3 + 5

    def tell_hub(self, **event) -> None:
        try:
            self._events.put_nowait(event)
        except asyncio.QueueFull:
            logger.error("event queue full; the next heartbeat will reconcile")

    async def _send_events(self) -> None:
        while True:
            event = await self._events.get()
            for attempt in range(6):
                try:
                    await self.hub.event({"instance": self.instance, **event})
                    break
                except HubUnavailable as exc:
                    logger.warning("event %s not delivered (%s)", event.get("event"), exc)
                    await asyncio.sleep(min(2**attempt, 15))

    # --- sessions ---------------------------------------------------------------------------------

    async def end_session(self, session: ConsoleSession, reason: str, *, tell_hub: bool, tell_gateway: bool = True):
        if session.ended:
            return
        session.ended = True
        self.sessions.pop(session.id, None)
        if session.cookie_digest:
            self.by_cookie.pop(session.cookie_digest, None)
            if len(self.tombstones) < 2000:
                self.tombstones[session.cookie_digest] = (time.monotonic(), session.return_url)
        tunnel = self.tunnels.get(session.gateway_id)
        if tunnel is not None:
            for stream in tunnel.streams_of(session.id):
                await tunnel.abandon(stream, "session_ended")
            if tell_gateway:
                try:
                    await tunnel.send_frame("session.end", session=session.id, reason=reason, ended_at=_now_text())
                except TunnelClosed:
                    pass
        if tell_hub:
            self.tell_hub(event="session.ended", session=session.id, reason=reason)
        logger.info("session %s ended: %s", session.id, reason)

    async def close_gateway(self, gateway_id: str, reason: str) -> None:
        tunnel = self.tunnels.get(gateway_id)
        if tunnel is not None:
            code = protocol.CLOSE_REVOKED if reason == "revoked" else protocol.CLOSE_GOING_AWAY
            await tunnel.close(code, "this gateway's credential is no longer accepted")
        for session in [s for s in self.sessions.values() if s.gateway_id == gateway_id]:
            await self.end_session(
                session, "gateway_revoked" if reason == "revoked" else "tunnel_dropped", tell_hub=False
            )

    # --- the tunnel listener ------------------------------------------------------------------------

    def _client_ip(self, request: web.Request) -> str:
        forwarded = [p.strip() for p in request.headers.get("X-Forwarded-For", "").split(",") if p.strip()]
        proxies = self.config.num_proxies
        if proxies and len(forwarded) >= proxies:
            return forwarded[-proxies]
        return request.remote or ""

    def _is_tls(self, request: web.Request) -> bool:
        return request.headers.get("X-Forwarded-Proto", "").lower() == "https"

    async def handle_tunnel(self, request: web.Request) -> web.StreamResponse:
        if not self.config.allow_plain_http and not self._is_tls(request):
            return web.json_response({"detail": "TLS is required."}, status=403)
        if "Origin" in request.headers:
            # A gateway is not a browser. Nothing running in a page may open a tunnel.
            return web.json_response({"detail": "Browsers cannot open a tunnel."}, status=403)
        if request.headers.get("Upgrade", "").lower() != "websocket":
            return web.json_response({"detail": "This address accepts a WebSocket upgrade only."}, status=400)
        if not self._tunnel_attempts.allow(self._client_ip(request)):
            return web.json_response({"detail": "Too many attempts."}, status=429, headers={"Retry-After": "60"})
        scheme, _, credential = request.headers.get("Authorization", "").partition(" ")
        credential = credential.strip()
        refusal = web.json_response({"detail": "This gateway's credential is not accepted."}, status=401)
        if scheme.lower() != "bearer" or not credential.startswith("hubgw_") or len(credential) > 200:
            return refusal
        if not self.ready:
            return web.json_response({"detail": "The hub is starting."}, status=503, headers={"Retry-After": "10"})
        try:
            gateway = await self.hub.authorize_tunnel(credential)
            del credential  # the relay never keeps it
            if gateway is None:
                return refusal
            offered = request.headers.get("Sec-WebSocket-Protocol", "")
            chosen = protocol.choose_subprotocol(offered)
            if chosen is None:
                await self.hub.tunnel_refused(gateway["gateway_id"], offered)
                return web.json_response(
                    {
                        "detail": "This hub does not speak any console protocol version the gateway offered.",
                        "supported": list(protocol.SUPPORTED_SUBPROTOCOLS),
                    },
                    status=426,
                    headers={
                        "Upgrade": "websocket",
                        "Sec-WebSocket-Protocol": ", ".join(protocol.SUPPORTED_SUBPROTOCOLS),
                    },
                )
        except HubUnavailable:
            return web.json_response({"detail": "The hub cannot be asked."}, status=503, headers={"Retry-After": "10"})

        ws = web.WebSocketResponse(
            protocols=(chosen,),
            heartbeat=protocol.PING_SECONDS,
            max_msg_size=protocol.MAX_TEXT_FRAME,
            autoclose=True,
            autoping=True,
            compress=False,
        )
        await ws.prepare(request)
        tunnel = Tunnel(ws, gateway, protocol_name=chosen)
        try:
            await self._greet(tunnel, request)
        except (TimeoutError, ProtocolError) as exc:
            await tunnel.close(protocol.CLOSE_PROTOCOL, f"hello: {exc or 'not received in time'}")
            return ws
        except (HubUnavailable, TunnelClosed):
            await tunnel.close(protocol.CLOSE_UNAVAILABLE, "the hub cannot be asked")
            return ws

        previous = self.tunnels.get(tunnel.gateway_id)
        self.tunnels[tunnel.gateway_id] = tunnel
        if previous is not None:
            # The older connection is very likely dead already. Its sessions end with it.
            await previous.close(protocol.CLOSE_REPLACED, "replaced by a newer tunnel from the same gateway")
            await self._tunnel_gone(previous, "replaced", tell_hub=False)
        tunnel.on_console_switched = self._console_switched
        tunnel.on_session_ended_by_gateway = self._ended_by_gateway
        logger.info("tunnel open: gateway %s (%s)", tunnel.gateway_id, chosen)
        try:
            await tunnel.run()
        finally:
            if self.tunnels.get(tunnel.gateway_id) is tunnel:
                del self.tunnels[tunnel.gateway_id]
                await self._tunnel_gone(tunnel, "tunnel_dropped", tell_hub=True)
            logger.info("tunnel closed: gateway %s (code %s)", tunnel.gateway_id, ws.close_code)
        return ws

    async def _greet(self, tunnel: Tunnel, request: web.Request) -> None:
        message = await asyncio.wait_for(tunnel.ws.receive(), protocol.HELLO_SECONDS)
        if message.type != aiohttp.WSMsgType.TEXT:
            raise ProtocolError("the first frame must be hello")
        hello = protocol.parse_text_frame(message.data)
        if hello["t"] != "hello":
            raise ProtocolError("the first frame must be hello")
        tunnel.console_enabled = hello.get("console_enabled") is True
        tunnel.software_version = str(hello.get("software_version") or request.headers.get("X-Gateway-Version", ""))[
            :64
        ]
        accepted = await self.hub.tunnel_opened(
            self.instance,
            tunnel.gateway_id,
            protocol=tunnel.protocol_name,
            software_version=tunnel.software_version,
            enabled=tunnel.console_enabled,
        )
        if not accepted:
            raise TunnelClosed
        await tunnel.send_frame(
            "welcome",
            gateway_id=tunnel.gateway_id,
            org_ref=tunnel.gateway.get("org_ref", ""),
            site_ref=tunnel.gateway.get("site_ref", ""),
            limits={
                "max_streams": protocol.MAX_STREAMS,
                "window": protocol.WINDOW,
                "max_data": protocol.MAX_DATA,
                "max_text_frame": protocol.MAX_TEXT_FRAME,
                "max_header_bytes": protocol.MAX_HEADER_BYTES,
                "max_request_body": self.config.max_request_body,
            },
            ping_seconds=protocol.PING_SECONDS,
            idle_seconds=protocol.IDLE_SECONDS,
        )

    async def _tunnel_gone(self, tunnel: Tunnel, reason: str, *, tell_hub: bool) -> None:
        for session in [s for s in self.sessions.values() if s.gateway_id == tunnel.gateway_id]:
            await self.end_session(session, "tunnel_dropped", tell_hub=False, tell_gateway=False)
        if tell_hub:
            self.tell_hub(event="tunnel.closed", gateway_id=tunnel.gateway_id, reason=reason)

    def _console_switched(self, tunnel: Tunnel) -> None:
        self.tell_hub(event="console.switched", gateway_id=tunnel.gateway_id, enabled=tunnel.console_enabled)
        if not tunnel.console_enabled:
            for session in [s for s in self.sessions.values() if s.gateway_id == tunnel.gateway_id]:
                asyncio.ensure_future(self.end_session(session, "gateway_ended", tell_hub=True))

    def _ended_by_gateway(self, tunnel: Tunnel, session_id: str, reason: str) -> None:
        session = self.sessions.get(session_id)
        if session is not None and session.gateway_id == tunnel.gateway_id:
            asyncio.ensure_future(self.end_session(session, "gateway_ended", tell_hub=True, tell_gateway=False))

    # --- the control listener -----------------------------------------------------------------------

    def _from_hub(self, request: web.Request) -> bool:
        scheme, _, presented = request.headers.get("Authorization", "").partition(" ")
        return scheme == "Bearer" and hmac.compare_digest(presented.encode(), self.config.internal_secret.encode())

    async def handle_control(self, request: web.Request) -> web.Response:
        if not self._from_hub(request):
            return web.json_response({"detail": "Not found."}, status=404)
        try:
            payload = await request.json()
        except ValueError:
            return web.json_response({"detail": "The body is not JSON."}, status=400)
        action = request.match_info["action"]
        if action == "session/start":
            return web.json_response(await self._control_start(payload))
        if action == "session/extend":
            session = self.sessions.get(str(payload.get("session")))
            if session is None:
                return web.json_response({"ok": False, "reason": "unknown"})
            session.expires_at = _epoch(payload["expires_at"])
            session.start_frame["expires_at"] = payload["expires_at"]
            tunnel = self.tunnels.get(session.gateway_id)
            if tunnel is not None:
                try:
                    await tunnel.send_frame("session.extend", session=session.id, expires_at=payload["expires_at"])
                except TunnelClosed:
                    pass
            return web.json_response({"ok": True})
        if action == "session/end":
            session = self.sessions.get(str(payload.get("session")))
            if session is not None:
                await self.end_session(session, str(payload.get("reason") or "hub"), tell_hub=False)
            return web.json_response({"ok": True})
        if action == "gateway/close":
            await self.close_gateway(str(payload.get("gateway_id")), "revoked")
            return web.json_response({"ok": True})
        return web.json_response({"detail": "Not found."}, status=404)

    async def _control_start(self, payload: dict) -> dict:
        frame = payload["frame"]
        tunnel = self.tunnels.get(str(payload.get("gateway_id")))
        if tunnel is None or tunnel.closed:
            return {"ok": False, "reason": "not_connected"}
        if not tunnel.console_enabled:
            return {"ok": False, "reason": "disabled"}
        ok, reason = await tunnel.start_session(frame)
        if not ok:
            return {"ok": False, "reason": reason}
        session = ConsoleSession(
            id=frame["session"],
            gateway_id=tunnel.gateway_id,
            origin=frame["console_origin"],
            expires_at=_epoch(frame["expires_at"]),
            start_frame=frame,
            return_url=str(payload.get("return_url") or ""),
            slots=asyncio.Semaphore(self.config.session_streams),
        )
        self.sessions[session.id] = session
        return {"ok": True}

    async def handle_health(self, request: web.Request) -> web.Response:
        return web.json_response({"status": "ok" if self.ready else "starting"}, status=200 if self.ready else 503)

    async def handle_tls_ask(self, request: web.Request) -> web.Response:
        """Caddy's on-demand TLS asks here before it obtains a certificate for a console host name:
        yes only for a gateway whose tunnel is open now."""
        label = request.query.get("domain", "").split(".", 1)[0].lower()
        known = any(gateway_label(gateway_id) == label for gateway_id in self.tunnels)
        return web.Response(status=200 if known else 404)

    # --- the console listener -----------------------------------------------------------------------

    def _cookie_name(self, session_origin: str) -> str:
        return SECURE_COOKIE_NAME if session_origin.startswith("https://") else COOKIE_NAME

    def _set_cookie(self, origin: str, value: str) -> str:
        secure = origin.startswith("https://")
        parts = [f"{self._cookie_name(origin)}={value}", "Path=/", "HttpOnly", "SameSite=Strict"]
        if secure:
            parts.append("Secure")
        if not value:
            parts.append("Max-Age=0")
        return "; ".join(parts)

    def _presented_cookies(self, request: web.Request) -> list[str]:
        values = []
        for header in request.headers.getall("Cookie", []):
            for item in header.split(";"):
                name, sep, value = item.strip().partition("=")
                if sep and name in (COOKIE_NAME, SECURE_COOKIE_NAME):
                    values.append(value.strip())
        return values

    def _request_origin(self, request: web.Request) -> str:
        scheme = "https" if self._is_tls(request) else "http"
        return f"{scheme}://{request.headers.get('Host', '').lower()}"

    async def handle_console(self, request: web.Request) -> web.StreamResponse:
        if not self.config.allow_plain_http and not self._is_tls(request):
            return pages.refused("TLS is required", "The remote console is served over HTTPS only.", status=403)
        path = request.path
        if path.startswith(protocol.RESERVED_PREFIX):
            if path == HANDOFF_PATH and request.method == "POST":
                return await self._handoff(request)
            if path == END_PATH and request.method == "POST":
                return await self._end_from_console(request)
            if path == ENDED_PATH and request.method == "GET":
                return self._ended_page(request)
            return pages.refused("Not found", "There is nothing at this address.", status=404)
        return await self._proxy(request)

    def _ended_page(self, request: web.Request, *, status: int = 200) -> web.Response:
        return_url = ""
        for value in self._presented_cookies(request):
            return_url = self.tombstones.get(_digest(value), (0, ""))[1] or return_url
        return pages.ended(return_url, status=status)

    def _no_session(self, request: web.Request) -> web.Response:
        """The answer to a request that has no live session behind it."""
        if request.headers.get("HX-Request") == "true":
            # htmx follows this header before it looks at the status, so a console page that was
            # polling when the session ended lands on the "ended" page instead of failing silently.
            response = web.Response(status=401, headers={"HX-Redirect": ENDED_PATH, "Cache-Control": "no-store"})
            return response
        return self._ended_page(request, status=401)

    async def _handoff(self, request: web.Request) -> web.Response:
        gone = pages.refused(
            "This link cannot be used",
            "It was already used or it has expired. Open the remote console again from the hub.",
            status=403,
        )
        if not self._handoff_attempts.allow(self._client_ip(request)):
            return pages.refused("Too many attempts", "Wait a minute and try again.", status=429)
        if (request.content_length or 0) > 4096 or not self.hub_is_fresh:
            return gone
        try:
            body = (await request.content.read(4097)).decode("ascii")
        except (UnicodeDecodeError, aiohttp.ClientError):
            return gone
        token = (parse_qs(body).get("token") or [""])[0]
        if not 40 <= len(token) <= 64 or not token.replace("-", "").replace("_", "").isalnum():
            return gone
        try:
            answer = await self.hub.redeem_handoff(token, self._request_origin(request))
        except HubUnavailable:
            return gone
        session = self.sessions.get(str((answer or {}).get("session"))) if answer else None
        if session is None or session.ended or session.cookie_digest:
            return gone
        secret = answer["cookie_secret"]
        session.cookie_digest = _digest(secret)
        self.by_cookie[session.cookie_digest] = session
        response = pages.opening()
        response.headers.add("Set-Cookie", self._set_cookie(session.origin, secret))
        return response

    def _session_for(self, request: web.Request) -> ConsoleSession | None:
        presented = self._presented_cookies(request)
        if len(presented) != 1:
            return None  # none, or two with the same name: something is trying to shadow the real one
        session = self.by_cookie.get(_digest(presented[0]))
        if session is None or session.ended or session.expires_at <= time.time():
            return None
        if self._request_origin(request) != session.origin.lower():
            return None  # a session is for one console origin; its cookie means nothing on another
        return session

    async def _end_from_console(self, request: web.Request) -> web.Response:
        session = self._session_for(request)
        if session is not None and protocol.same_origin_request("POST", request.headers.items(), session.origin):
            await self.end_session(session, "user", tell_hub=True)
            response = pages.ended(session.return_url)
            response.headers.add("Set-Cookie", self._set_cookie(session.origin, ""))
            return response
        return self._ended_page(request)

    async def _proxy(self, request: web.Request) -> web.StreamResponse:
        session = self._session_for(request)
        if session is None:
            return self._no_session(request)
        if not self.hub_is_fresh:
            return pages.refused(
                "The hub cannot confirm this session",
                "Try again in a moment.",
                status=503,
                headers={"Retry-After": "5"},
            )
        method = request.method.upper()
        if method not in protocol.ALLOWED_METHODS:
            return pages.refused(
                "Method not allowed", "The remote console does not carry this kind of request.", status=405
            )
        if "upgrade" in request.headers.get("Connection", "").lower() or request.headers.get("Upgrade"):
            return pages.refused(
                "Not supported", "The remote console does not carry WebSocket connections.", status=501
            )
        if request.headers.get("Service-Worker"):
            # A service worker would outlive the session and sit between the browser and every later one.
            return pages.refused(
                "Not available", "Service workers are not available through the remote console.", status=403
            )
        if not protocol.same_origin_request(method, request.headers.items(), session.origin):
            return pages.refused("Refused", "This request did not come from the console's own pages.", status=403)
        has_body = request.can_read_body and method not in ("GET", "HEAD")
        length = request.content_length
        if has_body:
            if length is None:
                return pages.refused("Length required", "An upload must say how large it is.", status=411)
            if length > self.config.max_request_body:
                await self._discard_body(request)
                megabytes = self.config.max_request_body // (1024 * 1024)
                return pages.refused(
                    "Too large", f"The largest upload through the remote console is {megabytes} MB.", status=413
                )
        tunnel = self.tunnels.get(session.gateway_id)
        if tunnel is None or tunnel.closed:
            return self._no_session(request)

        path = request.raw_path if request.raw_path.startswith("/") else "/"
        headers = protocol.request_headers_for_gateway(
            request.headers.items(),
            cookie_header=session.jar.header_for(request.path),
            client_ip=self._client_ip(request),
            origin=session.origin,
            session_id=session.id,
            content_length=length if has_body else (0 if method in ("POST", "PUT", "PATCH") else None),
        )
        try:
            protocol.check_header_size([(n, v) for n, v in headers])
        except ProtocolError:
            return pages.refused("Too large", "The request's headers are too large.", status=431)

        acquired = []
        try:
            for slots in (session.slots, tunnel.slots):
                await asyncio.wait_for(slots.acquire(), self.config.slot_seconds)
                acquired.append(slots)
        except TimeoutError:
            for slots in acquired:
                slots.release()
            return pages.refused("Busy", "The console is busy. Try again.", status=503, headers={"Retry-After": "2"})
        stream = tunnel.open_stream(session.id)
        try:
            return await self._exchange(request, session, tunnel, stream, method, path, headers, has_body)
        except asyncio.CancelledError:
            await tunnel.abandon(stream, "client_closed")  # the browser went away
            raise
        finally:
            tunnel.release(stream)
            for slots in acquired:
                slots.release()

    async def _discard_body(self, request: web.Request) -> None:
        """Read and drop an upload that is being refused, so the browser gets the refusal instead
        of a broken connection. Bounded in bytes and in time; nothing is kept."""
        remaining = self.config.max_request_body * 4
        try:
            async with asyncio.timeout(15):
                while remaining > 0:
                    chunk = await request.content.readany()
                    if not chunk:
                        return
                    remaining -= len(chunk)
        except (TimeoutError, ConnectionError, aiohttp.ClientError):
            pass
        if request.transport is not None:
            request.transport.close()

    async def _exchange(self, request, session, tunnel, stream, method, path, headers, has_body) -> web.StreamResponse:
        config = self.config
        try:
            await tunnel.send_frame(
                "req", s=stream.id, session=session.id, method=method, path=path, headers=headers, body=has_body
            )
            if has_body:
                sent = 0
                async for chunk in request.content.iter_chunked(protocol.MAX_DATA):
                    sent += len(chunk)
                    if sent > config.max_request_body:
                        await tunnel.abandon(stream, "too_large")
                        return pages.refused("Too large", "The upload is larger than it said.", status=413)
                    await tunnel.send_data(stream, chunk, timeout=config.idle_seconds)
                await tunnel.send_frame("req.end", s=stream.id)
            status, raw_headers, _ = await asyncio.wait_for(asyncio.shield(stream.head), config.response_seconds)
        except TimeoutError:
            await tunnel.abandon(stream, "timeout")
            return pages.refused("The gateway did not answer", "It took too long. Try again.", status=504)
        except (StreamReset, TunnelClosed) as exc:
            await tunnel.abandon(stream, "aborted")
            if session.ended:
                return self._no_session(request)
            timed_out = getattr(exc, "reason", "") == "timeout"
            return pages.refused(
                "The gateway did not answer",
                "The connection to the gateway was interrupted.",
                status=504 if timed_out else 502,
            )
        try:
            out_headers, set_cookies = protocol.response_headers_for_browser(
                raw_headers, shared_origin=config.shared_origin
            )
        except ProtocolError:
            await tunnel.abandon(stream, "protocol")
            return pages.refused(
                "The gateway's answer could not be used", "Its headers were not acceptable.", status=502
            )
        for value in set_cookies:
            session.jar.store(value, request_path=request.path)

        response = web.StreamResponse(status=status)
        for name, value in out_headers:
            response.headers.add(name, value)
        declared = [v.strip() for n, v in raw_headers if isinstance(n, str) and n.lower() == "content-length"]
        if len(declared) == 1 and declared[0].isdigit():
            response.content_length = int(declared[0])  # otherwise the body is sent chunked
        await response.prepare(request)
        try:
            while True:
                chunk = await read_body(stream, timeout=config.idle_seconds)
                if chunk is None:
                    break
                await response.write(chunk)  # waits while the browser is slow: that is the back-pressure
                await tunnel.consumed(stream, len(chunk))
            await response.write_eof()
        except (StreamReset, TunnelClosed, ConnectionError):
            # The status line has gone, so the only honest signal left is to cut the connection.
            await tunnel.abandon(stream, "client_closed")
            if request.transport is not None:
                request.transport.close()
        return response

    # --- wiring -------------------------------------------------------------------------------------

    @staticmethod
    async def _plain_server_header(request: web.Request, response: web.StreamResponse) -> None:
        response.headers["Server"] = "pulsar-hub"  # not the library's name and version

    def _app(self, **kwargs) -> web.Application:
        app = web.Application(**kwargs)
        app.on_response_prepare.append(self._plain_server_header)
        return app

    def tunnel_app(self) -> web.Application:
        app = self._app()
        app.router.add_route("*", "/api/v1/gateways/tunnel", self.handle_tunnel)
        return app

    def console_app(self) -> web.Application:
        # The body limit is enforced per request in `_proxy`; aiohttp's own cap is for bodies it buffers.
        app = self._app(client_max_size=self.config.max_request_body + 1024)
        app.router.add_route("*", "/{tail:.*}", self.handle_console)
        return app

    def control_app(self) -> web.Application:
        app = self._app(client_max_size=256 * 1024)
        app.router.add_get("/control/health", self.handle_health)
        app.router.add_get("/tls-ask", self.handle_tls_ask)
        app.router.add_post("/control/{action:.+}", self.handle_control)
        return app


def _now_text() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
