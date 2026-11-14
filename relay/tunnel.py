"""One gateway's tunnel: the WebSocket it opened, and the request streams carried on it."""

import asyncio
import logging
import secrets
import time

import aiohttp
from aiohttp import web

from relay import protocol
from relay.protocol import ProtocolError

logger = logging.getLogger("relay.tunnel")

_END = object()


class StreamReset(Exception):
    """A stream ended before it was complete. `reason` is for the log and the status code."""

    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


class TunnelClosed(Exception):
    pass


class Stream:
    """One browser request and its response. Bodies move under a credit window in each direction,
    so the relay never holds more than `protocol.WINDOW` bytes of either."""

    def __init__(self, stream_id: int, session_id: str, method: str, loop: asyncio.AbstractEventLoop):
        self.id = stream_id
        self.session_id = session_id
        self.method = method
        self.head: asyncio.Future = loop.create_future()  # (status, headers, has_body)
        self.body: asyncio.Queue = asyncio.Queue()  # bytes, _END, or StreamReset
        self.send_credit = protocol.WINDOW
        self.credit_changed = asyncio.Event()
        self.unacknowledged = 0  # received and queued, not yet handed back to the gateway as credit
        self.to_grant = 0
        self.reset: StreamReset | None = None
        self.finished = False

    def fail(self, reason: str) -> None:
        if self.reset is None:
            self.reset = StreamReset(reason)
        if not self.head.done():
            self.head.set_exception(self.reset)
            self.head.exception()  # mark retrieved: a request that already gave up must not warn
        self.body.put_nowait(self.reset)
        self.credit_changed.set()


class Tunnel:
    def __init__(self, ws: web.WebSocketResponse, gateway: dict, *, protocol_name: str, send_seconds: float = 30.0):
        self.ws = ws
        self.id = secrets.token_hex(8)  # this connection, so a late report about an earlier one is not mistaken for it
        self.gateway_id: str = gateway["gateway_id"]
        self.gateway = gateway
        self.protocol_name = protocol_name
        self.console_enabled = False
        self.software_version = ""
        self.opened_at = time.time()
        self.streams: dict[int, Stream] = {}
        self.slots = asyncio.Semaphore(protocol.MAX_STREAMS)
        self.closed = False
        self._next_stream = 0
        self._send_lock = asyncio.Lock()
        self._send_seconds = send_seconds
        self._acks: dict[str, asyncio.Future] = {}
        self._console_frame_at: float | None = None
        # Set by the relay: what to do when the gateway speaks about itself or a session.
        self.on_console_switched = lambda tunnel: None
        self.on_session_ended_by_gateway = lambda tunnel, session_id, reason: None

    # --- sending ----------------------------------------------------------------------------------

    async def _send(self, send, payload) -> None:
        if self.closed:
            raise TunnelClosed
        try:
            async with self._send_lock:
                await asyncio.wait_for(send(payload), self._send_seconds)
        except (TimeoutError, ConnectionError, RuntimeError, aiohttp.ClientError) as exc:
            # A gateway that has stopped reading holds every stream up. Drop it; it will reconnect.
            await self.close(protocol.CLOSE_PROTOCOL, "the gateway stopped reading")
            raise TunnelClosed from exc

    async def send_frame(self, frame_type: str, **fields) -> None:
        await self._send(self.ws.send_str, protocol.text_frame(frame_type, **fields))

    async def send_data(self, stream: Stream, chunk: bytes, *, timeout: float) -> None:
        """Send request body, waiting for the gateway's credit. Raises StreamReset if the stream died."""
        view = memoryview(chunk)
        while view:
            while stream.send_credit <= 0:
                if stream.reset:
                    raise stream.reset
                stream.credit_changed.clear()
                try:
                    await asyncio.wait_for(stream.credit_changed.wait(), timeout)
                except TimeoutError:
                    raise StreamReset("timeout") from None
            if stream.reset:
                raise stream.reset
            size = min(len(view), protocol.MAX_DATA, stream.send_credit)
            stream.send_credit -= size
            await self._send(self.ws.send_bytes, protocol.data_frame(stream.id, bytes(view[:size])))
            view = view[size:]

    # --- streams ----------------------------------------------------------------------------------

    def open_stream(self, session_id: str, method: str) -> Stream:
        self._next_stream += 1
        stream = Stream(self._next_stream, session_id, method, asyncio.get_running_loop())
        self.streams[stream.id] = stream
        return stream

    async def abandon(self, stream: Stream, reason: str) -> None:
        """Stop a stream from this side and tell the gateway, unless it already finished."""
        if self.streams.pop(stream.id, None) is None:
            return
        stream.fail(reason)
        if not stream.finished and not self.closed:
            try:
                await self.send_frame("rst", s=stream.id, reason=reason)
            except TunnelClosed:
                pass

    def release(self, stream: Stream) -> None:
        self.streams.pop(stream.id, None)

    async def consumed(self, stream: Stream, size: int) -> None:
        """`size` bytes of response body have gone on to the browser: give the gateway credit back."""
        stream.unacknowledged -= size
        stream.to_grant += size
        if stream.to_grant >= protocol.WINDOW // 2 and not stream.finished and stream.id in self.streams:
            grant, stream.to_grant = stream.to_grant, 0
            await self.send_frame("win", s=stream.id, n=grant)

    def streams_of(self, session_id: str) -> list[Stream]:
        return [stream for stream in self.streams.values() if stream.session_id == session_id]

    # --- sessions ---------------------------------------------------------------------------------

    async def start_session(self, payload: dict) -> tuple[bool, str]:
        """Tell the gateway about a session and wait for it to accept. (ok, reason)."""
        session_id = payload["session"]
        future = asyncio.get_running_loop().create_future()
        self._acks[session_id] = future
        try:
            await self.send_frame("session.start", **payload)
            ack = await asyncio.wait_for(future, protocol.SESSION_ACK_SECONDS)
        except TimeoutError:
            # It may still accept late. Tell it the session is off, so the two sides agree.
            try:
                await self.send_frame("session.end", session=session_id, reason="not_started")
            except TunnelClosed:
                pass
            return False, "gateway_silent"
        except TunnelClosed:
            return False, "not_connected"
        finally:
            self._acks.pop(session_id, None)
        if ack.get("ok") is True:
            return True, ""
        reason = ack.get("reason")
        return False, reason if reason in ("disabled", "busy") else "gateway_refused"

    # --- receiving --------------------------------------------------------------------------------

    async def run(self) -> None:
        """Read frames until the tunnel closes. Returns normally; the caller cleans up."""
        try:
            async for message in self.ws:
                if message.type == aiohttp.WSMsgType.TEXT:
                    self._on_text(protocol.parse_text_frame(message.data))
                elif message.type == aiohttp.WSMsgType.BINARY:
                    self._on_data(*protocol.parse_data_frame(message.data))
                elif message.type == aiohttp.WSMsgType.ERROR:
                    break
        except ProtocolError as exc:
            logger.warning("gateway %s broke the protocol: %s", self.gateway_id, exc)
            await self.close(protocol.CLOSE_PROTOCOL, str(exc))
        finally:
            self._fail_everything("tunnel_closed")

    def _fail_everything(self, reason: str) -> None:
        self.closed = True
        for stream in list(self.streams.values()):
            stream.fail(reason)
        self.streams.clear()
        for future in self._acks.values():
            if not future.done():
                future.set_result({"ok": False, "reason": "not_connected"})

    async def close(self, code: int, reason: str) -> None:
        if self.closed and self.ws.closed:
            return
        self.closed = True
        try:
            await asyncio.wait_for(self.ws.close(code=code, message=reason.encode()[:120]), 5)
        except (TimeoutError, ConnectionError, RuntimeError):
            pass

    def _on_text(self, frame: dict) -> None:
        kind = frame["t"]
        if kind == "res":
            stream = self.streams.get(protocol.stream_id_of(frame))
            if stream is None or stream.head.done():
                return  # a reply to a stream this side already gave up on
            status, headers = frame.get("status"), frame.get("headers", [])
            if isinstance(status, bool) or not isinstance(status, int) or not 200 <= status <= 599:
                raise ProtocolError('"status" must be a final HTTP status')
            if not isinstance(headers, list):
                raise ProtocolError('"headers" must be a list')
            has_body = frame.get("body") is True
            if has_body and protocol.response_is_bodiless(stream.method, status):
                # Not a matter of taste: bytes after a bodiless response would be read as the next
                # response by whatever shares the connection. The whole tunnel goes.
                raise ProtocolError(f"a response to {stream.method} with status {status} cannot have a body")
            stream.finished = not has_body
            stream.head.set_result((status, headers, has_body))
            if not has_body:
                stream.body.put_nowait(_END)
        elif kind == "res.end":
            stream = self.streams.get(protocol.stream_id_of(frame))
            if stream is not None and stream.head.done() and not stream.finished:
                stream.finished = True
                stream.body.put_nowait(_END)
        elif kind == "rst":
            stream = self.streams.pop(protocol.stream_id_of(frame), None)
            if stream is not None:
                stream.finished = True
                stream.fail("gateway_reset")
        elif kind == "win":
            stream = self.streams.get(protocol.stream_id_of(frame))
            grant = frame.get("n")
            if isinstance(grant, bool) or not isinstance(grant, int) or grant <= 0:
                raise ProtocolError('"n" must be a positive number of bytes')
            if stream is not None:
                stream.send_credit = min(stream.send_credit + grant, protocol.WINDOW)
                stream.credit_changed.set()
        elif kind == "session.ack":
            future = self._acks.get(str(frame.get("session")))
            if future is not None and not future.done():
                future.set_result(frame)
        elif kind == "session.end":
            self.on_session_ended_by_gateway(self, str(frame.get("session")), str(frame.get("reason") or "")[:64])
        elif kind == "console":
            now = time.monotonic()
            if self._console_frame_at is not None and now - self._console_frame_at < protocol.CONSOLE_FRAME_SECONDS:
                raise ProtocolError(f"console frames less than {protocol.CONSOLE_FRAME_SECONDS} seconds apart")
            self._console_frame_at = now
            if not isinstance(frame.get("enabled"), bool):
                raise ProtocolError('"enabled" must be true or false')
            enabled = frame["enabled"]
            if enabled != self.console_enabled:
                self.console_enabled = enabled
                self.on_console_switched(self)
        # Anything else is a frame from a newer gateway: ignored, as the contract says.

    def _on_data(self, stream_id: int, chunk: bytes) -> None:
        stream = self.streams.get(stream_id)
        if stream is None:
            return
        if not stream.head.done() or stream.finished:
            raise ProtocolError("body data outside a response")
        if stream.unacknowledged + len(chunk) > protocol.WINDOW:
            raise ProtocolError("more body data than the stream's window allows")
        stream.unacknowledged += len(chunk)
        stream.body.put_nowait(chunk)


async def read_body(stream: Stream, *, timeout: float):
    """The next piece of a response body, or None at its end. Raises StreamReset."""
    try:
        item = await asyncio.wait_for(stream.body.get(), timeout)
    except TimeoutError:
        raise StreamReset("timeout") from None
    if item is _END:
        return None
    if isinstance(item, StreamReset):
        raise item
    return item
