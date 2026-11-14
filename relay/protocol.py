"""The tunnel protocol (`pulsar-console.v1`) and the rules for what crosses the relay.

Everything in this file is a pure function or a constant, so the relay, the fake gateway and the
tests share one statement of the rules. `docs/CONTRACTS.md`, "Remote console", is the contract;
change it there first.
"""

import json
import re
import struct
import time
from email.utils import parsedate_to_datetime
from urllib.parse import urlsplit

SUBPROTOCOL_V1 = "pulsar-console.v1"
SUPPORTED_SUBPROTOCOLS = (SUBPROTOCOL_V1,)

# --- limits (sent to the gateway in `welcome`; both sides hold to them) ---------------------------

MAX_STREAMS = 32  # concurrent requests on one tunnel
WINDOW = 256 * 1024  # bytes of body a sender may have outstanding on one stream, each direction
MAX_DATA = 64 * 1024  # bytes of body in one binary frame
MAX_TEXT_FRAME = 128 * 1024  # bytes in one JSON frame
MAX_HEADER_BYTES = 64 * 1024  # all header names and values of one request or response
MAX_HEADER_COUNT = 200
MAX_REQUEST_BODY = 16 * 1024 * 1024  # an upload through the console; the default, see RelayConfig
PING_SECONDS = 20
IDLE_SECONDS = 60  # a side that hears nothing for this long treats the tunnel as dead
HELLO_SECONDS = 10
SESSION_ACK_SECONDS = 5
# A gateway says its switch changed only when it has, and never more often than this.
CONSOLE_FRAME_SECONDS = 5
# Responses that have no body, whatever a gateway says: an answer to HEAD, and these statuses.
BODILESS_STATUSES = frozenset({204, 304})

# --- close codes the hub uses ---------------------------------------------------------------------

CLOSE_GOING_AWAY = 1001  # the relay is restarting; reconnect with back-off
CLOSE_PROTOCOL = 4000  # the gateway broke the protocol; the reason says how
CLOSE_REPLACED = 4001  # the same gateway opened a newer tunnel
CLOSE_REVOKED = 4003  # the credential is no longer accepted; same meaning as a 401
CLOSE_UNAVAILABLE = 4004  # the hub cannot check anything just now; reconnect with back-off

SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})
ALLOWED_METHODS = frozenset({"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"})

# Paths on a console origin that the relay answers itself and never sends to a gateway.
RESERVED_PREFIX = "/__hub__/"

# --- frames ---------------------------------------------------------------------------------------

_STREAM_HEADER = struct.Struct(">I")


class ProtocolError(Exception):
    """The peer sent something the protocol does not allow."""


def text_frame(frame_type: str, **fields) -> str:
    return json.dumps({"t": frame_type, **fields}, separators=(",", ":"))


def parse_text_frame(raw: str) -> dict:
    if len(raw) > MAX_TEXT_FRAME:
        raise ProtocolError("a text frame is larger than the limit")
    try:
        frame = json.loads(raw)
    except ValueError as exc:
        raise ProtocolError("a text frame is not JSON") from exc
    if not isinstance(frame, dict) or not isinstance(frame.get("t"), str):
        raise ProtocolError('a text frame must be a JSON object with a string "t"')
    return frame


def data_frame(stream_id: int, chunk: bytes) -> bytes:
    return _STREAM_HEADER.pack(stream_id) + chunk


def parse_data_frame(raw: bytes) -> tuple[int, bytes]:
    if len(raw) <= _STREAM_HEADER.size:
        raise ProtocolError("a data frame carries no data")
    if len(raw) > _STREAM_HEADER.size + MAX_DATA:
        raise ProtocolError("a data frame is larger than the limit")
    (stream_id,) = _STREAM_HEADER.unpack_from(raw)
    return stream_id, raw[_STREAM_HEADER.size :]


def stream_id_of(frame: dict) -> int:
    stream_id = frame.get("s")
    if isinstance(stream_id, bool) or not isinstance(stream_id, int) or not 0 < stream_id < 2**32:
        raise ProtocolError('"s" must be a stream id')
    return stream_id


def response_is_bodiless(method: str, status: int) -> bool:
    """HTTP gives these responses no body. A byte written after one would be read, by whatever
    reuses the connection, as the start of the next response."""
    return method.upper() == "HEAD" or status in BODILESS_STATUSES


def choose_subprotocol(offered: str) -> str | None:
    """The newest version both sides speak, from a `Sec-WebSocket-Protocol` request header."""
    names = [name.strip() for name in (offered or "").split(",") if name.strip()]
    for candidate in reversed(SUPPORTED_SUBPROTOCOLS):
        if candidate in names:
            return candidate
    return None


# --- headers --------------------------------------------------------------------------------------

# RFC 9110 section 7.6.1, plus the obsolete ones proxies still meet.
HOP_BY_HOP = frozenset(
    {
        "connection",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "proxy-connection",
        "te",
        "trailer",
        "transfer-encoding",
        "upgrade",
    }
)

# Never sent from a browser to a gateway. `cookie` is replaced from the session's own jar;
# `authorization` could only be something meant for the hub; `host` is the gateway's to set. The
# forwarding headers are removed here and then written by the relay, so a gateway may believe them
# because they came down the tunnel. The prefixes cover headers a proxy in front of the gateway
# may trust for client certificates and for this hub's own identity headers.
_REQUEST_DROP = frozenset(
    {"cookie", "authorization", "host", "forwarded", "via", "x-real-ip", "expect", "content-length"}
)
_REQUEST_DROP_PREFIXES = ("x-forwarded-", "x-hub-", "x-pulsar-", "proxy-", "sec-websocket-", "x-ssl-", "x-client-cert")

# Never sent from a gateway to a browser. `set-cookie` goes to the jar. The rest would let one
# console change how the browser treats the console origin (or, on a bench where the origin shares
# its host name with the hub, the hub itself) after the session is over.
_RESPONSE_DROP = frozenset(
    {
        "set-cookie",
        "set-cookie2",
        "strict-transport-security",
        "public-key-pins",
        "public-key-pins-report-only",
        "alt-svc",
        "clear-site-data",
        "service-worker-allowed",
        "content-length",
        "date",
        "server",
        "nel",
        "report-to",
        "reporting-endpoints",
        "expect-ct",
        "origin-agent-cluster",
    }
)

# Response headers whose value is an address the browser will go to. Each is confined to the
# console origin: only the path, query and fragment survive.
_LOCATION_HEADERS = frozenset({"location", "content-location", "hx-redirect", "hx-push-url", "hx-replace-url"})

_TOKEN = re.compile(r"^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$")


def _connection_named(headers) -> set[str]:
    named = set()
    for name, value in headers:
        if name.lower() == "connection":
            named.update(part.strip().lower() for part in value.split(",") if part.strip())
    return named


def _clean_pairs(headers) -> list[tuple[str, str]]:
    """Header pairs with usable names and values; anything else is dropped, never passed on."""
    pairs = []
    for item in headers:
        try:
            name, value = item
        except (TypeError, ValueError) as exc:
            raise ProtocolError("headers must be a list of [name, value] pairs") from exc
        if not isinstance(name, str) or not isinstance(value, str):
            raise ProtocolError("header names and values must be strings")
        if not _TOKEN.match(name) or any(ch in value for ch in "\r\n\0"):
            continue
        try:
            value.encode("utf-8")
        except UnicodeEncodeError:
            continue  # a lone surrogate from undecodable bytes: it cannot be written back out
        pairs.append((name, value.strip()))
    return pairs


def check_header_size(headers) -> None:
    if len(headers) > MAX_HEADER_COUNT or sum(len(n) + len(v) for n, v in headers) > MAX_HEADER_BYTES:
        raise ProtocolError("headers are larger than the limit")


def request_headers_for_gateway(
    headers, *, cookie_header: str, client_ip: str, origin: str, session_id: str, content_length: int | None
) -> list[list[str]]:
    """What a gateway is sent for one browser request.

    `headers` is what the browser sent to the relay. The result carries no hop-by-hop header, no
    browser cookie, no credential and nothing a caller could have forged about where the request
    came from; then the four forwarding headers, written here.
    """
    pairs = _clean_pairs(headers)
    named = _connection_named(pairs)
    out: list[list[str]] = []
    for name, value in pairs:
        lower = name.lower()
        if lower in HOP_BY_HOP or lower in named or lower in _REQUEST_DROP:
            continue
        if lower.startswith(_REQUEST_DROP_PREFIXES):
            continue
        if "_" in lower:
            # Servers that hand headers on as CGI variables read x_forwarded_for as X-Forwarded-For.
            # No browser sends an underscore in a header name; nothing that does is passed on.
            continue
        out.append([lower, value])
    parts = urlsplit(origin)
    out.append(["x-forwarded-for", client_ip])
    out.append(["x-forwarded-proto", parts.scheme])
    out.append(["x-forwarded-host", parts.netloc])
    out.append(["x-hub-console-session", session_id])
    if cookie_header:
        out.append(["cookie", cookie_header])
    if content_length is not None:
        out.append(["content-length", str(content_length)])
    return out


def confine_location(value: str) -> str:
    """An address from a gateway, kept on the console origin.

    A console may send the browser anywhere on itself and nowhere else: the scheme and host of an
    absolute address are discarded and its path, query and fragment kept. This also turns a
    gateway's own local address (`http://10.0.0.5/ui/`) into the right place on the console origin.
    Backslashes count as slashes, as browsers treat them, so `/\\host` cannot leave either.
    """
    value = "".join(ch for ch in value.strip() if ch >= " " and ch != "\x7f").replace("\\", "/")
    try:
        parts = urlsplit(value)
    except ValueError:
        return "/"
    path = parts.path
    if parts.scheme or parts.netloc or value.startswith("//"):
        if parts.scheme and parts.scheme.lower() not in ("http", "https"):
            return "/"
        path = "/" + path.lstrip("/")
    elif path.startswith("//"):
        path = "/" + path.lstrip("/")
    confined = path
    if parts.query:
        confined += "?" + parts.query
    if parts.fragment:
        confined += "#" + parts.fragment
    return confined or "/"


def _confine_hx_location(value: str) -> str:
    """htmx's HX-Location is an address, or a JSON object with one under `path`."""
    stripped = value.strip()
    if stripped.startswith("{"):
        try:
            payload = json.loads(stripped)
        except ValueError:
            return "/"
        if not isinstance(payload, dict):
            return "/"
        if isinstance(payload.get("path"), str):
            payload["path"] = confine_location(payload["path"])
        return json.dumps(payload, separators=(",", ":"))
    return confine_location(stripped)


def _confine_refresh(value: str) -> str:
    """`Refresh: 5; url=/next` keeps its delay and has its address confined. Browsers accept the
    address with or without `url=` and with or without quotes round it, so every form is read the
    way a browser would read it, and what is written back is never quoted."""
    delay, _, rest = value.partition(";")
    delay = delay.strip()
    if not delay.replace(".", "", 1).isdigit() or not delay.isascii():
        delay = "0"
    rest = re.sub(r"^\s*url\s*=", "", rest, count=1, flags=re.IGNORECASE)
    rest = rest.strip("\"' \t")
    if not rest:
        return delay
    return f"{delay}; url={confine_location(rest)}"


def response_headers_for_browser(headers, *, shared_origin: bool) -> tuple[list[tuple[str, str]], list[str]]:
    """What a browser is sent for one gateway response: (headers, the Set-Cookie values).

    The Set-Cookie values never reach the browser; the caller puts them in the session's jar.
    `shared_origin` is the bench mode in which every gateway's console is served from one origin:
    there nothing may be cached, because the browser's cache is shared between gateways.
    """
    pairs = _clean_pairs(headers)
    check_header_size(pairs)
    named = _connection_named(pairs)
    out: list[tuple[str, str]] = []
    cookies: list[str] = []
    for name, value in pairs:
        lower = name.lower()
        if lower == "set-cookie":
            cookies.append(value)
            continue
        if lower in HOP_BY_HOP or lower in named or lower in _RESPONSE_DROP:
            continue
        if shared_origin and lower in ("cache-control", "expires", "pragma", "etag", "last-modified", "age"):
            continue
        if lower in _LOCATION_HEADERS:
            value = confine_location(value)
        elif lower == "hx-location":
            value = _confine_hx_location(value)
        elif lower == "refresh":
            value = _confine_refresh(value)
        out.append((name, value))
    present = {name.lower() for name, _ in out}
    if shared_origin:
        out.append(("Cache-Control", "no-store"))
    elif "cache-control" not in present:
        out.append(("Cache-Control", "private, no-cache"))
    # The relay's own floor. A console can be stricter, never looser.
    out = [(n, v) for n, v in out if n.lower() not in ("referrer-policy", "cross-origin-resource-policy")]
    out.append(("Referrer-Policy", "same-origin"))
    out.append(("Cross-Origin-Resource-Policy", "same-origin"))
    if "x-content-type-options" not in present:
        out.append(("X-Content-Type-Options", "nosniff"))
    if "cross-origin-opener-policy" not in present:
        out.append(("Cross-Origin-Opener-Policy", "same-origin"))
    return out, cookies


def origin_of(value: str) -> str:
    """`scheme://host[:port]` of an address, lower case; empty when it has none."""
    try:
        parts = urlsplit(value.strip())
    except ValueError:
        return ""
    if not parts.scheme or not parts.netloc:
        return ""
    return f"{parts.scheme.lower()}://{parts.netloc.lower()}"


def same_origin_request(method: str, headers, origin: str) -> bool:
    """Whether a request that changes something really came from the console's own pages.

    A browser sends `Origin` on every such request; `Referer` is the fallback. A request that
    carries neither is refused: nothing a browser sends for a form or a script lacks both.
    """
    if method.upper() in SAFE_METHODS:
        return True
    lowered = {name.lower(): value for name, value in headers}
    sent = lowered.get("origin")
    if sent is not None:
        return sent.strip().lower() == origin.lower()
    referer = lowered.get("referer")
    if referer:
        return origin_of(referer) == origin.lower()
    return False


# --- the cookie jar -------------------------------------------------------------------------------

JAR_MAX_COOKIES = 50
JAR_MAX_COOKIE_BYTES = 4096
_COOKIE_NAME = re.compile(r"^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$")


class CookieJar:
    """One console session's cookies from its gateway, kept by the relay and never by the browser.

    The gateway's console sets its session and CSRF cookies as it would for any browser; the relay
    keeps them here and sends them back with each request of the same session. The browser holds
    one cookie only, the relay's own. So a gateway's cookie cannot reach the hub, another gateway
    or another person, cannot outlive the session, and cannot be planted on anything else.

    `Domain` is ignored (every cookie is for this one console), as are `Secure`, `HttpOnly` and
    `SameSite` (no script and no other site can reach the jar at all). `Path`, `Max-Age` and
    `Expires` are honoured.
    """

    def __init__(self, *, now=time.time):
        self._cookies: dict[tuple[str, str], tuple[str, float | None]] = {}
        self._now = now

    def __len__(self) -> int:
        return len(self._cookies)

    def store(self, set_cookie: str, *, request_path: str) -> None:
        first, _, rest = set_cookie.partition(";")
        name, sep, value = first.partition("=")
        name, value = name.strip(), value.strip()
        if not sep or not _COOKIE_NAME.match(name) or len(name) + len(value) > JAR_MAX_COOKIE_BYTES:
            return
        if len(value) >= 2 and value[0] == value[-1] == '"':
            value = value[1:-1]
        if any(ch in value for ch in ' ",;\\\r\n\0'):
            return
        path = _default_path(request_path)
        expires: float | None = None
        max_age_seen = False
        for attribute in rest.split(";"):
            key, _, attr_value = attribute.partition("=")
            key, attr_value = key.strip().lower(), attr_value.strip()
            if key == "path" and attr_value.startswith("/"):
                path = attr_value
            elif key == "max-age":
                try:
                    seconds = int(attr_value)
                except ValueError:
                    continue
                max_age_seen = True
                expires = self._now() + seconds if seconds > 0 else 0.0
            elif key == "expires" and not max_age_seen:
                try:
                    expires = parsedate_to_datetime(attr_value).timestamp()
                except (TypeError, ValueError):
                    continue
        key = (name, path)
        if expires is not None and expires <= self._now():
            self._cookies.pop(key, None)
            return
        if key not in self._cookies and len(self._cookies) >= JAR_MAX_COOKIES:
            return  # full: a console that sets cookies without end loses the newest, not the relay
        self._cookies[key] = (value, expires)

    def header_for(self, request_path: str) -> str:
        """The `Cookie` header for a request to `request_path`; longest path first, as browsers do."""
        now = self._now()
        for key in [k for k, (_, expires) in self._cookies.items() if expires is not None and expires <= now]:
            del self._cookies[key]
        path = request_path.split("?", 1)[0] or "/"
        matching = [
            (name, cookie_path, value)
            for (name, cookie_path), (value, _) in self._cookies.items()
            if _path_matches(path, cookie_path)
        ]
        matching.sort(key=lambda item: -len(item[1]))
        return "; ".join(f"{name}={value}" for name, _, value in matching)


def _default_path(request_path: str) -> str:
    path = request_path.split("?", 1)[0]
    if not path.startswith("/") or path.count("/") <= 1:
        return "/"
    return path.rsplit("/", 1)[0] or "/"


def _path_matches(request_path: str, cookie_path: str) -> bool:
    if request_path == cookie_path:
        return True
    if request_path.startswith(cookie_path):
        return cookie_path.endswith("/") or request_path[len(cookie_path)] == "/"
    return False
