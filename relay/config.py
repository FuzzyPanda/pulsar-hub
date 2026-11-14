"""The relay's settings, all from the environment (CLAUDE.md rule 6). `.env.example` lists them."""

import os
import re
from dataclasses import dataclass
from urllib.parse import urlsplit

from relay import protocol

GATEWAY_PLACEHOLDER = "{gateway}"
HOST_PLACEHOLDER = "{host}"


class ConfigError(RuntimeError):
    pass


def _flag(name: str, default: bool = False) -> bool:
    return os.environ.get(name, str(default)).strip().lower() in ("1", "true", "yes", "on")


def _number(name: str, default: int, *, low: int, high: int) -> int:
    raw = os.environ.get(name, "").strip()
    if not raw:
        return default
    try:
        value = int(raw)
    except ValueError as exc:
        raise ConfigError(f"{name} must be a whole number.") from exc
    if not low <= value <= high:
        raise ConfigError(f"{name} must be between {low} and {high}.")
    return value


@dataclass(frozen=True)
class RelayConfig:
    internal_secret: str
    hub_url: str  # where the hub's web service answers on the internal network
    hub_host: str  # the Host header for those calls: one of the hub's own names
    origin_template: str
    allow_plain_http: bool = False
    num_proxies: int = 1
    max_request_body: int = protocol.MAX_REQUEST_BODY
    tunnel_port: int = 8001
    console_port: int = 8002
    control_port: int = 8003
    heartbeat_seconds: float = 10.0
    response_seconds: float = 60.0  # a gateway's time to start answering one request
    idle_seconds: float = 60.0  # the longest silence in the middle of a body
    slot_seconds: float = 10.0  # the longest a request waits for a free stream
    session_streams: int = 12  # concurrent requests of one console session

    @property
    def shared_origin(self) -> bool:
        """Every gateway's console on one origin: bench only, refused without the lab flag."""
        return GATEWAY_PLACEHOLDER not in self.origin_template

    @classmethod
    def from_env(cls) -> "RelayConfig | None":
        """The settings, or None when the remote console is not set up (no origin template): the
        relay then runs idle, refusing every tunnel and every console request."""
        template = os.environ.get("CONSOLE_ORIGIN_TEMPLATE", "").strip().rstrip("/")
        if not template:
            return None
        secret = os.environ.get("RELAY_INTERNAL_SECRET", "")
        if len(secret) < 32:
            raise ConfigError("RELAY_INTERNAL_SECRET must be set, and at least 32 characters long.")
        allow_plain = _flag("RELAY_ALLOW_PLAIN_HTTP")
        check_origin_template(template, allow_plain_http=allow_plain)
        hub_base = os.environ.get("HUB_BASE_URL", "").strip()
        hub_host = os.environ.get("RELAY_HUB_HOST", "").strip() or urlsplit(hub_base).netloc
        if not hub_host:
            raise ConfigError("HUB_BASE_URL (or RELAY_HUB_HOST) must be set.")
        megabytes = _number("CONSOLE_MAX_UPLOAD_MB", protocol.MAX_REQUEST_BODY // (1024 * 1024), low=1, high=64)
        return cls(
            internal_secret=secret,
            hub_url=os.environ.get("RELAY_HUB_URL", "http://web:8000").rstrip("/"),
            hub_host=hub_host,
            origin_template=template,
            allow_plain_http=allow_plain,
            num_proxies=_number("NUM_PROXIES", 1, low=0, high=5),
            max_request_body=megabytes * 1024 * 1024,
        )


def check_origin_template(template: str, *, allow_plain_http: bool) -> None:
    """The same rules the hub's settings apply (`hub/settings.py`), so the two cannot disagree."""
    if not template:
        raise ConfigError("CONSOLE_ORIGIN_TEMPLATE must be set for the relay to serve anything.")
    probe = template.replace(GATEWAY_PLACEHOLDER, "gateway").replace(HOST_PLACEHOLDER, "host.invalid")
    parts = urlsplit(probe)
    if parts.scheme not in ("http", "https") or not parts.netloc or parts.path or parts.query or parts.fragment:
        raise ConfigError("CONSOLE_ORIGIN_TEMPLATE must be an origin: scheme and host, nothing after.")
    if "{" in probe or "}" in probe:
        raise ConfigError("CONSOLE_ORIGIN_TEMPLATE may use {gateway} and {host} and no other placeholder.")
    if not allow_plain_http:
        if parts.scheme != "https":
            raise ConfigError("CONSOLE_ORIGIN_TEMPLATE must be https outside a plain-HTTP lab.")
        if GATEWAY_PLACEHOLDER not in template or HOST_PLACEHOLDER in template:
            raise ConfigError(
                "CONSOLE_ORIGIN_TEMPLATE must give every gateway its own origin ({gateway} in the host name) "
                "and may not use {host} outside a plain-HTTP lab."
            )
    if GATEWAY_PLACEHOLDER in template and not re.match(r"^https?://\{gateway\}[.-]", template):
        raise ConfigError("{gateway} must start the host name, as in https://{gateway}.console.example.net.")


def gateway_label(gateway_id: str) -> str:
    """A gateway's DNS label in a per-gateway console origin: its id without the dashes."""
    return gateway_id.replace("-", "").lower()
