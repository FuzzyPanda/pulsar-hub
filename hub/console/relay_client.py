"""The web service's calls to the relay: the other direction of the internal channel.

Docker network only; the relay's control port is never routed by Caddy and every call carries the
shared secret. The relay holds the tunnels, so this is how the hub starts a session on a gateway
and how a session or a tunnel is closed at once rather than at the relay's next heartbeat.

Every call is short, bounded and allowed to fail: the database row is the truth, and the relay's
heartbeat brings it back into step within seconds whatever happened here.
"""

import json
import logging
import urllib.error
import urllib.request

from django.conf import settings

logger = logging.getLogger("hub.console")


def call(action: str, payload: dict, *, timeout: float = 3.0) -> dict | None:
    """POST to the relay's control listener. Returns its answer, or None if it could not be asked."""
    base = settings.RELAY_CONTROL_URL
    if not base or not settings.RELAY_INTERNAL_SECRET:
        return None
    request = urllib.request.Request(  # noqa: S310 - a fixed internal address from settings
        f"{base}/control/{action}",
        data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json", "Authorization": f"Bearer {settings.RELAY_INTERNAL_SECRET}"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310
            answer = json.loads(response.read(65536) or b"{}")
    except (urllib.error.URLError, OSError, ValueError) as exc:
        logger.warning("relay not reachable for %s: %s", action, type(exc).__name__)
        return None
    return answer if isinstance(answer, dict) else None


def start_session(*, gateway_id: str, frame: dict, return_url: str) -> tuple[bool, str]:
    """Ask the gateway, through its tunnel, to accept a session. (accepted, reason if not)."""
    # The relay gives the gateway five seconds to accept (the contract's figure); a little more
    # than that here, and no longer: a web worker is waiting.
    answer = call("session/start", {"gateway_id": gateway_id, "frame": frame, "return_url": return_url}, timeout=8.0)
    if answer is None:
        return False, "relay_unreachable"
    if answer.get("ok") is True:
        return True, ""
    return False, str(answer.get("reason") or "gateway_refused")


def extend_session(session_id: str, expires_at: str) -> None:
    call("session/extend", {"session": session_id, "expires_at": expires_at})


def end_session(session_id: str, reason: str) -> None:
    call("session/end", {"session": session_id, "reason": reason})


def close_gateway(gateway_id: str) -> None:
    call("gateway/close", {"gateway_id": gateway_id})
