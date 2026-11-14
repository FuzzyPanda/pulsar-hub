"""The relay's side door into the web service: `/internal/relay/...`.

Not part of the public API. It is reached over the Docker network only: both Caddyfiles refuse
`/internal/*`, a request that came through a proxy at all is refused here as well, and every call
must carry the shared secret (compared in constant time). Every failure is a plain 404, so the
address says nothing to anyone who finds it.

The views decide nothing and write nothing themselves: each hands the relay's question or report
to `hub.console.services`.
"""

import hmac
import json
from functools import wraps

from django.conf import settings
from django.http import HttpResponseNotFound, JsonResponse
from django.views.decorators.csrf import csrf_exempt

from hub.console import services


def _authorised(request) -> bool:
    secret = settings.RELAY_INTERNAL_SECRET
    if not secret or request.method != "POST":
        return False
    # Caddy adds these to everything it forwards. The relay calls the web service directly.
    if "HTTP_X_FORWARDED_FOR" in request.META or "HTTP_X_FORWARDED_PROTO" in request.META:
        return False
    scheme, _, presented = request.META.get("HTTP_AUTHORIZATION", "").partition(" ")
    return scheme == "Bearer" and hmac.compare_digest(presented.encode(), secret.encode())


def relay_only(view):
    @csrf_exempt
    @wraps(view)
    def wrapper(request):
        if not _authorised(request):
            return HttpResponseNotFound()
        try:
            payload = json.loads(request.body or b"{}")
        except (ValueError, UnicodeDecodeError):
            return JsonResponse({"detail": "The body is not JSON."}, status=400)
        if not isinstance(payload, dict):
            return JsonResponse({"detail": "The body must be a JSON object."}, status=400)
        return view(request, payload)

    wrapper.relay_only = True
    return wrapper


def _answer(body: dict | None = None, status: int = 200) -> JsonResponse:
    return JsonResponse(body or {}, status=status, headers={"Cache-Control": "no-store"})


@relay_only
def started(request, payload):
    services.relay_started(str(payload.get("instance") or ""))
    return _answer()


@relay_only
def tunnel_authorize(request, payload):
    gateway = services.authorize_tunnel(str(payload.get("credential") or ""))
    if gateway is None:
        return _answer({"detail": "This gateway's credential is not accepted."}, status=401)
    return _answer(gateway)


@relay_only
def tunnel_refused(request, payload):
    services.tunnel_refused(payload.get("gateway_id"), str(payload.get("offered") or ""))
    return _answer()


@relay_only
def tunnel_opened(request, payload):
    opened = services.tunnel_opened(
        payload.get("gateway_id"),
        protocol=str(payload.get("protocol") or ""),
        software_version=str(payload.get("software_version") or ""),
        console_enabled=payload.get("console_enabled") is True,
    )
    return _answer() if opened else _answer({"detail": "This gateway may not open a tunnel."}, status=409)


@relay_only
def handoff_redeem(request, payload):
    answer = services.redeem_handoff(str(payload.get("token") or ""), str(payload.get("origin") or ""))
    if answer is None:
        return _answer({"detail": "That hand-off is not valid."}, status=403)
    return _answer(answer)


@relay_only
def event(request, payload):
    kind = payload.get("event")
    if kind == "tunnel.closed":
        services.tunnel_closed(payload.get("gateway_id"))
    elif kind == "console.switched":
        services.console_switched(payload.get("gateway_id"), payload.get("enabled") is True)
    elif kind == "session.ended":
        services.session_ended_by_relay(payload.get("session"), str(payload.get("reason") or ""))
    else:
        return _answer({"detail": "Unknown event."}, status=400)
    return _answer()


@relay_only
def heartbeat(request, payload):
    return _answer(services.heartbeat(payload.get("gateways") or [], payload.get("sessions") or []))
