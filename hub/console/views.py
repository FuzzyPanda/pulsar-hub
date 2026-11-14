"""Opening, extending and ending a remote console session from the hub's own pages.

Thin: `hub.console.services` decides and audits. The "open" view does not redirect to the console
with the token in the address. It answers with a page that posts the token to the console origin,
so the token is never in an address, a log, the browser's history or a Referer header.
"""

from functools import wraps

from django.contrib import messages
from django.core.exceptions import PermissionDenied, ValidationError
from django.shortcuts import get_object_or_404, redirect, render
from django.views.decorators.http import require_POST

from hub.accounts.stepup import step_up_required
from hub.console import services
from hub.console.models import ConsoleSession
from hub.gateways.models import Gateway
from hub.organisations.models import Role
from hub.organisations.services import Actor
from hub.organisations.views import _flash_errors

ERRORS = (ValidationError, PermissionDenied, ValueError)


def console_role_required(view):
    """Owner or Admin, like `role_required(Role.ADMIN)`, except that a refusal for this surface is
    also written to the audit log before the 403 is given."""

    @wraps(view)
    def wrapper(request, *args, **kwargs):
        actor = Actor.from_request(request)
        if not actor.has_role(Role.ADMIN):
            gateway = None
            if "gateway_id" in kwargs:
                gateway = Gateway.objects.select_related("site").filter(pk=kwargs["gateway_id"]).first()
            elif "session_id" in kwargs:
                session = ConsoleSession.objects.select_related("gateway__site").filter(pk=kwargs["session_id"]).first()
                gateway = session.gateway if session is not None else None
            if gateway is not None:
                services.record_refusal(gateway=gateway, request=request, reason="role")
            raise PermissionDenied("Only an Owner or an Admin can use a gateway's remote console.")
        return view(request, *args, **kwargs)

    wrapper.minimum_role = Role.ADMIN
    return wrapper


@require_POST
@console_role_required
@step_up_required
def console_open(request, org_slug: str, gateway_id):
    gateway = get_object_or_404(Gateway.objects.select_related("site"), pk=gateway_id)
    try:
        session, token = services.open_session(gateway, actor=Actor.from_request(request), request=request)
    except PermissionDenied:
        raise
    except ERRORS as exc:
        _flash_errors(request, exc)
        return redirect("site_detail", org_slug=org_slug, site_id=gateway.site_id)
    response = render(
        request,
        "console/handoff.html",
        {"action": f"{session.origin}/__hub__/handoff", "token": token, "site": gateway.site, "session": session},
    )
    # The page holds a one-time secret: never stored. Its form names the hub's origin, and only
    # its origin, to the console origin: the relay accepts the hand-off from nowhere else, and a
    # browser sends `Origin: null` under the hub's usual same-origin referrer policy.
    response["Cache-Control"] = "no-store"
    response["Referrer-Policy"] = "strict-origin"
    return response


@require_POST
@console_role_required
@step_up_required
def console_extend(request, org_slug: str, session_id):
    session = get_object_or_404(ConsoleSession.objects.select_related("gateway__site", "user"), pk=session_id)
    try:
        services.extend_session(session, actor=Actor.from_request(request), request=request)
    except PermissionDenied:
        raise
    except ERRORS as exc:
        _flash_errors(request, exc)
    else:
        messages.success(request, f"Session extended until {session.expires_at:%H:%M} UTC.")
    return redirect("site_detail", org_slug=org_slug, site_id=session.gateway.site_id)


@require_POST
@console_role_required
def console_end(request, org_slug: str, session_id):
    session = get_object_or_404(ConsoleSession.objects.select_related("gateway__site", "user"), pk=session_id)
    try:
        services.end_session(session, actor=Actor.from_request(request), request=request)
    except PermissionDenied:
        raise
    except ERRORS as exc:
        _flash_errors(request, exc)
    else:
        messages.success(request, "Remote console session ended.")
    return redirect("site_detail", org_slug=org_slug, site_id=session.gateway.site_id)
