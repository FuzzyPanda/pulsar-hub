"""Console pages for gateways and what they report."""

from django.contrib import messages
from django.core.exceptions import PermissionDenied, ValidationError
from django.core.paginator import Paginator
from django.shortcuts import get_object_or_404, redirect, render
from django.views.decorators.http import require_GET, require_POST

from hub.access.services import desired_access
from hub.accounts.stepup import step_up_required
from hub.directory.models import Site
from hub.gateways import services
from hub.gateways.models import Gateway, GatewayEvent
from hub.organisations.models import Role
from hub.organisations.services import Actor
from hub.organisations.views import _flash_errors, role_required

ERRORS = (ValidationError, PermissionDenied, ValueError)
NEW_PAIRING_CODE_KEY = "hub_new_pairing_code"


def site_sync_status(site: Site, gateway: Gateway | None) -> dict:
    """Where a site stands, in the words the console shows.

    `state` is one of: `elsewhere` (another system runs the doors), `unpaired`, `out_of_contact`,
    `unconfirmed` (the gateway has not yet acknowledged the current access), `failures` (applied,
    but some people could not be given what they should have), or `in_sync`.
    """
    if site.access_managed_elsewhere:
        return {"state": "elsewhere", "failures": []}
    if gateway is None:
        return {"state": "unpaired", "failures": []}
    current = desired_access(site)["version"]
    confirmed = gateway.applied_version == current
    if not gateway.is_in_contact():
        state = "out_of_contact"
    elif not confirmed:
        state = "unconfirmed"
    elif gateway.apply_failures:
        state = "failures"
    else:
        state = "in_sync"
    return {
        "state": state,
        "confirmed": confirmed,
        "failures": gateway.apply_failures if confirmed else [],
        "last_seen_at": gateway.last_seen_at,
        "applied_at": gateway.applied_at,
    }


@require_POST
@role_required(Role.ADMIN)
@step_up_required
def gateway_pairing_code(request, org_slug: str, site_id):
    site = get_object_or_404(Site.objects, pk=site_id)
    try:
        pairing, code = services.create_pairing_code(site, actor=Actor.from_request(request), request=request)
    except ERRORS as exc:
        _flash_errors(request, exc)
    else:
        # Shown once, on the next page, then gone: only its digest is stored.
        request.session[NEW_PAIRING_CODE_KEY] = {
            "site": str(site.pk),
            "code": code,
            "expires_at": pairing.expires_at.strftime("%Y-%m-%dT%H:%M:%SZ"),
        }
    return redirect("site_detail", org_slug=org_slug, site_id=site.pk)


@require_POST
@role_required(Role.ADMIN)
@step_up_required
def gateway_revoke(request, org_slug: str, gateway_id):
    gateway = get_object_or_404(Gateway.objects.select_related("site"), pk=gateway_id)
    try:
        services.revoke_gateway(gateway, actor=Actor.from_request(request), request=request)
    except ERRORS as exc:
        _flash_errors(request, exc)
    else:
        messages.success(
            request, "Gateway revoked. It keeps the people it last synced until someone changes them on site."
        )
    return redirect("site_detail", org_slug=org_slug, site_id=gateway.site_id)


@require_POST
@role_required(Role.ADMIN)
@step_up_required
def gateway_console_address(request, org_slug: str, gateway_id):
    gateway = get_object_or_404(Gateway.objects.select_related("site"), pk=gateway_id)
    try:
        services.set_console_address(
            gateway, actor=Actor.from_request(request), address=request.POST.get("console_address", ""), request=request
        )
    except ERRORS as exc:
        _flash_errors(request, exc)
    else:
        messages.success(request, "Console address saved." if gateway.console_address else "Console address removed.")
    return redirect("site_detail", org_slug=org_slug, site_id=gateway.site_id)


@require_GET
@role_required(Role.MANAGER)
def event_list(request, org_slug: str):
    events = GatewayEvent.objects.select_related("site", "person")
    site_id = request.GET.get("site", "")
    kind = request.GET.get("type", "")
    if site_id:
        events = events.filter(site=get_object_or_404(Site.objects, pk=site_id))
    if kind:
        events = events.filter(type__startswith=kind)
    page = Paginator(events, 50).get_page(request.GET.get("page"))
    context = {
        "page": page,
        "sites": Site.objects.all(),
        "selected_site": site_id,
        "selected_type": kind,
        "type_choices": [
            ("", "All"),
            ("attendance", "Clock in and out"),
            ("door", "Door alerts"),
            ("access", "Access"),
        ],
    }
    return render(request, "gateways/event_list.html", context)
