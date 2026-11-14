"""Console pages for people and sites. Thin: reads through the scoped managers, writes through services."""

from django.contrib import messages
from django.core.exceptions import PermissionDenied, ValidationError
from django.core.paginator import Paginator
from django.shortcuts import get_object_or_404, redirect, render
from django.views.decorators.http import require_GET, require_POST

from hub.access.models import AccessGroup, AccessGroupMember
from hub.accounts.stepup import step_up_required
from hub.directory import services
from hub.directory.models import Person, Site
from hub.gateways import services as gateways
from hub.gateways.models import Gateway, GatewayEvent
from hub.gateways.views import site_sync_status
from hub.organisations.models import Organisation, Role
from hub.organisations.services import Actor
from hub.organisations.views import _flash_errors, role_required
from hub.products.addresses import resolve_address

ERRORS = (ValidationError, PermissionDenied, ValueError)


def _hub_owned(request) -> bool:
    return request.organisation.directory_source == Organisation.DirectorySource.HUB


# --- sites ----------------------------------------------------------------------------------------


@require_GET
@role_required(Role.MANAGER)
def site_list(request, org_slug: str):
    actor = Actor.from_request(request)
    live = {g.site_id: g for g in Gateway.objects.live()}
    rows = [{"site": site, "gateway": live.get(site.pk)} for site in Site.objects.all()]
    context = {"rows": rows, "hub_owned": _hub_owned(request), "can_edit": actor.is_member_with(Role.ADMIN)}
    return render(request, "directory/site_list.html", context)


@require_POST
@role_required(Role.ADMIN)
def site_create(request, org_slug: str):
    try:
        site = services.create_site(
            actor=Actor.from_request(request),
            name=request.POST.get("name", ""),
            address=request.POST.get("address", ""),
            timezone_name=request.POST.get("timezone", ""),
            request=request,
        )
    except ERRORS as exc:
        _flash_errors(request, exc)
        return redirect("site_list", org_slug=org_slug)
    return redirect("site_detail", org_slug=org_slug, site_id=site.pk)


@require_GET
@role_required(Role.MANAGER)
def site_detail(request, org_slug: str, site_id):
    site = get_object_or_404(Site.objects, pk=site_id)
    actor = Actor.from_request(request)
    gateway = Gateway.objects.live().filter(site=site).first()
    context = {
        "site": site,
        "gateway": gateway,
        "sync": site_sync_status(site, gateway),
        "groups": AccessGroup.objects.filter(site_links__site=site),
        "on_site": gateways.people_on_site(site),
        "doors": (gateway.state or {}).get("doors", []) if gateway else [],
        "health": (gateway.state or {}).get("health", {}) if gateway else {},
        # The gateway's own console, as a link for the person's browser. Empty when none is set.
        "console_url": resolve_address(gateway.console_address, host="") if gateway else "",
        "recent_events": GatewayEvent.objects.filter(site=site).select_related("person")[:25],
        "hub_owned": _hub_owned(request),
        "can_edit": actor.is_member_with(Role.ADMIN),
        # The one-time pairing code, once, straight after it was made.
        "new_pairing_code": _pop_pairing_code(request, site),
    }
    return render(request, "directory/site_detail.html", context)


def _pop_pairing_code(request, site):
    from django.utils.dateparse import parse_datetime

    from hub.gateways.views import NEW_PAIRING_CODE_KEY

    held = request.session.get(NEW_PAIRING_CODE_KEY)
    if held and held.get("site") == str(site.pk):
        del request.session[NEW_PAIRING_CODE_KEY]
        return {"code": held["code"], "expires_at": parse_datetime(held["expires_at"])}
    return None


@require_POST
@role_required(Role.ADMIN)
def site_update(request, org_slug: str, site_id):
    site = get_object_or_404(Site.objects, pk=site_id)
    try:
        services.update_site(
            site,
            actor=Actor.from_request(request),
            name=request.POST.get("name", ""),
            address=request.POST.get("address", ""),
            timezone_name=request.POST.get("timezone", ""),
            request=request,
        )
    except ERRORS as exc:
        _flash_errors(request, exc)
    else:
        messages.success(request, "Saved.")
    return redirect("site_detail", org_slug=org_slug, site_id=site.pk)


@require_POST
@role_required(Role.ADMIN)
@step_up_required
def site_access_mode(request, org_slug: str, site_id):
    site = get_object_or_404(Site.objects, pk=site_id)
    try:
        services.set_access_managed_elsewhere(
            site, actor=Actor.from_request(request), elsewhere=request.POST.get("elsewhere") == "on", request=request
        )
    except ERRORS as exc:
        _flash_errors(request, exc)
    else:
        messages.success(request, "Saved.")
    return redirect("site_detail", org_slug=org_slug, site_id=site.pk)


# --- people ---------------------------------------------------------------------------------------


@require_GET
@role_required(Role.MANAGER)
def person_list(request, org_slug: str):
    people = Person.objects.all()
    status = request.GET.get("status", "active")
    if status in Person.Status.values:
        people = people.filter(status=status)
    query = request.GET.get("q", "").strip()
    if query:
        people = people.filter(name__icontains=query)
    page = Paginator(people, 50).get_page(request.GET.get("page"))
    context = {"page": page, "status": status, "query": query, "hub_owned": _hub_owned(request)}
    return render(request, "directory/person_list.html", context)


@require_POST
@role_required(Role.MANAGER)
def person_create(request, org_slug: str):
    try:
        person = services.create_person(
            actor=Actor.from_request(request),
            name=request.POST.get("name", ""),
            work_email=request.POST.get("work_email", ""),
            request=request,
        )
    except ERRORS as exc:
        _flash_errors(request, exc)
        return redirect("person_list", org_slug=org_slug)
    return redirect("person_detail", org_slug=org_slug, person_id=person.pk)


@require_GET
@role_required(Role.MANAGER)
def person_detail(request, org_slug: str, person_id):
    person = get_object_or_404(Person.objects, pk=person_id)
    memberships = AccessGroupMember.objects.filter(person=person).select_related("access_group")
    in_groups = [m.access_group for m in memberships]
    sites = Site.objects.filter(access_group_links__access_group__in=in_groups).distinct()
    live = {g.site_id: g for g in Gateway.objects.live().filter(site__in=sites)}
    context = {
        "person": person,
        "groups": in_groups,
        "memberships": memberships,
        "other_groups": AccessGroup.objects.exclude(pk__in=[g.pk for g in in_groups]),
        "site_rows": [{"site": site, "sync": site_sync_status(site, live.get(site.pk))} for site in sites],
        "recent_events": GatewayEvent.objects.filter(person=person).select_related("site")[:25],
        "hub_owned": _hub_owned(request),
    }
    return render(request, "directory/person_detail.html", context)


@require_POST
@role_required(Role.MANAGER)
def person_update(request, org_slug: str, person_id):
    person = get_object_or_404(Person.objects, pk=person_id)
    try:
        services.update_person(
            person,
            actor=Actor.from_request(request),
            name=request.POST.get("name", ""),
            work_email=request.POST.get("work_email", ""),
            request=request,
        )
    except ERRORS as exc:
        _flash_errors(request, exc)
    else:
        messages.success(request, "Saved.")
    return redirect("person_detail", org_slug=org_slug, person_id=person.pk)


@require_POST
@role_required(Role.MANAGER)
def person_end(request, org_slug: str, person_id):
    """Ending someone is never held up by a second-factor prompt: removing access must be quick."""
    person = get_object_or_404(Person.objects, pk=person_id)
    try:
        services.end_person(person, actor=Actor.from_request(request), request=request)
    except ERRORS as exc:
        _flash_errors(request, exc)
    else:
        messages.success(request, f"{person.name} has been ended. Each site removes their access on its next sync.")
    return redirect("person_detail", org_slug=org_slug, person_id=person.pk)


@require_POST
@role_required(Role.MANAGER)
@step_up_required
def person_reactivate(request, org_slug: str, person_id):
    person = get_object_or_404(Person.objects, pk=person_id)
    try:
        services.reactivate_person(person, actor=Actor.from_request(request), request=request)
    except ERRORS as exc:
        _flash_errors(request, exc)
    else:
        messages.success(request, f"{person.name} is active again.")
    return redirect("person_detail", org_slug=org_slug, person_id=person.pk)
