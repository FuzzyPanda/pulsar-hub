"""Console pages for access groups."""

from django.contrib import messages
from django.core.exceptions import PermissionDenied, ValidationError
from django.db.models import Count
from django.shortcuts import get_object_or_404, redirect, render
from django.views.decorators.http import require_GET, require_POST

from hub.access import services
from hub.access.models import AccessGroup, AccessGroupMember, AccessGroupPosition
from hub.accounts.stepup import step_up_required
from hub.directory.models import Person, Site
from hub.organisations.models import Role
from hub.organisations.services import Actor
from hub.organisations.views import _flash_errors, role_required

ERRORS = (ValidationError, PermissionDenied, ValueError)


@require_GET
@role_required(Role.MANAGER)
def group_list(request, org_slug: str):
    groups = AccessGroup.objects.annotate(
        people_count=Count("memberships", distinct=True), site_count=Count("site_links", distinct=True)
    )
    can_edit = Actor.from_request(request).is_member_with(Role.ADMIN)
    return render(request, "access/group_list.html", {"groups": groups, "can_edit": can_edit})


@require_POST
@role_required(Role.ADMIN)
def group_create(request, org_slug: str):
    try:
        group = services.create_group(
            actor=Actor.from_request(request),
            name=request.POST.get("name", ""),
            description=request.POST.get("description", ""),
            request=request,
        )
    except ERRORS as exc:
        _flash_errors(request, exc)
        return redirect("group_list", org_slug=org_slug)
    return redirect("group_detail", org_slug=org_slug, group_id=group.pk)


@require_GET
@role_required(Role.MANAGER)
def group_detail(request, org_slug: str, group_id):
    group = get_object_or_404(AccessGroup.objects, pk=group_id)
    actor = Actor.from_request(request)
    members = AccessGroupMember.objects.filter(access_group=group).select_related("person").order_by("person__name")
    member_ids = [m.person_id for m in members]
    site_ids = set(group.site_links.values_list("site_id", flat=True))
    # Positions the group names, and the others people currently hold, to tick.
    named = {link.position_key: link.position for link in AccessGroupPosition.objects.filter(access_group=group)}
    held: dict[str, str] = {}
    for positions in Person.objects.exclude(positions=[]).values_list("positions", flat=True):
        for name in positions:
            held.setdefault(services.position_key(name), name)
    context = {
        "group": group,
        "members": members,
        "position_rows": [
            {"name": name, "included": key in named}
            for key, name in sorted({**held, **named}.items(), key=lambda item: item[1].casefold())
        ],
        "candidates": Person.objects.filter(status=Person.Status.ACTIVE).exclude(pk__in=member_ids),
        "site_rows": [
            {"site": site, "included": site.pk in site_ids}
            for site in Site.objects.filter(is_active=True, access_managed_elsewhere=False)
        ],
        "can_edit": actor.is_member_with(Role.ADMIN),
        "can_assign": actor.is_member_with(Role.MANAGER),
    }
    return render(request, "access/group_detail.html", context)


@require_POST
@role_required(Role.ADMIN)
def group_update(request, org_slug: str, group_id):
    group = get_object_or_404(AccessGroup.objects, pk=group_id)
    try:
        services.rename_group(
            group,
            actor=Actor.from_request(request),
            name=request.POST.get("name", ""),
            description=request.POST.get("description", ""),
            request=request,
        )
    except ERRORS as exc:
        _flash_errors(request, exc)
    else:
        messages.success(request, "Saved.")
    return redirect("group_detail", org_slug=org_slug, group_id=group.pk)


@require_POST
@role_required(Role.ADMIN)
@step_up_required
def group_delete(request, org_slug: str, group_id):
    group = get_object_or_404(AccessGroup.objects, pk=group_id)
    try:
        services.delete_group(group, actor=Actor.from_request(request), request=request)
    except ERRORS as exc:
        _flash_errors(request, exc)
        return redirect("group_detail", org_slug=org_slug, group_id=group_id)
    messages.success(request, "Access group deleted.")
    return redirect("group_list", org_slug=org_slug)


@require_POST
@role_required(Role.ADMIN)
@step_up_required
def group_sites(request, org_slug: str, group_id):
    """Which sites the group opens. A change here can open doors at a site, hence the step-up."""
    group = get_object_or_404(AccessGroup.objects, pk=group_id)
    try:
        wanted = list(Site.objects.filter(pk__in=request.POST.getlist("sites")))
        services.set_group_sites(group, wanted, actor=Actor.from_request(request), request=request)
    except ERRORS as exc:
        _flash_errors(request, exc)
    else:
        messages.success(request, "Saved. Each site applies the change on its next sync.")
    return redirect("group_detail", org_slug=org_slug, group_id=group.pk)


@require_POST
@role_required(Role.ADMIN)
@step_up_required
def group_positions(request, org_slug: str, group_id):
    """Which job positions put a person in the group. Everyone who holds one joins it at once, so
    like the group's sites this can open doors, hence the step-up."""
    group = get_object_or_404(AccessGroup.objects, pk=group_id)
    try:
        wanted = [*request.POST.getlist("positions"), request.POST.get("new_position", "")]
        changed = services.set_group_positions(group, wanted, actor=Actor.from_request(request), request=request)
    except ERRORS as exc:
        _flash_errors(request, exc)
    else:
        messages.success(
            request,
            f"Saved. {changed['added']} added to the group and {changed['removed']} removed by their position. "
            "Each site applies the change on its next sync.",
        )
    return redirect("group_detail", org_slug=org_slug, group_id=group.pk)


@require_POST
@role_required(Role.MANAGER)
def group_member_add(request, org_slug: str, group_id):
    group = get_object_or_404(AccessGroup.objects, pk=group_id)
    person = get_object_or_404(Person.objects, pk=request.POST.get("person") or None)
    try:
        services.add_person_to_group(group, person, actor=Actor.from_request(request), request=request)
    except ERRORS as exc:
        _flash_errors(request, exc)
    return _back(request, org_slug, group, person)


@require_POST
@role_required(Role.MANAGER)
def group_member_remove(request, org_slug: str, group_id):
    group = get_object_or_404(AccessGroup.objects, pk=group_id)
    person = get_object_or_404(Person.objects, pk=request.POST.get("person") or None)
    try:
        still = services.remove_person_from_group(group, person, actor=Actor.from_request(request), request=request)
    except ERRORS as exc:
        _flash_errors(request, exc)
    else:
        if still:
            messages.info(request, f"{person.name} is still in {group.name} through a job position.")
    return _back(request, org_slug, group, person)


def _back(request, org_slug, group, person):
    """Return to whichever page the form was on: the group's, or the person's."""
    if request.POST.get("return") == "person":
        return redirect("person_detail", org_slug=org_slug, person_id=person.pk)
    return redirect("group_detail", org_slug=org_slug, group_id=group.pk)
