"""Access groups, and the state each site's gateway should be in."""

import hashlib
import json

from django.core.exceptions import ValidationError
from django.db import transaction
from django.utils import timezone

from hub.access.models import AccessGroup, AccessGroupMember, AccessGroupSite
from hub.directory.models import Person, Site
from hub.organisations.context import require_organisation
from hub.organisations.models import Role
from hub.organisations.services import Actor, _audit


def _clean_group_name(name: str) -> str:
    name = " ".join((name or "").split())
    if not name:
        raise ValidationError("An access group needs a name.")
    return name[:100]


@transaction.atomic
def create_group(*, actor: Actor, name: str, description: str = "", request=None) -> AccessGroup:
    actor.require_member(Role.ADMIN)
    name = _clean_group_name(name)
    if AccessGroup.objects.filter(name__iexact=name).exists():
        raise ValidationError("There is already an access group with that name.")
    group = AccessGroup.objects.create(name=name, description=(description or "").strip()[:255])
    _audit(actor, "access.group_created", request=request, target=group, target_label=group.name)
    return group


@transaction.atomic
def rename_group(group: AccessGroup, *, actor: Actor, name: str, description: str = "", request=None) -> None:
    """Renaming matters on site: a gateway maps group names to its own access levels, so a renamed
    group has no effect at a site until someone maps the new name there."""
    actor.require_member(Role.ADMIN)
    name = _clean_group_name(name)
    if AccessGroup.objects.filter(name__iexact=name).exclude(pk=group.pk).exists():
        raise ValidationError("There is already an access group with that name.")
    old = group.name
    group.name, group.description = name, (description or "").strip()[:255]
    group.save(update_fields=["name", "description", "updated_at"])
    _audit(actor, "access.group_renamed", request=request, target=group, target_label=name, data={"from": old})


@transaction.atomic
def delete_group(group: AccessGroup, *, actor: Actor, request=None) -> None:
    actor.require_member(Role.ADMIN)
    data = {"people": group.memberships.count(), "sites": group.site_links.count()}
    name, pk = group.name, group.pk
    AccessGroupMember.objects.filter(access_group=group).delete()
    AccessGroupSite.objects.filter(access_group=group).delete()
    group.delete()
    _audit(actor, "access.group_deleted", request=request, target_label=name, data={**data, "group_id": str(pk)})


@transaction.atomic
def add_person_to_group(group: AccessGroup, person: Person, *, actor: Actor, request=None) -> None:
    actor.require_member(Role.MANAGER)
    _member, created = AccessGroupMember.objects.get_or_create(access_group=group, person=person)
    if created:
        _audit(
            actor,
            "access.granted",
            request=request,
            target=person,
            target_label=person.name,
            data={"group": group.name},
        )


@transaction.atomic
def remove_person_from_group(group: AccessGroup, person: Person, *, actor: Actor, request=None) -> None:
    actor.require_member(Role.MANAGER)
    deleted, _ = AccessGroupMember.objects.filter(access_group=group, person=person).delete()
    if deleted:
        _audit(
            actor,
            "access.removed",
            request=request,
            target=person,
            target_label=person.name,
            data={"group": group.name},
        )


@transaction.atomic
def set_group_sites(group: AccessGroup, sites: list[Site], *, actor: Actor, request=None) -> None:
    actor.require_member(Role.ADMIN)
    for site in sites:
        if site.access_managed_elsewhere:
            raise ValidationError(f"{site.name} has its doors managed by another system.")
    wanted = {site.pk: site for site in sites}
    current = {link.site_id: link for link in AccessGroupSite.objects.filter(access_group=group)}
    added = [wanted[pk].name for pk in wanted.keys() - current.keys()]
    removed_ids = current.keys() - wanted.keys()
    removed = list(Site.objects.filter(pk__in=removed_ids).values_list("name", flat=True))
    for pk in wanted.keys() - current.keys():
        AccessGroupSite.objects.create(access_group=group, site=wanted[pk])
    AccessGroupSite.objects.filter(access_group=group, site_id__in=removed_ids).delete()
    if added or removed:
        _audit(
            actor,
            "access.group_sites_changed",
            request=request,
            target=group,
            target_label=group.name,
            data={"added": sorted(added), "removed": sorted(removed)},
        )


# --- what a site's gateway should hold ------------------------------------------------------------


def desired_access(site: Site) -> dict:
    """The complete state `site`'s gateway should be in. See docs/CONTRACTS.md, "Desired access".

    Everyone who belongs to a group that includes this site is listed, with the names of those
    groups. An ended person stays listed with `active: false` for as long as they are in such a
    group, so the gateway is told outright. A gateway must also treat anyone it holds from the hub
    who is *not* listed as inactive: absence is removal.

    `version` is a digest of the content. It changes when, and only when, what the gateway must
    hold changes, so an unchanged poll costs the gateway nothing and a restart on either side
    converges without replay (rule 4).
    """
    organisation = require_organisation()
    groups_here = list(AccessGroup.objects.filter(site_links__site=site).order_by("name").values_list("pk", "name"))
    names = dict(groups_here)
    people: dict = {}
    memberships = (
        AccessGroupMember.objects.filter(access_group_id__in=names.keys())
        .select_related("person")
        .order_by("person_id", "access_group__name")
    )
    for membership in memberships:
        person = membership.person
        entry = people.setdefault(
            person.pk,
            {"person_ref": str(person.pk), "name": person.name, "active": person.is_active, "access_groups": []},
        )
        entry["access_groups"].append(names[membership.access_group_id])
    people_list = sorted(people.values(), key=lambda p: p["person_ref"])
    for entry in people_list:
        entry["access_groups"].sort()
    body = {
        "org_ref": str(organisation.pk),
        "site_ref": str(site.pk),
        "access_groups": [name for _pk, name in groups_here],
        "people": people_list,
    }
    version = hashlib.sha256(json.dumps(body, sort_keys=True, separators=(",", ":")).encode()).hexdigest()[:32]
    return {**body, "version": version, "generated_at": timezone.now().strftime("%Y-%m-%dT%H:%M:%SZ")}
