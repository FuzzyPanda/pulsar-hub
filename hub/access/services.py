"""Access groups, and the state each site's gateway should be in."""

import hashlib
import json

from django.core.exceptions import ValidationError
from django.db import transaction
from django.utils import timezone

from hub.access.models import AccessGroup, AccessGroupMember, AccessGroupPosition, AccessGroupSite
from hub.directory.models import Person, Site
from hub.directory.services import plain_text
from hub.organisations.context import require_organisation
from hub.organisations.models import Role
from hub.organisations.services import Actor, _audit


def _clean_group_name(name: str) -> str:
    name = plain_text(name, 100)
    if not name:
        raise ValidationError("An access group needs a name.")
    return name


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
    AccessGroupPosition.objects.filter(access_group=group).delete()
    group.delete()
    _audit(actor, "access.group_deleted", request=request, target_label=name, data={**data, "group_id": str(pk)})


@transaction.atomic
def add_person_to_group(group: AccessGroup, person: Person, *, actor: Actor, request=None) -> None:
    """Put `person` in `group` by hand. If a position already put them there, the membership
    becomes a hand-made one, so it outlasts the position."""
    actor.require_member(Role.MANAGER)
    member, created = AccessGroupMember.objects.get_or_create(access_group=group, person=person)
    kept = not created and member.source == AccessGroupMember.Source.POSITIONS
    if kept:
        member.source = AccessGroupMember.Source.MANUAL
        member.save(update_fields=["source"])
    if created or kept:
        _audit(
            actor,
            "access.granted",
            request=request,
            target=person,
            target_label=person.name,
            data={"group": group.name, **({"was": "from a position"} if kept else {})},
        )


@transaction.atomic
def remove_person_from_group(group: AccessGroup, person: Person, *, actor: Actor, request=None) -> bool:
    """Take a hand-made membership away. Returns True if the person is still in the group
    afterwards, because one of the group's positions puts them there.

    A membership that comes from a position is not removed here: it would be back the next time
    positions are worked out. The way to end it is to change the group's positions, or the
    person's position where it is managed."""
    actor.require_member(Role.MANAGER)
    member = AccessGroupMember.objects.filter(access_group=group, person=person).first()
    if member is None:
        return False
    if member.source == AccessGroupMember.Source.POSITIONS:
        raise ValidationError(
            f"{person.name} is in {group.name} through a job position. Change the group's positions, "
            "or the person's position, to remove them."
        )
    member.delete()
    _audit(
        actor,
        "access.removed",
        request=request,
        target=person,
        target_label=person.name,
        data={"group": group.name},
    )
    sync_position_memberships()
    return AccessGroupMember.objects.filter(access_group=group, person=person).exists()


# --- positions that give a group ------------------------------------------------------------------

MAX_POSITIONS_PER_GROUP = 50


def position_key(name) -> str:
    """How two spellings of a position are compared: as plain text, ignoring case."""
    return plain_text(name, 60).casefold()


def sync_position_memberships() -> dict:
    """Make the memberships that come from positions equal to what the positions say, for the
    whole organisation. Returns how many were added and removed.

    A person holds a group through a position when the group names a position the person has.
    Only memberships whose source is `positions` are created or deleted here. One made by hand is
    never touched: if a position would also give it, nothing is added, and if the position goes,
    the hand-made membership stays. Safe to run at any time and any number of times.

    The caller audits: this runs inside a directory snapshot or a change of a group's positions,
    and that event carries the counts.
    """
    groups_by_key: dict[str, set] = {}
    for group_id, key in AccessGroupPosition.objects.values_list("access_group_id", "position_key"):
        groups_by_key.setdefault(key, set()).add(group_id)
    wanted = set()
    if groups_by_key:
        for person_id, positions in Person.objects.exclude(positions=[]).values_list("pk", "positions"):
            for name in positions if isinstance(positions, list) else []:
                for group_id in groups_by_key.get(position_key(name), ()):
                    wanted.add((group_id, person_id))
    derived, manual = {}, set()
    for pk, group_id, person_id, source in AccessGroupMember.objects.values_list(
        "pk", "access_group_id", "person_id", "source"
    ):
        if source == AccessGroupMember.Source.POSITIONS:
            derived[(group_id, person_id)] = pk
        else:
            manual.add((group_id, person_id))
    stale = [pk for pair, pk in derived.items() if pair not in wanted]
    missing = sorted(wanted - derived.keys() - manual, key=str)
    if stale:
        AccessGroupMember.objects.filter(pk__in=stale).delete()
    for group_id, person_id in missing:
        AccessGroupMember.objects.create(
            access_group_id=group_id, person_id=person_id, source=AccessGroupMember.Source.POSITIONS
        )
    return {"added": len(missing), "removed": len(stale)}


@transaction.atomic
def set_group_positions(group: AccessGroup, positions: list[str], *, actor: Actor, request=None) -> dict:
    """The job positions that put a person in `group`: the whole list, replacing the one before.

    Everyone who holds one of them joins the group at once, and so can enter every site the group
    opens on each gateway's next pull. That is why it is an Admin's change, like the group's sites.
    """
    actor.require_member(Role.ADMIN)
    wanted: dict[str, str] = {}
    for raw in positions:
        name = plain_text(raw, 60)
        if name:
            wanted.setdefault(name.casefold(), name)
    if len(wanted) > MAX_POSITIONS_PER_GROUP:
        raise ValidationError(f"A group can name at most {MAX_POSITIONS_PER_GROUP} positions.")
    current = {link.position_key: link for link in AccessGroupPosition.objects.filter(access_group=group)}
    added = sorted(wanted[key] for key in wanted.keys() - current.keys())
    removed = sorted(current[key].position for key in current.keys() - wanted.keys())
    for key in wanted.keys() - current.keys():
        AccessGroupPosition.objects.create(access_group=group, position=wanted[key], position_key=key)
    AccessGroupPosition.objects.filter(access_group=group, position_key__in=current.keys() - wanted.keys()).delete()
    changed = sync_position_memberships()
    if added or removed:
        _audit(
            actor,
            "access.group_positions_changed",
            request=request,
            target=group,
            target_label=group.name,
            data={
                "added": added,
                "removed": removed,
                "people_added": changed["added"],
                "people_removed": changed["removed"],
            },  # fmt: skip
        )
    return changed


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
    # Names are made plain here as well as when stored: one odd character must never be the
    # reason a gateway refuses the snapshot that would have removed someone's access.
    names = {
        pk: plain_text(name, 100) or "(unnamed group)"
        for pk, name in AccessGroup.objects.filter(site_links__site=site).values_list("pk", "name")
    }
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
            {
                "person_ref": str(person.pk),
                "name": plain_text(person.name, 200) or "(no name)",
                "active": person.is_active,
                "access_groups": [],
            },
        )
        entry["access_groups"].append(names[membership.access_group_id])
    people_list = sorted(people.values(), key=lambda p: p["person_ref"])
    for entry in people_list:
        entry["access_groups"] = sorted(set(entry["access_groups"]))
    body = {
        "org_ref": str(organisation.pk),
        "site_ref": str(site.pk),
        "access_groups": sorted(set(names.values())),
        "people": people_list,
    }
    version = hashlib.sha256(json.dumps(body, sort_keys=True, separators=(",", ":")).encode()).hexdigest()[:32]
    return {**body, "version": version, "generated_at": timezone.now().strftime("%Y-%m-%dT%H:%M:%SZ")}
