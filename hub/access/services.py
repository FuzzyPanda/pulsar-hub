"""Access groups, and the state each site's gateway should be in."""

import hashlib
import json

from django.core.exceptions import ValidationError
from django.db import transaction
from django.utils import timezone

from hub.access.models import (
    AccessGroup,
    AccessGroupExclusion,
    AccessGroupMember,
    AccessGroupPosition,
    AccessGroupSite,
)
from hub.audit import services as audit
from hub.audit.models import AuditEvent
from hub.directory.models import Person, Site
from hub.directory.services import plain_text
from hub.organisations.context import require_organisation
from hub.organisations.models import Organisation, Role
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
    lock_access()
    data = {"people": group.memberships.count(), "sites": group.site_links.count()}
    name, pk = group.name, group.pk
    AccessGroupMember.objects.filter(access_group=group).delete()
    AccessGroupSite.objects.filter(access_group=group).delete()
    AccessGroupPosition.objects.filter(access_group=group).delete()
    AccessGroupExclusion.objects.filter(access_group=group).delete()
    group.delete()
    _audit(actor, "access.group_deleted", request=request, target_label=name, data={**data, "group_id": str(pk)})


def lock_access() -> None:
    """One writer at a time, per organisation, for anything that decides who is in a group.

    Memberships are worked out from two things that change independently: the positions on each
    person (a directory snapshot) and the positions each group names (the console). Two
    transactions that each change one of them would each work memberships out from a state that
    does not include the other's change, and leave someone in a group with nothing behind it, or
    out of one they should be in. Every such change takes this lock first, so each sees what the
    one before it committed. It is taken before any other row lock, always in that order.

    `no_key` so that it does not hold up unrelated work: any row inserted for the organisation
    (a door event, an audit line) takes a key-share lock on this same row.
    """
    Organisation.objects.select_for_update(no_key=True).get(pk=require_organisation().pk)


def _audit_access(action: str, person: Person, data: dict, *, actor: Actor | None, request=None) -> None:
    if actor is not None:
        _audit(actor, action, request=request, target=person, target_label=person.name, data=data)
    else:
        # Worked out from what another system sent: no person did this.
        audit.record(
            action,
            request=request,
            actor=None,
            actor_kind=AuditEvent.ActorKind.SERVICE,
            target=person,
            target_label=person.name,
            data=data,
        )


@transaction.atomic
def add_person_to_group(group: AccessGroup, person: Person, *, actor: Actor, request=None) -> None:
    """Put `person` in `group` by hand. If a position already put them there, the membership
    becomes a hand-made one, so it outlasts the position; if they were being kept out, they no
    longer are."""
    actor.require_member(Role.MANAGER)
    lock_access()
    AccessGroupExclusion.objects.filter(access_group=group, person=person).delete()
    member, created = AccessGroupMember.objects.get_or_create(access_group=group, person=person)
    kept = not created and member.source == AccessGroupMember.Source.POSITIONS
    if kept:
        member.source = AccessGroupMember.Source.MANUAL
        member.save(update_fields=["source"])
    if created or kept:
        data = {"group": group.name, **({"was": "through a position"} if kept else {})}
        _audit_access("access.granted", person, data, actor=actor, request=request)


@transaction.atomic
def remove_person_from_group(group: AccessGroup, person: Person, *, actor: Actor, request=None) -> bool:
    """Take `person` out of `group`. Returns True if they are still in it afterwards.

    A hand-made membership is deleted. If one of the group's positions then puts the person back,
    they are still a member (through the position), and removing them again keeps them out.

    A membership that comes from a position is ended by recording that the person is **kept out**
    of this group (`AccessGroupExclusion`): the positions then leave them alone until someone
    allows them again. Without that, nobody here could take one person's access away while their
    positions are managed in another product.
    """
    actor.require_member(Role.MANAGER)
    lock_access()
    member = AccessGroupMember.objects.filter(access_group=group, person=person).first()
    if member is None:
        return False
    through_position = member.source == AccessGroupMember.Source.POSITIONS
    member.delete()
    if through_position:
        AccessGroupExclusion.objects.get_or_create(
            access_group=group, person=person, defaults={"created_by": actor.user}
        )
        data = {"group": group.name, "was": "through a position", "kept_out": True}
        _audit_access("access.removed", person, data, actor=actor, request=request)
        return False
    _audit_access("access.removed", person, {"group": group.name}, actor=actor, request=request)
    sync_position_memberships(actor=actor, request=request)
    return AccessGroupMember.objects.filter(access_group=group, person=person).exists()


@transaction.atomic
def allow_person_in_group(group: AccessGroup, person: Person, *, actor: Actor, request=None) -> bool:
    """Stop keeping `person` out of `group`. They rejoin it at once if a position gives it to
    them; returns whether they did. Granting, like adding by hand, so a Manager may."""
    actor.require_member(Role.MANAGER)
    lock_access()
    deleted, _ = AccessGroupExclusion.objects.filter(access_group=group, person=person).delete()
    if deleted:
        _audit_access("access.kept_out_ended", person, {"group": group.name}, actor=actor, request=request)
    sync_position_memberships(actor=actor, request=request)
    return AccessGroupMember.objects.filter(access_group=group, person=person).exists()


# --- positions that give a group ------------------------------------------------------------------

MAX_POSITIONS_PER_GROUP = 50


def position_key(name) -> str:
    """How two spellings of a position are compared: as plain text, ignoring case."""
    return plain_text(name, 60).casefold()


@transaction.atomic
def sync_position_memberships(*, actor: Actor | None = None, request=None) -> dict:
    """Make the memberships that come from positions equal to what the positions say, for the
    whole organisation. Returns how many were added and removed.

    A person holds a group through a position when they are active, the group names a position
    they have, and nobody is keeping them out of that group. Only memberships whose source is
    `positions` are created or deleted here. One made by hand is never touched: if a position
    would also give it, nothing is added, and if the position goes, the hand-made membership stays.

    It takes the organisation's access lock and reads everything after it, so it is correct
    whatever ran just before, and it is safe to run at any time and any number of times. Each
    membership it adds or removes is audited as an access change of that person (rule 7); `actor`
    is the person whose change led to it, or None when it follows from what another system sent.
    """
    lock_access()
    groups = {group.pk: group for group in AccessGroup.objects.all()}
    groups_by_key: dict[str, set] = {}
    for group_id, key in AccessGroupPosition.objects.values_list("access_group_id", "position_key"):
        groups_by_key.setdefault(key, set()).add(group_id)
    kept_out = set(AccessGroupExclusion.objects.values_list("access_group_id", "person_id"))
    wanted = set()
    if groups_by_key:
        holders = Person.objects.filter(status=Person.Status.ACTIVE).exclude(positions=[])
        for person_id, positions in holders.values_list("pk", "positions"):
            for name in positions if isinstance(positions, list) else []:
                for group_id in groups_by_key.get(position_key(name), ()):
                    wanted.add((group_id, person_id))
    wanted -= kept_out
    derived, manual = {}, set()
    for pk, group_id, person_id, source in AccessGroupMember.objects.values_list(
        "pk", "access_group_id", "person_id", "source"
    ):
        if source == AccessGroupMember.Source.POSITIONS:
            derived[(group_id, person_id)] = pk
        else:
            manual.add((group_id, person_id))
    stale = sorted((pair for pair in derived if pair not in wanted), key=str)
    missing = sorted(wanted - derived.keys() - manual, key=str)
    if not stale and not missing:
        return {"added": 0, "removed": 0}

    people = {p.pk: p for p in Person.objects.filter(pk__in={person_id for _g, person_id in [*stale, *missing]})}
    if stale:
        AccessGroupMember.objects.filter(pk__in=[derived[pair] for pair in stale]).delete()
    # The related rows are attached, not just their ids, so that the check that a row stays inside
    # its organisation reads them from memory: one insert for all of them, however many there are.
    AccessGroupMember.objects.bulk_create(
        [
            AccessGroupMember(
                access_group=groups[group_id], person=people[person_id], source=AccessGroupMember.Source.POSITIONS
            )
            for group_id, person_id in missing
        ]
    )
    rows = [
        {
            "action": action,
            "target": people[person_id],
            "target_label": people[person_id].name,
            "data": {"group": groups[group_id].name, "through": "position"},
        }
        for action, pairs in (("access.removed", stale), ("access.granted", missing))
        for group_id, person_id in pairs
    ]
    if actor is None:
        # Worked out from what another system sent: no person did this.
        audit.record_many(rows, request=request, actor=None, actor_kind=AuditEvent.ActorKind.SERVICE)
    else:
        operator = actor.is_operator and actor.membership is None
        kind = AuditEvent.ActorKind.OPERATOR if operator else AuditEvent.ActorKind.USER
        audit.record_many(rows, request=request, actor=actor.user, actor_kind=kind)
    return {"added": len(missing), "removed": len(stale)}


@transaction.atomic
def set_group_positions(group: AccessGroup, positions: list[str], *, actor: Actor, request=None) -> dict:
    """The job positions that put a person in `group`: the whole list, replacing the one before.

    Everyone who holds one of them joins the group at once, and so can enter every site the group
    opens on each gateway's next pull. That is why it is an Admin's change, like the group's sites.
    """
    actor.require_member(Role.ADMIN)
    lock_access()
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
    if added or removed:
        _audit(
            actor,
            "access.group_positions_changed",
            request=request,
            target=group,
            target_label=group.name,
            data={"added": added, "removed": removed},
        )
    return sync_position_memberships(actor=actor, request=request)


@transaction.atomic
def detach_positions() -> dict:
    """Stop positions deciding anything, keeping every door as it is: each membership that came
    from a position becomes a hand-made one, and every person's positions are cleared.

    For when an organisation's people stop coming from Pulsar Rostering. Nothing in the hub edits a
    person's positions, so left alone they would be frozen, and the access they give could never
    be changed for one person. The caller audits.
    """
    lock_access()
    kept = AccessGroupMember.objects.filter(source=AccessGroupMember.Source.POSITIONS).update(
        source=AccessGroupMember.Source.MANUAL
    )
    cleared = Person.objects.exclude(positions=[]).update(positions=[])
    AccessGroupExclusion.objects.all().delete()
    return {"memberships_kept_as_hand_made": kept, "people_cleared_of_positions": cleared}


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
