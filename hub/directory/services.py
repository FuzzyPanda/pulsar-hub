"""Changes to people and sites.

Where an organisation's directory comes from Pulsar Rostering (decision D3), only
`apply_rostering_snapshot` may change it; the hub's own console and API refuse. One direction per
organisation, never both.
"""

import unicodedata
import uuid

from django.core.exceptions import PermissionDenied, ValidationError
from django.db import IntegrityError, transaction
from django.utils import timezone

from hub.audit import services as audit
from hub.audit.models import AuditEvent
from hub.directory.models import Person, Site, validate_timezone
from hub.organisations.context import require_organisation
from hub.organisations.models import Organisation, Role
from hub.organisations.services import Actor, _audit


def _require_hub_owned() -> Organisation:
    organisation = require_organisation()
    if organisation.directory_source != Organisation.DirectorySource.HUB:
        raise PermissionDenied("People and sites for this organisation are managed in Pulsar Rostering.")
    return organisation


def plain_text(value, limit: int) -> str:
    """One line of visible text: control characters and runs of white space become single spaces.

    A gateway refuses a whole access snapshot if any name in it carries a control character or
    stray white space, and a refused snapshot means no change reaches that site, removals
    included. So names are made plain when they are stored, and again when they are sent.
    """
    text = "".join(" " if (ch.isspace() or unicodedata.category(ch).startswith("C")) else ch for ch in str(value or ""))
    return " ".join(text.split())[:limit].strip()


def _clean_name(name: str, what: str) -> str:
    name = plain_text(name, 200)
    if not name:
        raise ValidationError(f"{what} needs a name.")
    return name


# --- sites ----------------------------------------------------------------------------------------


@transaction.atomic
def create_site(*, actor: Actor, name: str, address: str = "", timezone_name: str = "", request=None) -> Site:
    actor.require_member(Role.ADMIN)
    _require_hub_owned()
    site = Site(name=_clean_name(name, "A site"), address=(address or "").strip()[:300])
    if timezone_name:
        validate_timezone(timezone_name)
        site.timezone = timezone_name
    site.save()
    _audit(actor, "directory.site_created", request=request, target=site, target_label=site.name)
    return site


@transaction.atomic
def update_site(site: Site, *, actor: Actor, name: str, address: str, timezone_name: str, request=None) -> None:
    actor.require_member(Role.ADMIN)
    _require_hub_owned()
    validate_timezone(timezone_name)
    site.name, site.address, site.timezone = _clean_name(name, "A site"), (address or "").strip()[:300], timezone_name
    site.save(update_fields=["name", "address", "timezone", "updated_at"])
    _audit(actor, "directory.site_updated", request=request, target=site, target_label=site.name)


@transaction.atomic
def set_access_managed_elsewhere(site: Site, *, actor: Actor, elsewhere: bool, request=None) -> None:
    """Mark a site whose doors another system runs (a PerfectGym site). This is the hub's own
    setting, whatever the directory source: it decides whether the hub's access features apply."""
    from hub.gateways.models import Gateway

    actor.require_member(Role.ADMIN)
    if elsewhere and Gateway.objects.live().filter(site=site).exists():
        raise ValidationError("Revoke this site's gateway first.")
    if site.access_managed_elsewhere != elsewhere:
        site.access_managed_elsewhere = elsewhere
        site.save(update_fields=["access_managed_elsewhere", "updated_at"])
        _audit(
            actor,
            "directory.site_access_mode_changed",
            request=request,
            target=site,
            target_label=site.name,
            data={"access_managed_elsewhere": elsewhere},
        )


# --- people ---------------------------------------------------------------------------------------


@transaction.atomic
def create_person(*, actor: Actor, name: str, work_email: str = "", request=None) -> Person:
    actor.require_member(Role.MANAGER)
    _require_hub_owned()
    person = Person.objects.create(name=_clean_name(name, "A person"), work_email=(work_email or "").strip().lower())
    _audit(actor, "directory.person_created", request=request, target=person, target_label=person.name)
    return person


@transaction.atomic
def update_person(person: Person, *, actor: Actor, name: str, work_email: str, request=None) -> None:
    actor.require_member(Role.MANAGER)
    _require_hub_owned()
    person.name, person.work_email = _clean_name(name, "A person"), (work_email or "").strip().lower()
    person.save(update_fields=["name", "work_email", "updated_at"])
    _audit(actor, "directory.person_updated", request=request, target=person, target_label=person.name)


@transaction.atomic
def end_person(person: Person, *, actor: Actor, request=None) -> None:
    """End someone. Their access is removed at every site on each gateway's next pull; the hub
    shows each site as unconfirmed until its gateway acknowledges (PLAN H3)."""
    actor.require_member(Role.MANAGER)
    _require_hub_owned()
    if person.status == Person.Status.ENDED:
        return
    person.status, person.ended_at = Person.Status.ENDED, timezone.now()
    person.save(update_fields=["status", "ended_at", "updated_at"])
    _audit(actor, "access.person_ended", request=request, target=person, target_label=person.name)


@transaction.atomic
def reactivate_person(person: Person, *, actor: Actor, request=None) -> None:
    actor.require_member(Role.MANAGER)
    _require_hub_owned()
    if person.status == Person.Status.ACTIVE:
        return
    person.status, person.ended_at = Person.Status.ACTIVE, None
    person.save(update_fields=["status", "ended_at", "updated_at"])
    _audit(actor, "access.person_reactivated", request=request, target=person, target_label=person.name)


# --- the copy Pulsar Rostering sends ---------------------------------------------------------------

MAX_SNAPSHOT_ROWS = 20000


def _as_uuid(value, what: str) -> uuid.UUID:
    try:
        return uuid.UUID(str(value))
    except (ValueError, AttributeError, TypeError) as exc:
        raise ValidationError(f"{what} is not a UUID.") from exc


def _insert(row) -> None:
    """Insert a row whose id the sender chose. Never an update: if the id already exists anywhere,
    including in another organisation, this fails and nothing is touched."""
    try:
        with transaction.atomic():
            row.save(force_insert=True)
    except IntegrityError as exc:
        raise ValidationError("A reference in this snapshot is already in use.") from exc


@transaction.atomic
def apply_rostering_snapshot(*, people: list[dict], sites: list[dict], allow_empty: bool = False, token=None) -> dict:
    """Make the hub's people and sites match the full list Pulsar Rostering sent.

    A snapshot, not a list of changes: sending it twice changes nothing (rule 9), and a missed one
    is repaired by the next (rule 4). Rows are never deleted: a person missing from the list is
    ended and a missing site made inactive, so their history and access records stay readable.

    An empty list of people would end everyone, and so remove every person's access at every
    door. That is refused unless the sender says it means it.
    """
    organisation = require_organisation()
    if organisation.directory_source != Organisation.DirectorySource.ROSTERING:
        raise PermissionDenied("This organisation's people and sites are managed in the hub, not sent to it.")
    if len(people) > MAX_SNAPSHOT_ROWS or len(sites) > MAX_SNAPSHOT_ROWS:
        raise ValidationError("The snapshot is too large.")

    # Check every row before anything is written or judged, so that a malformed snapshot is
    # reported as malformed and applied in no part.
    seen_people, seen_sites = set(), set()
    clean_people, clean_sites = [], []
    for row in sites:
        ref = _as_uuid(row.get("site_ref"), "site_ref")
        if ref in seen_sites:
            raise ValidationError("A site_ref appears twice.")
        seen_sites.add(ref)
        tz = row.get("timezone") or "Australia/Melbourne"
        validate_timezone(tz)
        clean_sites.append(
            (
                ref,
                {
                    "name": _clean_name(row.get("name"), "A site"),
                    "address": str(row.get("address") or "").strip()[:300],
                    "timezone": tz,
                    "is_active": bool(row.get("is_active", True)),
                },
            )
        )
    for row in people:
        ref = _as_uuid(row.get("person_ref"), "person_ref")
        if ref in seen_people:
            raise ValidationError("A person_ref appears twice.")
        seen_people.add(ref)
        status = row.get("status", "active")
        if status not in Person.Status.values:
            raise ValidationError("A person's status must be active or ended.")
        clean_people.append(
            (
                ref,
                {
                    "name": _clean_name(row.get("name"), "A person"),
                    "work_email": str(row.get("work_email") or "").strip().lower()[:254],
                    "status": status,
                },
            )
        )

    counts = {"people_created": 0, "people_updated": 0, "people_ended": 0, "sites_created": 0, "sites_updated": 0,
              "sites_deactivated": 0}  # fmt: skip
    existing_people = {p.pk: p for p in Person.objects.select_for_update()}
    existing_sites = {s.pk: s for s in Site.objects.select_for_update()}
    active_before = sum(1 for p in existing_people.values() if p.is_active)
    incoming_active = sum(1 for _ref, values in clean_people if values["status"] == "active")
    if active_before and not incoming_active and not allow_empty:
        raise ValidationError(
            "This snapshot has no active people and would end everyone. Send allow_empty=true if that is intended."
        )

    now = timezone.now()
    for ref, values in clean_sites:
        site = existing_sites.get(ref)
        if site is None:
            _insert(Site(id=ref, **values))
            counts["sites_created"] += 1
        elif any(getattr(site, k) != v for k, v in values.items()):
            for k, v in values.items():
                setattr(site, k, v)
            site.save(update_fields=[*values, "updated_at"])
            counts["sites_updated"] += 1
    for ref, site in existing_sites.items():
        if ref not in seen_sites and site.is_active:
            site.is_active = False
            site.save(update_fields=["is_active", "updated_at"])
            counts["sites_deactivated"] += 1

    for ref, values in clean_people:
        status = values["status"]
        person = existing_people.get(ref)
        if person is None:
            _insert(Person(id=ref, ended_at=now if status == "ended" else None, **values))
            counts["people_created"] += 1
        elif any(getattr(person, k) != v for k, v in values.items()):
            was_active = person.is_active
            for k, v in values.items():
                setattr(person, k, v)
            if was_active and status == "ended":
                person.ended_at = now
                counts["people_ended"] += 1
            elif not was_active and status == "active":
                person.ended_at = None
            person.save(update_fields=[*values, "ended_at", "updated_at"])
            counts["people_updated"] += 1
    for ref, person in existing_people.items():
        if ref not in seen_people and person.is_active:
            person.status, person.ended_at = Person.Status.ENDED, now
            person.save(update_fields=["status", "ended_at", "updated_at"])
            counts["people_ended"] += 1

    if any(counts.values()):
        # One event per snapshot that changed something, not one per row: an unchanged snapshot
        # arrives every minute and must leave no trace.
        audit.record(
            "directory.snapshot_applied",
            actor=None,
            actor_kind=AuditEvent.ActorKind.SERVICE,
            target=token,
            target_label=getattr(token, "name", "") or "",
            data=counts,
        )
    return counts
