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
    person.status, person.ended_at, person.positions = Person.Status.ENDED, timezone.now(), []
    person.save(update_fields=["status", "ended_at", "positions", "updated_at"])
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
# How many refused rows one answer lists. `rejected_count` is always the full number.
MAX_REJECTED_LISTED = 100


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
        raise ValidationError("This reference is already in use.", code="reference_in_use") from exc


def _text(value, what: str) -> str:
    """An optional text field: text, or nothing. A number or a list where text belongs is the
    sender's mistake, and is said so rather than stored as whatever it prints as."""
    if value is None:
        return ""
    if not isinstance(value, str):
        raise ValidationError(f"{what} must be text.")
    return value


def _site_values(row: dict) -> dict:
    tz = _text(row.get("timezone"), "A site's timezone") or "Australia/Melbourne"
    validate_timezone(tz)
    is_active = row.get("is_active", True)
    if not isinstance(is_active, bool):
        raise ValidationError("A site's is_active must be true or false.")
    return {
        "name": _clean_name(_text(row.get("name"), "A site's name"), "A site"),
        "address": _text(row.get("address"), "A site's address").strip()[:300],
        "timezone": tz,
        "is_active": is_active,
    }


MAX_POSITIONS_PER_PERSON = 20


def _positions(value) -> list[str]:
    """A person's job positions as sent: plain names of at most 60 characters, sorted, with blanks
    and repeats (whatever their case) dropped."""
    problem = ValidationError(f"A person's positions must be a list of at most {MAX_POSITIONS_PER_PERSON} names.")
    if not isinstance(value, list) or len(value) > 50 * MAX_POSITIONS_PER_PERSON:
        raise problem
    names: dict[str, str] = {}
    for item in value:
        if not isinstance(item, str):
            raise problem
        name = plain_text(item, 60)
        if name:
            names.setdefault(name.casefold(), name)
    # Counted after blanks and repeats are dropped: the limit is on positions, not on spellings.
    if len(names) > MAX_POSITIONS_PER_PERSON:
        raise problem
    return sorted(names.values())


def _person_values(row: dict) -> dict:
    status = row.get("status", "active")
    if status not in Person.Status.values:
        raise ValidationError("A person's status must be active or ended.")
    values = {
        "name": _clean_name(_text(row.get("name"), "A person's name"), "A person"),
        "work_email": _text(row.get("work_email"), "A person's work_email").strip().lower()[:254],
        "status": status,
    }
    # Only when the sender says something about positions. A row without the key (a sender that
    # does not send positions, or has stopped) leaves the positions the hub holds as they were:
    # silence is not "this person has no position", which would take their access away.
    if "positions" in row:
        values["positions"] = _positions(row["positions"])
    if status == Person.Status.ENDED:
        # Someone who has left holds no position, whatever the row says or leaves unsaid. If
        # they come back, a position has to be sent again before it gives them anything.
        values["positions"] = []
    return values


class _Rows:
    """One list of a snapshot (its people, or its sites), with every row judged alone.

    `valid` maps a reference to the values to store. `removals` are references whose row asks for a
    removal (a person ended, a site made inactive) but is otherwise not acceptable: the removal is
    applied, and nothing else about the row. `named` is every reference the list mentions at all,
    acceptable or not: something the hub holds that is *named* is never treated as missing, so a
    row the hub cannot take leaves its person or site exactly as they were.
    """

    def __init__(self, rows: list[dict], *, key: str, values, is_removal, held: dict, taken: set, removed: str):
        self.key, self.valid, self.removals, self.named, self.rejected = key, {}, set(), set(), []
        refs = []
        for row in rows:
            try:
                refs.append(_as_uuid(row.get(key), key))
            except ValidationError as exc:
                refs.append(None)
                # Echoed as plain text and cut short: it is whatever the sender put there.
                self._reject(plain_text(row.get(key), 64), "invalid_row", exc.messages[0])
        seen, twice = set(), set()
        for ref in refs:
            if ref is not None:
                (twice if ref in seen else seen).add(ref)
        self.named = seen
        for row, ref in zip(rows, refs, strict=True):
            if ref is None:
                continue
            if ref in twice:
                # Neither row is applied (which one is right is not the hub's to guess), and each is
                # listed, so `rejected_count` is the number of rows not taken.
                self._reject(ref, "duplicate_reference", f"This {key} appears more than once in the list.")
                continue
            try:
                if ref not in held and ref in taken:
                    raise ValidationError("This reference is already in use.", code="reference_in_use")
                self.valid[ref] = values(row)
            except ValidationError as exc:
                reason = "; ".join(exc.messages)
                if ref in held and is_removal(row):
                    # The safety-relevant half of a row never waits for the rest of it.
                    self.removals.add(ref)
                    reason = f"{reason} {removed}"
                self._reject(ref, getattr(exc, "code", None) or "invalid_row", reason)

    def _reject(self, ref, code: str, reason: str) -> None:
        self.rejected.append({self.key: str(ref), "code": code, "reason": reason[:200]})


def _refs_held_elsewhere(model, refs: set) -> set:
    """Which of `refs` already name a row of `model` in ANOTHER organisation. A sender mints its
    own references, so one can collide with a row it has no right to; such a row is refused before
    anything is counted or written, and the insert's own constraint catches a race."""
    if not refs:
        return set()
    organisation = require_organisation()
    taken = model.all_organisations.filter(pk__in=refs)  # unscoped: a sender-chosen id may already exist elsewhere
    return set(taken.exclude(organisation=organisation).values_list("pk", flat=True))


@transaction.atomic
def apply_rostering_snapshot(*, people: list[dict], sites: list[dict], allow_empty: bool = False, token=None) -> dict:
    """Make the hub's people and sites match the full list Pulsar Rostering sent.

    A snapshot, not a list of changes: sending it twice changes nothing (rule 9), and a missed one
    is repaired by the next (rule 4). Rows are never deleted: a person missing from the list is
    ended and a missing site made inactive, so their history and access records stay readable.

    **Each row is judged alone** (docs/CONTRACTS.md). A row the hub cannot take is reported in
    `rejected` and every other row is applied, because the rows that end people are how access is
    removed at every door, and one unrelated bad name must not hold them back. A row that is
    refused but names someone the hub holds leaves them exactly as they were: it neither updates
    them nor ends them for being "missing". The one thing applied from a refused row is a removal
    it asks for.

    A list that would leave nobody active would remove every person's access at every door. That
    is refused whole unless the sender says it means it.
    """
    from hub.access.services import lock_access, sync_position_memberships

    organisation = require_organisation()
    if organisation.directory_source != Organisation.DirectorySource.ROSTERING:
        raise PermissionDenied("This organisation's people and sites are managed in the hub, not sent to it.")
    if len(people) > MAX_SNAPSHOT_ROWS or len(sites) > MAX_SNAPSHOT_ROWS:
        raise ValidationError("The snapshot is too large.", code="snapshot_too_large")

    # Before any row is locked: a snapshot can change who is in an access group (positions), and
    # everything that does so runs one at a time for an organisation (see `lock_access`).
    lock_access()
    existing_people = {p.pk: p for p in Person.objects.select_for_update()}
    existing_sites = {s.pk: s for s in Site.objects.select_for_update()}

    def new_refs(rows: list[dict], key: str, held: dict) -> set:
        refs = set()
        for row in rows:
            try:
                ref = _as_uuid(row.get(key), key)
            except ValidationError:
                continue
            if ref not in held:
                refs.add(ref)
        return refs

    site_rows = _Rows(
        sites,
        key="site_ref",
        values=_site_values,
        is_removal=lambda row: row.get("is_active") is False,
        held=existing_sites,
        taken=_refs_held_elsewhere(Site, new_refs(sites, "site_ref", existing_sites)),
        removed="The site was made inactive; its other details were not changed.",
    )
    person_rows = _Rows(
        people,
        key="person_ref",
        values=_person_values,
        is_removal=lambda row: row.get("status") == Person.Status.ENDED,
        held=existing_people,
        taken=_refs_held_elsewhere(Person, new_refs(people, "person_ref", existing_people)),
        removed="The person was ended; their other details were not changed.",
    )

    # Who would be active afterwards, worked out before anything is written.
    def active_after(ref, person=None) -> bool:
        if ref in person_rows.valid:
            return person_rows.valid[ref]["status"] == Person.Status.ACTIVE
        if person is None or ref in person_rows.removals or ref not in person_rows.named:
            return False
        return person.is_active  # named by a row the hub could not take: left as they were

    active_before = sum(1 for p in existing_people.values() if p.is_active)
    remaining = sum(1 for ref, p in existing_people.items() if active_after(ref, p))
    arriving = sum(1 for ref in person_rows.valid if ref not in existing_people and active_after(ref))
    if active_before and not (remaining + arriving) and not allow_empty:
        raise ValidationError(
            "This snapshot has no active people and would end everyone. Send allow_empty=true if that is intended.",
            code="empty_snapshot",
        )

    counts = {"people_created": 0, "people_updated": 0, "people_ended": 0, "sites_created": 0, "sites_updated": 0,
              "sites_deactivated": 0}  # fmt: skip
    rejected = [*site_rows.rejected, *person_rows.rejected]
    now = timezone.now()

    for ref, values in site_rows.valid.items():
        site = existing_sites.get(ref)
        if site is None:
            try:
                _insert(Site(id=ref, **values))
            except ValidationError as exc:
                rejected.append({"site_ref": str(ref), "code": exc.code, "reason": exc.messages[0]})
                continue
            counts["sites_created"] += 1
        elif any(getattr(site, k) != v for k, v in values.items()):
            for k, v in values.items():
                setattr(site, k, v)
            site.save(update_fields=[*values, "updated_at"])
            counts["sites_updated"] += 1
    for ref, site in existing_sites.items():
        if site.is_active and (ref in site_rows.removals or ref not in site_rows.named):
            site.is_active = False
            site.save(update_fields=["is_active", "updated_at"])
            counts["sites_deactivated"] += 1

    for ref, values in person_rows.valid.items():
        status = values["status"]
        person = existing_people.get(ref)
        if person is None:
            try:
                _insert(Person(id=ref, ended_at=now if status == "ended" else None, **values))
            except ValidationError as exc:
                rejected.append({"person_ref": str(ref), "code": exc.code, "reason": exc.messages[0]})
                continue
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
        if person.is_active and (ref in person_rows.removals or ref not in person_rows.named):
            person.status, person.ended_at, person.positions = Person.Status.ENDED, now, []
            person.save(update_fields=["status", "ended_at", "positions", "updated_at"])
            counts["people_ended"] += 1

    # A group that names a position takes in whoever holds it. Worked out here, in the same
    # transaction, so that who may enter never lags the people it is worked out from; and on every
    # snapshot, changed or not, so that anything out of step is put right by the next one. Each
    # membership it adds or removes is audited on its own, as an access change of that person.
    access = sync_position_memberships()
    if any(counts.values()):
        data = dict(counts)
        if rejected:
            data["rows_rejected"] = len(rejected)
        if any(access.values()):
            data |= {"access_granted_by_position": access["added"], "access_removed_by_position": access["removed"]}
        # One event per snapshot that changed something, not one per row: an unchanged snapshot
        # arrives every minute and must leave no trace. Rows it refused are counted on that event;
        # a snapshot that changed nothing is not recorded for its refusals alone, because a sender
        # repeats it until a person fixes the row.
        audit.record(
            "directory.snapshot_applied",
            actor=None,
            actor_kind=AuditEvent.ActorKind.SERVICE,
            target=token,
            target_label=getattr(token, "name", "") or "",
            data=data,
        )
    return {**counts, "rejected_count": len(rejected), "rejected": rejected[:MAX_REJECTED_LISTED]}
