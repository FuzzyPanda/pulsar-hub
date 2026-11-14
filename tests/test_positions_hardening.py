"""Job positions and door access: the defects an independent review proved on 2026-11-14, each
kept as a test. Positions decide who is in an access group, and a group decides who can open a
door, so every one of these was a way to hold a door open or shut wrongly.

The three race tests hold one transaction open just before it commits and start the other. With
the organisation's access lock the second waits for the first (about three seconds each here);
before the lock, both committed a state worked out without the other's change."""

import json
import threading
import time
import uuid

import pytest
from django.core.exceptions import PermissionDenied
from django.db import connection
from django.test.utils import CaptureQueriesContext
from django.urls import reverse

from hub.access import services as access
from hub.access.models import AccessGroupMember, AccessGroupPosition
from hub.audit.models import AuditEvent
from hub.directory.models import Person
from hub.organisations.context import organisation_context
from hub.organisations.models import Organisation
from hub.organisations.services import Actor
from tests import factories as f
from tests.isolation.test_machine_api import gateway_headers, service_headers


def actor(world, role):
    return Actor(world.user(role), world.memberships[role])


def rostering_world(world):
    Organisation.objects.filter(pk=world.organisation.pk).update(directory_source="rostering")
    world.organisation.refresh_from_db()
    return world


def kept(world) -> dict:
    from hub.directory.models import Site

    return {
        "people": [
            {
                "person_ref": str(world.person.pk),
                "name": world.person.name,
                "work_email": world.person.work_email,
                "status": "active",
            }
        ],
        "sites": [
            {"site_ref": str(site.pk), "name": site.name, "address": site.address, "timezone": site.timezone}
            for site in Site.all_organisations.filter(organisation=world.organisation)
        ],
    }


def with_positions(world, positions, **extra) -> bytes:
    body = kept(world)
    body["people"][0] |= {"positions": positions} | extra
    return json.dumps(body).encode()


def put_directory(client, world, body):
    return client.put(reverse("api_directory"), data=body, content_type="application/json", **service_headers(world))


def get_access(client, world):
    return client.get(reverse("api_gateway_access", kwargs={"site_ref": world.site.pk}), **gateway_headers(world))


def members(group) -> dict:
    return dict(AccessGroupMember.all_organisations.filter(access_group=group).values_list("person_id", "source"))


def guards_group(world, positions=("Guard",)):
    with organisation_context(world.organisation):
        guards = f.AccessGroupFactory(organisation=world.organisation, name="Guards")
        f.AccessGroupSiteFactory(organisation=world.organisation, access_group=guards, site=world.site)
        if positions:
            access.set_group_positions(guards, list(positions), actor=actor(world, "admin"))
    return guards


def in_thread_paused_before_commit(world, work, monkeypatch, *, after="sync"):
    """Run `work()` in another thread and connection, inside the organisation. It stops inside its
    transaction, holding the access lock, until `release` is set or 3s pass: with `after="sync"`
    once it has worked the memberships out (so what it decided cannot see anything committed
    later), with `after="audit"` at its audit line."""
    reached, release, result = threading.Event(), threading.Event(), {}
    name = "sync_position_memberships" if after == "sync" else "_audit"
    real = getattr(access, name)

    def paused(*args, **kwargs):
        if threading.current_thread().name != "other":
            return real(*args, **kwargs)
        if after == "sync":
            value = real(*args, **kwargs)
        reached.set()
        release.wait(3)
        return value if after == "sync" else real(*args, **kwargs)

    monkeypatch.setattr(access, name, paused)

    def run():
        try:
            with organisation_context(world.organisation):
                result["value"] = work()
        except Exception as exc:  # noqa: BLE001
            result["error"] = exc
        finally:
            connection.close()

    thread = threading.Thread(target=run, name="other")
    thread.start()
    assert reached.wait(10), result
    return thread, release, result


# --- 1. a console change of a group's positions racing a snapshot -------------------------------------


@pytest.mark.django_db(transaction=True)
def test_race_group_stops_naming_a_position_while_a_snapshot_gives_it(client, world_a, monkeypatch):
    """An Admin takes "Guard" off the group; in the same moment Rostering's snapshot makes the
    person a Guard. Afterwards the group names no position at all, so nobody may be in it through
    a position."""
    rostering_world(world_a)
    guards = guards_group(world_a)
    admin = actor(world_a, "admin")
    thread, release, result = in_thread_paused_before_commit(
        world_a, lambda: access.set_group_positions(guards, [], actor=admin), monkeypatch
    )
    response = put_directory(client, world_a, with_positions(world_a, ["Guard"]))
    assert response.status_code == 200, response.content
    release.set()
    thread.join(10)
    assert "error" not in result, result
    with organisation_context(world_a.organisation):
        assert not AccessGroupPosition.objects.filter(access_group=guards).exists()
    # Right once both have committed, not only after a later snapshot puts it right.
    assert members(guards) == {}, "a derived membership outlived the mapping that gave it"
    for _ in range(3):
        again = put_directory(client, world_a, with_positions(world_a, ["Guard"])).json()
        assert not any(v for k, v in again.items() if k.startswith(("people_", "sites_")))
    sent = {p["name"]: p["access_groups"] for p in get_access(client, world_a).json()["people"]}
    assert members(guards) == {}, "a derived membership outlived the mapping that gave it"
    assert all("Guards" not in groups for groups in sent.values())


@pytest.mark.django_db(transaction=True)
def test_race_group_starts_naming_a_position_while_a_snapshot_takes_it_away(client, world_a, monkeypatch):
    """The person is a Guard. An Admin names "Guard" on the group; in the same moment the snapshot
    takes the position off the person. Afterwards the person holds no position."""
    rostering_world(world_a)
    put_directory(client, world_a, with_positions(world_a, ["Guard"]))
    guards = guards_group(world_a, positions=())
    admin = actor(world_a, "admin")
    thread, release, result = in_thread_paused_before_commit(
        world_a, lambda: access.set_group_positions(guards, ["Guard"], actor=admin), monkeypatch
    )
    response = put_directory(client, world_a, with_positions(world_a, []))
    assert response.status_code == 200, response.content
    release.set()
    thread.join(10)
    assert "error" not in result, result
    assert Person.all_organisations.get(pk=world_a.person.pk).positions == []
    assert members(guards) == {}, "the person lost the position but kept the door access it gave"
    for _ in range(3):
        put_directory(client, world_a, with_positions(world_a, []))
    sent = {p["name"]: p["access_groups"] for p in get_access(client, world_a).json()["people"]}
    assert members(guards) == {}, "the person lost the position but kept the door access it gave"
    assert all("Guards" not in groups for groups in sent.values())


@pytest.mark.django_db(transaction=True)
def test_race_manager_adds_by_hand_while_a_snapshot_derives_the_same_membership(client, world_a, monkeypatch):
    """A Manager adds the new Guard by hand at the moment the snapshot arrives with their position.
    The snapshot (which may also carry people to END) must still be applied."""
    rostering_world(world_a)
    guards = guards_group(world_a)
    with organisation_context(world_a.organisation):
        leaver = f.PersonFactory(organisation=world_a.organisation, name="Leaver")
    manager = actor(world_a, "manager")
    thread, release, result = in_thread_paused_before_commit(
        world_a, lambda: access.add_person_to_group(guards, world_a.person, actor=manager), monkeypatch, after="audit"
    )
    client.raise_request_exception = False
    # This snapshot gives the person "Guard" and, by leaving `leaver` out, ends them.
    response = put_directory(client, world_a, with_positions(world_a, ["Guard"]))
    release.set()
    thread.join(10)
    # Neither is sacrificed to a deadlock: the snapshot is applied and the Manager's add stands.
    assert response.status_code == 200 and "error" not in result, result
    assert Person.all_organisations.get(pk=leaver.pk).status == "ended"
    assert members(guards) == {world_a.person.pk: "manual"}


# --- 2. a list that is long only because it repeats itself ---------------------------------------


@pytest.mark.django_db
def test_repeats_do_not_count_towards_the_limit_so_a_lost_position_is_not_pinned(client, world_a):
    """The person was a Guard and is now only a Cleaner, sent as 22 spellings of one name. The
    limit is on positions, counted after repeats are dropped, so the row is taken and the Guard
    access goes. (Before, the row was rejected for its length and the old positions stayed.)"""
    rostering_world(world_a)
    guards = guards_group(world_a)
    put_directory(client, world_a, with_positions(world_a, ["Guard"]))
    assert members(guards) == {world_a.person.pk: "positions"}
    data = put_directory(client, world_a, with_positions(world_a, ["Cleaner", "Cleaner "] * 11)).json()
    assert data["rejected"] == [] and Person.all_organisations.get(pk=world_a.person.pk).positions == ["Cleaner"]
    assert members(guards) == {}


# --- 3. the audit log -------------------------------------------------------------------------------


@pytest.mark.django_db
def test_audit_says_who_got_which_group_through_a_position(client, world_a):
    rostering_world(world_a)
    guards = guards_group(world_a)
    put_directory(client, world_a, with_positions(world_a, ["Guard"]))
    assert members(guards) == {world_a.person.pk: "positions"}
    events = list(
        AuditEvent.all_organisations.filter(organisation=world_a.organisation)
        .exclude(action="access.group_positions_changed")
        .values("action", "target_type", "target_ref", "target_label", "data")
    )
    text = json.dumps(events, default=str)
    assert str(world_a.person.pk) in text or world_a.person.name in text, "nothing names the person who gained access"
    assert "Guards" in text, "nothing names the group they gained"


@pytest.mark.django_db
def test_audit_of_a_removal_that_removed_nothing(client, world_a):
    """A hand-made membership is removed while a position still gives the group. The person never
    leaves the group, but the log says `access.removed` and nothing more."""
    rostering_world(world_a)
    guards = guards_group(world_a)
    with organisation_context(world_a.organisation):
        access.add_person_to_group(guards, world_a.person, actor=actor(world_a, "manager"))
    put_directory(client, world_a, with_positions(world_a, ["Guard"]))
    assert members(guards) == {world_a.person.pk: "manual"}
    with organisation_context(world_a.organisation):
        still = access.remove_person_from_group(guards, world_a.person, actor=actor(world_a, "manager"))
    assert still and members(guards) == {world_a.person.pk: "positions"}
    trail = list(
        AuditEvent.all_organisations.filter(organisation=world_a.organisation, target_ref=str(world_a.person.pk))
        .order_by("occurred_at", "id")
        .values_list("action", "data")
    )[-2:]
    assert trail == [
        ("access.removed", {"group": "Guards"}),
        ("access.granted", {"group": "Guards", "through": "position"}),
    ]


# --- 4. one person can be taken out here, whoever manages their positions ---------------------------


@pytest.mark.django_db
def test_a_manager_can_take_one_person_out_of_a_group_their_position_gives(client, world_a):
    """Rostering owns the people, so nobody here can end the person or change their position. A
    Manager can still take this one person's access away at once, and it stays away: the person
    is kept out of the group until someone allows them again."""
    rostering_world(world_a)
    guards = guards_group(world_a)
    put_directory(client, world_a, with_positions(world_a, ["Guard"]))
    version = get_access(client, world_a).json()["version"]
    with organisation_context(world_a.organisation):
        person = Person.objects.get(pk=world_a.person.pk)
        assert access.remove_person_from_group(guards, person, actor=actor(world_a, "manager")) is False
    assert members(guards) == {}
    after = get_access(client, world_a).json()
    assert after["version"] != version and "Guards" not in after["people"][0]["access_groups"]
    removed = AuditEvent.all_organisations.filter(action="access.removed").latest("occurred_at")
    assert removed.data == {"group": "Guards", "was": "through a position", "kept_out": True}
    assert removed.actor_id == world_a.manager.pk
    # The next snapshots, and a change of the group's positions, leave them out.
    put_directory(client, world_a, with_positions(world_a, ["Guard", "Supervisor"]))
    with organisation_context(world_a.organisation):
        access.set_group_positions(guards, ["Guard", "Supervisor"], actor=actor(world_a, "admin"))
        assert members(guards) == {}
        # Staff may not lift it; a Manager may, and the position gives the group back at once.
        with pytest.raises(PermissionDenied):
            access.allow_person_in_group(guards, person, actor=actor(world_a, "staff"))
        assert access.allow_person_in_group(guards, person, actor=actor(world_a, "manager")) is True
        assert members(guards) == {person.pk: "positions"}
        # Adding by hand also ends the keeping out.
        access.remove_person_from_group(guards, person, actor=actor(world_a, "manager"))
        access.add_person_to_group(guards, person, actor=actor(world_a, "manager"))
        assert members(guards) == {person.pk: "manual"}
        assert not guards.exclusions.exists()


@pytest.mark.django_db
def test_the_console_removes_and_allows_again(client, world_a):
    rostering_world(world_a)
    guards = guards_group(world_a)
    put_directory(client, world_a, with_positions(world_a, ["Guard"]))
    kwargs = {"org_slug": world_a.organisation.slug, "group_id": guards.pk}
    f.sign_in(client, world_a.manager, mfa=True)
    page = client.get(reverse("group_detail", kwargs=kwargs)).content.decode()
    assert "Through a position" in page and "Remove and keep out" in page
    client.post(reverse("group_member_remove", kwargs=kwargs), {"person": world_a.person.pk})
    assert members(guards) == {}
    page = client.get(reverse("group_detail", kwargs=kwargs)).content.decode()
    assert "Kept out" in page and "Allow again" in page
    client.post(reverse("group_member_allow", kwargs=kwargs), {"person": world_a.person.pk})
    assert members(guards) == {world_a.person.pk: "positions"}


@pytest.mark.django_db
def test_when_the_directory_comes_back_to_the_hub_positions_stop_deciding_and_doors_stay(client, world_a):
    """An Owner takes the directory back from Rostering. Nothing in the hub edits positions, so
    they would be frozen for good: instead every membership a position gave becomes a hand-made
    one (no door changes), positions are cleared, and each person can be managed by hand."""
    from hub.organisations import services as org_services

    rostering_world(world_a)
    guards = guards_group(world_a)
    put_directory(client, world_a, with_positions(world_a, ["Guard"]))
    version = get_access(client, world_a).json()["version"]
    with organisation_context(world_a.organisation):
        org_services.set_directory_source(actor=actor(world_a, "owner"), source="hub")
    assert Person.all_organisations.get(pk=world_a.person.pk).positions == []
    assert members(guards) == {world_a.person.pk: "manual"}
    assert get_access(client, world_a).json()["version"] == version  # no door hears of it
    event = AuditEvent.all_organisations.get(action="organisation.directory_source_changed")
    assert event.data == {
        "from": "rostering",
        "to": "hub",
        "memberships_kept_as_hand_made": 1,
        "people_cleared_of_positions": 1,
    }
    with organisation_context(world_a.organisation):
        person = Person.objects.get(pk=world_a.person.pk)
        assert access.remove_person_from_group(guards, person, actor=actor(world_a, "manager")) is False
    assert members(guards) == {}


# --- 5. a rehire --------------------------------------------------------------------------------------


@pytest.mark.django_db
def test_someone_who_left_and_comes_back_without_positions_on_the_row(client, world_a):
    rostering_world(world_a)
    guards = guards_group(world_a)
    other = {"person_ref": str(uuid.uuid4()), "name": "Stays"}
    body = json.loads(with_positions(world_a, ["Guard"]))
    body["people"].append(other)
    put_directory(client, world_a, json.dumps(body).encode())
    gone = dict(body, people=[other])
    put_directory(client, world_a, json.dumps(gone).encode())  # the Guard is missing: ended
    assert Person.all_organisations.get(pk=world_a.person.pk).status == "ended"
    back = kept(world_a)  # back, in a row that says nothing about positions
    back["people"].append(other)
    put_directory(client, world_a, json.dumps(back).encode())
    assert Person.all_organisations.get(pk=world_a.person.pk).positions == []
    sent = {p["name"]: (p["active"], p["access_groups"]) for p in get_access(client, world_a).json()["people"]}
    assert "Guards" not in sent[world_a.person.name][1] and members(guards) == {}


# --- 6. cost of the sync, and a long key ----------------------------------------------------------------


@pytest.mark.django_db
def test_cost_of_one_sync(client, world_a):
    rostering_world(world_a)
    n = 1000
    body = kept(world_a)
    body["people"] += [{"person_ref": str(uuid.uuid4()), "name": f"P {i}", "positions": ["Guard"]} for i in range(n)]
    put_directory(client, world_a, json.dumps(body).encode())
    with organisation_context(world_a.organisation):
        guards = f.AccessGroupFactory(organisation=world_a.organisation, name="Guards")
        started = time.monotonic()
        with CaptureQueriesContext(connection) as queries:
            changed = access.set_group_positions(guards, ["Guard"], actor=actor(world_a, "admin"))
        took = time.monotonic() - started
    assert changed == {"added": n, "removed": 0}
    # One insert for the memberships and one per 500 audit events, however many people there are.
    assert len(queries) < 30, f"{len(queries)} queries, {took:.2f}s"
    assert AuditEvent.all_organisations.filter(action="access.granted", data__through="position").count() == n


@pytest.mark.django_db
def test_a_position_whose_case_folded_form_is_longer_than_the_column(client, world_a):
    name = "ΐ" * 60  # each folds to three code points, so the key is 180 long
    assert len(access.position_key(name)) == 180
    f.sign_in(client, world_a.admin, mfa=True)
    client.raise_request_exception = False
    kwargs = {"org_slug": world_a.organisation.slug, "group_id": world_a.access_group.pk}
    response = client.post(reverse("group_positions", kwargs=kwargs), {"positions": [], "new_position": name})
    assert response.status_code == 302
    with organisation_context(world_a.organisation):
        assert world_a.access_group.position_links.filter(position=name).exists()
