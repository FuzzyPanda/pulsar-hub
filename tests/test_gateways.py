"""H2 and H3: people, sites, access groups, gateway pairing, access sync and event intake."""

import json
import uuid

import pytest
from django.core.exceptions import PermissionDenied, ValidationError
from django.urls import reverse
from django.utils import timezone

from hub.access import services as access
from hub.access.models import AccessGroupMember
from hub.audit.models import AuditEvent
from hub.directory import services as directory
from hub.directory.models import Person, Site
from hub.gateways import services as gateways
from hub.gateways.models import Gateway, GatewayEvent, PairingCode
from hub.gateways.views import site_sync_status
from hub.organisations import services as org_services
from hub.organisations.context import organisation_context
from hub.organisations.models import Organisation, Role
from hub.organisations.services import Actor
from tests import factories as f
from tests.isolation.test_machine_api import call_gateway, directory_body, envelope, gateway_headers, service_headers

pytestmark = pytest.mark.django_db


def actor(world, role):
    return Actor(world.user(role), world.memberships[role])


def audit_actions(world):
    return list(
        AuditEvent.all_organisations.filter(organisation=world.organisation)
        .order_by("occurred_at")
        .values_list("action", flat=True)
    )


def pair(client, code, **extra):
    return client.post(
        reverse("api_gateway_pair"), data=json.dumps({"code": code, **extra}), content_type="application/json"
    )


# --- pairing --------------------------------------------------------------------------------------


def test_admin_creates_a_code_the_gateway_pairs_and_the_code_is_spent(client, world_a):
    site = world_a.pairing_code.site
    with organisation_context(world_a.organisation):
        pairing, code = gateways.create_pairing_code(site, actor=actor(world_a, "admin"))
    assert len(code) == 14 and code.count("-") == 2
    assert code not in str(PairingCode.all_organisations.filter(pk=pairing.pk).values())  # only a digest is kept

    # Typed in lower case with spaces instead of hyphens: still the same code.
    response = pair(client, code.lower().replace("-", " "), name="Front office R1100", software_version="1.4.0")
    assert response.status_code == 201 and response["Cache-Control"] == "no-store"
    data = response.json()
    assert data["credential"].startswith("hubgw_") and data["site_name"] == site.name and data["poll_seconds"] == 60
    gateway = Gateway.all_organisations.get(pk=data["gateway_id"])
    assert gateway.site_id == site.pk and gateway.name == "Front office R1100" and gateway.software_version == "1.4.0"
    assert data["credential"] not in str(Gateway.all_organisations.filter(pk=gateway.pk).values())

    assert pair(client, code).status_code == 403  # single use
    assert audit_actions(world_a)[-2:] == ["gateway.pairing_code_created", "gateway.paired"]
    paired = AuditEvent.all_organisations.get(action="gateway.paired")
    assert paired.actor_kind == "gateway" and paired.data["code_created_by"] == world_a.admin.email


@pytest.mark.parametrize("bad", ["", "AAAA-BBBB", "ZZZZ-ZZZZ-ZZZZ", "AAAA-BBBB-CCCC-DDDD", None, 12345])
def test_every_bad_code_gets_the_same_answer(client, world_a, bad):
    response = pair(client, bad)
    assert response.status_code == 403 and response.json() == {
        "detail": "That pairing code is not valid.",
        "code": "pairing_code_not_valid",
    }
    assert Gateway.all_organisations.count() == 1


def test_codes_expire_and_a_new_code_cancels_the_last(client, world_a):
    site = world_a.pairing_code.site
    with organisation_context(world_a.organisation):
        _first, first_code = gateways.create_pairing_code(site, actor=actor(world_a, "admin"))
        second, second_code = gateways.create_pairing_code(site, actor=actor(world_a, "admin"))
    assert pair(client, first_code).status_code == 403
    with organisation_context(world_a.organisation):
        PairingCode.objects.filter(pk=second.pk).update(expires_at=timezone.now())
    assert pair(client, second_code).status_code == 403
    assert pair(client, "AAAA-BBBB-CCCC").status_code == 403  # the fixture's code went the same way


def test_who_may_create_a_pairing_code(world_a):
    site = world_a.pairing_code.site
    with organisation_context(world_a.organisation):
        for role in ("manager", "staff"):
            with pytest.raises(PermissionDenied):
                gateways.create_pairing_code(site, actor=actor(world_a, role))
        visiting = Actor(world_a.operator_access.operator, None, world_a.operator_access)
        with pytest.raises(PermissionDenied):
            gateways.create_pairing_code(site, actor=visiting)
        gateways.create_pairing_code(site, actor=actor(world_a, "admin"))


def test_pairing_a_replacement_revokes_the_old_gateway(client, world_a):
    with organisation_context(world_a.organisation):
        _pairing, code = gateways.create_pairing_code(world_a.site, actor=actor(world_a, "admin"))
    assert pair(client, code).status_code == 201
    with organisation_context(world_a.organisation):
        assert Gateway.objects.live().filter(site=world_a.site).count() == 1
        assert Gateway.objects.get(pk=world_a.gateway.pk).revoked_at is not None
    assert call_gateway(client, "api_gateway_access", world_a, world_a).status_code == 401  # the old credential


def test_a_site_whose_doors_another_system_runs_cannot_be_paired(client, world_a):
    """Rule 10: at a PerfectGym site the hub's access features stay off."""
    site = world_a.pairing_code.site
    with organisation_context(world_a.organisation):
        directory.set_access_managed_elsewhere(site, actor=actor(world_a, "admin"), elsewhere=True)
        with pytest.raises(ValidationError):
            gateways.create_pairing_code(site, actor=actor(world_a, "admin"))
        with pytest.raises(ValidationError):
            access.set_group_sites(world_a.access_group, [site], actor=actor(world_a, "admin"))
        # And a site that already has a gateway must lose it first.
        with pytest.raises(ValidationError):
            directory.set_access_managed_elsewhere(world_a.site, actor=actor(world_a, "admin"), elsewhere=True)
    assert pair(client, "AAAA-BBBB-CCCC").status_code == 403  # the code made before the change
    with organisation_context(world_a.organisation):
        assert site_sync_status(site, None)["state"] == "elsewhere"


def test_pairing_is_rate_limited(client, world_a, settings):
    for _ in range(10):
        assert pair(client, "ZZZZ-ZZZZ-ZZZZ").status_code == 403
    assert pair(client, "ZZZZ-ZZZZ-ZZZZ").status_code == 429
    assert pair(client, "AAAA-BBBB-CCCC").status_code == 429  # even the right code, once over the limit


def test_revoking_stops_the_gateway_and_is_audited(client, world_a):
    with organisation_context(world_a.organisation):
        with pytest.raises(PermissionDenied):
            gateways.revoke_gateway(world_a.gateway, actor=actor(world_a, "manager"))
        gateways.revoke_gateway(world_a.gateway, actor=actor(world_a, "admin"))
    assert call_gateway(client, "api_gateway_access", world_a, world_a).status_code == 401
    assert "gateway.revoked" in audit_actions(world_a)


# --- desired access -------------------------------------------------------------------------------


def get_access(client, world, version=None):
    url = reverse("api_gateway_access", kwargs={"site_ref": world.site.pk})
    return client.get(url + (f"?version={version}" if version else ""), **gateway_headers(world))


def test_desired_access_is_a_complete_stable_snapshot(client, world_a):
    first = get_access(client, world_a).json()
    assert set(first) == {"org_ref", "site_ref", "version", "generated_at", "access_groups", "people"}
    assert first["access_groups"] == [world_a.access_group.name]
    assert first["people"] == [
        {
            "person_ref": str(world_a.person.pk),
            "name": world_a.person.name,
            "active": True,
            "access_groups": [world_a.access_group.name],
        }
    ]
    # Nothing a card could travel in (rule 2), and nothing personal beyond the name.
    assert "email" not in json.dumps(first) and "card" not in json.dumps(first).lower()
    # Unchanged content: the same version, and a 304 when the gateway already holds it.
    assert get_access(client, world_a).json()["version"] == first["version"]
    unchanged = get_access(client, world_a, first["version"])
    assert unchanged.status_code == 304 and unchanged.content == b""
    assert get_access(client, world_a, "0" * 32).status_code == 200


def test_every_change_that_matters_changes_the_version(client, world_a):
    versions = [get_access(client, world_a).json()["version"]]

    def changed():
        versions.append(get_access(client, world_a).json()["version"])
        assert versions[-1] != versions[-2]

    owner, admin = actor(world_a, "owner"), actor(world_a, "admin")
    with organisation_context(world_a.organisation):
        other = f.PersonFactory(organisation=world_a.organisation, name="Second Person")
        access.add_person_to_group(world_a.access_group, other, actor=admin)
    changed()
    with organisation_context(world_a.organisation):
        directory.update_person(other, actor=owner, name="Second Person Renamed", work_email="")
    changed()
    with organisation_context(world_a.organisation):
        directory.end_person(other, actor=owner)
    changed()
    with organisation_context(world_a.organisation):
        access.rename_group(world_a.access_group, actor=admin, name="Renamed group")
    changed()
    with organisation_context(world_a.organisation):
        access.remove_person_from_group(world_a.access_group, other, actor=admin)
    changed()
    # Things that do not matter to the gateway leave the version alone.
    with organisation_context(world_a.organisation):
        directory.update_person(world_a.person, actor=owner, name=world_a.person.name, work_email="new@example.test")
        f.PersonFactory(organisation=world_a.organisation, name="Not in any group")
    assert get_access(client, world_a).json()["version"] == versions[-1]


def test_an_ended_person_is_sent_as_inactive_and_a_removed_one_disappears(client, world_a):
    with organisation_context(world_a.organisation):
        directory.end_person(world_a.person, actor=actor(world_a, "manager"))
    people = get_access(client, world_a).json()["people"]
    assert [(p["person_ref"], p["active"]) for p in people] == [(str(world_a.person.pk), False)]
    with organisation_context(world_a.organisation):
        access.remove_person_from_group(world_a.access_group, world_a.person, actor=actor(world_a, "manager"))
    assert get_access(client, world_a).json()["people"] == []


def test_a_group_opens_only_the_sites_it_includes(client, world_a):
    """Multi-site access: the same group at two sites, and a second group at only one."""
    with organisation_context(world_a.organisation):
        depot = world_a.pairing_code.site
        cleaners = access.create_group(actor=actor(world_a, "admin"), name="Cleaners")
        cleaner = f.PersonFactory(organisation=world_a.organisation, name="Casey Cleaner")
        access.add_person_to_group(cleaners, cleaner, actor=actor(world_a, "manager"))
        access.add_person_to_group(cleaners, world_a.person, actor=actor(world_a, "manager"))
        access.set_group_sites(cleaners, [depot], actor=actor(world_a, "admin"))
        clinic, at_depot = access.desired_access(world_a.site), access.desired_access(depot)
    assert clinic["access_groups"] == [world_a.access_group.name]
    assert [p["name"] for p in clinic["people"]] == [world_a.person.name]
    assert clinic["people"][0]["access_groups"] == [world_a.access_group.name]  # not Cleaners: not at this site
    assert at_depot["access_groups"] == ["Cleaners"]
    assert sorted(p["name"] for p in at_depot["people"]) == sorted([world_a.person.name, "Casey Cleaner"])


def test_acknowledgement_is_what_makes_a_site_confirmed(client, world_a):
    with organisation_context(world_a.organisation):
        assert site_sync_status(world_a.site, world_a.gateway)["state"] == "unconfirmed"
    version = get_access(client, world_a).json()["version"]
    ack = call_gateway(client, "api_gateway_access_ack", world_a, world_a, {"version": version, "failures": []})
    assert ack.status_code == 204
    with organisation_context(world_a.organisation):
        gateway = Gateway.objects.get(pk=world_a.gateway.pk)
        assert site_sync_status(world_a.site, gateway)["state"] == "in_sync"
        # A change in the hub makes the site unconfirmed again until the gateway catches up.
        directory.end_person(world_a.person, actor=actor(world_a, "manager"))
        assert site_sync_status(world_a.site, gateway)["state"] == "unconfirmed"
    assert AuditEvent.all_organisations.get(action="access.applied").data == {"version": version, "failures": 0}

    version = get_access(client, world_a).json()["version"]
    failures = [{"person_ref": str(world_a.person.pk), "reason": "access group Nurses is not mapped at this site"}]
    call_gateway(client, "api_gateway_access_ack", world_a, world_a, {"version": version, "failures": failures})
    with organisation_context(world_a.organisation):
        status = site_sync_status(world_a.site, Gateway.objects.get(pk=world_a.gateway.pk))
    assert status["state"] == "failures" and status["failures"] == failures


@pytest.mark.parametrize(
    "payload",
    [{"version": "not hex!"}, {"version": ""}, {"version": "abcdef12", "failures": [{"person_ref": "nope"}]},
     {"version": "abcdef12", "failures": ["x"]}],
)  # fmt: skip
def test_a_malformed_acknowledgement_is_refused(client, world_a, payload):
    assert call_gateway(client, "api_gateway_access_ack", world_a, world_a, payload).status_code == 400
    assert Gateway.all_organisations.get(pk=world_a.gateway.pk).applied_version == ""


def test_a_silent_gateway_is_shown_as_out_of_contact(world_a, settings):
    with organisation_context(world_a.organisation):
        Gateway.objects.update(
            last_seen_at=timezone.now() - timezone.timedelta(seconds=settings.GATEWAY_OUT_OF_CONTACT_SECONDS + 5)
        )
        assert site_sync_status(world_a.site, Gateway.objects.get(pk=world_a.gateway.pk))["state"] == "out_of_contact"
        assert site_sync_status(world_a.pairing_code.site, None)["state"] == "unpaired"


def test_a_poll_notes_contact_without_writing_every_time(client, world_a, django_assert_max_num_queries):
    with organisation_context(world_a.organisation):
        Gateway.objects.update(last_seen_at=timezone.now() - timezone.timedelta(minutes=10))
    get_access(client, world_a)
    seen = Gateway.all_organisations.get(pk=world_a.gateway.pk).last_seen_at
    assert timezone.now() - seen < timezone.timedelta(seconds=5)
    get_access(client, world_a)
    assert Gateway.all_organisations.get(pk=world_a.gateway.pk).last_seen_at == seen


# --- events ---------------------------------------------------------------------------------------


def post_events(client, world, events, **overrides):
    return call_gateway(client, "api_gateway_events", world, world, {"events": events}, **overrides)


def test_events_are_stored_once(client, world_a):
    events = [envelope(world_a), envelope(world_a, type="attendance.clock_out")]
    assert post_events(client, world_a, events).json() == {"accepted": 2, "duplicates": 0, "rejected": []}
    # The gateway was not sure the batch arrived and sends it again, with one new event.
    again = post_events(client, world_a, [*events, envelope(world_a, type="door.forced", person_ref=None)])
    assert again.json() == {"accepted": 1, "duplicates": 2, "rejected": []}
    stored = GatewayEvent.all_organisations.filter(event_id__in=[e["id"] for e in events])
    assert stored.count() == 2 and all(e.person_id == world_a.person.pk for e in stored)


def test_events_need_a_signature_over_the_exact_body(client, world_a):
    url = reverse("api_gateway_events", kwargs={"site_ref": world_a.site.pk})
    body = json.dumps({"events": [envelope(world_a)]}).encode()
    good = gateway_headers(world_a, body)
    before = GatewayEvent.all_organisations.count()

    unsigned = client.post(
        url, data=body, content_type="application/json", HTTP_AUTHORIZATION=good["HTTP_AUTHORIZATION"]
    )
    tampered = client.post(url, data=body.replace(b"clock_in", b"clock_out"), content_type="application/json", **good)
    wrong_key = client.post(
        url, data=body, content_type="application/json",
        HTTP_AUTHORIZATION=good["HTTP_AUTHORIZATION"], HTTP_X_HUB_SIGNATURE="sha256=" + "0" * 64,
    )  # fmt: skip
    assert unsigned.status_code == tampered.status_code == wrong_key.status_code == 400
    assert GatewayEvent.all_organisations.count() == before
    assert client.post(url, data=body, content_type="application/json", **good).status_code == 200


@pytest.mark.parametrize(
    ("change", "reason"),
    [
        ({"type": "member.checked_in"}, "unknown type"),
        ({"id": "not-a-uuid"}, "id is not a UUID"),
        ({"occurred_at": "yesterday"}, "occurred_at"),
        ({"occurred_at": "2026-11-13T05:00:00"}, "occurred_at"),  # no zone
        ({"occurred_at": "2099-01-01T00:00:00Z"}, "future"),
        ({"person_ref": None}, "person_ref is required"),
        ({"person_ref": str(uuid.uuid4())}, "not a person"),
        ({"data": {"door": "Front", "card_number": "12345678"}}, "card_number"),
        ({"data": {"door": "Front", "credential_hash": "hmac-sha256:" + "a" * 64}}, "credential_hash"),
        ({"data": {"pin": "1234"}}, "pin"),
        ({"data": {"door": 5}}, "must be text"),
        ({"data": ["door"]}, "must be an object"),
    ],
)
def test_one_bad_event_is_refused_and_the_rest_of_the_batch_stands(client, world_a, change, reason):
    """Rule 2 is enforced here: there is no key a card number, PIN or credential hash can use."""
    bad, good = envelope(world_a, **change), envelope(world_a)
    result = post_events(client, world_a, [bad, good]).json()
    assert result["accepted"] == 1 and len(result["rejected"]) == 1
    assert reason in result["rejected"][0]["reason"]
    assert not GatewayEvent.all_organisations.filter(
        data__has_any_keys=["card_number", "credential_hash", "pin"]
    ).exists()


@pytest.mark.parametrize("payload", [{"events": "nope"}, {"events": [{}] * 501}, {}, []])
def test_a_malformed_batch_is_refused_whole(client, world_a, payload):
    before = GatewayEvent.all_organisations.count()
    assert call_gateway(client, "api_gateway_events", world_a, world_a, payload).status_code == 400
    assert GatewayEvent.all_organisations.count() == before


def test_long_text_is_cut_and_door_alerts_need_no_person(client, world_a):
    events = [
        envelope(world_a, type="door.held_open", person_ref=None, data={"door": "D" * 500, "seconds": 95}),
        envelope(world_a, type="gateway.health", person_ref=None, data={"status": "degraded", "detail": "bus"}),
    ]
    assert post_events(client, world_a, events).json()["accepted"] == 2
    held = GatewayEvent.all_organisations.get(type="door.held_open")
    assert held.person is None and len(held.data["door"]) == 100 and held.data["seconds"] == 95


def test_who_is_on_site_follows_the_latest_clock_event(client, world_a):
    with organisation_context(world_a.organisation):
        GatewayEvent.objects.all().delete()  # the fixture's own clock-in
        second = f.PersonFactory(organisation=world_a.organisation, name="Second Person")
    t = timezone.now() - timezone.timedelta(hours=2)

    def at(minutes):
        return (t + timezone.timedelta(minutes=minutes)).strftime("%Y-%m-%dT%H:%M:%SZ")

    post_events(
        client,
        world_a,
        [
            envelope(world_a, person_ref=str(second.pk), occurred_at=at(0)),
            envelope(world_a, person_ref=str(second.pk), occurred_at=at(30), type="attendance.clock_out"),
            envelope(world_a, occurred_at=at(10), data={"door": "Staff entrance"}),
        ],
    )
    with organisation_context(world_a.organisation):
        present = gateways.people_on_site(world_a.site)
    assert [(row["person"].pk, row["door"]) for row in present] == [(world_a.person.pk, "Staff entrance")]


# --- state ----------------------------------------------------------------------------------------


def test_state_replaces_the_last_snapshot(client, world_a):
    payload = {
        "doors": [{"door_ref": "front", "name": "Front door", "state": "held_open", "mode": "normal"}],
        "health": {"status": "ok", "detail": "", "queued_events": 3},
    }
    assert call_gateway(client, "api_gateway_state", world_a, world_a, payload).status_code == 204
    gateway = Gateway.all_organisations.get(pk=world_a.gateway.pk)
    assert gateway.state == payload and gateway.state_reported_at is not None


@pytest.mark.parametrize(
    "payload",
    [
        {"doors": [{"name": "Front", "state": "ajar"}]},
        {"doors": [{"name": "Front", "state": "locked", "last_card": "1234"}]},
        {"doors": "all of them"},
        {"health": {"status": "ok", "credential_hash": "x"}},
        {"health": {"queued_events": -1}},
    ],
)
def test_state_with_anything_unexpected_is_refused(client, world_a, payload):
    before = Gateway.all_organisations.get(pk=world_a.gateway.pk).state
    assert call_gateway(client, "api_gateway_state", world_a, world_a, payload).status_code == 400
    assert Gateway.all_organisations.get(pk=world_a.gateway.pk).state == before


# --- the directory and who owns it ----------------------------------------------------------------


def put_directory(client, world, body):
    return client.put(reverse("api_directory"), data=body, content_type="application/json", **service_headers(world))


def test_hub_owned_directory_is_edited_in_the_hub_and_refuses_rostering(client, world_a):
    assert put_directory(client, world_a, directory_body(world_a)).status_code == 403
    with organisation_context(world_a.organisation):
        person = directory.create_person(
            actor=actor(world_a, "manager"), name="  New Hire ", work_email="NEW@Example.Test"
        )
        assert (person.name, person.work_email) == ("New Hire", "new@example.test")
        with pytest.raises(PermissionDenied):
            directory.create_person(actor=actor(world_a, "staff"), name="X")
        with pytest.raises(PermissionDenied):
            directory.create_site(actor=actor(world_a, "manager"), name="X")
        with pytest.raises(ValidationError):
            directory.create_site(actor=actor(world_a, "admin"), name="Site", timezone_name="Mars/Olympus")
        site = directory.create_site(actor=actor(world_a, "admin"), name="Site", timezone_name="Australia/Perth")
        assert site.timezone == "Australia/Perth"


def test_handing_the_directory_to_rostering_needs_an_empty_one(world_a):
    with organisation_context(world_a.organisation):
        with pytest.raises(PermissionDenied):
            org_services.set_directory_source(actor=actor(world_a, "admin"), source="rostering")
        with pytest.raises(ValidationError):
            org_services.set_directory_source(actor=actor(world_a, "owner"), source="rostering")
    empty = f.OrganisationFactory()
    owner = f.MembershipFactory(organisation=empty, role=Role.OWNER)
    with organisation_context(empty):
        org_services.set_directory_source(actor=Actor(owner.user, owner), source="rostering")
        empty.refresh_from_db()
        assert empty.directory_source == "rostering"
        # Taking it back is always allowed.
        org_services.set_directory_source(actor=Actor(owner.user, owner), source="hub")
    assert AuditEvent.all_organisations.filter(action="organisation.directory_source_changed").count() == 2


def test_rostering_owned_directory_cannot_be_edited_in_the_hub(world_a):
    Organisation.objects.filter(pk=world_a.organisation.pk).update(directory_source="rostering")
    world_a.organisation.refresh_from_db()
    with organisation_context(world_a.organisation):
        for attempt in (
            lambda: directory.create_person(actor=actor(world_a, "owner"), name="X"),
            lambda: directory.update_person(world_a.person, actor=actor(world_a, "owner"), name="X", work_email=""),
            lambda: directory.end_person(world_a.person, actor=actor(world_a, "owner")),
            lambda: directory.create_site(actor=actor(world_a, "owner"), name="X"),
        ):
            with pytest.raises(PermissionDenied):
                attempt()
        # Access is still the hub's: groups and who is in them are edited here.
        access.remove_person_from_group(world_a.access_group, world_a.person, actor=actor(world_a, "manager"))


def rostering_world(world):
    Organisation.objects.filter(pk=world.organisation.pk).update(directory_source="rostering")
    return world


def test_a_snapshot_creates_updates_and_ends_and_twice_changes_nothing(client, world_a):
    rostering_world(world_a)
    new_person, new_site = str(uuid.uuid4()), str(uuid.uuid4())
    body = json.dumps(
        {
            "people": [
                {
                    "person_ref": str(world_a.person.pk),
                    "name": "Nurse Renamed",
                    "work_email": "N@Example.Test",
                    "status": "active",
                },
                {"person_ref": new_person, "name": "From Rostering", "status": "active"},
            ],
            "sites": [
                {"site_ref": new_site, "name": "New Site", "address": "9 Dock Rd", "timezone": "Australia/Perth"}
            ],
        }
    ).encode()
    first = put_directory(client, world_a, body)
    assert first.status_code == 200
    assert first.json() == {
        "people_created": 1, "people_updated": 1, "people_ended": 0,
        "sites_created": 1, "sites_updated": 0, "sites_deactivated": 2,
        "rejected_count": 0, "rejected": [],
    }  # fmt: skip
    # The ids are the ones Rostering minted.
    assert Person.all_organisations.get(pk=new_person).organisation_id == world_a.organisation.pk
    assert Site.all_organisations.get(pk=new_site).timezone == "Australia/Perth"
    renamed = Person.all_organisations.get(pk=world_a.person.pk)
    assert (renamed.name, renamed.work_email) == ("Nurse Renamed", "n@example.test")
    assert not Site.all_organisations.get(pk=world_a.site.pk).is_active  # missing from the list: inactive, not deleted
    events_before = AuditEvent.all_organisations.filter(action="directory.snapshot_applied").count()
    assert events_before == 1

    second = put_directory(client, world_a, body)
    assert second.status_code == 200 and not any(second.json().values())
    assert AuditEvent.all_organisations.filter(action="directory.snapshot_applied").count() == events_before

    # A person left off the next list is ended, and keeps their group membership so the gateway is told.
    third = put_directory(client, world_a, body.replace(str(world_a.person.pk).encode(), str(uuid.uuid4()).encode()))
    assert third.json()["people_ended"] == 1
    ended = Person.all_organisations.get(pk=world_a.person.pk)
    assert ended.status == "ended" and ended.ended_at is not None
    assert AccessGroupMember.all_organisations.filter(person=ended).exists()


def test_a_snapshot_that_would_end_everyone_is_refused_unless_it_says_so(client, world_a):
    rostering_world(world_a)
    empty = json.dumps({"people": [], "sites": []}).encode()
    refused = put_directory(client, world_a, empty)
    assert refused.status_code == 409 and "would end everyone" in refused.json()["detail"]
    assert refused.json()["code"] == "empty_snapshot"
    assert Person.all_organisations.get(pk=world_a.person.pk).status == "active"
    meant = put_directory(client, world_a, json.dumps({"people": [], "sites": [], "allow_empty": True}).encode())
    assert meant.status_code == 200 and meant.json()["people_ended"] == 1


@pytest.mark.parametrize(
    ("body", "code"),
    [
        ({"people": [{"person_ref": "{ref}", "name": "X", "date_of_birth": "1990-01-01"}], "sites": []}, "unexpected_field"),
        ({"people": [{"person_ref": "{ref}", "name": "X", "pay_rate": "42.50"}], "sites": []}, "unexpected_field"),
        (
            {
                "people": [{"person_ref": "{ref}", "name": "X"}],
                "sites": [{"site_ref": "{ref}", "name": "S", "notes": "alarm 1234"}],
            },
            "unexpected_field",
        ),
        ({"people": "everyone", "sites": []}, "invalid_request"),
        ({"sites": []}, "invalid_request"),
        ({"people": ["Sam"], "sites": []}, "invalid_request"),
        ([], "invalid_request"),
    ],
)  # fmt: skip
def test_a_bad_snapshot_is_refused_whole(client, world_a, body, code):
    """A snapshot that is not the contract's shape, or that carries a field the hub must never
    hold (rule 11), is refused whole: refused, not ignored, and not judged row by row."""
    rostering_world(world_a)
    ref = str(uuid.uuid4())
    before = list(Person.all_organisations.values()), list(Site.all_organisations.values())
    response = put_directory(client, world_a, json.dumps(body).replace("{ref}", ref).encode())
    assert response.status_code == 400 and response.json()["code"] == code
    assert (list(Person.all_organisations.values()), list(Site.all_organisations.values())) == before


def test_a_body_that_is_not_json_and_a_snapshot_that_is_too_large_are_refused_whole(client, world_a, monkeypatch):
    rostering_world(world_a)
    not_json = put_directory(client, world_a, b"{people")
    assert not_json.status_code == 400 and not_json.json()["code"] == "invalid_request"
    monkeypatch.setattr(directory, "MAX_SNAPSHOT_ROWS", 1)
    people = [{"person_ref": str(uuid.uuid4()), "name": "X"} for _ in range(2)]
    too_large = put_directory(client, world_a, json.dumps({"people": people, "sites": []}).encode())
    assert too_large.status_code == 400 and too_large.json()["code"] == "snapshot_too_large"
    assert Person.all_organisations.get(pk=world_a.person.pk).status == "active"


def kept(world) -> dict:
    """The world's own person and site as Rostering would send them, unchanged."""
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


@pytest.mark.parametrize(
    ("row", "reason"),
    [
        ({"person_ref": "{new}", "name": "   "}, "A person needs a name."),
        ({"person_ref": "{new}", "name": "​​"}, "A person needs a name."),
        ({"person_ref": "{new}", "name": 42}, "A person's name must be text."),
        ({"person_ref": "{new}", "name": "X", "status": "sacked"}, "A person's status must be active or ended."),
        ({"person_ref": "{new}", "name": "X", "work_email": ["a@b.test"]}, "A person's work_email must be text."),
        ({"person_ref": "not-a-uuid", "name": "X"}, "person_ref is not a UUID."),
        ({"name": "X"}, "person_ref is not a UUID."),
    ],
)
def test_a_row_the_hub_cannot_take_is_reported_and_every_other_row_is_applied(client, world_a, row, reason):
    """H2 of Rostering's review: one bad row must not hold back the rest of the list."""
    rostering_world(world_a)
    new, other = str(uuid.uuid4()), str(uuid.uuid4())
    bad = json.loads(json.dumps(row).replace("{new}", new))
    body = kept(world_a)
    body["people"] += [bad, {"person_ref": other, "name": "Taken On", "status": "active"}]
    response = put_directory(client, world_a, json.dumps(body).encode())
    assert response.status_code == 200, response.content
    data = response.json()
    assert data["people_created"] == 1 and data["rejected_count"] == 1
    assert data["rejected"] == [
        {"person_ref": bad.get("person_ref", ""), "code": "invalid_row", "reason": reason}
    ]  # fmt: skip
    assert Person.all_organisations.filter(pk=other).exists()
    assert not Person.all_organisations.filter(pk=new).exists()
    assert Person.all_organisations.get(pk=world_a.person.pk).status == "active"


def test_a_removal_is_never_held_back_by_a_bad_row(client, world_a):
    """The point of judging rows alone: the rows that end people are how access is removed at
    every door. Before, one unrelated bad name refused the list and the leaver kept their access."""
    rostering_world(world_a)
    with organisation_context(world_a.organisation):
        leaver = f.PersonFactory(organisation=world_a.organisation, name="Leaver", work_email="leaver@example.test")
        gone = f.PersonFactory(organisation=world_a.organisation, name="Gone")
    body = kept(world_a)
    body["people"] += [
        {"person_ref": str(uuid.uuid4()), "name": "", "status": "active"},  # the unrelated bad row
        # A removal whose own row is otherwise unacceptable: the removal is applied, nothing else.
        {"person_ref": str(leaver.pk), "name": "", "work_email": "changed@example.test", "status": "ended"},
        # `gone` is left out altogether: ended, as before.
    ]
    response = put_directory(client, world_a, json.dumps(body).encode())
    assert response.status_code == 200
    data = response.json()
    assert data["people_ended"] == 2 and data["rejected_count"] == 2
    ended_row = next(r for r in data["rejected"] if r["person_ref"] == str(leaver.pk))
    assert ended_row["code"] == "invalid_row" and "The person was ended" in ended_row["reason"]
    leaver = Person.all_organisations.get(pk=leaver.pk)
    assert (leaver.status, leaver.name, leaver.work_email) == ("ended", "Leaver", "leaver@example.test")
    assert leaver.ended_at is not None
    assert Person.all_organisations.get(pk=gone.pk).status == "ended"
    # The gateway is told on its next pull.
    assert AuditEvent.all_organisations.get(action="directory.snapshot_applied").data["rows_rejected"] == 2

    # Sent again unchanged: nothing more changes, and the rejected rows are listed again.
    again = put_directory(client, world_a, json.dumps(body).encode())
    assert again.json()["people_ended"] == 0 and again.json()["rejected_count"] == 2
    assert AuditEvent.all_organisations.filter(action="directory.snapshot_applied").count() == 1


def test_a_rejected_row_leaves_whoever_it_names_exactly_as_they_were(client, world_a):
    """Named by a row the hub could not take is not "missing from the list": the person is neither
    updated nor ended, and the same for a site."""
    rostering_world(world_a)
    body = kept(world_a)
    body["people"][0] |= {"name": "", "work_email": "new@example.test"}
    body["sites"][0] |= {"name": "Renamed", "timezone": "Mars/Olympus"}
    site_ref = body["sites"][0]["site_ref"]
    with organisation_context(world_a.organisation):
        f.PersonFactory(
            organisation=world_a.organisation, name="Someone Else"
        )  # so the list still has an active person besides
    body["people"].append({"person_ref": str(uuid.uuid4()), "name": "Someone New"})
    before_person = Person.all_organisations.filter(pk=world_a.person.pk).values().get()
    before_site = Site.all_organisations.filter(pk=site_ref).values().get()
    data = put_directory(client, world_a, json.dumps(body).encode()).json()
    assert {(r.get("person_ref") or r.get("site_ref"), r["code"]) for r in data["rejected"]} == {
        (str(world_a.person.pk), "invalid_row"),
        (site_ref, "invalid_row"),
    }
    assert Person.all_organisations.filter(pk=world_a.person.pk).values().get() == before_person
    assert Site.all_organisations.filter(pk=site_ref).values().get() == before_site
    assert data["sites_deactivated"] == 0 and data["sites_updated"] == 0


def test_a_site_is_made_inactive_even_when_the_rest_of_its_row_is_bad(client, world_a):
    rostering_world(world_a)
    body = kept(world_a)
    body["sites"][0] |= {"name": "", "is_active": False}
    data = put_directory(client, world_a, json.dumps(body).encode()).json()
    site = Site.all_organisations.get(pk=body["sites"][0]["site_ref"])
    assert not site.is_active and site.name  # inactive, and still carrying its old name
    assert data["sites_deactivated"] == 1 and "made inactive" in data["rejected"][0]["reason"]
    # is_active that is neither true nor false is not a removal: the site is left as it was.
    body = kept(world_a)
    body["sites"][1] |= {"is_active": "no"}
    data = put_directory(client, world_a, json.dumps(body).encode()).json()
    assert data["rejected"][-1]["reason"] == "A site's is_active must be true or false."
    assert Site.all_organisations.get(pk=body["sites"][1]["site_ref"]).is_active


def test_a_reference_sent_twice_is_refused_for_both_rows_and_changes_nobody(client, world_a):
    rostering_world(world_a)
    body = kept(world_a)
    body["people"].append(body["people"][0] | {"name": "A Second Name", "status": "ended"})
    with organisation_context(world_a.organisation):
        f.PersonFactory(organisation=world_a.organisation, name="Someone Else")
    body["people"].append({"person_ref": str(uuid.uuid4()), "name": "Someone New"})
    data = put_directory(client, world_a, json.dumps(body).encode()).json()
    assert data["rejected_count"] == 2 and data["rejected"] == 2 * [
        {
            "person_ref": str(world_a.person.pk),
            "code": "duplicate_reference",
            "reason": "This person_ref appears more than once in the list.",
        }
    ]
    person = Person.all_organisations.get(pk=world_a.person.pk)
    assert (person.status, person.name) == ("active", world_a.person.name)


def test_rejected_rows_cannot_be_used_to_end_everyone_and_do_not_hide_that_a_list_would(client, world_a):
    """The guard is on the outcome. Rows the hub refuses leave their people as they were, so they
    neither count as "sent active" for someone new nor as an ending for someone held."""
    rostering_world(world_a)
    # Everyone held is left out, and the only "active" row is one the hub cannot take: nobody
    # would be left active, so this is still the empty snapshot.
    body = {"people": [{"person_ref": str(uuid.uuid4()), "name": "", "status": "active"}], "sites": []}
    refused = put_directory(client, world_a, json.dumps(body).encode())
    assert refused.status_code == 409 and refused.json()["code"] == "empty_snapshot"
    assert Person.all_organisations.get(pk=world_a.person.pk).status == "active"
    assert Site.all_organisations.get(pk=world_a.site.pk).is_active  # nothing was applied
    # The only person held is named by a row the hub cannot take: they stay active, so nothing
    # is ended and there is nothing to refuse.
    body = kept(world_a)
    body["people"][0]["name"] = ""
    accepted = put_directory(client, world_a, json.dumps(body).encode())
    assert accepted.status_code == 200 and accepted.json()["people_ended"] == 0
    assert Person.all_organisations.get(pk=world_a.person.pk).status == "active"


def test_at_most_a_hundred_rejected_rows_are_listed_and_the_count_is_exact(client, world_a):
    rostering_world(world_a)
    body = kept(world_a)
    body["people"] += [{"person_ref": str(uuid.uuid4()), "name": ""} for _ in range(130)]
    data = put_directory(client, world_a, json.dumps(body).encode()).json()
    assert data["rejected_count"] == 130 and len(data["rejected"]) == 100


# --- what a service may read about a site's gateway (H3 of Rostering's review) ---------------------


def site_rows(client, world) -> dict:
    response = client.get(reverse("api_sites"), **service_headers(world))
    assert response.status_code == 200
    return {row["site_ref"]: row for row in response.json()}


def test_sites_carry_the_hubs_view_of_each_gateway_and_nothing_about_a_door(client, world_a, settings):
    rows = site_rows(client, world_a)
    paired, unpaired = rows[str(world_a.site.pk)], rows[str(world_a.pairing_code.site_id)]
    assert set(paired) == {
        "site_ref", "name", "address", "timezone", "is_active", "access_managed_elsewhere", "gateway",
    }  # fmt: skip
    assert unpaired["gateway"] == {"status": "none", "last_contact_at": None, "access_confirmed": False}
    # In contact, nothing reported, access not yet acknowledged.
    assert set(paired["gateway"]) == {"status", "last_contact_at", "access_confirmed"}
    assert paired["gateway"]["status"] == "ok" and paired["gateway"]["access_confirmed"] is False
    seen = Gateway.all_organisations.get(pk=world_a.gateway.pk).last_seen_at
    assert paired["gateway"]["last_contact_at"] == seen.strftime("%Y-%m-%dT%H:%M:%SZ")
    # The fixture's gateway reported a door; none of it may leave by this call (no door names,
    # states or modes: this says how far to trust attendance from a site, not what a door does).
    assert "front door" not in json.dumps(rows) and "locked" not in json.dumps(rows)

    # Acknowledging the current access confirms it; a change in the hub unconfirms it again.
    version = get_access(client, world_a).json()["version"]
    call_gateway(client, "api_gateway_access_ack", world_a, world_a, {"version": version, "failures": []})
    assert site_rows(client, world_a)[str(world_a.site.pk)]["gateway"]["access_confirmed"] is True
    with organisation_context(world_a.organisation):
        directory.end_person(world_a.person, actor=actor(world_a, "manager"))
    assert site_rows(client, world_a)[str(world_a.site.pk)]["gateway"]["access_confirmed"] is False

    # What the gateway says about itself, then silence.
    for reported, expected in (("degraded", "degraded"), ("ok", "ok"), ("something new", "degraded")):
        state = {"doors": [], "health": {"status": reported, "detail": "", "queued_events": 3}}
        assert call_gateway(client, "api_gateway_state", world_a, world_a, state).status_code == 204
        assert site_rows(client, world_a)[str(world_a.site.pk)]["gateway"]["status"] == expected
    with organisation_context(world_a.organisation):
        Gateway.objects.update(
            last_seen_at=timezone.now() - timezone.timedelta(seconds=settings.GATEWAY_OUT_OF_CONTACT_SECONDS + 5)
        )
    silent = site_rows(client, world_a)[str(world_a.site.pk)]["gateway"]
    assert silent["status"] == "out_of_contact" and silent["last_contact_at"] is not None


def test_a_revoked_gateway_and_a_site_run_by_another_system_have_no_gateway(client, world_a):
    with organisation_context(world_a.organisation):
        gateways.revoke_gateway(world_a.gateway, actor=actor(world_a, "admin"))
    assert site_rows(client, world_a)[str(world_a.site.pk)]["gateway"]["status"] == "none"
    with organisation_context(world_a.organisation):
        directory.set_access_managed_elsewhere(world_a.site, actor=actor(world_a, "admin"), elsewhere=True)
    row = site_rows(client, world_a)[str(world_a.site.pk)]
    assert row["access_managed_elsewhere"] is True and row["gateway"]["status"] == "none"


def test_reading_sites_costs_the_same_however_many_have_no_gateway(client, world_a, django_assert_max_num_queries):
    with organisation_context(world_a.organisation):
        for n in range(20):
            f.SiteFactory(organisation=world_a.organisation, name=f"Unpaired {n}")
    client.get(reverse("api_sites"), **service_headers(world_a))  # the token's last-used time is set now
    with django_assert_max_num_queries(12):
        assert len(site_rows(client, world_a)) == 22


# --- every refusal carries a code (H1 of Rostering's review) ---------------------------------------


def test_every_refusal_of_a_service_call_says_why_in_a_code(client, world_a):
    from hub.api.models import ServiceToken

    def refused(response, status, code):
        assert response.status_code == status, response.content
        body = response.json()
        assert set(body) == {"detail", "code"} and body["code"] == code and body["detail"]

    url = reverse("api_directory")
    put = lambda body, **headers: client.put(url, data=body, content_type="application/json", **headers)  # noqa: E731
    # No credential, and one nothing recognises.
    refused(put(directory_body(world_a)), 401, "not_authenticated")
    refused(put(directory_body(world_a), HTTP_AUTHORIZATION="Bearer hubsvc_wrong"), 401, "token_not_accepted")
    refused(put(directory_body(world_a), **gateway_headers(world_a)), 401, "token_not_accepted")
    # The two 403s a caller could not tell apart before.
    refused(put_directory(client, world_a, directory_body(world_a)), 403, "directory_source_is_hub")
    rostering_world(world_a)
    with organisation_context(world_a.organisation):
        ServiceToken.objects.update(scopes=["events:read"])
    missing = put_directory(client, world_a, directory_body(world_a))
    refused(missing, 403, "missing_scope")
    assert "directory:write" in missing.json()["detail"]
    refused(client.get(reverse("api_sites"), **service_headers(world_a)), 403, "missing_scope")
    # ...and a token that lacks one scope still works for the ones it has.
    assert client.get(reverse("api_events"), **service_headers(world_a)).status_code == 200
    refused(client.get(f"{reverse('api_events')}?after=abc", **service_headers(world_a)), 400, "invalid_request")
    refused(client.post(reverse("api_events"), **service_headers(world_a)), 405, "method_not_allowed")
    with organisation_context(world_a.organisation):
        ServiceToken.objects.update(revoked_at=timezone.now())
    refused(client.get(reverse("api_events"), **service_headers(world_a)), 401, "token_not_accepted")


def test_every_refusal_of_a_gateway_call_says_why_in_a_code(client, world_a, world_b):
    def refused(response, status, code):
        assert response.status_code == status, response.content
        assert response.json()["code"] == code and response.json()["detail"]

    access = reverse("api_gateway_access", kwargs={"site_ref": world_a.site.pk})
    refused(client.get(access), 401, "not_authenticated")
    refused(client.get(access, HTTP_AUTHORIZATION="Bearer hubgw_wrong"), 401, "token_not_accepted")
    refused(call_gateway(client, "api_gateway_access", world_a, world_b), 404, "not_found")
    refused(call_gateway(client, "api_gateway_access_ack", world_a, world_a, {"version": "x"}), 400, "invalid_request")
    refused(call_gateway(client, "api_gateway_state", world_a, world_a, {"doors": "all"}), 400, "invalid_request")
    url = reverse("api_gateway_events", kwargs={"site_ref": world_a.site.pk})
    unsigned = client.post(url, data=b'{"events": []}', content_type="application/json", **gateway_headers(world_a))
    refused(unsigned, 400, "invalid_signature")


def test_a_user_token_refusal_says_the_role_is_too_low(client, world_a):
    from tests.isolation.test_api import token_for

    headers = token_for(world_a, "staff")
    response = client.get(reverse("api_members"), **headers)
    assert response.status_code == 403 and response.json()["code"] == "role_too_low"
    assert client.get(reverse("api_sites"), **headers).json()["code"] == "role_too_low"
    assert client.get(reverse("api_me"), HTTP_AUTHORIZATION="Bearer nonsense").json()["code"] == "token_not_accepted"


def test_rostering_follows_the_event_stream_with_a_cursor(client, world_a):
    post_events(
        client,
        world_a,
        [envelope(world_a) for _ in range(3)] + [envelope(world_a, type="door.forced", person_ref=None)],
    )
    url = reverse("api_events")
    first = client.get(f"{url}?after=0&limit=2&type=attendance", **service_headers(world_a)).json()
    assert len(first["events"]) == 2 and first["more"] is True
    assert set(first["events"][0]) == {
        "cursor",
        "id",
        "type",
        "occurred_at",
        "org_ref",
        "site_ref",
        "person_ref",
        "data",
    }
    rest = client.get(f"{url}?after={first['next_cursor']}&type=attendance", **service_headers(world_a)).json()
    assert len(rest["events"]) == 2 and rest["more"] is False
    assert all(e["type"].startswith("attendance.") for e in first["events"] + rest["events"])
    cursors = [e["cursor"] for e in first["events"] + rest["events"]]
    assert cursors == sorted(cursors) and rest["next_cursor"] == cursors[-1]
    # Nothing new: the cursor comes back unchanged, so a reader can poll forever.
    idle = client.get(f"{url}?after={rest['next_cursor']}&type=attendance", **service_headers(world_a)).json()
    assert idle == {"events": [], "next_cursor": rest["next_cursor"], "more": False}
    assert client.get(f"{url}?after=abc", **service_headers(world_a)).status_code == 400


# --- service tokens and the console ---------------------------------------------------------------


def test_only_an_owner_connects_another_system_and_the_token_is_shown_once(client, world_a):
    f.sign_in(client, world_a.admin, mfa=True)
    slug = world_a.organisation.slug
    url = reverse("service_token_create", kwargs={"org_slug": slug})
    assert client.post(url, {"name": "Rostering", "scopes": ["events:read"]}).status_code == 403

    f.sign_in(client, world_a.owner, mfa=True)
    assert client.post(url, {"name": "Rostering", "scopes": ["directory:write", "events:read"]}).status_code == 302
    page = client.get(reverse("org_settings", kwargs={"org_slug": slug})).content.decode()
    token = next(part for part in page.replace("<", " ").replace(">", " ").split() if part.startswith("hubsvc_"))
    assert client.get(reverse("api_events"), HTTP_AUTHORIZATION=f"Bearer {token}").status_code == 200
    assert client.get(reverse("api_people"), HTTP_AUTHORIZATION=f"Bearer {token}").status_code == 403  # scope not given
    # Shown once: gone on the next view, and never stored.
    assert token not in client.get(reverse("org_settings", kwargs={"org_slug": slug})).content.decode()
    from hub.api.models import ServiceToken

    assert token not in str(ServiceToken.all_organisations.values())
    assert "service_token.created" in audit_actions(world_a)


def test_pairing_code_is_shown_once_in_the_console(client, world_a):
    f.sign_in(client, world_a.admin, mfa=True)
    slug, site = world_a.organisation.slug, world_a.pairing_code.site
    assert (
        client.post(reverse("gateway_pairing_code", kwargs={"org_slug": slug, "site_id": site.pk})).status_code == 302
    )
    detail = reverse("site_detail", kwargs={"org_slug": slug, "site_id": site.pk})
    page = client.get(detail).content.decode()
    import re

    code = re.search(r"\b[A-Z2-9]{4}-[A-Z2-9]{4}-[A-Z2-9]{4}\b", page).group(0)
    assert code not in client.get(detail).content.decode()
    assert pair(client, code).status_code == 201
    assert "No gateway is paired" not in client.get(detail).content.decode()


def test_console_pages_say_when_rostering_owns_the_directory(client, world_a):
    rostering_world(world_a)
    f.sign_in(client, world_a.owner, mfa=True)
    slug = world_a.organisation.slug
    for name in ("person_list", "site_list"):
        page = client.get(reverse(name, kwargs={"org_slug": slug})).content.decode()
        assert "Pulsar Rostering" in page
    response = client.post(reverse("person_create", kwargs={"org_slug": slug}), {"name": "Sneaky"}, follow=True)
    assert "managed in Pulsar Rostering" in response.content.decode()
    assert not Person.all_organisations.filter(name="Sneaky").exists()


def test_ending_someone_needs_no_second_factor_prompt_but_reactivating_does(client, world_a, settings):
    from tests.test_hardening import age_session

    f.sign_in(client, world_a.manager, mfa=True)
    age_session(client, settings.MFA_STEP_UP_MAX_AGE + 60)
    kwargs = {"org_slug": world_a.organisation.slug, "person_id": world_a.person.pk}
    assert client.post(reverse("person_end", kwargs=kwargs))["Location"].endswith(f"/people/{world_a.person.pk}/")
    assert Person.all_organisations.get(pk=world_a.person.pk).status == "ended"
    assert client.post(reverse("person_reactivate", kwargs=kwargs))["Location"].startswith(
        reverse("mfa_reauthenticate")
    )
    assert Person.all_organisations.get(pk=world_a.person.pk).status == "ended"
    assert "access.person_ended" in audit_actions(world_a)


def test_names_reach_a_gateway_as_plain_single_line_text(client, world_a):
    """A gateway refuses a whole snapshot over one control character, and a refused snapshot means
    no removal reaches the site. So odd names are made plain, both when stored and when sent."""
    with organisation_context(world_a.organisation):
        person = directory.create_person(actor=actor(world_a, "manager"), name="  Sam\tLee\n(night​shift)\x00  ")
        assert person.name == "Sam Lee (night shift)"
        group = access.create_group(actor=actor(world_a, "admin"), name=" Night\r\nstaff ")
        assert group.name == "Night staff"
        # A name that got into the database some other way is still sent plain.
        Person.objects.filter(pk=world_a.person.pk).update(name="Odd\tName\n")
        type(group).objects.filter(pk=group.pk).update(name="Odd\tGroup ")
        access.add_person_to_group(group, world_a.person, actor=actor(world_a, "manager"))
        access.set_group_sites(group, [world_a.site], actor=actor(world_a, "admin"))
    snapshot = get_access(client, world_a).json()
    texts = [p["name"] for p in snapshot["people"]] + snapshot["access_groups"]
    texts += [g for p in snapshot["people"] for g in p["access_groups"]]
    assert "Odd Name" in texts and "Odd Group" in texts
    for text in texts:
        assert text == text.strip() and text and all(ch.isprintable() for ch in text), repr(text)
    # Every group a person carries is declared at the top level.
    assert {g for p in snapshot["people"] for g in p["access_groups"]} <= set(snapshot["access_groups"])
