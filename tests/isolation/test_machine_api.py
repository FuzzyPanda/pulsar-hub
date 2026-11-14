"""Rule 1 for machines: a gateway sees one site, a service token one organisation."""

import hashlib
import hmac
import json
import uuid

import pytest
from django.urls import reverse
from django.utils import timezone

from hub.directory.models import Person, Site
from hub.gateways.models import Gateway, GatewayEvent
from hub.organisations.context import current_organisation, organisation_context
from hub.organisations.models import Organisation
from tests.isolation.routes import API_ROUTES, GATEWAY_API_ROUTES, SERVICE_API_ROUTES
from tests.isolation.test_routes import snapshot

pytestmark = [pytest.mark.isolation, pytest.mark.django_db]


def gateway_headers(world, body: bytes | None = None) -> dict:
    headers = {"HTTP_AUTHORIZATION": f"Bearer {world.gateway_credential}"}
    if body is not None:
        signature = hmac.new(world.gateway_credential.encode(), body, hashlib.sha256).hexdigest()
        headers["HTTP_X_HUB_SIGNATURE"] = f"sha256={signature}"
    return headers


def service_headers(world) -> dict:
    return {"HTTP_AUTHORIZATION": f"Bearer {world.service_token_value}"}


def envelope(world, **overrides) -> dict:
    return {
        "id": str(uuid.uuid4()),
        "type": "attendance.clock_in",
        "occurred_at": timezone.now().strftime("%Y-%m-%dT%H:%M:%SZ"),
        "org_ref": str(world.organisation.pk),
        "site_ref": str(world.site.pk),
        "person_ref": str(world.person.pk),
        "data": {"door": "Front door", "door_ref": "front"},
    } | overrides


def call_gateway(client, name, caller, site_world, payload=None):
    """Call a gateway route as `caller`'s gateway, addressing `site_world`'s site."""
    url = reverse(name, kwargs={"site_ref": site_world.site.pk})
    if API_ROUTES[name].method == "GET":
        return client.get(url, **gateway_headers(caller))
    body = json.dumps(payload if payload is not None else {}).encode()
    return client.post(url, data=body, content_type="application/json", **gateway_headers(caller, body))


def gateway_payload(name, world):
    return {
        "api_gateway_access_ack": {"version": "0123456789abcdef", "failures": []},
        "api_gateway_events": {"events": [envelope(world)]},
        "api_gateway_state": {"doors": [], "health": {"status": "ok"}},
    }.get(name)


# --- gateways -------------------------------------------------------------------------------------


@pytest.mark.parametrize("name", GATEWAY_API_ROUTES)
def test_gateway_calls_need_the_credential(client, world_a, name):
    url = reverse(name, kwargs={"site_ref": world_a.site.pk})
    before = snapshot(world_a.organisation)
    for headers in ({}, {"HTTP_AUTHORIZATION": "Bearer hubgw_wrong"}, {"HTTP_AUTHORIZATION": "Bearer nonsense"}):
        response = client.get(url, **headers) if API_ROUTES[name].method == "GET" else client.post(url, **headers)
        assert response.status_code == 401, (name, headers)
        assert world_a.marker not in response.content.decode()
    assert snapshot(world_a.organisation) == before


@pytest.mark.parametrize("name", GATEWAY_API_ROUTES)
def test_gateway_of_a_gets_404_for_bs_site_and_changes_nothing(client, world_a, world_b, name):
    before = snapshot(world_b.organisation)
    response = call_gateway(client, name, world_a, world_b, gateway_payload(name, world_b))
    assert response.status_code == 404
    assert world_b.marker not in response.content.decode()
    assert snapshot(world_b.organisation) == before
    assert current_organisation() is None


def test_gateway_gets_404_for_another_site_of_its_own_organisation(client, world_a):
    """The credential is bound to one site, not to the organisation."""
    url = reverse("api_gateway_access", kwargs={"site_ref": world_a.pairing_code.site_id})
    assert client.get(url, **gateway_headers(world_a)).status_code == 404


def test_desired_access_holds_only_this_sites_people(client, world_a, world_b):
    response = call_gateway(client, "api_gateway_access", world_a, world_a)
    assert response.status_code == 200
    body = response.content.decode()
    assert world_b.marker not in body and str(world_b.person.pk) not in body
    data = response.json()
    assert data["org_ref"] == str(world_a.organisation.pk) and data["site_ref"] == str(world_a.site.pk)
    assert [p["person_ref"] for p in data["people"]] == [str(world_a.person.pk)]


def test_events_naming_another_organisation_are_refused(client, world_a, world_b):
    """A's gateway cannot write an event about B's person, into B's site, or under B's org_ref."""
    events = [
        envelope(world_a, person_ref=str(world_b.person.pk)),
        envelope(world_a, site_ref=str(world_b.site.pk)),
        envelope(world_a, org_ref=str(world_b.organisation.pk)),
        envelope(world_a, org_ref=str(world_b.organisation.pk), site_ref=str(world_b.site.pk)),
        envelope(world_a),
    ]
    before_b = snapshot(world_b.organisation)
    response = call_gateway(client, "api_gateway_events", world_a, world_a, {"events": events})
    assert response.status_code == 200
    assert response.json()["accepted"] == 1 and len(response.json()["rejected"]) == 4
    assert snapshot(world_b.organisation) == before_b
    stored = GatewayEvent.all_organisations.filter(event_id__in=[e["id"] for e in events])
    assert [e.organisation_id for e in stored] == [world_a.organisation.pk]


def test_an_event_id_already_used_by_b_does_not_collide(client, world_a, world_b):
    """The idempotency key is per organisation: A cannot learn of, or block, B's event ids."""
    response = call_gateway(
        client, "api_gateway_events", world_a, world_a, {"events": [envelope(world_a, id=str(world_b.event.event_id))]}
    )
    assert response.json() == {"accepted": 1, "duplicates": 0, "rejected": []}


@pytest.mark.parametrize("name", GATEWAY_API_ROUTES)
def test_revoked_gateways_and_closed_organisations_are_refused(client, world_a, name):
    assert call_gateway(client, name, world_a, world_a, gateway_payload(name, world_a)).status_code in (200, 204)
    Organisation.objects.filter(pk=world_a.organisation.pk).update(status=Organisation.Status.SUSPENDED)
    assert call_gateway(client, name, world_a, world_a, gateway_payload(name, world_a)).status_code == 401
    Organisation.objects.filter(pk=world_a.organisation.pk).update(status=Organisation.Status.ACTIVE)
    with organisation_context(world_a.organisation):
        Gateway.objects.update(revoked_at=timezone.now())
    assert call_gateway(client, name, world_a, world_a, gateway_payload(name, world_a)).status_code == 401


def test_a_gateway_credential_is_not_a_user_or_service_credential(client, world_a):
    for name in ("api_me", "api_members", "api_people", "api_events"):
        assert client.get(reverse(name), **gateway_headers(world_a)).status_code in (401, 403), name
    body = json.dumps({"people": [], "sites": [], "allow_empty": True}).encode()
    response = client.put(
        reverse("api_directory"), data=body, content_type="application/json", **gateway_headers(world_a)
    )
    assert response.status_code in (401, 403)
    assert Person.all_organisations.filter(pk=world_a.person.pk, status="active").exists()


# --- service tokens -------------------------------------------------------------------------------


def directory_body(world, **overrides) -> bytes:
    return json.dumps(
        {
            "people": [{"person_ref": str(world.person.pk), "name": "Kept", "work_email": "", "status": "active"}],
            "sites": [{"site_ref": str(world.site.pk), "name": "Kept site", "timezone": "Australia/Melbourne"}],
        }
        | overrides
    ).encode()


def use_rostering(world):
    Organisation.objects.filter(pk=world.organisation.pk).update(directory_source="rostering")


@pytest.mark.parametrize("name", SERVICE_API_ROUTES)
def test_service_token_of_a_sees_and_changes_only_a(client, world_a, world_b, name):
    use_rostering(world_a)
    use_rostering(world_b)
    before_b = snapshot(world_b.organisation)
    if API_ROUTES[name].method == "PUT":
        response = client.put(
            reverse(name), data=directory_body(world_a), content_type="application/json", **service_headers(world_a)
        )
    else:
        response = client.get(reverse(name), **service_headers(world_a))
    assert response.status_code == 200, response.content
    body = response.content.decode()
    assert world_b.marker not in body and str(world_b.organisation.pk) not in body
    assert snapshot(world_b.organisation) == before_b
    assert current_organisation() is None


def test_a_snapshot_cannot_claim_or_touch_bs_people_or_sites(client, world_a, world_b):
    """A's Rostering sends ids that belong to B. Nothing of B changes, A is told only that the
    reference is in use, and A's own rows in the same list are applied as normal."""
    use_rostering(world_a)
    client.get(reverse("api_people"), **service_headers(world_a))  # so the token's last-used time is already set
    before_a, before_b = snapshot(world_a.organisation), snapshot(world_b.organisation)
    own = json.loads(directory_body(world_a))
    own["people"][0] |= {"name": world_a.person.name, "work_email": world_a.person.work_email}
    own["sites"] = [
        {"site_ref": str(site.pk), "name": site.name, "address": site.address, "timezone": site.timezone}
        for site in Site.all_organisations.filter(organisation=world_a.organisation)
    ]
    theirs_person = {"person_ref": str(world_b.person.pk), "name": "Taken", "status": "active"}
    theirs_site = {"site_ref": str(world_b.site.pk), "name": "Taken"}
    body = {"people": [*own["people"], theirs_person], "sites": [*own["sites"], theirs_site]}
    response = client.put(
        reverse("api_directory"),
        data=json.dumps(body).encode(),
        content_type="application/json",
        **service_headers(world_a),
    )
    assert response.status_code == 200
    data = response.json()
    assert world_b.marker not in response.content.decode()
    assert sorted((r.get("person_ref") or r.get("site_ref"), r["code"]) for r in data["rejected"]) == sorted(
        [(str(world_b.person.pk), "reference_in_use"), (str(world_b.site.pk), "reference_in_use")]
    )
    assert data["people_created"] == 0 and data["sites_created"] == 0
    assert snapshot(world_b.organisation) == before_b
    assert snapshot(world_a.organisation) == before_a  # A's own rows were unchanged, so nothing changed
    assert Person.all_organisations.get(pk=world_b.person.pk).name == world_b.person.name
    assert Site.all_organisations.get(pk=world_b.site.pk).organisation_id == world_b.organisation.pk

    # A list made only of B's ids would leave A with nobody: refused whole, and still nothing of B's.
    for body in (
        directory_body(world_a, people=[theirs_person]),
        directory_body(world_a, people=[theirs_person | {"status": "ended"}]),
    ):
        response = client.put(
            reverse("api_directory"), data=body, content_type="application/json", **service_headers(world_a)
        )
        assert response.status_code == 409 and world_b.marker not in response.content.decode()
    # ...and saying "ended" or "inactive" about B's rows removes nothing of B's.
    body = {
        "people": [*own["people"], theirs_person | {"status": "ended", "name": ""}],
        "sites": [*own["sites"], theirs_site | {"is_active": False, "name": ""}],
    }
    response = client.put(
        reverse("api_directory"),
        data=json.dumps(body).encode(),
        content_type="application/json",
        **service_headers(world_a),
    )
    assert response.status_code == 200 and response.json()["rejected_count"] == 2
    assert snapshot(world_b.organisation) == before_b
    assert snapshot(world_a.organisation) == before_a
    assert Person.all_organisations.get(pk=world_b.person.pk).status == "active"
    assert Site.all_organisations.get(pk=world_b.site.pk).is_active


def test_sites_show_a_only_as_gateways(client, world_a, world_b):
    """The gateway block on `GET /sites` is worked out per organisation: B's gateway, its contact
    time and its confirmation never colour A's answer."""
    with organisation_context(world_b.organisation):
        Gateway.objects.update(revoked_at=timezone.now())
    rows = {row["site_ref"]: row for row in client.get(reverse("api_sites"), **service_headers(world_a)).json()}
    assert set(rows) == {
        str(pk) for pk in Site.all_organisations.filter(organisation=world_a.organisation).values_list("pk", flat=True)
    }
    assert rows[str(world_a.site.pk)]["gateway"]["status"] == "ok"
    theirs = {row["site_ref"]: row for row in client.get(reverse("api_sites"), **service_headers(world_b)).json()}
    assert theirs[str(world_b.site.pk)]["gateway"]["status"] == "none"
    assert str(world_a.site.pk) not in theirs and current_organisation() is None


def test_the_organisation_cannot_be_named_by_a_service_caller(client, world_a, world_b):
    b = world_b.organisation
    response = client.get(
        f"{reverse('api_people')}?org={b.pk}&org_ref={b.pk}", HTTP_X_ORGANISATION=str(b.pk), **service_headers(world_a)
    )
    assert response.status_code == 200 and world_b.marker not in response.content.decode()


@pytest.mark.parametrize("name", SERVICE_API_ROUTES)
def test_service_tokens_need_the_scope_and_die_when_revoked(client, world_a, name):
    from hub.api.models import ServiceToken

    use_rostering(world_a)

    def call():
        if API_ROUTES[name].method == "PUT":
            return client.put(
                reverse(name), data=directory_body(world_a), content_type="application/json", **service_headers(world_a)
            )
        return client.get(reverse(name), **service_headers(world_a))

    assert call().status_code == 200
    with organisation_context(world_a.organisation):
        others = [s for s in ("directory:read", "directory:write", "events:read") if s != API_ROUTES[name].scope]
        ServiceToken.objects.update(scopes=others)
    assert call().status_code == 403
    with organisation_context(world_a.organisation):
        ServiceToken.objects.update(scopes=[API_ROUTES[name].scope], revoked_at=timezone.now())
    assert call().status_code == 401


def test_a_service_token_is_not_a_gateway_or_user_credential(client, world_a):
    assert client.get(reverse("api_me"), **service_headers(world_a)).status_code in (401, 403)
    url = reverse("api_gateway_access", kwargs={"site_ref": world_a.site.pk})
    assert client.get(url, **service_headers(world_a)).status_code in (401, 403)


def test_event_cursor_stream_holds_only_as_events(client, world_a, world_b):
    response = client.get(f"{reverse('api_events')}?after=0", **service_headers(world_a))
    data = response.json()
    assert [e["id"] for e in data["events"]] == [str(world_a.event.event_id)]
    assert data["events"][0]["org_ref"] == str(world_a.organisation.pk)
    assert data["next_cursor"] == world_a.event.pk and data["more"] is False


# --- pairing --------------------------------------------------------------------------------------


def test_pairing_binds_the_gateway_to_the_codes_own_site_only(client, world_a, world_b):
    before_b = snapshot(world_b.organisation)
    response = client.post(
        reverse("api_gateway_pair"),
        data=json.dumps({"code": "AAAA-BBBB-CCCC", "name": "R1100"}),
        content_type="application/json",
    )
    assert response.status_code == 201
    data = response.json()
    assert data["org_ref"] == str(world_a.organisation.pk) and data["site_ref"] == str(world_a.pairing_code.site_id)
    assert world_b.marker not in response.content.decode()
    assert snapshot(world_b.organisation) == before_b
    # The new credential opens that site and nothing else.
    headers = {"HTTP_AUTHORIZATION": f"Bearer {data['credential']}"}
    assert (
        client.get(reverse("api_gateway_access", kwargs={"site_ref": data["site_ref"]}), **headers).status_code == 200
    )
    for site in (world_a.site, world_b.site):
        assert client.get(reverse("api_gateway_access", kwargs={"site_ref": site.pk}), **headers).status_code == 404
