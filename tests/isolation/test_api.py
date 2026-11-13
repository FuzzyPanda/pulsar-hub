"""Rule 1 on the API: a token sees its own organisation and nothing else."""

import pytest
from django.urls import reverse
from django.utils import timezone

from hub.accounts.models import AccessToken
from hub.organisations.context import current_organisation, organisation_context
from hub.organisations.models import Membership, Organisation, Role
from tests import factories as f
from tests.isolation.routes import API_ROUTES

pytestmark = [pytest.mark.isolation, pytest.mark.django_db]

ROLES = ["owner", "admin", "manager", "staff"]


def token_for(world, role, *, expires_in=600) -> dict:
    token = AccessToken.objects.create(
        user=world.user(role),
        organisation=world.organisation,
        application=f.ApplicationFactory(),
        token=f"tok-{world.marker}-{role}",
        expires=timezone.now() + timezone.timedelta(seconds=expires_in),
        scope="openid profile email",
    )
    return {"HTTP_AUTHORIZATION": f"Bearer {token.token}"}


@pytest.mark.parametrize("name", API_ROUTES)
def test_no_token_no_data(client, world_a, name):
    response = client.get(reverse(name))
    assert response.status_code == 401
    assert world_a.marker not in response.content.decode()


@pytest.mark.parametrize("name", API_ROUTES)
def test_a_browser_session_is_not_an_api_credential(client, world_a, name):
    f.sign_in(client, world_a.owner, mfa=True)
    assert client.get(reverse(name)).status_code == 401


@pytest.mark.parametrize("role", ROLES)
@pytest.mark.parametrize("name", API_ROUTES)
def test_token_of_a_sees_only_a(client, world_a, world_b, name, role):
    route = API_ROUTES[name]
    response = client.get(reverse(name), **token_for(world_a, role))
    allowed = Role(role).at_least(route.minimum_role)
    assert response.status_code == (200 if allowed else 403), (name, role)
    body = response.content.decode()
    assert world_b.marker not in body and world_b.marker.lower() not in body
    assert str(world_b.organisation.pk) not in body
    if allowed:
        assert world_a.marker in body
    assert current_organisation() is None


@pytest.mark.parametrize("name", API_ROUTES)
def test_the_organisation_cannot_be_named_by_the_caller(client, world_a, world_b, name):
    """Only the token chooses the organisation: not a header, a query parameter or a body."""
    headers = token_for(world_a, "owner")
    b = world_b.organisation
    attempts = [
        {"path": f"{reverse(name)}?org={b.pk}&organisation={b.pk}&org_ref={b.pk}&org_slug={b.slug}"},
        {"path": reverse(name), "HTTP_X_ORGANISATION": str(b.pk), "HTTP_X_ORG_REF": str(b.pk)},
    ]
    for attempt in attempts:
        response = client.get(attempt.pop("path"), **headers, **attempt)
        assert response.status_code == 200
        body = response.content.decode()
        assert world_b.marker not in body and str(b.pk) not in body


def test_members_endpoint_lists_exactly_the_members_of_a(client, world_a, world_b):
    response = client.get(reverse("api_members"), **token_for(world_a, "manager"))
    emails = {row["email"] for row in response.json()}
    assert emails == {world_a.user(role).email for role in ROLES}
    assert set(response.json()[0]) == {"user_ref", "name", "email", "role"}


@pytest.mark.parametrize("name", API_ROUTES)
def test_dead_tokens(client, world_a, name):
    expired = token_for(world_a, "owner", expires_in=-1)
    assert client.get(reverse(name), **expired).status_code == 401

    AccessToken.objects.all().delete()
    live = token_for(world_a, "owner")
    assert client.get(reverse(name), **live).status_code == 200
    with organisation_context(world_a.organisation):
        Membership.objects.filter(user=world_a.owner).update(is_active=False)
    assert client.get(reverse(name), **live).status_code == 401


@pytest.mark.parametrize("status", [Organisation.Status.SUSPENDED, Organisation.Status.DELETING])
def test_tokens_of_an_inactive_organisation_are_refused(client, world_a, status):
    headers = token_for(world_a, "owner")
    Organisation.objects.filter(pk=world_a.organisation.pk).update(status=status)
    for name in API_ROUTES:
        assert client.get(reverse(name), **headers).status_code == 401


def test_a_deactivated_login_cannot_use_its_token(client, world_a):
    headers = token_for(world_a, "owner")
    type(world_a.owner).objects.filter(pk=world_a.owner.pk).update(is_active=False)
    assert client.get(reverse("api_me"), **headers).status_code == 401


@pytest.mark.parametrize("name", API_ROUTES)
def test_api_is_read_only_for_now(client, world_a, name):
    headers = token_for(world_a, "owner")
    for method in ("post", "put", "patch", "delete"):
        response = getattr(client, method)(reverse(name), data="{}", content_type="application/json", **headers)
        assert response.status_code == 405


def _keys(value) -> set[str]:
    if isinstance(value, dict):
        return {k.lower() for k in value} | {k for inner in value.values() for k in _keys(inner)}
    if isinstance(value, list):
        return {k for inner in value for k in _keys(inner)}
    return set()


def test_api_never_returns_fields_named_in_rule_11(client, world_a):
    forbidden = ("pay", "bank", "birth", "dob", "licence", "license", "address", "password", "token_hash")
    for name in API_ROUTES:
        response = client.get(reverse(name), **token_for(world_a, "owner"))
        AccessToken.objects.all().delete()
        keys = _keys(response.json())
        assert keys and not [k for k in keys if any(word in k for word in forbidden)], (name, keys)
