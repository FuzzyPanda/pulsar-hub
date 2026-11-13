"""Rule 1 on every console route: a user of organisation A gets nothing from organisation B."""

import json

import pytest
from django.apps import apps
from django.urls import URLPattern, URLResolver, get_resolver, reverse

from hub.organisations.models import Organisation, Role
from hub.organisations.scoping import OrganisationScopedModel
from tests import factories as f
from tests.isolation.routes import API_ROUTES, NON_ORGANISATION_PREFIXES, ORG_ROUTES

pytestmark = [pytest.mark.isolation, pytest.mark.django_db]

ROLES = ["owner", "admin", "manager", "staff"]
OPERATOR_OBJECT_ROUTES = ["operator_open_access", "operator_invite_owner", "operator_set_status", "operator_delete"]


def all_routes(resolver=None, prefix=""):
    """(full route pattern, url name) for every pattern Django will serve."""
    resolver = resolver or get_resolver()
    for entry in resolver.url_patterns:
        pattern = prefix + str(entry.pattern)
        if isinstance(entry, URLResolver):
            yield from all_routes(entry, pattern)
        elif isinstance(entry, URLPattern):
            yield pattern, entry.name


def snapshot(organisation) -> str:
    """Every business row of one organisation, to prove a request changed nothing."""
    state = {"organisation": Organisation.objects.filter(pk=organisation.pk).values().first()}
    for model in apps.get_models():
        if issubclass(model, OrganisationScopedModel):
            rows = model.all_organisations.filter(organisation=organisation).order_by("pk").values()
            state[model._meta.label] = list(rows)
    return json.dumps(state, default=str, sort_keys=True)


def call(client, name, route, slug_world, object_world):
    url = reverse(name, kwargs={"org_slug": slug_world.organisation.slug, **route.kwargs(object_world)})
    if route.method == "POST":
        return client.post(url, route.data(object_world))
    return client.get(url)


# --- completeness: no route escapes the suite -----------------------------------------------------


def test_every_route_is_accounted_for():
    org_names, api_names, unknown = set(), set(), []
    for pattern, name in all_routes():
        if pattern.startswith("org/<slug:org_slug>/"):
            org_names.add(name)
        elif pattern.startswith("api/v1/"):
            api_names.add(name)
        elif "org_slug" in pattern:
            unknown.append(f"{pattern}: takes org_slug but is not under /org/<org_slug>/")
        elif not any(pattern.lstrip("^").startswith(p) for p in NON_ORGANISATION_PREFIXES if p) and pattern != "":
            unknown.append(f"{pattern}: not under a known prefix")
    assert not unknown, unknown
    assert org_names == set(ORG_ROUTES), (
        "tests/isolation/routes.py ORG_ROUTES is out of step with hub/organisations/urls.py: "
        f"missing {org_names - set(ORG_ROUTES)}, stale {set(ORG_ROUTES) - org_names}"
    )
    assert api_names == set(API_ROUTES), (
        f"API_ROUTES is out of step: missing {api_names - set(API_ROUTES)}, stale {set(API_ROUTES) - api_names}"
    )


def test_org_views_declare_the_role_this_suite_expects():
    """The role in ORG_ROUTES is what the view enforces, so the table cannot drift from the code."""
    resolver = get_resolver()
    for name, route in ORG_ROUTES.items():
        url = reverse(
            name, kwargs={"org_slug": "x", **{k: "00000000-0000-0000-0000-000000000000" for k in _kwarg_names(name)}}
        )
        view = resolver.resolve(url).func
        assert getattr(view, "organisation_view", False), f"{name}: declare it with org_path() in urls.py"
        assert getattr(view, "minimum_role", Role.STAFF) == route.minimum_role, name
        assert _has_step_up(view) == route.step_up, name


def _kwarg_names(name):
    for pattern, route_name in all_routes():
        if route_name == name:
            import re

            return [k for k in re.findall(r"<(?:\w+:)?(\w+)>", pattern) if k != "org_slug"]
    raise AssertionError(name)


def _has_step_up(view) -> bool:
    while view is not None:
        if getattr(view, "step_up_required", False):
            return True
        view = getattr(view, "__wrapped__", None)
    return False


# --- the boundary -------------------------------------------------------------------------------


@pytest.mark.parametrize("name", ORG_ROUTES)
def test_anonymous_gets_the_login_page(client, world_a, name):
    route = ORG_ROUTES[name]
    before = snapshot(world_a.organisation)
    response = call(client, name, route, world_a, world_a)
    assert response.status_code == 302 and response["Location"].startswith("/accounts/login/")
    assert snapshot(world_a.organisation) == before


@pytest.mark.parametrize("role", ROLES)
@pytest.mark.parametrize("name", ORG_ROUTES)
def test_member_of_a_gets_404_from_b(client, world_a, world_b, name, role):
    """Every role of A, fully signed in with MFA, asking for B's address."""
    route = ORG_ROUTES[name]
    f.sign_in(client, world_a.user(role), mfa=True)
    before = snapshot(world_b.organisation)
    response = call(client, name, route, world_b, world_b)
    assert response.status_code == 404
    assert world_b.marker not in response.content.decode()
    assert snapshot(world_b.organisation) == before


class _AnyWorld:
    """Stands in for a World when all that is wanted is whether a route takes object ids."""

    def __getattr__(self, name):
        return _AnyWorld()

    def __getitem__(self, key):
        return _AnyWorld()


ROUTES_WITH_OBJECT_IDS = [name for name, route in ORG_ROUTES.items() if route.kwargs(_AnyWorld())]


@pytest.mark.parametrize("name", ROUTES_WITH_OBJECT_IDS)
def test_owner_of_a_cannot_reach_bs_rows_through_as_address(client, world_a, world_b, name):
    """A's own address, B's object ids: the scoped manager must not find them."""
    route = ORG_ROUTES[name]
    f.sign_in(client, world_a.owner, mfa=True)
    before_a, before_b = snapshot(world_a.organisation), snapshot(world_b.organisation)
    response = call(client, name, route, world_a, world_b)
    assert response.status_code == 404
    assert world_b.marker not in response.content.decode()
    assert snapshot(world_b.organisation) == before_b
    assert snapshot(world_a.organisation) == before_a


@pytest.mark.parametrize("role", ROLES)
@pytest.mark.parametrize("name", [n for n, r in ORG_ROUTES.items() if r.method == "GET"])
def test_pages_of_a_never_contain_bs_data(client, world_a, world_b, name, role):
    route = ORG_ROUTES[name]
    f.sign_in(client, world_a.user(role), mfa=True)
    response = call(client, name, route, world_a, world_a)
    allowed = Role(role).at_least(route.minimum_role)
    assert response.status_code == (200 if allowed else 403), (name, role)
    body = response.content.decode()
    assert world_b.marker not in body and world_b.marker.lower() not in body
    if allowed and name in ("org_home", "member_list", "org_settings"):
        assert world_a.marker in body  # the page really did render A's data


@pytest.mark.parametrize("name", ORG_ROUTES)
def test_roles_below_the_minimum_are_refused_and_change_nothing(client, world_a, name):
    route = ORG_ROUTES[name]
    for role in ROLES:
        if Role(role).at_least(route.minimum_role):
            continue
        f.sign_in(client, world_a.user(role), mfa=True)
        before = snapshot(world_a.organisation)
        response = call(client, name, route, world_a, world_a)
        assert response.status_code == 403, (name, role)
        assert snapshot(world_a.organisation) == before


@pytest.mark.parametrize("name", [n for n, r in ORG_ROUTES.items() if r.method == "POST"])
def test_write_routes_refuse_get(client, world_a, name):
    route = ORG_ROUTES[name]
    f.sign_in(client, world_a.owner, mfa=True)
    url = reverse(name, kwargs={"org_slug": world_a.organisation.slug, **route.kwargs(world_a)})
    assert client.get(url).status_code == 405


def test_owner_export_contains_only_a(client, world_a, world_b):
    f.sign_in(client, world_a.owner, mfa=True)
    response = client.post(reverse("org_export", kwargs={"org_slug": world_a.organisation.slug}))
    assert response.status_code == 200 and response["Content-Type"] == "application/json"
    body = response.content.decode()
    assert world_a.marker in body and world_b.marker not in body


def test_home_lists_only_the_users_own_organisations(client, world_a, world_b):
    user = f.UserFactory()
    f.MembershipFactory(organisation=world_a.organisation, user=user)
    f.MembershipFactory(organisation=f.OrganisationFactory(name="Second Place"), user=user)
    f.sign_in(client, user)
    body = client.get("/").content.decode()
    assert world_a.marker in body and "Second Place" in body and world_b.marker not in body


# --- Pulsar operators ---------------------------------------------------------------------------


@pytest.mark.parametrize("name", ORG_ROUTES)
def test_operator_without_a_visit_gets_404(client, world_a, operator, name):
    route = ORG_ROUTES[name]
    f.sign_in(client, operator, mfa=True)
    before = snapshot(world_a.organisation)
    assert call(client, name, route, world_a, world_a).status_code == 404
    assert snapshot(world_a.organisation) == before


@pytest.mark.parametrize("name", ORG_ROUTES)
def test_operator_visiting_b_gets_404_from_a(client, world_a, world_b, name):
    route = ORG_ROUTES[name]
    f.sign_in(client, world_b.operator_access.operator, mfa=True)
    assert call(client, name, route, world_a, world_a).status_code == 404
    if route.kwargs(world_a):
        # The organisation the operator is visiting, with A's object ids: not found there.
        before = snapshot(world_a.organisation)
        assert call(client, name, route, world_b, world_a).status_code in (404, 403)
        assert snapshot(world_a.organisation) == before


def test_operator_visit_reads_one_organisation_and_changes_nothing(client, world_a, world_b):
    operator = world_a.operator_access.operator
    f.sign_in(client, operator, mfa=True)
    slug = world_a.organisation.slug
    for name in ("org_home", "member_list", "org_settings", "audit_list"):
        page = client.get(reverse(name, kwargs={"org_slug": slug}))
        assert page.status_code == 200, name
        assert world_b.marker not in page.content.decode()
    # Every write route, called as the visiting operator, leaves the organisation exactly as it was.
    before = snapshot(world_a.organisation)
    for name, route in ORG_ROUTES.items():
        if route.method == "POST" and name != "operator_access_end":
            response = call(client, name, route, world_a, world_a)
            assert response.status_code in (302, 403), name
    assert snapshot(world_a.organisation) == before


def test_operator_must_have_passed_mfa(client, world_a):
    f.sign_in(client, world_a.operator_access.operator)
    response = client.get(reverse("org_home", kwargs={"org_slug": world_a.organisation.slug}))
    assert response.status_code == 302 and response["Location"].startswith("/accounts/2fa/")


def test_expired_and_ended_visits_open_nothing(client, world_a):
    from django.utils import timezone

    from hub.organisations.context import organisation_context
    from hub.organisations.models import OperatorAccess

    operator = world_a.operator_access.operator
    f.sign_in(client, operator, mfa=True)
    url = reverse("org_home", kwargs={"org_slug": world_a.organisation.slug})
    assert client.get(url).status_code == 200
    with organisation_context(world_a.organisation):
        OperatorAccess.objects.update(expires_at=timezone.now())
    assert client.get(url).status_code == 404


def test_operator_console_is_hidden_from_everyone_else(client, world_a):
    for user in (world_a.owner, world_a.staff):
        f.sign_in(client, user, mfa=True)
        assert client.get("/operator/").status_code == 404
        assert (
            client.post("/operator/organisations/", {"name": "X", "owner_email": "x@example.test"}).status_code == 404
        )
        for name in OPERATOR_OBJECT_ROUTES:
            url = reverse(name, kwargs={"org_ref": world_a.organisation.pk})
            assert client.post(url, {"reason": "because", "action": "suspend"}).status_code == 404
    world_a.organisation.refresh_from_db()
    assert world_a.organisation.is_active


def test_every_operator_route_is_operator_only():
    """The table above cannot fall behind urls.py, and each view carries the operator check."""
    resolver = get_resolver()
    names = {name for pattern, name in all_routes() if pattern.startswith("operator/")}
    assert names == {"operator_home", "operator_provision", *OPERATOR_OBJECT_ROUTES}
    for pattern, name in all_routes():
        if pattern.startswith("operator/"):
            kwargs = {"org_ref": "00000000-0000-0000-0000-000000000000"} if "org_ref" in pattern else {}
            assert getattr(resolver.resolve(reverse(name, kwargs=kwargs)).func, "operator_only", False), name


def test_operator_console_shows_names_and_status_only(client, world_a, world_b, operator):
    f.sign_in(client, operator, mfa=True)
    body = client.get("/operator/").content.decode()
    assert world_a.organisation.name in body and world_b.organisation.name in body
    # No member, invitation or identity-provider data of any organisation.
    for world in (world_a, world_b):
        assert world.owner.email not in body
        assert world.invitation.email not in body
        assert world.identity_provider.tenant not in body


# --- other states -------------------------------------------------------------------------------


def test_suspended_organisation_is_closed_to_members(client, world_a):
    Organisation.objects.filter(pk=world_a.organisation.pk).update(status=Organisation.Status.SUSPENDED)
    f.sign_in(client, world_a.owner, mfa=True)
    for name, route in ORG_ROUTES.items():
        assert call(client, name, route, world_a, world_a).status_code == 403, name


def test_an_org_view_called_without_the_middleware_still_checks_entry(rf, world_a, world_b):
    """allauth replays an interrupted request by calling the view directly. That path must pass
    the same checks, not skip them."""
    from django.contrib.sessions.backends.db import SessionStore
    from django.http import Http404

    from hub.organisations.context import current_organisation
    from hub.organisations.middleware import OrganisationMiddleware

    resolver = get_resolver()
    for name, route in ORG_ROUTES.items():
        url = reverse(name, kwargs={"org_slug": world_b.organisation.slug, **route.kwargs(world_b)})
        match = resolver.resolve(url)
        request = rf.post(url, route.data(world_b)) if route.method == "POST" else rf.get(url)
        request.user = world_a.owner  # a member of A, calling B's view with no middleware in front
        request.session = SessionStore()
        before = snapshot(world_b.organisation)
        try:
            with pytest.raises(Http404):
                match.func(request, *match.args, **match.kwargs)
        finally:
            OrganisationMiddleware._clear(request)
        assert snapshot(world_b.organisation) == before
        assert current_organisation() is None


def test_the_organisation_is_never_left_current_after_a_request(client, world_a):
    from hub.organisations.context import current_organisation

    f.sign_in(client, world_a.owner, mfa=True)
    slug = world_a.organisation.slug
    client.get(reverse("org_home", kwargs={"org_slug": slug}))
    assert current_organisation() is None
    client.get(f"/org/{slug}/members/00000000-0000-0000-0000-000000000000/role/")  # 405
    client.post(f"/org/{slug}/invitations/00000000-0000-0000-0000-000000000000/revoke/")  # 404 inside the view
    assert current_organisation() is None
