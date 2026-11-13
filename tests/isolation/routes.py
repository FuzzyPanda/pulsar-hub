"""Every route the hub serves, and what the isolation suite must do with it.

`test_routes.py` walks Django's URL resolver and fails if it finds a route that is not accounted
for here. Adding a view therefore means deciding, in this file, which kind of route it is:

* under `/org/<org_slug>/`: add it to ORG_ROUTES with how to call it, and the suite then proves a
  member of another organisation gets a 404 and changes nothing;
* under `/api/v1/`: add it to API_ROUTES; the suite proves the token's organisation is the only one
  it can see;
* anywhere else: it must sit under one of the prefixes below, none of which may show an
  organisation's data.
"""

from collections.abc import Callable
from dataclasses import dataclass, field

from hub.organisations.models import Role

# Prefixes whose routes hold no organisation's business data. Each has its own tests.
NON_ORGANISATION_PREFIXES = {
    "healthz": "liveness; no data",
    "readyz": "readiness; no data",
    "accounts/": "django-allauth: the signed-in user's own login, MFA, sessions",
    "oauth/": "OIDC endpoints; tokens are bound to one organisation (tests/test_oidc.py)",
    "admin/": "Django admin: platform records only, staff with MFA (tests/test_auth.py)",
    "operator/": "Pulsar operators: organisation names and status only (test_routes.py)",
    "invitations/": "one invitation, reached by its secret token (tests/test_auth.py)",
    "": "home: the signed-in user's own memberships",
}


@dataclass
class OrgRoute:
    method: str = "GET"
    minimum_role: Role = Role.STAFF
    # Builds the extra URL kwargs from a World (tests/conftest.py), so the same route can be aimed
    # at organisation A's rows or at organisation B's.
    kwargs: Callable = lambda world: {}
    data: Callable = lambda world: {}
    step_up: bool = False
    owner_member_only: bool = False  # a visiting operator may not use it


ORG_ROUTES: dict[str, OrgRoute] = {
    "org_home": OrgRoute(),
    "member_list": OrgRoute(minimum_role=Role.MANAGER),
    "member_role": OrgRoute(
        "POST",
        Role.ADMIN,
        kwargs=lambda w: {"membership_id": w.memberships["staff"].pk},
        data=lambda w: {"role": "manager"},
        step_up=True,
    ),
    "member_remove": OrgRoute(
        "POST", Role.ADMIN, kwargs=lambda w: {"membership_id": w.memberships["staff"].pk}, step_up=True
    ),
    "invitation_create": OrgRoute(
        "POST", Role.ADMIN, data=lambda w: {"email": f"new.{w.marker.lower()}@example.test", "role": "staff"}
    ),
    "invitation_revoke": OrgRoute("POST", Role.ADMIN, kwargs=lambda w: {"invitation_id": w.invitation.pk}),
    "org_settings": OrgRoute(minimum_role=Role.ADMIN),
    "org_security": OrgRoute("POST", Role.OWNER, data=lambda w: {"staff_mfa_required": "on"}, step_up=True),
    "identity_provider_add": OrgRoute(
        "POST", Role.OWNER, data=lambda w: {"provider": "google", "tenant": "added.example.test"}, step_up=True
    ),
    "identity_provider_remove": OrgRoute(
        "POST", Role.OWNER, kwargs=lambda w: {"idp_id": w.identity_provider.pk}, step_up=True
    ),
    "org_export": OrgRoute("POST", Role.OWNER, step_up=True, owner_member_only=True),
    "audit_list": OrgRoute(minimum_role=Role.ADMIN),
    "operator_access_end": OrgRoute("POST", Role.OWNER, kwargs=lambda w: {"access_id": w.operator_access.pk}),
}


@dataclass
class ApiRoute:
    minimum_role: Role = Role.STAFF
    methods: list = field(default_factory=lambda: ["GET"])


API_ROUTES: dict[str, ApiRoute] = {
    "api_me": ApiRoute(),
    "api_organisation": ApiRoute(),
    "api_members": ApiRoute(minimum_role=Role.MANAGER),
}
