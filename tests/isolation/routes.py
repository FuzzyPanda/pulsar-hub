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
from dataclasses import dataclass

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
    # Settings: where people and sites come from, and tokens for other systems.
    "directory_source": OrgRoute("POST", Role.OWNER, data=lambda w: {"source": "hub"}, step_up=True),
    "service_token_create": OrgRoute(
        "POST", Role.OWNER, data=lambda w: {"name": "New link", "scopes": ["events:read"]}, step_up=True
    ),
    "service_token_revoke": OrgRoute(
        "POST", Role.OWNER, kwargs=lambda w: {"token_id": w.service_token.pk}, step_up=True
    ),
    # Sites and people (H2).
    "site_list": OrgRoute(minimum_role=Role.MANAGER),
    "site_create": OrgRoute("POST", Role.ADMIN, data=lambda w: {"name": "New site"}),
    "site_detail": OrgRoute(minimum_role=Role.MANAGER, kwargs=lambda w: {"site_id": w.site.pk}),
    "site_update": OrgRoute(
        "POST",
        Role.ADMIN,
        kwargs=lambda w: {"site_id": w.site.pk},
        data=lambda w: {"name": "Renamed", "address": "", "timezone": "Australia/Sydney"},
    ),
    "site_access_mode": OrgRoute(
        "POST",
        Role.ADMIN,
        kwargs=lambda w: {"site_id": w.pairing_code.site_id},
        data=lambda w: {"elsewhere": "on"},
        step_up=True,
    ),  # fmt: skip
    "person_list": OrgRoute(minimum_role=Role.MANAGER),
    "person_create": OrgRoute("POST", Role.MANAGER, data=lambda w: {"name": "New person"}),
    "person_detail": OrgRoute(minimum_role=Role.MANAGER, kwargs=lambda w: {"person_id": w.person.pk}),
    "person_update": OrgRoute(
        "POST", Role.MANAGER, kwargs=lambda w: {"person_id": w.person.pk}, data=lambda w: {"name": "Renamed"}
    ),
    "person_end": OrgRoute("POST", Role.MANAGER, kwargs=lambda w: {"person_id": w.person.pk}),
    "person_reactivate": OrgRoute("POST", Role.MANAGER, kwargs=lambda w: {"person_id": w.person.pk}, step_up=True),
    # Access groups (H3).
    "group_list": OrgRoute(minimum_role=Role.MANAGER),
    "group_create": OrgRoute("POST", Role.ADMIN, data=lambda w: {"name": "New group"}),
    "group_detail": OrgRoute(minimum_role=Role.MANAGER, kwargs=lambda w: {"group_id": w.access_group.pk}),
    "group_update": OrgRoute(
        "POST", Role.ADMIN, kwargs=lambda w: {"group_id": w.access_group.pk}, data=lambda w: {"name": "Renamed"}
    ),
    "group_delete": OrgRoute("POST", Role.ADMIN, kwargs=lambda w: {"group_id": w.access_group.pk}, step_up=True),
    "group_sites": OrgRoute(
        "POST",
        Role.ADMIN,
        kwargs=lambda w: {"group_id": w.access_group.pk},
        data=lambda w: {"sites": []},
        step_up=True,
    ),  # fmt: skip
    "group_member_add": OrgRoute(
        "POST", Role.MANAGER, kwargs=lambda w: {"group_id": w.access_group.pk}, data=lambda w: {"person": w.person.pk}
    ),
    "group_member_remove": OrgRoute(
        "POST", Role.MANAGER, kwargs=lambda w: {"group_id": w.access_group.pk}, data=lambda w: {"person": w.person.pk}
    ),
    # Gateways and what they report (H3, H4).
    "gateway_pairing_code": OrgRoute(
        "POST", Role.ADMIN, kwargs=lambda w: {"site_id": w.pairing_code.site_id}, step_up=True
    ),
    "gateway_revoke": OrgRoute("POST", Role.ADMIN, kwargs=lambda w: {"gateway_id": w.gateway.pk}, step_up=True),
    "gateway_console_address": OrgRoute(
        "POST",
        Role.ADMIN,
        kwargs=lambda w: {"gateway_id": w.gateway.pk},
        data=lambda w: {"console_address": "https://changed.example.test/ui/"},
        step_up=True,
    ),
    "event_list": OrgRoute(minimum_role=Role.MANAGER),
    # Connected products (the Apps launcher).
    "app_connect": OrgRoute("POST", Role.OWNER, data=lambda w: {"product": "access_control"}, step_up=True),
    "app_update": OrgRoute(
        "POST",
        Role.OWNER,
        kwargs=lambda w: {"app_id": w.connected_app.pk},
        data=lambda w: {"base_address": "https://changed.example.test", "enabled": "on"},
        step_up=True,
    ),
    "app_disconnect": OrgRoute("POST", Role.OWNER, kwargs=lambda w: {"app_id": w.connected_app.pk}, step_up=True),
}


@dataclass
class ApiRoute:
    """`kind` is who may call it: a `user` token, a `service` token (optionally also a user of
    `minimum_role`), a paired `gateway`, or nobody in particular (`public`: the pairing call)."""

    kind: str = "user"
    minimum_role: Role | None = Role.STAFF
    scope: str = ""
    method: str = "GET"


API_ROUTES: dict[str, ApiRoute] = {
    "api_me": ApiRoute(),
    "api_organisation": ApiRoute(),
    "api_members": ApiRoute(minimum_role=Role.MANAGER),
    "api_people": ApiRoute("service", Role.MANAGER, "directory:read"),
    "api_sites": ApiRoute("service", Role.MANAGER, "directory:read"),
    "api_events": ApiRoute("service", Role.MANAGER, "events:read"),
    "api_directory": ApiRoute("service", None, "directory:write", "PUT"),
    "api_gateway_pair": ApiRoute("public", None, method="POST"),
    "api_gateway_access": ApiRoute("gateway", None),
    "api_gateway_access_ack": ApiRoute("gateway", None, method="POST"),
    "api_gateway_events": ApiRoute("gateway", None, method="POST"),
    "api_gateway_state": ApiRoute("gateway", None, method="POST"),
}
# Routes a signed-in person's app can call, with the least role that may.
USER_API_ROUTES = {name: route for name, route in API_ROUTES.items() if route.minimum_role is not None}
SERVICE_API_ROUTES = {name: route for name, route in API_ROUTES.items() if route.kind == "service"}
GATEWAY_API_ROUTES = {name: route for name, route in API_ROUTES.items() if route.kind == "gateway"}
