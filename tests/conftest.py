from dataclasses import dataclass, field

import pytest
from django.core.cache import cache
from django.utils import timezone

from hub.organisations.context import current_organisation
from hub.organisations.models import Organisation, Role, hash_token
from tests import factories as f


@pytest.fixture(autouse=True)
def _clean_state():
    """Rate-limit counters live in the cache; no test may leave an organisation current."""
    cache.clear()
    assert current_organisation() is None
    yield
    assert current_organisation() is None, "a test left an organisation current"


@dataclass
class World:
    """One organisation with a member in every role and one row of every business model."""

    organisation: Organisation
    marker: str
    owner: object = None
    admin: object = None
    manager: object = None
    staff: object = None
    memberships: dict = field(default_factory=dict)
    invitation: object = None
    identity_provider: object = None
    operator_access: object = None
    site: object = None
    person: object = None
    access_group: object = None
    pairing_code: object = None
    gateway: object = None
    gateway_credential: str = ""
    event: object = None
    service_token: object = None
    service_token_value: str = ""
    connected_app: object = None
    console_session: object = None

    def user(self, role: str):
        return getattr(self, role)


def make_world(letter: str) -> World:
    # The marker appears in every text field of the organisation's rows. The isolation suite
    # searches every response given to the other organisation for it.
    marker = f"ZZ{letter}MARKERZZ"
    organisation = f.OrganisationFactory(name=f"{marker} Pty Ltd", slug=f"world-{letter.lower()}")
    world = World(organisation=organisation, marker=marker)
    for role in (Role.OWNER, Role.ADMIN, Role.MANAGER, Role.STAFF):
        user = f.UserFactory(email=f"{role}.{marker.lower()}@example.test", name=f"{marker} {role.label}")
        world.memberships[role.value] = f.MembershipFactory(organisation=organisation, user=user, role=role)
        setattr(world, role.value, user)
    world.invitation = f.InvitationFactory(organisation=organisation, email=f"invitee.{marker.lower()}@example.test")
    world.identity_provider = f.IdentityProviderFactory(
        organisation=organisation, tenant=f"{marker.lower()}.example.test"
    )
    world.operator_access = f.OperatorAccessFactory(
        organisation=organisation,
        operator=f.UserFactory(email=f"operator.{marker.lower()}@pulsar.test", is_platform_operator=True),
        reason=f"{marker} support visit",
    )
    # H2 and H3: a site with a paired gateway, a person in an access group that opens the site,
    # an event from the gateway, an unused pairing code and a service token.
    world.site = f.SiteFactory(organisation=organisation, name=f"{marker} Clinic", address=f"1 {marker} Street")
    world.person = f.PersonFactory(
        organisation=organisation, name=f"{marker} Nurse", work_email=f"nurse.{marker.lower()}@example.test"
    )
    world.access_group = f.AccessGroupFactory(organisation=organisation, name=f"{marker} Nurses")
    f.AccessGroupMemberFactory(organisation=organisation, access_group=world.access_group, person=world.person)
    f.AccessGroupSiteFactory(organisation=organisation, access_group=world.access_group, site=world.site)
    world.gateway_credential = f"hubgw_{marker.lower()}_credential"
    world.gateway = f.GatewayFactory(
        organisation=organisation,
        site=world.site,
        name=f"{marker} gateway",
        credential_hash=hash_token(world.gateway_credential),
        state={"doors": [{"door_ref": "front", "name": f"{marker} front door", "state": "locked", "mode": "normal"}]},
    )
    world.pairing_code = f.PairingCodeFactory(
        organisation=organisation,
        site=f.SiteFactory(organisation=organisation, name=f"{marker} Depot"),
        code_hash=hash_token(f"{letter}AAA-BBBB-CCCC"),
    )
    world.event = f.GatewayEventFactory(
        organisation=organisation,
        site=world.site,
        gateway=world.gateway,
        person=world.person,
        data={"door": f"{marker} front door"},
    )
    world.service_token_value = f"hubsvc_{marker.lower()}_token"
    world.service_token = f.ServiceTokenFactory(
        organisation=organisation, name=f"{marker} rostering", token_hash=hash_token(world.service_token_value)
    )
    # The product launcher: one connected product whose address carries the marker.
    world.connected_app = f.ConnectedAppFactory(
        organisation=organisation,
        product_key="rostering",
        base_address=f"https://rostering.{marker.lower()}.example.test",
        connected_by=world.owner,
    )
    # The remote console: one session, long over, whose browser details carry the marker.
    world.console_session = f.ConsoleSessionFactory(
        organisation=organisation,
        gateway=world.gateway,
        user=world.owner,
        user_agent=f"{marker} browser",
        origin=f"https://{marker.lower()}.console.test",
        ended_at=timezone.now(),
        end_reason="user",
    )
    return world


@pytest.fixture
def world_a(db) -> World:
    return make_world("A")


@pytest.fixture
def world_b(db) -> World:
    return make_world("B")


@pytest.fixture
def operator(db):
    return f.UserFactory(email="operator@pulsar.test", is_platform_operator=True)
