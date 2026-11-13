from dataclasses import dataclass, field

import pytest
from django.core.cache import cache

from hub.organisations.context import current_organisation
from hub.organisations.models import Organisation, Role
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
