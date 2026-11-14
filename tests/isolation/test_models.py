"""Rule 1 at the model layer: the scoped manager, the write guards and the system checks."""

import pytest
from django.apps import apps
from django.core import checks

from hub.organisations.context import (
    CrossOrganisationAccess,
    NoOrganisationContext,
    current_organisation,
    organisation_context,
)
from hub.organisations.models import IdentityProvider, Invitation, Membership, OperatorAccess, Role
from hub.organisations.registry import GLOBAL_MODELS
from hub.organisations.scoping import OrganisationScopedModel
from tests import factories as f

pytestmark = [pytest.mark.isolation, pytest.mark.django_db]

SCOPED_MODELS = [m for m in apps.get_models() if issubclass(m, OrganisationScopedModel)]

# One factory per business model. `test_every_scoped_model_has_a_factory` fails when a model is
# added without one, which is what keeps every model inside this suite.
FACTORIES = {
    Membership: f.MembershipFactory,
    Invitation: f.InvitationFactory,
    IdentityProvider: f.IdentityProviderFactory,
    OperatorAccess: f.OperatorAccessFactory,
    f.Site: f.SiteFactory,
    f.Person: f.PersonFactory,
    f.AccessGroup: f.AccessGroupFactory,
    f.AccessGroupMember: f.AccessGroupMemberFactory,
    f.AccessGroupSite: f.AccessGroupSiteFactory,
    f.PairingCode: f.PairingCodeFactory,
    f.Gateway: f.GatewayFactory,
    f.GatewayEvent: f.GatewayEventFactory,
    f.ServiceToken: f.ServiceTokenFactory,
    f.ConnectedApp: f.ConnectedAppFactory,
}


def test_every_scoped_model_has_a_factory():
    missing = [m._meta.label for m in SCOPED_MODELS if m not in FACTORIES]
    assert not missing, f"add a factory and an entry in FACTORIES for: {missing}"


def test_system_checks_pass():
    assert not [e for e in checks.run_checks() if e.id and e.id.startswith("hub.")]


def test_every_hub_model_is_scoped_or_explained():
    for model in apps.get_models():
        if not model.__module__.startswith("hub."):
            continue
        scoped = issubclass(model, OrganisationScopedModel)
        assert scoped != (model._meta.label in GLOBAL_MODELS), model._meta.label


def test_global_models_registry_has_no_stale_entries():
    labels = {m._meta.label for m in apps.get_models()}
    assert set(GLOBAL_MODELS) <= labels


@pytest.mark.parametrize("model", SCOPED_MODELS, ids=lambda m: m._meta.label)
def test_no_organisation_means_no_rows(model, world_a):
    assert current_organisation() is None
    with pytest.raises(NoOrganisationContext):
        list(model.objects.all())
    with pytest.raises(NoOrganisationContext):
        model.objects.count()
    with pytest.raises(NoOrganisationContext):
        model.objects.filter(pk=None).exists()


@pytest.mark.parametrize("model", SCOPED_MODELS, ids=lambda m: m._meta.label)
def test_manager_returns_only_the_current_organisation(model, world_a, world_b):
    total = model.all_organisations.count()
    assert total >= 2
    with organisation_context(world_a.organisation):
        rows_a = list(model.objects.all())
    with organisation_context(world_b.organisation):
        rows_b = list(model.objects.all())
    assert rows_a and rows_b
    assert {r.organisation_id for r in rows_a} == {world_a.organisation.pk}
    assert {r.organisation_id for r in rows_b} == {world_b.organisation.pk}
    assert len(rows_a) + len(rows_b) == total


@pytest.mark.parametrize("model", SCOPED_MODELS, ids=lambda m: m._meta.label)
def test_a_row_of_b_cannot_be_fetched_by_pk_from_a(model, world_a, world_b):
    with organisation_context(world_b.organisation):
        row_b = model.objects.first()
    with organisation_context(world_a.organisation):
        assert not model.objects.filter(pk=row_b.pk).exists()
        with pytest.raises(model.DoesNotExist):
            model.objects.get(pk=row_b.pk)


@pytest.mark.parametrize("model", SCOPED_MODELS, ids=lambda m: m._meta.label)
def test_a_row_of_b_cannot_be_saved_or_deleted_from_a(model, world_a, world_b):
    with organisation_context(world_b.organisation):
        row_b = model.objects.first()
    with organisation_context(world_a.organisation):
        with pytest.raises(CrossOrganisationAccess):
            row_b.save()
        with pytest.raises(CrossOrganisationAccess):
            row_b.delete()
    with pytest.raises(NoOrganisationContext):
        row_b.save()
    with pytest.raises(NoOrganisationContext):
        row_b.delete()
    assert model.all_organisations.filter(pk=row_b.pk).exists()


@pytest.mark.parametrize("model", SCOPED_MODELS, ids=lambda m: m._meta.label)
def test_bulk_update_and_delete_touch_only_the_current_organisation(model, world_a, world_b):
    before_b = model.all_organisations.filter(organisation=world_b.organisation).count()
    with organisation_context(world_a.organisation):
        model.objects.all().delete()
    assert model.all_organisations.filter(organisation=world_a.organisation).count() == 0
    assert model.all_organisations.filter(organisation=world_b.organisation).count() == before_b


def test_new_rows_take_the_current_organisation(world_a):
    user = f.UserFactory()
    with organisation_context(world_a.organisation):
        membership = Membership.objects.create(user=user, role=Role.STAFF)
    assert membership.organisation_id == world_a.organisation.pk


def test_a_row_cannot_be_moved_to_another_organisation(world_a, world_b):
    with organisation_context(world_a.organisation):
        with pytest.raises(CrossOrganisationAccess):
            Membership.objects.update(organisation=world_b.organisation)
        with pytest.raises(CrossOrganisationAccess):
            Membership.objects.update(organisation_id=world_b.organisation.pk)
        membership = Membership.objects.first()
        membership.organisation = world_b.organisation
        with pytest.raises(CrossOrganisationAccess):
            membership.save()


def test_bulk_create_cannot_write_into_another_organisation(world_a, world_b):
    user = f.UserFactory()
    with organisation_context(world_a.organisation):
        with pytest.raises(CrossOrganisationAccess):
            Membership.objects.bulk_create([Membership(user=user, organisation=world_b.organisation)])
        created = Membership.objects.bulk_create([Membership(user=user)])
    assert created[0].organisation_id == world_a.organisation.pk


def test_reverse_relations_are_scoped(world_a, world_b):
    """`user.memberships` goes through the scoped manager too."""
    user = world_a.staff
    f.MembershipFactory(organisation=world_b.organisation, user=user)
    with pytest.raises(NoOrganisationContext):
        list(user.memberships.all())
    with organisation_context(world_a.organisation):
        assert [m.organisation_id for m in user.memberships.all()] == [world_a.organisation.pk]


def test_contexts_nest_and_unwind(world_a, world_b):
    with organisation_context(world_a.organisation):
        with organisation_context(world_b.organisation):
            assert current_organisation() == world_b.organisation
        assert current_organisation() == world_a.organisation
    assert current_organisation() is None


def test_context_is_cleared_when_the_block_raises(world_a):
    with pytest.raises(RuntimeError):
        with organisation_context(world_a.organisation):
            raise RuntimeError
    assert current_organisation() is None
