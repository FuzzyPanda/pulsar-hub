"""Organisation lifecycle, invitations, roles and operator visits."""

import pytest
from django.core import mail
from django.core.exceptions import PermissionDenied, ValidationError
from django.db import connection, transaction
from django.utils import timezone

from hub.accounts.models import AccessToken, User
from hub.audit.models import AuditEvent
from hub.organisations import services
from hub.organisations.context import organisation_context
from hub.organisations.models import Invitation, Membership, OperatorAccess, Organisation, Role
from hub.organisations.services import Actor
from tests import factories as f

pytestmark = pytest.mark.django_db


def actor(world, role):
    return Actor(world.user(role), world.memberships[role])


def actions(organisation=None):
    return list(
        AuditEvent.all_organisations.filter(organisation=organisation)
        .order_by("occurred_at")
        .values_list("action", flat=True)
    )


# --- provisioning ---------------------------------------------------------------------------------


def test_provision_creates_the_organisation_and_invites_the_owner(operator):
    organisation, invitation, token = services.provision_organisation(
        name="Harbour Dental", owner_email="Owner@Harbour.Test", operator=operator
    )
    assert organisation.slug == "harbour-dental" and organisation.is_active
    assert invitation.email == "owner@harbour.test" and invitation.role == Role.OWNER
    assert invitation.organisation_id == organisation.pk
    assert services.find_pending_invitation(token).pk == invitation.pk
    assert len(mail.outbox) == 1 and token in mail.outbox[0].body
    assert actions(organisation) == ["organisation.provisioned", "member.invited"]
    # The token itself is never stored.
    assert token not in str(Invitation.all_organisations.filter(pk=invitation.pk).values())


def test_only_an_operator_can_provision(world_a):
    with pytest.raises(PermissionDenied):
        services.provision_organisation(name="X", owner_email="x@example.test", operator=world_a.owner)


def test_slugs_are_unique_and_never_reserved(operator):
    first, *_ = services.provision_organisation(name="Admin", owner_email="a@example.test", operator=operator)
    second, *_ = services.provision_organisation(name="Admin", owner_email="b@example.test", operator=operator)
    assert first.slug == "admin-org" and second.slug == "admin-org-2"


# --- invitations ----------------------------------------------------------------------------------


def test_owner_invited_through_to_membership(operator):
    organisation, invitation, token = services.provision_organisation(
        name="Harbour Dental", owner_email="owner@harbour.test", operator=operator
    )
    user = f.UserFactory(email="owner@harbour.test")
    membership = services.accept_invitation(services.find_pending_invitation(token), user=user)
    assert membership.role == Role.OWNER and membership.organisation_id == organisation.pk
    assert services.find_pending_invitation(token) is None  # single use
    assert "member.joined" in actions(organisation)


def test_invitation_is_bound_to_its_email_address(world_a):
    _invitation, token = _invite(world_a, "new@example.test", Role.STAFF)
    with pytest.raises(PermissionDenied):
        services.accept_invitation(
            services.find_pending_invitation(token), user=f.UserFactory(email="other@example.test")
        )


def _invite(world, email, role, by="owner"):
    with organisation_context(world.organisation):
        return services.invite_member(actor=actor(world, by), email=email, role=role)


def test_expired_and_revoked_invitations_do_nothing(world_a):
    invitation, token = _invite(world_a, "new@example.test", Role.STAFF)
    with organisation_context(world_a.organisation):
        services.revoke_invitation(invitation, actor=actor(world_a, "admin"))
    assert services.find_pending_invitation(token) is None

    invitation, token = _invite(world_a, "late@example.test", Role.STAFF)
    with organisation_context(world_a.organisation):
        Invitation.objects.filter(pk=invitation.pk).update(expires_at=timezone.now())
    assert services.find_pending_invitation(token) is None


def test_reinviting_replaces_the_earlier_link(world_a):
    _first, first_token = _invite(world_a, "new@example.test", Role.STAFF)
    _second, second_token = _invite(world_a, "new@example.test", Role.MANAGER)
    assert services.find_pending_invitation(first_token) is None
    assert services.find_pending_invitation(second_token) is not None


@pytest.mark.parametrize(
    ("by", "role", "allowed"),
    [
        ("owner", Role.OWNER, True),
        ("owner", Role.ADMIN, True),
        ("admin", Role.MANAGER, True),
        ("admin", Role.STAFF, True),
        ("admin", Role.ADMIN, False),
        ("admin", Role.OWNER, False),
        ("manager", Role.STAFF, False),
        ("staff", Role.STAFF, False),
    ],
)
def test_who_may_invite_whom(world_a, by, role, allowed):
    if allowed:
        _invite(world_a, "new@example.test", role, by=by)
    else:
        with pytest.raises(PermissionDenied):
            _invite(world_a, "new@example.test", role, by=by)


def test_a_visiting_operator_cannot_create_owners_or_admins(world_a):
    visiting = Actor(world_a.operator_access.operator, None, world_a.operator_access)
    with organisation_context(world_a.organisation):
        services.invite_member(actor=visiting, email="s@example.test", role=Role.STAFF)
        for role in (Role.OWNER, Role.ADMIN):
            with pytest.raises(PermissionDenied):
                services.invite_member(actor=visiting, email="o@example.test", role=role)


def test_an_existing_member_cannot_be_invited_again(world_a):
    with pytest.raises(ValidationError):
        _invite(world_a, world_a.staff.email, Role.STAFF)


# --- roles ----------------------------------------------------------------------------------------


def test_role_change_is_audited_and_revokes_tokens(world_a):
    token = _token(world_a, "staff")
    with organisation_context(world_a.organisation):
        services.change_role(world_a.memberships["staff"], actor=actor(world_a, "owner"), new_role=Role.MANAGER)
        assert Membership.objects.get(pk=world_a.memberships["staff"].pk).role == Role.MANAGER
    event = AuditEvent.all_organisations.get(action="member.role_changed")
    assert event.data == {"from": "staff", "to": "manager"} and event.actor == world_a.owner
    assert not AccessToken.objects.filter(pk=token.pk).exists()


def _token(world, role):
    return f.issue_access_token(world.user(role), world.organisation, f"token-{world.marker}-{role}")


def test_nobody_changes_their_own_role(world_a):
    with organisation_context(world_a.organisation), pytest.raises(PermissionDenied):
        services.change_role(world_a.memberships["owner"], actor=actor(world_a, "owner"), new_role=Role.STAFF)


def test_admin_cannot_touch_owners_or_admins(world_a):
    with organisation_context(world_a.organisation):
        with pytest.raises(PermissionDenied):
            services.change_role(world_a.memberships["owner"], actor=actor(world_a, "admin"), new_role=Role.STAFF)
        with pytest.raises(PermissionDenied):
            services.change_role(world_a.memberships["staff"], actor=actor(world_a, "admin"), new_role=Role.ADMIN)
        with pytest.raises(PermissionDenied):
            services.remove_member(world_a.memberships["owner"], actor=actor(world_a, "admin"))


def test_the_last_owner_cannot_leave_or_be_demoted(world_a):
    second = f.MembershipFactory(organisation=world_a.organisation, role=Role.OWNER)
    with organisation_context(world_a.organisation):
        services.remove_member(second, actor=actor(world_a, "owner"))
        with pytest.raises(ValidationError):
            services.remove_member(world_a.memberships["owner"], actor=actor(world_a, "owner"))
        assert Membership.objects.get(pk=world_a.memberships["owner"].pk).is_active


def test_removed_member_loses_tokens_and_can_be_reinvited(world_a):
    token = _token(world_a, "staff")
    with organisation_context(world_a.organisation):
        services.remove_member(world_a.memberships["staff"], actor=actor(world_a, "admin"))
    assert not AccessToken.objects.filter(pk=token.pk).exists()
    assert services.resolve_access(world_a.staff, world_a.organisation) == (None, None)
    assert User.objects.filter(pk=world_a.staff.pk).exists()  # the login is untouched

    _invitation, invite_token = _invite(world_a, world_a.staff.email, Role.MANAGER)
    membership = services.accept_invitation(services.find_pending_invitation(invite_token), user=world_a.staff)
    assert membership.is_active and membership.role == Role.MANAGER


# --- sign-in rules --------------------------------------------------------------------------------


def test_only_an_owner_changes_sign_in_rules(world_a):
    with organisation_context(world_a.organisation):
        with pytest.raises(PermissionDenied):
            services.update_security_settings(
                actor=actor(world_a, "admin"), staff_mfa_required=True, sso_required=False
            )
        services.update_security_settings(actor=actor(world_a, "owner"), staff_mfa_required=True, sso_required=True)
    world_a.organisation.refresh_from_db()
    assert world_a.organisation.staff_mfa_required and world_a.organisation.sso_required
    assert AuditEvent.all_organisations.get(action="organisation.security_changed").data == {
        "staff_mfa_required": {"from": False, "to": True},
        "sso_required": {"from": False, "to": True},
    }


def test_sso_cannot_be_required_without_an_identity_provider(world_a):
    with organisation_context(world_a.organisation):
        services.remove_identity_provider(world_a.identity_provider, actor=actor(world_a, "owner"))
        with pytest.raises(ValidationError):
            services.update_security_settings(
                actor=actor(world_a, "owner"), staff_mfa_required=False, sso_required=True
            )


def test_staff_mfa_follows_the_organisation_setting(world_a):
    assert world_a.memberships["manager"].mfa_required
    assert not world_a.memberships["staff"].mfa_required
    world_a.organisation.staff_mfa_required = True
    assert world_a.memberships["staff"].mfa_required


# --- operator visits ------------------------------------------------------------------------------


def test_operator_access_is_time_limited_and_audited(operator, world_a, settings):
    assert services.resolve_access(operator, world_a.organisation) == (None, None)
    with pytest.raises(ValidationError):
        services.open_operator_access(world_a.organisation, operator=operator, reason="")
    access = services.open_operator_access(world_a.organisation, operator=operator, reason="Ticket 42", hours=999)
    assert access.expires_at - access.starts_at == timezone.timedelta(hours=settings.OPERATOR_ACCESS_MAX_HOURS)
    assert services.resolve_access(operator, world_a.organisation)[1].pk == access.pk
    event = AuditEvent.all_organisations.get(action="operator.access_opened")
    assert event.organisation == world_a.organisation and event.actor_kind == "operator"
    assert event.data["reason"] == "Ticket 42"

    with organisation_context(world_a.organisation):
        OperatorAccess.objects.filter(pk=access.pk).update(expires_at=timezone.now())
    assert services.resolve_access(operator, world_a.organisation) == (None, None)


def test_owner_can_end_an_operator_visit(world_a):
    access = world_a.operator_access
    with organisation_context(world_a.organisation):
        services.end_operator_access(access, ended_by=world_a.owner)
    assert services.resolve_access(access.operator, world_a.organisation) == (None, None)
    assert "operator.access_ended" in actions(world_a.organisation)


def test_a_former_operator_keeps_no_access(world_a):
    access = world_a.operator_access
    User.objects.filter(pk=access.operator_id).update(is_platform_operator=False)
    access.operator.refresh_from_db()
    assert services.resolve_access(access.operator, world_a.organisation) == (None, None)


# --- suspend, export, delete ----------------------------------------------------------------------


def test_suspend_and_reactivate(operator, world_a):
    token = _token(world_a, "staff")
    services.suspend_organisation(world_a.organisation, operator=operator, reason="Unpaid")
    world_a.organisation.refresh_from_db()
    assert world_a.organisation.status == Organisation.Status.SUSPENDED
    assert not AccessToken.objects.filter(pk=token.pk).exists()
    services.reactivate_organisation(world_a.organisation, operator=operator)
    world_a.organisation.refresh_from_db()
    assert world_a.organisation.is_active
    assert actions(world_a.organisation)[-2:] == ["organisation.suspended", "organisation.reactivated"]


def test_export_holds_one_organisation_and_no_secrets(world_a, world_b):
    data = services.export_organisation(world_a.organisation, actor_user=world_a.owner)
    text = str(data)
    assert world_a.marker in text and world_b.marker not in text
    assert data["organisation"]["org_ref"] == str(world_a.organisation.pk)
    assert len(data["records"]["organisations.Membership"]) == 4
    assert "token_hash" not in text and "password" not in text
    assert world_a.invitation.token_hash not in text
    # Every business model is in the export without being listed by hand.
    from django.apps import apps

    from hub.organisations.scoping import OrganisationScopedModel

    for model in apps.get_models():
        if issubclass(model, OrganisationScopedModel):
            assert model._meta.label in data["records"]


def test_delete_removes_everything_of_one_organisation_only(operator, world_a, world_b):
    _token(world_a, "staff")
    org_ref = world_a.organisation.pk
    with pytest.raises(ValidationError):
        services.delete_organisation(world_a.organisation, operator=operator, confirm_slug="wrong")
    services.delete_organisation(world_a.organisation, operator=operator, confirm_slug=world_a.organisation.slug)

    assert not Organisation.objects.filter(pk=org_ref).exists()
    from django.apps import apps

    from hub.organisations.scoping import OrganisationScopedModel

    for model in apps.get_models():
        if issubclass(model, OrganisationScopedModel):
            assert not model.all_organisations.filter(organisation_id=org_ref).exists(), model
            assert model.all_organisations.filter(organisation=world_b.organisation).exists(), model
    assert not AccessToken.objects.filter(organisation_id=org_ref).exists()
    assert not AuditEvent.all_organisations.filter(organisation_id=org_ref).exists()
    record = AuditEvent.all_organisations.get(action="organisation.deleted")
    assert record.organisation is None and record.data["org_ref"] == str(org_ref)
    assert User.objects.filter(pk=world_a.owner.pk).exists()  # logins survive; they may belong elsewhere


# --- the audit log is append-only -----------------------------------------------------------------


def test_audit_events_cannot_be_changed_or_deleted(world_a):
    with organisation_context(world_a.organisation):
        from hub.audit import services as audit

        event = audit.record("test.event", actor=world_a.owner)
    event.action = "tampered"
    with pytest.raises(TypeError):
        event.save()
    with pytest.raises(TypeError):
        event.delete()
    # And not through the database either.
    for sql in (
        "UPDATE audit_auditevent SET action = 'tampered' WHERE id = %s",
        "DELETE FROM audit_auditevent WHERE id = %s",
    ):
        with pytest.raises(Exception, match="append-only"), transaction.atomic(), connection.cursor() as cursor:
            cursor.execute(sql, [event.pk])
    assert AuditEvent.all_organisations.get(pk=event.pk).action == "test.event"


def test_deleting_a_login_keeps_its_audit_trail(world_a):
    with organisation_context(world_a.organisation):
        from hub.audit import services as audit

        event = audit.record("test.event", actor=world_a.staff)
        Membership.objects.filter(user=world_a.staff).delete()
    world_a.staff.delete()
    event = AuditEvent.all_organisations.get(pk=event.pk)
    assert event.actor is None and event.actor_label == world_a.staff.email


# --- mail outages and the first owner -------------------------------------------------------------


def test_a_mail_outage_does_not_undo_the_invitation(operator, settings):
    settings.EMAIL_BACKEND = "django.core.mail.backends.smtp.EmailBackend"
    settings.EMAIL_HOST, settings.EMAIL_PORT = "127.0.0.1", 9  # nothing listens here
    organisation, invitation, token = services.provision_organisation(
        name="Harbour Dental", owner_email="owner@harbour.test", operator=operator
    )
    assert invitation.email_sent is False
    assert Organisation.objects.filter(pk=organisation.pk).exists()
    assert services.find_pending_invitation(token) is not None


def test_operator_can_resend_the_owner_invitation_until_there_is_an_owner(operator):
    organisation, _invitation, first_token = services.provision_organisation(
        name="Harbour Dental", owner_email="typo@harbour.test", operator=operator
    )
    assert organisation.pk in services.organisations_without_owner()
    _invitation, token = services.invite_first_owner(organisation, owner_email="owner@harbour.test", operator=operator)
    assert services.find_pending_invitation(first_token) is not None  # a different address: both stand
    services.accept_invitation(services.find_pending_invitation(token), user=f.UserFactory(email="owner@harbour.test"))

    assert organisation.pk not in services.organisations_without_owner()
    with pytest.raises(PermissionDenied):
        services.invite_first_owner(organisation, owner_email="second@harbour.test", operator=operator)


def test_only_an_operator_can_send_the_first_owner_invitation(world_a, operator):
    with pytest.raises(PermissionDenied):
        services.invite_first_owner(world_a.organisation, owner_email="x@example.test", operator=world_a.owner)
    with pytest.raises(PermissionDenied):  # world_a has an owner
        services.invite_first_owner(world_a.organisation, owner_email="x@example.test", operator=operator)
