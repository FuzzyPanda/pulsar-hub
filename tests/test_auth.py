"""Sign-in, invitations, two-step sign-in, step-up, sessions and single sign-on, driven through the
real django-allauth views."""

import time

import jwt
import pytest
from allauth.account.models import EmailAddress
from allauth.mfa.models import Authenticator
from allauth.mfa.totp.internal import auth as totp
from allauth.socialaccount.providers.oauth2.client import OAuth2Error
from django.core import mail
from django.core.cache import cache
from django.urls import reverse

from hub.accounts.entra.provider import tenant_from_id_token
from hub.accounts.models import User
from hub.audit.models import AuditEvent
from hub.organisations import services
from hub.organisations.context import organisation_context
from hub.organisations.models import Membership, Organisation, Role
from hub.organisations.services import Actor
from tests import factories as f

pytestmark = pytest.mark.django_db


def audit_actions(**filters):
    return list(AuditEvent.all_organisations.filter(**filters).order_by("occurred_at").values_list("action", flat=True))


def totp_code(secret: str) -> str:
    cache.clear()  # allauth refuses a code it has already seen in this period
    return totp.format_hotp_value(totp.hotp_value(secret, next(totp.yield_hotp_counters_from_time())))


def secret_of(user) -> str:
    from allauth.mfa.adapter import get_adapter

    authenticator = Authenticator.objects.get(user=user, type=Authenticator.Type.TOTP)
    return get_adapter().decrypt(authenticator.data["secret"])


def login(client, user, password=f.PASSWORD):
    return client.post("/accounts/login/", {"login": user.email, "password": password})


def invite(world, email, role=Role.STAFF, by="owner"):
    with organisation_context(world.organisation):
        return services.invite_member(actor=Actor(world.user(by), world.memberships[by]), email=email, role=role)


# --- password sign-in -----------------------------------------------------------------------------


def test_password_sign_in_and_out_are_audited(client, world_a):
    response = login(client, world_a.staff)
    assert response.status_code == 302 and response["Location"] == "/"
    assert client.get("/").status_code == 302  # one organisation: straight in
    client.post("/accounts/logout/")
    assert audit_actions(actor=world_a.staff, organisation=None) == ["auth.signed_in", "auth.signed_out"]
    event = AuditEvent.all_organisations.get(action="auth.signed_in")
    assert event.data == {"methods": ["password"]} and event.ip_address == "127.0.0.1"


def test_entering_an_organisation_is_recorded_once_per_session(client, world_a):
    login(client, world_a.staff)
    url = reverse("org_home", kwargs={"org_slug": world_a.organisation.slug})
    assert client.get(url).status_code == 200
    assert client.get(url).status_code == 200
    events = AuditEvent.all_organisations.filter(action="organisation.session_started")
    assert events.count() == 1 and events.get().organisation == world_a.organisation


def test_failed_sign_in_is_audited_and_rate_limited(client, world_a):
    for _ in range(5):
        assert login(client, world_a.staff, "wrong password").status_code == 200
    assert audit_actions(action="auth.sign_in_failed") == ["auth.sign_in_failed"] * 5
    assert AuditEvent.all_organisations.filter(action="auth.sign_in_failed").first().target_label == world_a.staff.email
    # The sixth attempt is refused even with the right password.
    response = login(client, world_a.staff)
    assert response.status_code == 200 and not response.wsgi_request.user.is_authenticated


def test_unknown_email_and_wrong_password_look_the_same(client, world_a):
    known = login(client, world_a.staff, "wrong password")
    unknown = client.post("/accounts/login/", {"login": "nobody@example.test", "password": "wrong password"})
    assert known.status_code == unknown.status_code == 200
    assert not unknown.wsgi_request.user.is_authenticated


def test_inactive_login_cannot_sign_in(client, world_a):
    User.objects.filter(pk=world_a.staff.pk).update(is_active=False)
    response = login(client, world_a.staff)
    assert not response.wsgi_request.user.is_authenticated


# --- there is no public sign-up -------------------------------------------------------------------


def test_signup_is_closed_without_an_invitation(client):
    assert b'name="password1"' not in client.get("/accounts/signup/").content
    client.post(
        "/accounts/signup/",
        {"name": "Mallory", "email": "mallory@example.test", "password1": f.PASSWORD, "password2": f.PASSWORD},
    )
    assert not User.objects.filter(email="mallory@example.test").exists()


def test_invitation_to_new_login_to_membership(client, world_a):
    _invitation, token = invite(world_a, "newhire@example.test", Role.STAFF)
    link = reverse("invitation_accept", kwargs={"token": token})
    assert token in mail.outbox[-1].body and world_a.organisation.name in mail.outbox[-1].body

    page = client.get(link)
    assert page.status_code == 200 and world_a.organisation.name in page.content.decode()

    # The invitation is for one address.
    wrong = client.post(
        "/accounts/signup/",
        {"name": "New Hire", "email": "someone.else@example.test", "password1": f.PASSWORD, "password2": f.PASSWORD},
    )
    assert wrong.status_code == 200 and not User.objects.filter(email="someone.else@example.test").exists()

    weak = client.post(
        "/accounts/signup/",
        {"name": "New Hire", "email": "newhire@example.test", "password1": "short", "password2": "short"},
    )
    assert weak.status_code == 200 and not User.objects.filter(email="newhire@example.test").exists()

    created = client.post(
        "/accounts/signup/",
        {"name": "New Hire", "email": "newhire@example.test", "password1": f.PASSWORD, "password2": f.PASSWORD},
    )
    assert created.status_code == 302 and created["Location"] == link
    user = User.objects.get(email="newhire@example.test")
    assert user.name == "New Hire"
    # The link reached the address, so it is verified without a second email.
    assert EmailAddress.objects.get(user=user).verified
    assert not Membership.all_organisations.filter(user=user).exists()  # joining is an explicit step

    joined = client.post(link)
    assert joined.status_code == 302
    assert joined["Location"] == reverse("org_home", kwargs={"org_slug": world_a.organisation.slug})
    membership = Membership.all_organisations.get(user=user)
    assert membership.organisation == world_a.organisation and membership.role == Role.STAFF
    assert client.get(joined["Location"]).status_code == 200
    assert client.get(link).status_code == 404  # used


def test_invitation_for_someone_else_cannot_be_accepted(client, world_a, world_b):
    _invitation, token = invite(world_b, "newhire@example.test")
    link = reverse("invitation_accept", kwargs={"token": token})
    f.sign_in(client, world_a.staff)
    assert client.get(link).status_code == 200
    assert client.post(link).status_code == 403
    assert not Membership.all_organisations.filter(user=world_a.staff, organisation=world_b.organisation).exists()


def test_existing_login_accepts_after_signing_in(client, world_a, world_b):
    _invitation, token = invite(world_b, world_a.staff.email)
    link = reverse("invitation_accept", kwargs={"token": token})
    client.get(link)
    assert login(client, world_a.staff)["Location"] == link
    assert client.post(link).status_code == 302
    assert Membership.all_organisations.filter(user=world_a.staff).count() == 2


def test_bad_invitation_links(client, world_a):
    assert client.get("/invitations/not-a-real-token/").status_code == 404
    _invitation, token = invite(world_a, "x@example.test")
    Organisation.objects.filter(pk=world_a.organisation.pk).update(status=Organisation.Status.SUSPENDED)
    assert client.get(reverse("invitation_accept", kwargs={"token": token})).status_code == 404


# --- two-step sign-in -----------------------------------------------------------------------------


# allauth announces a new factor in an on-commit hook. Inside the usual test transaction that hook
# never runs, so this test uses real commits.
@pytest.mark.django_db(transaction=True)
@pytest.mark.parametrize("role", ["owner", "admin", "manager"])
def test_roles_that_need_mfa_must_enrol_before_entering(client, world_a, role):
    login(client, world_a.user(role))
    url = reverse("org_home", kwargs={"org_slug": world_a.organisation.slug})
    response = client.get(url)
    assert response.status_code == 302 and response["Location"] == reverse("mfa_index")

    # Enrol through allauth's own page: fetch the secret it generated, post a code for it.
    response = client.get(reverse("mfa_activate_totp"))
    if response.status_code == 302:  # allauth wants a recent password first
        client.post(response["Location"].split("?")[0], {"password": f.PASSWORD})
        response = client.get(reverse("mfa_activate_totp"))
    assert response.status_code == 200
    secret = client.session[totp.SECRET_SESSION_KEY]
    assert client.post(reverse("mfa_activate_totp"), {"code": totp_code(secret)}).status_code == 302
    assert Authenticator.objects.filter(user=world_a.user(role), type="totp").exists()
    assert "auth.mfa_added" in audit_actions(actor=world_a.user(role))
    # Recovery codes were generated alongside.
    assert Authenticator.objects.filter(user=world_a.user(role), type="recovery_codes").exists()

    assert client.get(url).status_code == 200
    # After enrolment the home page returns the user to where they were going.


def test_staff_need_mfa_only_when_the_organisation_says_so(client, world_a):
    login(client, world_a.staff)
    url = reverse("org_home", kwargs={"org_slug": world_a.organisation.slug})
    assert client.get(url).status_code == 200
    Organisation.objects.filter(pk=world_a.organisation.pk).update(staff_mfa_required=True)
    assert client.get(url)["Location"] == reverse("mfa_index")


def test_sign_in_with_totp_challenge(client, world_a):
    f.add_totp(world_a.manager)
    response = login(client, world_a.manager)
    assert response["Location"] == reverse("mfa_authenticate")
    url = reverse("org_home", kwargs={"org_slug": world_a.organisation.slug})
    assert client.get(url)["Location"].startswith("/accounts/login/")  # not signed in until the code is given

    assert client.post(reverse("mfa_authenticate"), {"code": "000000"}).status_code == 200
    response = client.post(reverse("mfa_authenticate"), {"code": totp_code(secret_of(world_a.manager))})
    assert response.status_code == 302
    assert client.get(url).status_code == 200
    assert AuditEvent.all_organisations.get(action="auth.signed_in").data == {"methods": ["password", "mfa:totp"]}


def test_recovery_code_works_once(client, world_a):
    f.add_totp(world_a.manager)
    from allauth.mfa.recovery_codes.internal.auth import RecoveryCodes

    code = RecoveryCodes.activate(world_a.manager).get_unused_codes()[0]
    login(client, world_a.manager)
    assert client.post(reverse("mfa_authenticate"), {"code": code}).status_code == 302
    client.post("/accounts/logout/")
    cache.clear()
    login(client, world_a.manager)
    assert client.post(reverse("mfa_authenticate"), {"code": code}).status_code == 200  # refused


def test_the_last_factor_cannot_be_removed_while_a_role_needs_it(client, world_a):
    from hub.accounts.adapters import MFAAdapter

    manager_factor = f.add_totp(world_a.manager)
    staff_factor = f.add_totp(world_a.staff)
    assert not MFAAdapter().can_delete_authenticator(manager_factor)
    assert MFAAdapter().can_delete_authenticator(staff_factor)

    f.sign_in(client, world_a.manager, mfa=True)
    client.post(reverse("mfa_deactivate_totp"))
    assert Authenticator.objects.filter(pk=manager_factor.pk).exists()


def test_passkeys_are_offered(client, world_a):
    f.sign_in(client, world_a.staff)
    body = client.get(reverse("mfa_index")).content.decode()
    assert reverse("mfa_add_webauthn") in body or reverse("mfa_list_webauthn") in body
    assert client.get(reverse("mfa_login_webauthn")).status_code in (200, 302)  # passkey sign-in endpoint exists


# --- step-up --------------------------------------------------------------------------------------


def test_step_up_asks_for_a_fresh_code_then_finishes_the_request(client, world_a, settings):
    owner = world_a.owner
    f.sign_in(client, owner, mfa=True)
    session = client.session
    records = session["account_authentication_methods"]
    for record in records:
        record["at"] = time.time() - settings.MFA_STEP_UP_MAX_AGE - 60  # signed in a while ago
    session["account_authentication_methods"] = records
    session.save()

    slug = world_a.organisation.slug
    assert client.get(reverse("member_list", kwargs={"org_slug": slug})).status_code == 200  # reading is fine
    url = reverse("member_role", kwargs={"org_slug": slug, "membership_id": world_a.memberships["staff"].pk})
    response = client.post(url, {"role": "manager"})
    assert response.status_code == 302 and response["Location"].startswith(reverse("mfa_reauthenticate"))
    with organisation_context(world_a.organisation):
        assert Membership.objects.get(pk=world_a.memberships["staff"].pk).role == Role.STAFF  # nothing happened yet

    assert client.post(response["Location"], {"code": "000000"}).status_code == 200
    done = client.post(response["Location"], {"code": totp_code(secret_of(owner))})
    assert done.status_code == 302
    with organisation_context(world_a.organisation):
        assert Membership.objects.get(pk=world_a.memberships["staff"].pk).role == Role.MANAGER
    assert "member.role_changed" in audit_actions(organisation=world_a.organisation)


def test_step_up_passes_straight_through_when_fresh(client, world_a):
    f.sign_in(client, world_a.owner, mfa=True)
    url = reverse(
        "member_role",
        kwargs={"org_slug": world_a.organisation.slug, "membership_id": world_a.memberships["staff"].pk},
    )
    assert client.post(url, {"role": "manager"})["Location"].endswith("/members/")
    with organisation_context(world_a.organisation):
        assert Membership.objects.get(pk=world_a.memberships["staff"].pk).role == Role.MANAGER


# --- sessions -------------------------------------------------------------------------------------


def test_sessions_are_listed_and_can_be_revoked(client, world_a, django_user_model):
    from django.test import Client

    other = Client()
    login(other, world_a.staff)
    login(client, world_a.staff)
    url = reverse("org_home", kwargs={"org_slug": world_a.organisation.slug})
    assert other.get(url).status_code == 200

    page = client.get(reverse("usersessions_list"))
    assert page.status_code == 200
    from allauth.usersessions.models import UserSession

    assert UserSession.objects.filter(user=world_a.staff).count() == 2
    client.post(reverse("usersessions_list"))  # "sign out other sessions"
    assert UserSession.objects.filter(user=world_a.staff).count() == 1
    assert other.get(url)["Location"].startswith("/accounts/login/")
    assert client.get(url).status_code == 200


def test_session_cookie_is_hardened(client, world_a, settings):
    assert settings.SESSION_COOKIE_SECURE and settings.SESSION_COOKIE_HTTPONLY and settings.CSRF_COOKIE_SECURE
    assert settings.SESSION_COOKIE_AGE == 12 * 3600 and not settings.SESSION_SAVE_EVERY_REQUEST
    response = login(client, world_a.staff)
    cookie = response.cookies[settings.SESSION_COOKIE_NAME]
    assert cookie["secure"] and cookie["httponly"] and cookie["samesite"] == "Lax"


# --- Pulsar staff ---------------------------------------------------------------------------------


def test_admin_and_operator_console_need_mfa(client, operator):
    User.objects.filter(pk=operator.pk).update(is_staff=True, is_superuser=True)
    login(client, operator)
    for path in ("/admin/", "/operator/"):
        assert client.get(path)["Location"] == reverse("mfa_index")
    f.sign_in(client, operator, mfa=True)
    assert client.get("/admin/").status_code == 200
    assert client.get("/operator/").status_code == 200


def test_the_admin_has_no_login_form_of_its_own(client, operator):
    """Django's admin login would skip rate limits, MFA and the audit trail."""
    User.objects.filter(pk=operator.pk).update(is_staff=True, is_superuser=True)
    assert client.get("/admin/login/")["Location"].startswith("/accounts/login/")
    response = client.post("/admin/login/", {"username": operator.email, "password": f.PASSWORD})
    assert response.status_code == 302 and response["Location"].startswith("/accounts/login/")
    assert "_auth_user_id" not in client.session


def test_admin_registers_no_business_model():
    from django.contrib import admin

    from hub.organisations.scoping import OrganisationScopedModel

    assert not [m for m in admin.site._registry if issubclass(m, OrganisationScopedModel)]


def test_operator_provisions_through_the_console(client, operator):
    f.sign_in(client, operator, mfa=True)
    response = client.post("/operator/organisations/", {"name": "Harbour Dental", "owner_email": "owner@harbour.test"})
    assert response.status_code == 302
    organisation = Organisation.objects.get(slug="harbour-dental")
    assert mail.outbox[-1].to == ["owner@harbour.test"]

    # No visit yet: the organisation is closed to the operator who created it.
    home = reverse("org_home", kwargs={"org_slug": organisation.slug})
    assert client.get(home).status_code == 404
    opened = client.post(
        reverse("operator_open_access", kwargs={"org_ref": organisation.pk}), {"reason": "Onboarding call"}
    )
    assert opened["Location"] == home and client.get(home).status_code == 200
    assert "Onboarding call" in client.get(home).content.decode()  # the visit is visible on the page

    client.post(
        reverse("operator_set_status", kwargs={"org_ref": organisation.pk}), {"action": "suspend", "reason": "Test"}
    )
    assert Organisation.objects.get(pk=organisation.pk).status == "suspended"
    client.post(reverse("operator_delete", kwargs={"org_ref": organisation.pk}), {"confirm_slug": "wrong"})
    assert Organisation.objects.filter(pk=organisation.pk).exists()
    client.post(reverse("operator_delete", kwargs={"org_ref": organisation.pk}), {"confirm_slug": organisation.slug})
    assert not Organisation.objects.filter(pk=organisation.pk).exists()


# --- single sign-on -------------------------------------------------------------------------------

TENANT = "11111111-2222-3333-4444-555555555555"


def entra_token(**overrides):
    claims = {
        "aud": "test-microsoft-client",
        "tid": TENANT,
        "iss": f"https://login.microsoftonline.com/{TENANT}/v2.0",
        "exp": time.time() + 300,
        "sub": "abc",
    } | overrides
    return jwt.encode(claims, "x" * 32, algorithm="HS256")


def test_entra_tenant_is_read_from_the_id_token():
    assert tenant_from_id_token(entra_token(), "test-microsoft-client") == TENANT


@pytest.mark.parametrize(
    "overrides",
    [
        {"aud": "another-application"},
        {"tid": ""},
        {"iss": "https://login.microsoftonline.com/99999999-9999-9999-9999-999999999999/v2.0"},
        {"iss": "https://evil.example/v2.0"},
        {"exp": time.time() - 10},
    ],
)
def test_entra_tokens_that_do_not_add_up_are_refused(overrides):
    with pytest.raises(OAuth2Error):
        tenant_from_id_token(entra_token(**overrides), "test-microsoft-client")
    with pytest.raises(OAuth2Error):
        tenant_from_id_token("not-a-jwt", "test-microsoft-client")


def sso_world(world):
    idp = world.identity_provider
    Organisation.objects.filter(pk=world.organisation.pk).update(sso_required=True)
    return idp.provider, idp.tenant


def test_sso_organisation_refuses_a_password_session(client, world_a):
    sso = sso_world(world_a)
    url = reverse("org_home", kwargs={"org_slug": world_a.organisation.slug})

    f.sign_in(client, world_a.staff)
    response = client.get(url)
    assert response.status_code == 403 and b"microsoft/login" in response.content

    f.sign_in(client, world_a.staff, sso=(sso[0], "some-other-tenant"))
    assert client.get(url).status_code == 403

    f.sign_in(client, world_a.staff, sso=sso)
    assert client.get(url).status_code == 200
    assert AuditEvent.all_organisations.get(action="organisation.session_started").data == {
        "methods": ["sso:microsoft"]
    }


def test_sso_members_who_need_mfa_still_need_it(client, world_a):
    sso = sso_world(world_a)
    url = reverse("org_home", kwargs={"org_slug": world_a.organisation.slug})
    f.sign_in(client, world_a.manager, sso=sso)
    assert client.get(url)["Location"] == reverse("mfa_index")
    f.sign_in(client, world_a.manager, sso=sso, mfa=True)
    assert client.get(url).status_code == 200


class _SocialLogin:
    def __init__(self, provider, tenant, email):
        from allauth.socialaccount.models import SocialAccount

        self.account = SocialAccount(provider=provider, uid="u1", extra_data={"tid": tenant})
        self.user = User(email=email)


def test_first_sso_sign_in_needs_a_matching_invitation(rf, client, world_a, world_b):
    from hub.accounts import invitations
    from hub.accounts.adapters import SocialAccountAdapter

    provider, tenant = world_a.identity_provider.provider, world_a.identity_provider.tenant
    _invitation, token = invite(world_a, "newhire@example.test")
    adapter = SocialAccountAdapter()

    def open_for(session_token, tenant_id, email):
        request = rf.get("/")
        request.session = {}
        if session_token:
            invitations.remember(request, session_token)
        return adapter.is_open_for_signup(request, _SocialLogin(provider, tenant_id, email))

    assert open_for(token, tenant, "newhire@example.test")
    assert open_for(token, tenant, "NewHire@Example.Test")
    assert not open_for(None, tenant, "newhire@example.test")  # no invitation
    assert not open_for(token, world_b.identity_provider.tenant, "newhire@example.test")  # another directory
    assert not open_for(token, "", "newhire@example.test")  # no tenant established
    assert not open_for(token, tenant, "someone.else@example.test")  # another address
    # A directory's word is never enough to match an existing login by email.
    assert adapter.is_email_verified(None, "anything@example.test") is False


def test_microsoft_and_google_login_endpoints_exist(client):
    for name in ("microsoft_login", "google_login"):
        assert client.get(reverse(name)).status_code == 200  # a confirmation page; the redirect needs a POST
