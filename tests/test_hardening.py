"""Regression tests for the defects found by the independent security review of H1 (2026-11-13).

Each test is the attack, and asserts that it now fails.
"""

import base64
import hashlib
import io
import json
import logging
import time
from datetime import timedelta
from urllib.parse import parse_qs, urlparse

import pytest
from allauth.mfa.models import Authenticator
from allauth.mfa.recovery_codes.internal.auth import RecoveryCodes
from django.contrib import admin
from django.contrib.sessions.models import Session
from django.urls import reverse
from django.utils import timezone

from hub.accounts.models import AccessToken, Application, Grant, RefreshToken, User
from hub.audit.models import AuditEvent
from hub.middleware import redact_path
from hub.organisations import services
from hub.organisations.context import organisation_context
from hub.organisations.models import Membership, Organisation, Role
from hub.organisations.services import Actor
from tests import factories as f
from tests.test_oidc import REDIRECT, authorize, bearer, exchange, pkce, sign_in_and_get_tokens

pytestmark = pytest.mark.django_db


def age_session(client, seconds: int) -> None:
    session = client.session
    records = session["account_authentication_methods"]
    for record in records:
        record["at"] = time.time() - seconds
    session["account_authentication_methods"] = records
    session.save()


def role_change_url(world):
    return reverse(
        "member_role", kwargs={"org_slug": world.organisation.slug, "membership_id": world.memberships["staff"].pk}
    )


def staff_role(world) -> str:
    with organisation_context(world.organisation):
        return Membership.objects.get(pk=world.memberships["staff"].pk).role


def refresh(client, app, token):
    return client.post(
        "/oauth/token/", {"grant_type": "refresh_token", "refresh_token": token, "client_id": app.client_id}
    )


@pytest.fixture
def app(db):
    return f.ApplicationFactory()


# --- step-up means the device ---------------------------------------------------------------------


def test_step_up_cannot_be_passed_with_the_password_and_a_recovery_code(client, world_a, settings):
    owner = world_a.owner
    f.sign_in(client, owner, mfa=True)
    code = RecoveryCodes.activate(owner).get_unused_codes()[0]
    age_session(client, settings.MFA_STEP_UP_MAX_AGE + 60)

    assert client.post(role_change_url(world_a), {"role": "manager"})["Location"].startswith(
        reverse("mfa_reauthenticate")
    )
    # A password is not accepted as "confirm it is you" for a login that has a second factor...
    assert client.get(reverse("account_reauthenticate"))["Location"].startswith(reverse("mfa_reauthenticate"))
    assert client.post(reverse("account_reauthenticate"), {"password": f.PASSWORD})["Location"].startswith(
        reverse("mfa_reauthenticate")
    )
    # ...so the recovery codes cannot be read...
    assert client.get(reverse("mfa_view_recovery_codes"))["Location"].startswith(reverse("mfa_reauthenticate"))
    # ...and even a recovery code obtained some other way does not count as the device.
    client.post(reverse("mfa_reauthenticate"), {"code": code})
    client.post(role_change_url(world_a), {"role": "manager"})
    assert staff_role(world_a) == Role.STAFF


def test_enrolling_a_factor_does_not_count_as_step_up(client, world_a):
    f.sign_in(client, world_a.owner)
    f.add_totp(world_a.owner)
    session = client.session
    session["hub_mfa_enrolled_at"] = time.time()
    session.save()
    # Enough to enter the organisation, not enough for a guarded action.
    assert client.get(reverse("org_home", kwargs={"org_slug": world_a.organisation.slug})).status_code == 200
    assert client.post(role_change_url(world_a), {"role": "manager"})["Location"].startswith(
        reverse("mfa_reauthenticate")
    )
    assert staff_role(world_a) == Role.STAFF


def confirm_with_device(client, *, seconds_ago: int = 0) -> None:
    """Write the session record allauth writes after an authenticator-app check."""
    session = client.session
    session["account_authentication_methods"] = [
        *session["account_authentication_methods"],
        {"method": "mfa", "at": time.time() - seconds_ago, "type": "totp", "id": 0, "reauthenticated": True},
    ]
    session.save()


@pytest.mark.parametrize(
    "name",
    ["mfa_add_webauthn", "mfa_list_webauthn", "mfa_generate_recovery_codes", "mfa_deactivate_totp",
     "account_change_password", "account_email", "socialaccount_connections"],
)  # fmt: skip
def test_account_security_pages_need_a_recent_second_factor(client, world_a, settings, name):
    """Someone holding a live session must not be able to add their own passkey, make new recovery
    codes or change the email address without the device."""
    f.sign_in(client, world_a.owner, mfa=True)
    confirm_with_device(client)
    assert client.get(reverse(name)).status_code == 200

    f.sign_in(client, world_a.owner, mfa=True)
    age_session(client, settings.ACCOUNT_REAUTHENTICATION_TIMEOUT + 60)
    for response in (client.get(reverse(name)), client.post(reverse(name), {})):
        assert response.status_code == 302 and response["Location"].startswith(reverse("mfa_reauthenticate"))
    # A password does not open them either.
    client.post(reverse("account_reauthenticate"), {"password": f.PASSWORD})
    assert client.get(reverse(name))["Location"].startswith(reverse("mfa_reauthenticate"))


def test_a_login_without_a_factor_can_still_enrol_one(client, world_a):
    f.sign_in(client, world_a.manager)
    response = client.get(reverse("mfa_activate_totp"))
    # allauth asks for the password first; it does not send a login with no factor to an MFA page.
    assert response.status_code == 200 or reverse("account_reauthenticate") in response["Location"]


# The refusal is raised inside Django's own delete transaction. Under the usual test transaction
# that poisons the rest of the request, which production (no outer transaction) never sees.
@pytest.mark.django_db(transaction=True)
def test_the_last_passkey_cannot_be_removed_while_the_role_requires_mfa(client, world_a):
    manager = world_a.manager
    passkey = Authenticator.objects.create(
        user=manager, type=Authenticator.Type.WEBAUTHN, data={"name": "key", "credential": {}}
    )
    f.sign_in(client, manager)
    confirm_with_device(client)
    assert client.post(reverse("mfa_remove_webauthn", kwargs={"pk": passkey.pk})).status_code == 403
    assert Authenticator.objects.filter(pk=passkey.pk).exists()

    # With a second factor in place the first may go, and deleting the login is never blocked.
    f.add_totp(manager)
    assert client.post(reverse("mfa_remove_webauthn", kwargs={"pk": passkey.pk})).status_code == 302
    assert not Authenticator.objects.filter(pk=passkey.pk).exists()
    with organisation_context(world_a.organisation):
        Membership.objects.filter(user=manager).delete()
    manager.delete()
    assert not User.objects.filter(pk=manager.pk).exists()


# --- the session lifetime is absolute -------------------------------------------------------------


def test_a_session_ends_a_fixed_time_after_sign_in_however_busy_it_is(client, world_a, settings):
    f.sign_in(client, world_a.staff)
    url = reverse("org_home", kwargs={"org_slug": world_a.organisation.slug})
    assert client.get(url).status_code == 200  # this request also records when the session began
    key = client.session.session_key

    # Django's own expiry slides with every save; that is why the hub keeps its own clock.
    Session.objects.filter(session_key=key).update(expire_date=timezone.now() + timedelta(hours=11))
    session = client.session
    session["hub_session_started_at"] = time.time() - settings.SESSION_COOKIE_AGE - 5
    session.save()

    response = client.get(url)
    assert response.status_code == 302 and response["Location"].startswith("/accounts/login/")
    assert "_auth_user_id" not in client.session
    assert AuditEvent.all_organisations.filter(action="auth.signed_out", actor=world_a.staff).exists()


# --- OIDC -----------------------------------------------------------------------------------------


def test_plain_pkce_is_refused(client, app, world_a):
    f.sign_in(client, world_a.staff)
    verifier, _challenge = pkce()
    response = authorize(client, app, code_challenge=verifier, code_challenge_method="plain")
    assert response.status_code == 302 and "error=invalid_request" in response["Location"]
    assert "code=" not in response["Location"] and not Grant.objects.exists()


def test_authorisation_response_names_the_issuer(client, app, world_a):
    f.sign_in(client, world_a.staff)
    _verifier, challenge = pkce()
    query = parse_qs(urlparse(authorize(client, app, challenge=challenge)["Location"]).query)
    assert query["iss"] == ["https://hub.test/oauth"]


def test_tokens_are_not_accepted_in_the_query_string(client, app, world_a):
    tokens = sign_in_and_get_tokens(client, app, world_a.staff)
    assert client.get(f"/api/v1/me?access_token={tokens['access_token']}").status_code == 401
    assert client.get("/api/v1/me", **bearer(tokens)).status_code == 200


def test_changing_sign_in_rules_ends_every_app_sign_in(client, app, world_a):
    """A Staff member without MFA must not keep refreshing after the Owner requires MFA for Staff."""
    tokens = sign_in_and_get_tokens(client, app, world_a.staff)
    with organisation_context(world_a.organisation):
        services.update_security_settings(
            actor=Actor(world_a.owner, world_a.memberships["owner"]), staff_mfa_required=True, sso_required=False
        )
    assert client.get("/api/v1/me", **bearer(tokens)).status_code == 401
    assert refresh(client, app, tokens["refresh_token"]).status_code == 400


def test_refresh_is_refused_when_the_role_needs_mfa_the_session_never_passed(client, app, world_a):
    """Belt and braces for the test above: even a refresh token that survived is judged on what
    its session had proved."""
    tokens = sign_in_and_get_tokens(client, app, world_a.staff)
    assert RefreshToken.objects.get().mfa_passed is False
    Organisation.objects.filter(pk=world_a.organisation.pk).update(staff_mfa_required=True)  # no revocation
    assert refresh(client, app, tokens["refresh_token"]).status_code == 400

    AccessToken.objects.all().delete()
    RefreshToken.objects.all().delete()
    f.add_totp(world_a.staff)
    tokens = sign_in_and_get_tokens(client, app, world_a.staff, mfa=True)
    assert RefreshToken.objects.get().mfa_passed is True
    assert refresh(client, app, tokens["refresh_token"]).status_code == 200


def test_a_password_change_ends_every_app_sign_in(client, app, world_a):
    tokens = sign_in_and_get_tokens(client, app, world_a.staff)
    response = client.post(
        reverse("account_change_password"),
        {
            "oldpassword": f.PASSWORD,
            "password1": "a different long passphrase",
            "password2": "a different long passphrase",
        },
    )
    assert response.status_code == 302
    assert client.get("/api/v1/me", **bearer(tokens)).status_code == 401
    assert refresh(client, app, tokens["refresh_token"]).status_code == 400
    assert not RefreshToken.objects.filter(user=world_a.staff).exists()


def test_removing_a_second_factor_ends_every_app_sign_in(client, app, world_a):
    f.add_totp(world_a.staff)
    tokens = sign_in_and_get_tokens(client, app, world_a.staff, mfa=True)
    confirm_with_device(client)
    assert client.post(reverse("mfa_deactivate_totp")).status_code == 302
    assert not Authenticator.objects.filter(user=world_a.staff, type="totp").exists()
    assert client.get("/api/v1/me", **bearer(tokens)).status_code == 401


def test_sso_refresh_needs_the_organisations_own_directory(client, app, world_a):
    """A token obtained through an unrelated directory does not count as single sign-on."""
    tokens = sign_in_and_get_tokens(client, app, world_a.staff, sso=("microsoft", "unrelated-tenant"))
    assert RefreshToken.objects.get().via_sso is False
    Organisation.objects.filter(pk=world_a.organisation.pk).update(sso_required=True)  # no revocation
    assert refresh(client, app, tokens["refresh_token"]).status_code == 400


def test_a_refresh_token_has_an_absolute_end(client, app, world_a, settings):
    tokens = sign_in_and_get_tokens(client, app, world_a.staff)
    first = refresh(client, app, tokens["refresh_token"])
    assert first.status_code == 200
    RefreshToken.objects.update(
        authenticated_at=timezone.now() - timedelta(days=settings.OIDC_SESSION_MAX_DAYS, minutes=1)
    )
    assert refresh(client, app, first.json()["refresh_token"]).status_code == 400


# --- the admin ------------------------------------------------------------------------------------


def test_the_admin_holds_logins_and_applications_only():
    """No tokens, social accounts, email addresses or queued jobs: through those a staff login
    could read organisation-bound records or edit what the sign-in rules trust."""
    assert set(admin.site._registry) == {User, Application}


def test_privilege_changes_are_audited_however_they_are_made(world_a):
    user = world_a.staff
    user.is_platform_operator = True
    user.is_staff = True
    user.save()
    event = AuditEvent.all_organisations.get(action="account.privileges_changed", target_ref=str(user.pk))
    assert event.organisation is None
    assert event.data == {
        "is_platform_operator": {"from": False, "to": True},
        "is_staff": {"from": False, "to": True},
    }
    user.name = "Renamed"
    user.save()
    assert (
        AuditEvent.all_organisations.filter(action="account.privileges_changed", target_ref=str(user.pk)).count() == 1
    )
    # Creating an operator is a privilege change too.
    made = f.UserFactory(is_platform_operator=True)
    assert AuditEvent.all_organisations.get(action="account.privileges_changed", target_ref=str(made.pk)).data == {
        "is_platform_operator": {"from": False, "to": True}
    }


# --- nothing secret in logs -----------------------------------------------------------------------


@pytest.mark.parametrize(
    ("path", "expected"),
    [
        ("/invitations/AbC-123_secret/", "/invitations/[redacted]/"),
        ("/accounts/confirm-email/MQ:1abc:xyz/", "/accounts/confirm-email/[redacted]/"),
        ("/accounts/password/reset/key/3f-set-password/", "/accounts/password/reset/key/[redacted]/"),
        ("/org/harbour-dental/members/", "/org/harbour-dental/members/"),
        ("/accounts/login/", "/accounts/login/"),
    ],
)
def test_secret_bearing_paths_are_redacted(path, expected):
    assert redact_path(path) == expected


def test_the_access_log_never_holds_an_invitation_token_or_a_query_string(client, world_a):
    with organisation_context(world_a.organisation):
        _invitation, token = services.invite_member(
            actor=Actor(world_a.owner, world_a.memberships["owner"]), email="new@example.test", role=Role.STAFF
        )
    stream = io.StringIO()
    handler = logging.StreamHandler(stream)
    for name in ("hub.access", "django.request", "django.server"):
        logging.getLogger(name).addHandler(handler)
    try:
        assert client.get(f"/invitations/{token}/?state=query-secret").status_code == 200
        assert client.get("/invitations/not-a-real-token-but-still-private/").status_code == 404
    finally:
        for name in ("hub.access", "django.request", "django.server"):
            logging.getLogger(name).removeHandler(handler)
    logged = stream.getvalue()
    assert "GET /invitations/[redacted]/ 200" in logged
    assert token not in logged and "query-secret" not in logged and "not-a-real-token" not in logged


def test_error_reports_are_scrubbed():
    from hub.monitoring import _scrub

    event = {
        "request": {
            "url": "https://hub.test/invitations/SECRET-TOKEN/",
            "query_string": "code=oauth-code",
            "cookies": {"sessionid": "x"},
            "data": {"password": "x"},
            "headers": {"Authorization": "Bearer abc", "User-Agent": "ua"},
        }
    }
    scrubbed = json.dumps(_scrub(event, None))
    assert "SECRET-TOKEN" not in scrubbed and "oauth-code" not in scrubbed and "Bearer abc" not in scrubbed
    assert "/invitations/[redacted]/" in scrubbed


def test_a_password_typed_into_the_email_field_is_not_recorded(client):
    client.post("/accounts/login/", {"login": "hunter2-my-real-password", "password": "x"})
    client.post("/accounts/login/", {"login": "someone@example.test", "password": "x"})
    labels = list(
        AuditEvent.all_organisations.filter(action="auth.sign_in_failed").values_list("target_label", flat=True)
    )
    assert "hunter2-my-real-password" not in str(labels)
    assert sorted(labels) == ["(not an email address)", "someone@example.test"] or labels == ["someone@example.test"]


# --- exchanging a code still needs the organisation to stand ---------------------------------------


def test_a_code_is_useless_once_the_membership_is_gone(client, app, world_a):
    f.sign_in(client, world_a.staff)
    verifier, challenge = pkce()
    code = parse_qs(urlparse(authorize(client, app, challenge=challenge)["Location"]).query)["code"][0]
    with organisation_context(world_a.organisation):
        Membership.objects.filter(user=world_a.staff).update(is_active=False)
    assert exchange(client, app, code, verifier).status_code == 400
    assert not AccessToken.objects.exists()
    assert REDIRECT and base64 and hashlib  # helpers shared with tests/test_oidc.py


# --- the application's database role ----------------------------------------------------------------


def _can_create_roles() -> bool:
    from django.db import connection

    with connection.cursor() as cursor:
        cursor.execute("SELECT rolcreaterole OR rolsuper FROM pg_roles WHERE rolname = current_user")
        return bool(cursor.fetchone()[0])


@pytest.mark.django_db(transaction=True)
def test_the_application_role_can_add_to_the_audit_log_and_nothing_else(world_a, monkeypatch):
    """In production the service connects as a second, lesser role (`manage.py grant_app_role`).
    Even with raw SQL that role cannot change, remove or unprotect audit events, or alter the
    schema; it can still do its ordinary work and delete an organisation through the function."""
    import psycopg
    from django.core.management import call_command
    from django.db import connection

    if not _can_create_roles():
        pytest.skip("the test database role may not create roles")

    with organisation_context(world_a.organisation):
        from hub.audit import services as audit

        event = audit.record("member.removed", actor=world_a.admin)
    db = connection.settings_dict
    role, password = "hub_app_roletest", "roletest-only"
    host, port = db["HOST"] or "127.0.0.1", db["PORT"] or 5432
    monkeypatch.setenv("DATABASE_URL", f"postgres://{role}:{password}@{host}:{port}/{db['NAME']}")
    try:
        call_command("grant_app_role", stdout=io.StringIO())
        call_command("grant_app_role", stdout=io.StringIO())  # idempotent
        with psycopg.connect(
            host=host, port=port, dbname=db["NAME"], user=role, password=password, autocommit=True
        ) as app:

            def refused(sql, params=None):
                with pytest.raises(psycopg.Error):
                    app.execute(sql, params)

            # Ordinary work.
            assert app.execute("SELECT count(*) FROM organisations_membership").fetchone()[0] >= 4
            app.execute("UPDATE organisations_organisation SET name = name WHERE id = %s", [world_a.organisation.pk])
            app.execute(
                "INSERT INTO audit_auditevent (id, occurred_at, action, actor_kind, actor_label, target_type,"
                " target_ref, target_label, user_agent, request_id, data)"
                " VALUES (gen_random_uuid(), now(), 'test.insert', 'system', '', '', '', '', '', '', '{}')"
            )
            # History cannot be rewritten, removed, or left unguarded.
            refused("UPDATE audit_auditevent SET actor_id = NULL WHERE id = %s", [event.pk])
            refused("DELETE FROM audit_auditevent WHERE id = %s", [event.pk])
            refused("TRUNCATE audit_auditevent")
            refused("ALTER TABLE audit_auditevent DISABLE TRIGGER hub_audit_append_only")
            refused("DROP TRIGGER hub_audit_append_only ON audit_auditevent")
            refused("SELECT hub_purge_organisation_audit(%s)", [world_a.organisation.pk])  # not being deleted
            # Nor the schema or the migration record.
            refused("CREATE TABLE sneaky (id int)")
            refused("ALTER TABLE organisations_membership ADD COLUMN sneaky int")
            refused("DELETE FROM django_migrations")
            assert not app.execute("SELECT rolsuper FROM pg_roles WHERE rolname = current_user").fetchone()[0]

            # Deleting an organisation still works for this role, through the one function.
            app.execute(
                "UPDATE organisations_organisation SET status = 'deleting' WHERE id = %s", [world_a.organisation.pk]
            )
            assert app.execute("SELECT hub_purge_organisation_audit(%s)", [world_a.organisation.pk]).fetchone()[0] >= 1
            app.execute("DELETE FROM organisations_membership WHERE organisation_id = %s", [world_a.organisation.pk])
        assert not AuditEvent.all_organisations.filter(pk=event.pk).exists()
    finally:
        with connection.cursor() as cursor:
            cursor.execute("SELECT 1 FROM pg_roles WHERE rolname = %s", [role])
            if cursor.fetchone():
                for statement in (
                    f"REVOKE ALL ON ALL TABLES IN SCHEMA public FROM {role}",
                    f"REVOKE ALL ON ALL SEQUENCES IN SCHEMA public FROM {role}",
                    f"REVOKE ALL ON FUNCTION hub_purge_organisation_audit(uuid) FROM {role}",
                    f"REVOKE ALL ON SCHEMA public FROM {role}",
                    f'REVOKE ALL ON DATABASE "{db["NAME"]}" FROM {role}',
                    f"DROP ROLE {role}",
                ):
                    cursor.execute(statement)
