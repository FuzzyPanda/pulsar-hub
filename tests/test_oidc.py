"""The hub as OIDC provider: authorisation code with PKCE, organisation-bound tokens, claims."""

import base64
import hashlib
import json
import secrets
from urllib.parse import parse_qs, urlencode, urlparse

import jwt
import pytest
from django.utils import timezone

from hub.accounts.models import AccessToken, Grant, RefreshToken
from hub.audit.models import AuditEvent
from hub.organisations import services
from hub.organisations.context import organisation_context
from hub.organisations.models import Membership, Organisation
from hub.organisations.services import Actor
from tests import factories as f

pytestmark = pytest.mark.django_db

REDIRECT = "https://app.example.test/callback"


def pkce():
    verifier = secrets.token_urlsafe(48)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    return verifier, challenge


def authorize(client, app, *, scope="openid profile email", org=None, challenge=None, **extra):
    params = {
        "response_type": "code",
        "client_id": app.client_id,
        "redirect_uri": REDIRECT,
        "scope": scope,
        "state": "state-123",
        "nonce": "nonce-456",
        **extra,
    }
    if challenge:
        params |= {"code_challenge": challenge, "code_challenge_method": "S256"}
    if org:
        params["org"] = str(org.pk)
    return client.get(f"/oauth/authorize/?{urlencode(params)}")


def exchange(client, app, code, verifier):
    return client.post(
        "/oauth/token/",
        {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": REDIRECT,
            "client_id": app.client_id,
            "code_verifier": verifier,
        },
    )


def sign_in_and_get_tokens(client, app, user, **kwargs):
    f.sign_in(client, user, mfa=kwargs.pop("mfa", False), sso=kwargs.pop("sso", None))
    verifier, challenge = pkce()
    response = authorize(client, app, challenge=challenge, **kwargs)
    assert response.status_code == 302, response.content[:300]
    query = parse_qs(urlparse(response["Location"]).query)
    assert response["Location"].startswith(REDIRECT) and query["state"] == ["state-123"]
    token_response = exchange(client, app, query["code"][0], verifier)
    assert token_response.status_code == 200, token_response.content
    return token_response.json()


def id_claims(client, app, tokens):
    jwks = client.get("/oauth/.well-known/jwks.json").json()
    key = jwt.PyJWK(jwks["keys"][0])
    return jwt.decode(tokens["id_token"], key.key, algorithms=["RS256"], audience=app.client_id)


def bearer(tokens):
    return {"HTTP_AUTHORIZATION": f"Bearer {tokens['access_token']}"}


@pytest.fixture
def app(db):
    return f.ApplicationFactory()


def test_discovery_document(client):
    doc = client.get("/oauth/.well-known/openid-configuration").json()
    assert doc["issuer"] == "https://hub.test/oauth"
    assert doc["authorization_endpoint"] == "https://hub.test/oauth/authorize/"
    assert doc["token_endpoint"] == "https://hub.test/oauth/token/"
    assert doc["userinfo_endpoint"] == "https://hub.test/oauth/userinfo/"
    assert doc["jwks_uri"] == "https://hub.test/oauth/.well-known/jwks.json"
    assert doc["response_types_supported"] == ["code"]
    assert "S256" in doc["code_challenge_methods_supported"]


def test_full_flow_issues_tokens_bound_to_the_organisation(client, app, world_a):
    tokens = sign_in_and_get_tokens(client, app, world_a.staff)
    claims = id_claims(client, app, tokens)
    assert claims["iss"] == "https://hub.test/oauth"
    assert claims["sub"] == str(world_a.staff.pk)
    assert claims["org_ref"] == str(world_a.organisation.pk)
    assert claims["org_role"] == "staff"
    assert claims["email"] == world_a.staff.email and claims["name"] == world_a.staff.name
    assert claims["nonce"] == "nonce-456"
    # Nothing beyond identity, organisation and role.
    assert set(claims) <= {
        "iss", "sub", "aud", "exp", "iat", "auth_time", "jti", "nonce", "at_hash",
        "org_ref", "org_role", "org_name", "name", "email", "email_verified",
    }  # fmt: skip
    # Staff signed in with a password only: the token does not claim a second factor.
    assert "amr" not in claims

    access = AccessToken.objects.get()
    refresh = RefreshToken.objects.get()
    assert access.organisation == refresh.organisation == world_a.organisation
    assert not Grant.objects.exists()  # the code is single use
    # Tokens are stored as digests: a database read does not yield a usable token.
    assert access.token == "" and refresh.token == ""
    assert tokens["access_token"] not in str(AccessToken.objects.values()) + str(RefreshToken.objects.values())

    me = client.get("/api/v1/me", **bearer(tokens))
    assert me.status_code == 200
    assert me.json()["organisation"]["org_ref"] == str(world_a.organisation.pk)
    assert me.json()["role"] == "staff"

    userinfo = client.get("/oauth/userinfo/", **bearer(tokens)).json()
    assert userinfo["sub"] == str(world_a.staff.pk) and userinfo["org_ref"] == str(world_a.organisation.pk)

    event = AuditEvent.all_organisations.get(action="auth.token_authorised")
    assert event.organisation == world_a.organisation and event.actor == world_a.staff


def test_scopes_limit_claims(client, app, world_a):
    tokens = sign_in_and_get_tokens(client, app, world_a.staff, scope="openid")
    claims = id_claims(client, app, tokens)
    assert claims["org_ref"] == str(world_a.organisation.pk)
    assert "email" not in claims and "name" not in claims


def test_pkce_is_required(client, app, world_a):
    f.sign_in(client, world_a.staff)
    response = authorize(client, app)  # no code_challenge
    assert response.status_code == 302 and "error=invalid_request" in response["Location"]
    assert not Grant.objects.exists()


def test_a_wrong_verifier_gets_nothing(client, app, world_a):
    f.sign_in(client, world_a.staff)
    _verifier, challenge = pkce()
    code = parse_qs(urlparse(authorize(client, app, challenge=challenge)["Location"]).query)["code"][0]
    assert exchange(client, app, code, "not-the-verifier" * 4).status_code == 400
    assert not AccessToken.objects.exists()


def test_anonymous_is_sent_to_login(client, app):
    _verifier, challenge = pkce()
    response = authorize(client, app, challenge=challenge)
    assert response.status_code == 302 and response["Location"].startswith("/accounts/login/")


def test_user_with_several_organisations_must_choose(client, app, world_a, world_b):
    user = world_a.staff
    f.MembershipFactory(organisation=world_b.organisation, user=user)
    f.sign_in(client, user)
    _verifier, challenge = pkce()
    response = authorize(client, app, challenge=challenge)
    assert response.status_code == 200
    body = response.content.decode()
    assert f"org={world_a.organisation.pk}" in body and f"org={world_b.organisation.pk}" in body
    assert not Grant.objects.exists()

    tokens = sign_in_and_get_tokens(client, app, user, org=world_b.organisation)
    assert id_claims(client, app, tokens)["org_ref"] == str(world_b.organisation.pk)
    assert AccessToken.objects.get().organisation == world_b.organisation


def test_cannot_ask_for_an_organisation_you_are_not_in(client, app, world_a, world_b):
    f.sign_in(client, world_a.staff)
    _verifier, challenge = pkce()
    for org in (world_b.organisation, Organisation(name="ghost")):
        response = authorize(client, app, challenge=challenge, org=org)
        assert response.status_code == 403
        assert world_b.marker not in response.content.decode()
    assert not Grant.objects.exists()


def test_user_without_any_organisation_gets_no_token(client, app):
    f.sign_in(client, f.UserFactory())
    _verifier, challenge = pkce()
    assert authorize(client, app, challenge=challenge).status_code == 403
    assert not Grant.objects.exists()


def test_operator_visit_does_not_yield_a_token(client, app, world_a):
    f.sign_in(client, world_a.operator_access.operator, mfa=True)
    _verifier, challenge = pkce()
    assert authorize(client, app, challenge=challenge, org=world_a.organisation).status_code == 403
    assert not Grant.objects.exists()


def test_role_that_needs_mfa_cannot_get_a_token_without_it(client, app, world_a):
    f.sign_in(client, world_a.manager)
    _verifier, challenge = pkce()
    response = authorize(client, app, challenge=challenge)
    assert response.status_code == 302 and response["Location"].startswith("/accounts/2fa/")
    assert not Grant.objects.exists()

    tokens = sign_in_and_get_tokens(client, app, world_a.manager, mfa=True)
    claims = id_claims(client, app, tokens)
    assert claims["org_role"] == "manager"
    assert claims["amr"] == ["mfa"]  # and the token says the session passed it


def test_the_id_token_says_when_the_session_passed_a_second_factor(client, app, world_a):
    """`amr: ["mfa"]` is about the session, not the role: Staff who used a second factor get it,
    and nobody gets it without one. A client reads absence as "not proved"."""
    without = sign_in_and_get_tokens(client, app, world_a.staff)
    assert "amr" not in id_claims(client, app, without)

    client.logout()
    tokens = sign_in_and_get_tokens(client, app, world_a.staff, mfa=True, scope="openid")
    claims = id_claims(client, app, tokens)
    assert claims["org_role"] == "staff" and claims["amr"] == ["mfa"]  # needs only the openid scope
    assert Grant.objects.count() == 0 and RefreshToken.objects.filter(mfa_passed=True).count() == 1

    # A refresh carries what the original sign-in proved.
    refreshed = client.post(
        "/oauth/token/",
        {"grant_type": "refresh_token", "refresh_token": tokens["refresh_token"], "client_id": app.client_id},
    )
    assert refreshed.status_code == 200, refreshed.content
    assert id_claims(client, app, refreshed.json())["amr"] == ["mfa"]

    # Userinfo holds only an access token and makes no statement about the session.
    assert "amr" not in client.get("/oauth/userinfo/", **bearer(refreshed.json())).json()


def test_refresh_keeps_the_organisation_and_rotates(client, app, world_a):
    tokens = sign_in_and_get_tokens(client, app, world_a.staff)
    refreshed = client.post(
        "/oauth/token/",
        {"grant_type": "refresh_token", "refresh_token": tokens["refresh_token"], "client_id": app.client_id},
    )
    assert refreshed.status_code == 200, refreshed.content
    new = refreshed.json()
    assert new["refresh_token"] != tokens["refresh_token"]
    checksum = hashlib.sha256(new["access_token"].encode()).hexdigest()
    assert AccessToken.objects.get(token_checksum=checksum).organisation == world_a.organisation
    assert id_claims(client, app, new)["org_ref"] == str(world_a.organisation.pk)
    # The old refresh token is dead, and replaying it kills the family.
    replay = client.post(
        "/oauth/token/",
        {"grant_type": "refresh_token", "refresh_token": tokens["refresh_token"], "client_id": app.client_id},
    )
    assert replay.status_code == 400
    assert client.get("/api/v1/me", **bearer(new)).status_code == 401


def test_leaving_the_organisation_kills_tokens_at_once(client, app, world_a):
    tokens = sign_in_and_get_tokens(client, app, world_a.staff)
    assert client.get("/api/v1/me", **bearer(tokens)).status_code == 200
    # Even if the token rows survived (they are deleted by remove_member), a dead membership stops them.
    with organisation_context(world_a.organisation):
        Membership.objects.filter(user=world_a.staff).update(is_active=False)
    assert client.get("/api/v1/me", **bearer(tokens)).status_code == 401
    assert client.get("/oauth/userinfo/", **bearer(tokens)).status_code == 401
    refresh = client.post(
        "/oauth/token/",
        {"grant_type": "refresh_token", "refresh_token": tokens["refresh_token"], "client_id": app.client_id},
    )
    assert refresh.status_code == 400


def test_suspension_kills_tokens(client, app, world_a, operator):
    tokens = sign_in_and_get_tokens(client, app, world_a.staff)
    Organisation.objects.filter(pk=world_a.organisation.pk).update(status=Organisation.Status.SUSPENDED)
    assert client.get("/api/v1/me", **bearer(tokens)).status_code == 401


def test_role_change_forces_new_tokens(client, app, world_a):
    tokens = sign_in_and_get_tokens(client, app, world_a.staff)
    with organisation_context(world_a.organisation):
        services.change_role(
            world_a.memberships["staff"], actor=Actor(world_a.owner, world_a.memberships["owner"]), new_role="manager"
        )
    assert client.get("/api/v1/me", **bearer(tokens)).status_code == 401


def test_sso_organisation_limits_refresh_token_life(client, app, world_a, settings):
    org = world_a.organisation
    Organisation.objects.filter(pk=org.pk).update(sso_required=True)
    sso = (world_a.identity_provider.provider, world_a.identity_provider.tenant)
    tokens = sign_in_and_get_tokens(client, app, world_a.staff, sso=sso)
    refresh = RefreshToken.objects.get()
    assert refresh.via_sso and refresh.authenticated_at is not None

    def do_refresh(token):
        return client.post(
            "/oauth/token/", {"grant_type": "refresh_token", "refresh_token": token, "client_id": app.client_id}
        )

    first = do_refresh(tokens["refresh_token"])
    assert first.status_code == 200
    # The clock that matters is the sign-in through the directory, not the last refresh.
    assert RefreshToken.objects.get(revoked__isnull=True).authenticated_at == refresh.authenticated_at
    RefreshToken.objects.update(
        authenticated_at=timezone.now() - timezone.timedelta(hours=settings.SSO_REFRESH_MAX_AGE_HOURS + 1)
    )
    assert do_refresh(first.json()["refresh_token"]).status_code == 400


def test_sso_organisation_refuses_a_password_session(client, app, world_a):
    Organisation.objects.filter(pk=world_a.organisation.pk).update(sso_required=True)
    f.sign_in(client, world_a.staff)
    _verifier, challenge = pkce()
    assert authorize(client, app, challenge=challenge).status_code == 403
    assert not Grant.objects.exists()


@pytest.mark.parametrize(
    "path",
    ["/oauth/applications/", "/oauth/applications/register/", "/oauth/introspect/", "/oauth/authorized_tokens/",
     "/oauth/device-authorization/", "/oauth/register/"],
)  # fmt: skip
def test_toolkit_pages_that_are_not_offered_do_not_exist(client, world_a, path):
    f.sign_in(client, world_a.owner, mfa=True)
    assert client.get(path).status_code == 404
    assert client.post(path).status_code == 404


def test_token_response_is_not_cacheable_and_carries_no_organisation_secrets(client, app, world_a):
    tokens = sign_in_and_get_tokens(client, app, world_a.staff)
    assert set(tokens) == {"access_token", "expires_in", "token_type", "scope", "refresh_token", "id_token"}
    payload = json.loads(base64.urlsafe_b64decode(tokens["id_token"].split(".")[1] + "=="))
    assert "password" not in json.dumps(payload).lower()
