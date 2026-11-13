"""The hub as an OpenID Connect provider for the Pulsar app and Time Is Money 2.

A token belongs to one user in one organisation. The organisation is chosen on the authorisation
screen (`hub.accounts.oidc_views`), stored on the authorisation code, and copied to the access
and refresh tokens here. Claims say who the user is, which organisation the token is for and the
role held there, and nothing else (rule 11).
"""

from datetime import timedelta

from django.conf import settings
from django.utils import timezone
from oauth2_provider.oauth2_validators import OAuth2Validator

from hub.accounts.models import Grant
from hub.organisations.models import Membership, Organisation


def active_membership(user, organisation: Organisation | None) -> Membership | None:
    """The user's live membership, or None if they have left or the organisation is not active."""
    if user is None or organisation is None or not user.is_active or not organisation.is_active:
        return None
    return Membership.all_organisations.filter(  # unscoped: checks the token's own user and organisation
        organisation=organisation, user=user, is_active=True
    ).first()


def sso_refresh_allowed(organisation: Organisation, *, via_sso: bool, authenticated_at) -> bool:
    """An organisation that requires single sign-on only honours a refresh token for a limited
    time after the user last came through its directory. After that the app must send the user
    through sign-in again, which is where a disabled directory account is stopped."""
    if not organisation.sso_required:
        return True
    if not via_sso or authenticated_at is None:
        return False
    return timezone.now() - authenticated_at < timedelta(hours=settings.SSO_REFRESH_MAX_AGE_HOURS)


class HubOAuth2Validator(OAuth2Validator):
    oidc_claim_scope = {
        "sub": "openid",
        "org_ref": "openid",
        "org_role": "openid",
        "name": "profile",
        "org_name": "profile",
        "email": "email",
        "email_verified": "email",
    }

    # -- authorisation code ------------------------------------------------------------------------

    def _create_authorization_code(self, request, code, expires=None):
        organisation = getattr(request, "organisation", None)
        if organisation is None:
            raise ValueError("An authorisation code cannot be issued without an organisation.")
        if not expires:
            from oauth2_provider.settings import oauth2_settings

            expires = timezone.now() + timedelta(seconds=oauth2_settings.AUTHORIZATION_CODE_EXPIRE_SECONDS)
        import json

        return Grant.objects.create(
            application=request.client,
            user=request.user,
            code=code["code"],
            expires=expires,
            redirect_uri=request.redirect_uri,
            scope=" ".join(request.scopes),
            code_challenge=request.code_challenge or "",
            code_challenge_method=request.code_challenge_method or "",
            nonce=request.nonce or "",
            claims=json.dumps(request.claims or {}),
            resource=getattr(request, "resource", []),
            organisation=organisation,
            authenticated_at=getattr(request, "authenticated_at", None) or timezone.now(),
            via_sso=bool(getattr(request, "via_sso", False)),
        )

    def validate_code(self, client_id, code, client, request, *args, **kwargs):
        if not super().validate_code(client_id, code, client, request, *args, **kwargs):
            return False
        grant = Grant.objects.select_related("organisation").filter(code=code, application=client).first()
        if grant is None or active_membership(grant.user, grant.organisation) is None:
            return False
        request.organisation = grant.organisation
        request.authenticated_at = grant.authenticated_at
        request.via_sso = grant.via_sso
        return True

    # -- tokens ------------------------------------------------------------------------------------

    def _create_access_token(self, expires, request, token, source_refresh_token=None):
        from oauth2_provider.models import set_token_value

        from hub.accounts.models import AccessToken

        organisation = getattr(request, "organisation", None)
        if organisation is None:
            raise ValueError("An access token cannot be issued without an organisation.")
        id_token = token.get("id_token", None)
        if id_token:
            id_token = self._load_id_token(id_token)
        access_token = AccessToken(
            user=request.user,
            scope=token["scope"],
            expires=expires,
            id_token=id_token,
            application=request.client,
            source_refresh_token=source_refresh_token,
            resource=getattr(request, "resource", []),
            organisation=organisation,
        )
        set_token_value(access_token, token["access_token"])
        access_token.save()
        return access_token

    def _create_refresh_token(self, request, refresh_token_code, access_token, previous_refresh_token):
        import uuid

        from oauth2_provider.models import set_token_value

        from hub.accounts.models import RefreshToken

        refresh_token = RefreshToken(
            user=request.user,
            application=request.client,
            access_token=access_token,
            token_family=previous_refresh_token.token_family if previous_refresh_token else uuid.uuid4(),
            resource=getattr(request, "resource", []),
            organisation=access_token.organisation,
            authenticated_at=getattr(request, "authenticated_at", None) or timezone.now(),
            via_sso=bool(getattr(request, "via_sso", False)),
        )
        set_token_value(refresh_token, refresh_token_code)
        refresh_token.save()
        return refresh_token

    def validate_refresh_token(self, refresh_token, client, request, *args, **kwargs):
        if not super().validate_refresh_token(refresh_token, client, request, *args, **kwargs):
            return False
        rt = request.refresh_token_instance
        organisation = rt.organisation
        if active_membership(rt.user, organisation) is None:
            return False
        if not sso_refresh_allowed(organisation, via_sso=rt.via_sso, authenticated_at=rt.authenticated_at):
            return False
        request.organisation = organisation
        request.authenticated_at = rt.authenticated_at
        request.via_sso = rt.via_sso
        return True

    def validate_bearer_token(self, token, scopes, request):
        """A token stops working the moment its user leaves the organisation or it is suspended."""
        if not super().validate_bearer_token(token, scopes, request):
            return False
        access_token = getattr(request, "access_token", None)
        organisation = getattr(access_token, "organisation", None)
        if active_membership(request.user, organisation) is None:
            return False
        request.organisation = organisation
        return True

    # -- claims ------------------------------------------------------------------------------------

    def get_additional_claims(self, request):
        organisation = getattr(request, "organisation", None)
        if organisation is None:
            access_token = getattr(request, "access_token", None)
            organisation = getattr(access_token, "organisation", None)
        membership = active_membership(request.user, organisation)
        if membership is None:
            # Never issue claims for an organisation the user has no live place in.
            raise ValueError("No active membership for this token's organisation.")
        user = request.user
        return {
            "org_ref": str(organisation.pk),
            "org_role": membership.role,
            "org_name": organisation.name,
            "name": user.name,
            "email": user.email,
            "email_verified": True,
        }
