"""Sign in with Microsoft Entra.

allauth's Microsoft provider reads the profile from Microsoft Graph, which does not say which
tenant the user belongs to. The hub needs the tenant: it is how a sign-in is matched to an
organisation's identity provider. This provider keeps allauth's flow and adds the `tid` claim of
the ID token to the account's data.
"""

import time

import jwt
from allauth.socialaccount.providers.microsoft.provider import MicrosoftGraphProvider
from allauth.socialaccount.providers.microsoft.views import MicrosoftGraphOAuth2Adapter
from allauth.socialaccount.providers.oauth2.client import OAuth2Error


def tenant_from_id_token(id_token: str, client_id: str) -> str:
    """Return the Entra tenant id from an ID token received from the token endpoint.

    The token came straight from Microsoft over TLS in exchange for our client secret, so its
    signature need not be checked again (OpenID Connect Core 3.1.3.7). Audience, issuer and expiry
    still are: a token for another application, or one whose issuer disagrees with its tenant,
    is refused.
    """
    try:
        claims = jwt.decode(id_token, options={"verify_signature": False})
    except jwt.PyJWTError as exc:
        raise OAuth2Error("Microsoft returned an unreadable ID token.") from exc
    audience = claims.get("aud")
    audiences = audience if isinstance(audience, list) else [audience]
    if client_id not in audiences:
        raise OAuth2Error("The Microsoft ID token was issued to another application.")
    tenant = str(claims.get("tid") or "").lower()
    if not tenant:
        raise OAuth2Error("The Microsoft ID token carries no tenant.")
    if str(claims.get("iss") or "").lower().rstrip("/") != f"https://login.microsoftonline.com/{tenant}/v2.0":
        raise OAuth2Error("The Microsoft ID token issuer does not match its tenant.")
    if float(claims.get("exp") or 0) < time.time():
        raise OAuth2Error("The Microsoft ID token has expired.")
    return tenant


class EntraOAuth2Adapter(MicrosoftGraphOAuth2Adapter):
    def complete_login(self, request, app, token, **kwargs):
        response = kwargs.get("response") or {}
        id_token = response.get("id_token")
        if not id_token:
            raise OAuth2Error("Microsoft returned no ID token; the tenant cannot be established.")
        tenant = tenant_from_id_token(id_token, app.client_id)
        login = super().complete_login(request, app, token, **kwargs)
        login.account.extra_data["tid"] = tenant
        return login


class EntraProvider(MicrosoftGraphProvider):
    oauth2_adapter_class = EntraOAuth2Adapter

    def get_default_scope(self):
        # `openid` makes the token endpoint return the ID token that carries `tid`.
        return ["openid", "email", "profile", "User.Read"]


provider_classes = [EntraProvider]
