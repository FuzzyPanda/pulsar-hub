"""API authentication. A request is authenticated as one user in one organisation, both taken
from the bearer token, and that organisation becomes current for the rest of the request.

There is no session authentication on the API and no way to name an organisation in the URL, a
header or the body: the token is the only source.
"""

from oauth2_provider.contrib.rest_framework import OAuth2Authentication
from rest_framework import exceptions
from rest_framework.authentication import BaseAuthentication

from hub.accounts.oidc import active_membership
from hub.organisations.context import set_current_organisation


class OrganisationTokenAuthentication(OAuth2Authentication):
    def authenticate(self, request):
        result = super().authenticate(request)
        if result is None:
            return None
        user, token = result
        organisation = getattr(token, "organisation", None)
        membership = active_membership(user, organisation)
        if membership is None:
            raise exceptions.AuthenticationFailed("This token is no longer valid for its organisation.")
        django_request = request._request
        django_request.organisation = organisation
        django_request.membership = membership
        # OrganisationMiddleware clears this when the response has been produced.
        if getattr(django_request, "_organisation_tokens", None) is None:
            django_request._organisation_tokens = set_current_organisation(organisation)
        return user, token


# --- machines ---------------------------------------------------------------------------------
#
# A gateway and a service token are not people. Each authenticates as itself, is bound to one
# organisation, and (like a user token) is the only thing that decides the organisation.


class MachinePrincipal:
    """What `request.user` is for a gateway or a service token."""

    is_authenticated = True
    is_anonymous = False
    is_active = True

    def __init__(self, kind: str, ref):
        self.kind = kind
        self.pk = f"{kind}:{ref}"  # also the key rate limits are counted against

    def __str__(self) -> str:
        return self.pk


def _bearer(request) -> str:
    header = request.META.get("HTTP_AUTHORIZATION", "")
    scheme, _, value = header.partition(" ")
    return value.strip() if scheme.lower() == "bearer" else ""


def _enter(request, organisation) -> None:
    django_request = request._request
    django_request.organisation = organisation
    if getattr(django_request, "_organisation_tokens", None) is None:
        django_request._organisation_tokens = set_current_organisation(organisation)


class GatewayAuthentication(BaseAuthentication):
    """`Authorization: Bearer hubgw_...`, the credential a gateway was given when it paired."""

    def authenticate(self, request):
        from hub.gateways import services

        credential = _bearer(request)
        if not credential.startswith("hubgw_"):
            return None
        gateway = services.find_gateway(credential)
        if gateway is None:
            raise exceptions.AuthenticationFailed("This gateway's credential is not accepted.")
        _enter(request, gateway.organisation)
        request._request.gateway = gateway
        request._request.gateway_credential = credential
        return MachinePrincipal("gateway", gateway.pk), gateway

    def authenticate_header(self, request):
        return 'Bearer realm="gateway"'


class ServiceTokenAuthentication(BaseAuthentication):
    """`Authorization: Bearer hubsvc_...`, a token an Owner created for another system."""

    def authenticate(self, request):
        from django.utils import timezone

        from hub.api.models import ServiceToken
        from hub.api.services import find_service_token

        token = _bearer(request)
        if not token.startswith("hubsvc_"):
            return None
        row = find_service_token(token)
        if row is None:
            raise exceptions.AuthenticationFailed("This token is not accepted.")
        _enter(request, row.organisation)
        now = timezone.now()
        if row.last_used_at is None or (now - row.last_used_at).total_seconds() > 60:
            ServiceToken.objects.filter(pk=row.pk).update(last_used_at=now)
        request._request.service_token = row
        return MachinePrincipal("service", row.pk), row

    def authenticate_header(self, request):
        return 'Bearer realm="service"'
