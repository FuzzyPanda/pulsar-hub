"""API authentication. A request is authenticated as one user in one organisation, both taken
from the bearer token, and that organisation becomes current for the rest of the request.

There is no session authentication on the API and no way to name an organisation in the URL, a
header or the body: the token is the only source.
"""

from oauth2_provider.contrib.rest_framework import OAuth2Authentication
from rest_framework import exceptions

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
