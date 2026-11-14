from rest_framework.permissions import BasePermission

from hub.organisations.models import Role

ROLE_TOO_LOW = ("role_too_low", "Your role in this organisation does not allow this.")


class IsOrganisationMember(BasePermission):
    """The default: an authenticated user with a live membership in the token's organisation."""

    def has_permission(self, request, view) -> bool:
        membership = getattr(request._request, "membership", None)
        if not (request.user and request.user.is_authenticated and membership is not None):
            return False
        minimum = getattr(view, "minimum_role", Role.STAFF)
        if membership.has_role(minimum):
            return True
        self.code, self.message = ROLE_TOO_LOW
        return False


class IsGateway(BasePermission):
    """The caller is a paired gateway, and the site in the address is the one it is paired to.

    A gateway asking about any other site, in its own organisation or another, gets the same 404
    as for a site that does not exist."""

    def has_permission(self, request, view) -> bool:
        from django.http import Http404

        gateway = getattr(request._request, "gateway", None)
        if gateway is None:
            return False
        site_ref = view.kwargs.get("site_ref")
        if site_ref is not None and str(site_ref) != str(gateway.site_id):
            raise Http404
        return True


class IsServiceToken(BasePermission):
    """Any live service token, whatever its scopes."""

    def has_permission(self, request, view) -> bool:
        return getattr(request._request, "service_token", None) is not None


class HasScope(BasePermission):
    """A service token holding the view's `required_scope`, or (where the view sets
    `minimum_role`) a member with at least that role using a user token.

    A refusal says which of the two it was (`missing_scope`, `role_too_low`), so a caller whose
    token is accepted but lacks one scope can keep using the scopes it has (docs/CONTRACTS.md,
    "Refusals"). DRF makes a new permission object for every request, so the code set here is
    this request's alone."""

    def has_permission(self, request, view) -> bool:
        token = getattr(request._request, "service_token", None)
        if token is not None:
            if token.has_scope(view.required_scope):
                return True
            self.code = "missing_scope"
            self.message = f"This token does not have the {view.required_scope} scope."
            return False
        minimum = getattr(view, "minimum_role", None)
        membership = getattr(request._request, "membership", None)
        if minimum is not None and membership is not None and membership.has_role(minimum):
            return True
        if membership is not None:
            self.code, self.message = ROLE_TOO_LOW
        return False
