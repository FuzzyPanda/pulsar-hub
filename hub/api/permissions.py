from rest_framework.permissions import BasePermission

from hub.organisations.models import Role


class IsOrganisationMember(BasePermission):
    """The default: an authenticated user with a live membership in the token's organisation."""

    def has_permission(self, request, view) -> bool:
        membership = getattr(request._request, "membership", None)
        if not (request.user and request.user.is_authenticated and membership is not None):
            return False
        minimum = getattr(view, "minimum_role", Role.STAFF)
        return membership.has_role(minimum)
