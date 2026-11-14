"""How `/api/v1/` says no: `{"detail": "<one sentence>", "code": "<stable code>"}`.

`detail` is for a person and may be reworded. `code` is for a program and is a promise: the list
is in docs/CONTRACTS.md, "Refusals", and a code is never renamed or reused there.
"""

import logging

from rest_framework import exceptions, status
from rest_framework.response import Response
from rest_framework.views import exception_handler as drf_exception_handler

from hub.organisations.context import CrossOrganisationAccess, NoOrganisationContext

logger = logging.getLogger("hub.api")

# Codes a view or a permission sets itself. Anything else falls back to the status below.
_BY_STATUS = {
    status.HTTP_400_BAD_REQUEST: "invalid_request",
    status.HTTP_401_UNAUTHORIZED: "not_authenticated",
    status.HTTP_403_FORBIDDEN: "permission_denied",
    status.HTTP_404_NOT_FOUND: "not_found",
    status.HTTP_405_METHOD_NOT_ALLOWED: "method_not_allowed",
    status.HTTP_406_NOT_ACCEPTABLE: "invalid_request",
    status.HTTP_415_UNSUPPORTED_MEDIA_TYPE: "invalid_request",
    status.HTTP_429_TOO_MANY_REQUESTS: "rate_limited",
}
# The codes DRF gives its own exceptions that are already ours, word for word.
_KEPT = {"permission_denied", "not_found", "method_not_allowed", "not_authenticated"}
# Codes set on purpose by this codebase (hub.api.permissions).
_OURS = {"missing_scope", "role_too_low"}


def refusal(detail: str, code: str, http_status: int, **headers) -> Response:
    """A refusal a view makes itself, in the one shape every refusal has."""
    return Response({"detail": detail, "code": code}, status=http_status, headers=headers or None)


def _sent_a_credential(context) -> bool:
    request = context.get("request")
    return bool(request is not None and request.META.get("HTTP_AUTHORIZATION", "").strip())


def _code(exc, response, context) -> str:
    if isinstance(exc, exceptions.AuthenticationFailed):
        return "token_not_accepted"
    if isinstance(exc, exceptions.NotAuthenticated):
        # A credential was sent and nothing recognised it (a revoked user token, or one kind of
        # credential on another kind's call): for the caller that is the same as a refused one.
        return "token_not_accepted" if _sent_a_credential(context) else "not_authenticated"
    if isinstance(exc, exceptions.APIException):
        given = getattr(exc.detail, "code", None)
        if given in _OURS or given in _KEPT:
            return given
    return _BY_STATUS.get(response.status_code, "invalid_request" if response.status_code < 500 else "error")


def exception_handler(exc, context):
    """DRF's handler, plus a `code` on every refusal, plus a loud log line if isolation ever
    trips. Those are bugs, never user errors, and the response is a plain 500 with no detail."""
    if isinstance(exc, (NoOrganisationContext, CrossOrganisationAccess)):
        logger.error("organisation isolation violation in API view", exc_info=exc)
        return None
    response = drf_exception_handler(exc, context)
    if response is not None and isinstance(response.data, dict) and "code" not in response.data:
        response.data["code"] = _code(exc, response, context)
    return response
