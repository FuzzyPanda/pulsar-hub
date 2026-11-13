import logging

from rest_framework.views import exception_handler as drf_exception_handler

from hub.organisations.context import CrossOrganisationAccess, NoOrganisationContext

logger = logging.getLogger("hub.api")


def exception_handler(exc, context):
    """DRF's handler, plus a loud log line if isolation ever trips. Those are bugs, never user
    errors, and the response is a plain 500 with no detail."""
    if isinstance(exc, (NoOrganisationContext, CrossOrganisationAccess)):
        logger.error("organisation isolation violation in API view", exc_info=exc)
        return None
    return drf_exception_handler(exc, context)
