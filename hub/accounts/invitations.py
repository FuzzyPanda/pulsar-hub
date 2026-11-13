"""The invitation a browser session is in the middle of accepting."""

from hub.organisations.models import Invitation
from hub.organisations.services import find_pending_invitation

SESSION_KEY = "hub_invitation_token"


def remember(request, token: str) -> None:
    request.session[SESSION_KEY] = token


def forget(request) -> None:
    request.session.pop(SESSION_KEY, None)


def pending(request) -> Invitation | None:
    """The still-valid invitation this session opened, or None."""
    token = request.session.get(SESSION_KEY)
    return find_pending_invitation(token) if token else None
