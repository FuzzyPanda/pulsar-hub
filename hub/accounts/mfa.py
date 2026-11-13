"""What the current session has proved about the user, read from allauth's own records."""

import time

from allauth.account.internal.flows.login import get_authentication_records
from allauth.mfa.models import Authenticator
from allauth.mfa.utils import is_mfa_enabled

ENROLLED_IN_SESSION_KEY = "hub_mfa_enrolled_at"
SECOND_FACTORS = [Authenticator.Type.TOTP, Authenticator.Type.WEBAUTHN]


def has_mfa(user) -> bool:
    """The user has an authenticator app or a passkey. Recovery codes alone do not count."""
    return bool(user and user.is_authenticated and is_mfa_enabled(user, SECOND_FACTORS))


def _records(request) -> list[dict]:
    return get_authentication_records(request, request.user)


def last_mfa_at(request) -> float | None:
    """When this session last passed a second factor (epoch seconds), or None.

    Enrolling a factor counts: activating it means entering a code or touching the key.
    """
    times = [r["at"] for r in _records(request) if r.get("method") == "mfa" and "at" in r]
    enrolled_at = request.session.get(ENROLLED_IN_SESSION_KEY)
    if enrolled_at:
        times.append(enrolled_at)
    return max(times) if times else None


def mfa_satisfied(request) -> bool:
    """The user has a second factor and this session has used it."""
    return has_mfa(request.user) and last_mfa_at(request) is not None


def mfa_is_fresh(request, max_age: int) -> bool:
    at = last_mfa_at(request)
    return has_mfa(request.user) and at is not None and (time.time() - at) < max_age


def authentication_methods(request) -> list[str]:
    """Short names of how this session signed in, for the audit log: ['password', 'mfa:totp']."""
    names = []
    for record in _records(request):
        method = record.get("method", "")
        if method == "mfa":
            method = f"mfa:{record.get('type', '')}"
        elif method == "socialaccount":
            method = f"sso:{record.get('provider', '')}"
        if method and method not in names:
            names.append(method)
    return names


def authenticated_at(request) -> float | None:
    """When this session first signed in."""
    times = [r["at"] for r in _records(request) if "at" in r]
    return min(times) if times else None


def session_sso_identity(request) -> tuple[str, str] | None:
    """The (provider, tenant) this session signed in through, or None for a local login.

    The tenant is Microsoft's `tid` or Google's `hd`, read from the social account that allauth
    refreshed at this sign-in. It is the directory that vouched for the user, which is what an
    organisation that requires single sign-on is matched against.
    """
    from allauth.socialaccount.models import SocialAccount

    social = [r for r in _records(request) if r.get("method") == "socialaccount"]
    if not social:
        return None
    record = social[-1]
    account = SocialAccount.objects.filter(
        user=request.user, provider=record.get("provider"), uid=record.get("uid")
    ).first()
    if account is None:
        return None
    tenant = account.extra_data.get("tid") or account.extra_data.get("hd") or ""
    if not tenant:
        return None
    return account.provider, str(tenant).lower()
