"""Step-up: a fresh second-factor check on demand.

Wrap a view in `step_up_required` and it only runs if the session checked the authenticator app or
a passkey within MFA_STEP_UP_MAX_AGE seconds. A password, an emailed code, a recovery code or having
just enrolled a factor do not count: step-up proves the device is with whoever holds the session. Otherwise the user is sent to allauth's MFA re-authentication page
and comes back to the same request (a suspended POST is replayed by allauth). Remote door actions
(phase H6) will use it; today it guards role changes, security settings and operator access.
"""

from functools import wraps

from allauth.account.internal.flows.reauthentication import suspend_request
from django.conf import settings
from django.contrib import messages
from django.shortcuts import redirect
from django.urls import reverse

from hub.accounts.mfa import has_mfa, mfa_is_fresh


def is_step_up_fresh(request, max_age: int | None = None) -> bool:
    return mfa_is_fresh(request, max_age or settings.MFA_STEP_UP_MAX_AGE, device_only=True)


def step_up_required(view=None, *, max_age: int | None = None):
    def decorator(func):
        @wraps(func)
        def wrapper(request, *args, **kwargs):
            if not request.user.is_authenticated:
                return redirect(f"{reverse(settings.LOGIN_URL)}?next={request.get_full_path()}")
            if not has_mfa(request.user):
                messages.warning(request, "Set up two-step sign-in before doing this.")
                return redirect("mfa_index")
            if not is_step_up_fresh(request, max_age):
                return suspend_request(request, reverse("mfa_reauthenticate"))
            return func(request, *args, **kwargs)

        wrapper.step_up_required = True
        return wrapper

    return decorator(view) if view is not None else decorator
