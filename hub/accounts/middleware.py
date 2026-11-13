"""Account-level policy that applies before any organisation is involved."""

from allauth.account.internal.flows.reauthentication import suspend_request
from django.contrib import messages
from django.shortcuts import redirect
from django.urls import reverse

from hub.accounts.mfa import has_mfa, mfa_satisfied
from hub.logging import user_ref_var

# Places Pulsar's own staff work. Each needs a login that has passed MFA in this session.
STAFF_PREFIXES = ("/admin/", "/operator/")


class AccountPolicyMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        user = getattr(request, "user", None)
        if user is not None and user.is_authenticated:
            user_ref_var.set(str(user.pk))
            if request.path.startswith(STAFF_PREFIXES) and not mfa_satisfied(request):
                if has_mfa(user):
                    return suspend_request(request, reverse("mfa_reauthenticate"))
                messages.warning(request, "Set up two-step sign-in to continue.")
                return redirect("mfa_index")
        return self.get_response(request)
