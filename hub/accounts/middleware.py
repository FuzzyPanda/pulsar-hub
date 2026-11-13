"""Account-level policy that applies before any organisation is involved."""

import time

from allauth.account.internal.flows.reauthentication import suspend_request
from django.conf import settings
from django.contrib import messages
from django.contrib.auth import logout
from django.contrib.auth.views import redirect_to_login
from django.shortcuts import redirect
from django.urls import Resolver404, resolve, reverse

from hub.accounts.mfa import has_mfa, mfa_is_fresh, mfa_satisfied
from hub.logging import user_ref_var

# Places Pulsar's own staff work. Each needs a login that has passed MFA in this session.
STAFF_PREFIXES = ("/admin/", "/operator/")

SESSION_STARTED_KEY = "hub_session_started_at"

# Pages that change how a login is protected. For a login that has a second factor, each needs a
# second-factor check within ACCOUNT_REAUTHENTICATION_TIMEOUT. Without this, someone holding a
# live session and the password could add their own passkey, read the recovery codes, or change
# the email address, and from there pass any later check.
ACCOUNT_SECURITY_PAGES = frozenset(
    {
        "mfa_activate_totp",
        "mfa_deactivate_totp",
        "mfa_list_webauthn",
        "mfa_add_webauthn",
        "mfa_edit_webauthn",
        "mfa_remove_webauthn",
        "mfa_view_recovery_codes",
        "mfa_generate_recovery_codes",
        "mfa_download_recovery_codes",
        "account_change_password",
        "account_set_password",
        "account_email",
        "socialaccount_connections",
    }
)
# allauth's other ways to "confirm it is you". A login with a second factor must use the factor.
WEAKER_REAUTHENTICATION_PAGES = frozenset(
    {"account_reauthenticate", "account_request_reauthentication_code", "account_confirm_reauthentication_code"}
)


class AccountPolicyMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        user = getattr(request, "user", None)
        if user is None or not user.is_authenticated:
            return self.get_response(request)
        user_ref_var.set(str(user.pk))

        # An absolute session lifetime. Django's own expiry moves forward every time the session
        # is saved, so it cannot bound how long a login outlives a disabled directory account.
        started = request.session.get(SESSION_STARTED_KEY)
        if started is None:
            request.session[SESSION_STARTED_KEY] = time.time()
        elif time.time() - started > settings.SESSION_COOKIE_AGE:
            logout(request)
            if request.path.startswith("/api/") or request.path.startswith("/oauth/token"):
                return self.get_response(request)
            return redirect_to_login(request.get_full_path(), reverse(settings.LOGIN_URL))

        if request.path.startswith(STAFF_PREFIXES) and not mfa_satisfied(request):
            if has_mfa(user):
                return suspend_request(request, reverse("mfa_reauthenticate"))
            messages.warning(request, "Set up two-step sign-in to continue.")
            return redirect("mfa_index")

        if request.path.startswith("/accounts/") and has_mfa(user):
            try:
                name = resolve(request.path_info).url_name
            except Resolver404:
                name = None
            if name in WEAKER_REAUTHENTICATION_PAGES:
                query = request.META.get("QUERY_STRING", "")
                return redirect(reverse("mfa_reauthenticate") + (f"?{query}" if query else ""))
            if name in ACCOUNT_SECURITY_PAGES and not mfa_is_fresh(request, settings.ACCOUNT_REAUTHENTICATION_TIMEOUT):
                return suspend_request(request, reverse("mfa_reauthenticate"))
        return self.get_response(request)
