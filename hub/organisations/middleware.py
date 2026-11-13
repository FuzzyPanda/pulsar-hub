"""Resolves the organisation for a console request and makes it current.

Every console route that shows business data lives under `/org/<org_slug>/`. This middleware is
the only way such a view gets an organisation:

1. not signed in: to the login page;
2. no such organisation, or the user is neither an active member nor an operator on an open
   visit: 404, the same answer either way, so the response does not reveal which organisations
   exist;
3. the organisation requires single sign-on and this session did not come through one of its
   directories: to the single sign-on page;
4. the role requires MFA and this session has not passed it: to MFA set-up or challenge.

Only then is the organisation made current for the scoped managers. It is always cleared when the
response has been produced, whatever happened in between.
"""

from functools import wraps

from allauth.account.internal.flows.reauthentication import suspend_request
from django.conf import settings
from django.contrib import messages
from django.contrib.auth.views import redirect_to_login
from django.http import Http404
from django.shortcuts import redirect, render
from django.urls import reverse

from hub.accounts.mfa import authentication_methods
from hub.audit import services as audit
from hub.organisations.context import reset_current_organisation, set_current_organisation
from hub.organisations.entry import Entry, evaluate_entry
from hub.organisations.models import Organisation
from hub.organisations.services import sign_in_providers_for

ENTERED_KEY = "hub_organisations_entered"


def refusal_response(request, decision):
    """The response for an entry decision that is not OK. Shared with the OIDC authorisation screen."""
    organisation = decision.organisation
    if decision.outcome is Entry.NOT_FOUND:
        raise Http404
    if decision.outcome is Entry.SUSPENDED:
        return render(request, "organisations/suspended.html", {"suspended_organisation": organisation}, status=403)
    if decision.outcome is Entry.SSO_REQUIRED:
        return render(
            request,
            "organisations/sso_required.html",
            {
                "sso_organisation": organisation,
                "providers": sign_in_providers_for(organisation),
                "next": request.get_full_path(),
            },
            status=403,
        )
    if decision.outcome is Entry.MFA_CHALLENGE:
        return suspend_request(request, reverse("mfa_reauthenticate"))
    if decision.outcome is Entry.MFA_ENROL:
        messages.warning(request, f"{organisation.name} requires two-step sign-in. Set it up to continue.")
        request.session["hub_after_mfa"] = request.get_full_path()
        return redirect("mfa_index")
    raise AssertionError(decision.outcome)


def enter_organisation(request, slug: str):
    """Check the user's place in the organisation at `slug` and make it current.

    Returns None when the request may proceed, or the response that refuses it. Safe to call twice
    for one request: the second call for the same organisation does nothing.
    """
    current = getattr(request, "organisation", None)
    if current is not None and getattr(request, "_organisation_tokens", None) is not None:
        if current.slug == slug:
            return None
        raise Http404  # one request, one organisation

    if not request.user.is_authenticated:
        return redirect_to_login(request.get_full_path(), reverse(settings.LOGIN_URL))

    organisation = Organisation.objects.filter(slug=slug).first()
    decision = evaluate_entry(request, organisation)
    if not decision.ok:
        return refusal_response(request, decision)

    request.organisation = organisation
    request.membership = decision.membership
    request.operator_access = decision.operator_access
    request._organisation_tokens = set_current_organisation(organisation)

    entered = request.session.get(ENTERED_KEY, [])
    if str(organisation.pk) not in entered:
        # Sign-in is account-level; this is the organisation's own record that the person came in.
        audit.record("organisation.session_started", request=request, data={"methods": authentication_methods(request)})
        request.session[ENTERED_KEY] = [*entered, str(organisation.pk)]
    return None


def organisation_view(view):
    """Wraps every view under `/org/<org_slug>/` (see `org_path` in urls.py).

    Normally `OrganisationMiddleware.process_view` has already entered the organisation and this
    does nothing. It matters when a view is called without the middleware: allauth does exactly
    that when it replays a request that was interrupted for a step-up check. Without this the
    replayed view would run with no organisation, and with it the replay passes the same checks as
    any other request.
    """

    @wraps(view)
    def wrapper(request, *args, **kwargs):
        response = enter_organisation(request, kwargs["org_slug"])
        if response is not None:
            return response
        return view(request, *args, **kwargs)

    wrapper.organisation_view = True
    return wrapper


class OrganisationMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        request.organisation = None
        request.membership = None
        request.operator_access = None
        request._organisation_tokens = None
        try:
            return self.get_response(request)
        finally:
            self._clear(request)

    @staticmethod
    def _clear(request) -> None:
        tokens = getattr(request, "_organisation_tokens", None)
        if tokens is not None:
            reset_current_organisation(tokens)
            request._organisation_tokens = None

    def process_view(self, request, view_func, view_args, view_kwargs):
        slug = view_kwargs.get("org_slug")
        if slug is None:
            return None
        return enter_organisation(request, slug)
