"""The authorisation screen: sign in, choose an organisation, and (for third parties) consent."""

from datetime import UTC, datetime

from django.shortcuts import render
from oauth2_provider.views import AuthorizationView as BaseAuthorizationView

from hub.accounts.mfa import authenticated_at, session_sso_identity
from hub.audit import services as audit
from hub.organisations.context import organisation_context
from hub.organisations.entry import evaluate_entry
from hub.organisations.middleware import refusal_response
from hub.organisations.services import memberships_for_user


class AuthorizationView(BaseAuthorizationView):
    """django-oauth-toolkit's view, with the organisation settled before anything is issued.

    The client may name the organisation with `org=<org_ref>`. Without it a user with one
    organisation gets that one, and a user with several is asked. Whichever way it was chosen, the
    session must pass the same entry rules as the console (membership, single sign-on, MFA).
    """

    template_name = "accounts/oidc_authorize.html"
    organisation = None

    def dispatch(self, request, *args, **kwargs):
        if request.user.is_authenticated:
            response = self._settle_organisation(request)
            if response is not None:
                return response
        return super().dispatch(request, *args, **kwargs)

    def _settle_organisation(self, request):
        memberships = list(memberships_for_user(request.user))
        wanted = request.GET.get("org", "")
        organisation = None
        if wanted:
            organisation = next((m.organisation for m in memberships if str(m.organisation.pk) == wanted), None)
            if organisation is None:
                # Not a member, or no such organisation: the same answer for both.
                return render(request, "accounts/oidc_no_organisation.html", status=403)
        elif len(memberships) == 1:
            organisation = memberships[0].organisation
        elif not memberships:
            return render(request, "accounts/oidc_no_organisation.html", status=403)
        else:
            query = request.GET.copy()
            choices = []
            for membership in memberships:
                query["org"] = str(membership.organisation.pk)
                choices.append({"organisation": membership.organisation, "url": f"{request.path}?{query.urlencode()}"})
            return render(request, "accounts/oidc_choose_organisation.html", {"choices": choices})

        decision = evaluate_entry(request, organisation, allow_operator=False)
        if not decision.ok:
            return refusal_response(request, decision)
        self.organisation = organisation
        return None

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context["token_organisation"] = self.organisation
        return context

    def create_authorization_response(self, request, scopes, credentials, allow):
        if allow:
            if self.organisation is None:
                raise ValueError("No organisation was settled for this authorisation.")
            at = authenticated_at(request)
            credentials["organisation"] = self.organisation
            credentials["authenticated_at"] = datetime.fromtimestamp(at, tz=UTC) if at else None
            credentials["via_sso"] = session_sso_identity(request) is not None
        response = super().create_authorization_response(request, scopes, credentials, allow)
        if allow:
            with organisation_context(self.organisation):
                audit.record(
                    "auth.token_authorised",
                    request=request,
                    target_label=str(credentials.get("client_id", ""))[:254],
                    data={"scopes": scopes if isinstance(scopes, str) else " ".join(scopes)},
                )
        return response
