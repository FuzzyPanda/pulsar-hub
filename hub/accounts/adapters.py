"""How the hub bends django-allauth: accounts exist only by invitation, MFA cannot be dropped
while a role needs it, and a Microsoft or Google sign-in is tied to the directory it came from."""

from urllib.parse import urlparse

from allauth.account.adapter import DefaultAccountAdapter
from allauth.mfa.adapter import DefaultMFAAdapter
from allauth.mfa.models import Authenticator
from allauth.socialaccount.adapter import DefaultSocialAccountAdapter
from django.conf import settings
from django.core.exceptions import ValidationError
from django.urls import reverse

from hub.accounts import invitations
from hub.accounts.mfa import SECOND_FACTORS, has_mfa
from hub.organisations.services import identity_providers_for, user_requires_mfa


class AccountAdapter(DefaultAccountAdapter):
    def is_open_for_signup(self, request) -> bool:
        """There is no public sign-up. A login is created only while accepting an invitation."""
        return invitations.pending(request) is not None

    def clean_email(self, email: str) -> str:
        email = super().clean_email(email)
        request = self.request
        if request is not None and not request.user.is_authenticated:
            invitation = invitations.pending(request)
            if invitation is not None and email.strip().lower() != invitation.email.lower():
                raise ValidationError("Use the email address the invitation was sent to.")
        return email

    def get_login_redirect_url(self, request) -> str:
        if invitations.pending(request) is not None:
            return reverse("invitation_accept", kwargs={"token": request.session[invitations.SESSION_KEY]})
        return super().get_login_redirect_url(request)

    def get_signup_redirect_url(self, request) -> str:
        return self.get_login_redirect_url(request)

    def get_reauthentication_methods(self, user) -> list[dict]:
        """A login that has a second factor confirms itself with that factor, not with a password
        or an emailed code. (AccountPolicyMiddleware enforces the same on the pages themselves.)"""
        methods = super().get_reauthentication_methods(user)
        if has_mfa(user):
            return [m for m in methods if m["id"].startswith("mfa_")] or methods
        return methods


class MFAAdapter(DefaultMFAAdapter):
    def get_public_key_credential_rp_entity(self) -> dict[str, str]:
        """What a passkey is bound to: the hub's own host name, and the product name the browser
        shows when it asks. Taken from HUB_BASE_URL, never from the request's Host header."""
        return {"id": urlparse(settings.HUB_BASE_URL).hostname, "name": settings.PRODUCT_NAME}

    def can_delete_authenticator(self, authenticator: Authenticator) -> bool:
        """The last second factor cannot be removed while any of the user's roles requires MFA."""
        if authenticator.type not in SECOND_FACTORS:
            return True
        others = (
            Authenticator.objects.filter(user_id=authenticator.user_id, type__in=SECOND_FACTORS)
            .exclude(pk=authenticator.pk)
            .exists()
        )
        return others or not user_requires_mfa(authenticator.user)


def sso_tenant(sociallogin) -> tuple[str, str]:
    """(provider, tenant) for a social login: Microsoft's `tid` or Google's `hd`."""
    data = sociallogin.account.extra_data or {}
    tenant = data.get("tid") or data.get("hd") or ""
    return sociallogin.account.provider, str(tenant).lower()


class SocialAccountAdapter(DefaultSocialAccountAdapter):
    def is_open_for_signup(self, request, sociallogin) -> bool:
        """A first sign-in with Microsoft or Google creates a login only when all of these hold:
        the browser is accepting an invitation, the invitation's organisation lists the directory
        the user came from, and the directory reports the invited email address.
        """
        invitation = invitations.pending(request)
        if invitation is None:
            return False
        provider, tenant = sso_tenant(sociallogin)
        if not tenant:
            return False
        allowed = {(idp.provider, idp.tenant) for idp in identity_providers_for(invitation.organisation)}
        if (provider, tenant) not in allowed:
            return False
        email = (sociallogin.user.email or "").strip().lower()
        return bool(email) and email == invitation.email.lower()

    def is_auto_signup_allowed(self, request, sociallogin) -> bool:
        return True

    def populate_user(self, request, sociallogin, data):
        user = super().populate_user(request, sociallogin, data)
        first, last = data.get("first_name") or "", data.get("last_name") or ""
        user.name = (data.get("name") or f"{first} {last}").strip()[:200]
        return user

    def is_email_verified(self, provider, email) -> bool:
        """Never take a directory's word for an email address.

        Entra's `mail` attribute is whatever a tenant administrator typed. The hub therefore never
        matches a social login to a login by email (SOCIALACCOUNT_EMAIL_AUTHENTICATION is off), and
        a new login's address counts as verified only because the invitation link reached it.
        """
        return False
