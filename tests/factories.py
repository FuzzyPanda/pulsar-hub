"""Test data. Business rows are created inside their organisation's context, as in real code."""

import time

import factory
from allauth.account.models import EmailAddress
from allauth.mfa.models import Authenticator
from django.utils import timezone

from hub.accounts.models import Application, User
from hub.organisations.context import organisation_context
from hub.organisations.models import (
    IdentityProvider,
    Invitation,
    Membership,
    OperatorAccess,
    Organisation,
    Role,
    hash_token,
)

PASSWORD = "correct horse battery staple"


class UserFactory(factory.django.DjangoModelFactory):
    class Meta:
        model = User
        skip_postgeneration_save = True

    email = factory.Sequence(lambda n: f"user{n}@example.test")
    name = factory.Sequence(lambda n: f"User {n}")

    @factory.post_generation
    def password(obj, create, extracted, **kwargs):
        obj.set_password(extracted or PASSWORD)
        if create:
            obj.save()
            EmailAddress.objects.get_or_create(user=obj, email=obj.email, defaults={"verified": True, "primary": True})


class OrganisationFactory(factory.django.DjangoModelFactory):
    class Meta:
        model = Organisation

    name = factory.Sequence(lambda n: f"Organisation {n}")
    slug = factory.Sequence(lambda n: f"org-{n}")


class ScopedFactory(factory.django.DjangoModelFactory):
    """Creates the row inside `organisation_context(organisation)`."""

    class Meta:
        abstract = True

    organisation = factory.SubFactory(OrganisationFactory)

    @classmethod
    def _create(cls, model_class, *args, **kwargs):
        with organisation_context(kwargs["organisation"]):
            return super()._create(model_class, *args, **kwargs)


class MembershipFactory(ScopedFactory):
    class Meta:
        model = Membership

    user = factory.SubFactory(UserFactory)
    role = Role.STAFF


class InvitationFactory(ScopedFactory):
    class Meta:
        model = Invitation

    email = factory.Sequence(lambda n: f"invitee{n}@example.test")
    role = Role.STAFF
    token_hash = factory.LazyFunction(lambda: hash_token(Invitation.new_token()))
    expires_at = factory.LazyFunction(Invitation.default_expiry)


class IdentityProviderFactory(ScopedFactory):
    class Meta:
        model = IdentityProvider

    provider = IdentityProvider.Provider.MICROSOFT
    tenant = factory.Sequence(lambda n: f"00000000-0000-0000-0000-{n:012d}")


class OperatorAccessFactory(ScopedFactory):
    class Meta:
        model = OperatorAccess

    operator = factory.SubFactory(UserFactory, is_platform_operator=True)
    reason = "Support ticket 1234"
    expires_at = factory.LazyFunction(lambda: timezone.now() + timezone.timedelta(hours=1))


class ApplicationFactory(factory.django.DjangoModelFactory):
    class Meta:
        model = Application

    name = "Pulsar app"
    client_type = Application.CLIENT_PUBLIC
    authorization_grant_type = Application.GRANT_AUTHORIZATION_CODE
    redirect_uris = "https://app.example.test/callback"
    skip_authorization = True
    algorithm = Application.RS256_ALGORITHM


def add_totp(user) -> Authenticator:
    """Give the user an authenticator app, as allauth stores one."""
    from allauth.mfa.totp.internal.auth import TOTP, generate_totp_secret

    return TOTP.activate(user, generate_totp_secret()).instance


def sign_in(client, user, *, mfa: bool = False, sso: tuple[str, str] | None = None) -> None:
    """Log the test client in and write the session records allauth would have written."""
    client.force_login(user, backend="allauth.account.auth_backends.AuthenticationBackend")
    now = time.time()
    records = [{"method": "password", "at": now, "email": user.email}]
    if sso is not None:
        from allauth.socialaccount.models import SocialAccount

        provider, tenant = sso
        account, _ = SocialAccount.objects.update_or_create(
            user=user,
            provider=provider,
            defaults={"uid": f"uid-{user.pk}", "extra_data": {"tid": tenant, "hd": tenant}},
        )
        records = [{"method": "socialaccount", "at": now, "provider": provider, "uid": account.uid}]
    if mfa:
        authenticator = Authenticator.objects.filter(user=user, type=Authenticator.Type.TOTP).first() or add_totp(user)
        records.append({"method": "mfa", "at": now, "id": authenticator.pk, "type": "totp"})
    session = client.session
    session["account_authentication_methods"] = records
    session["account_authentication_methods_user"] = str(user.pk)
    session.save()


def issue_access_token(user, organisation, raw: str, *, expires_in: int = 600, scope: str = "openid profile email"):
    """An access token as the validator stores one (a digest, never the token itself)."""
    from oauth2_provider.models import set_token_value

    from hub.accounts.models import AccessToken

    token = AccessToken(
        user=user,
        organisation=organisation,
        application=ApplicationFactory(),
        expires=timezone.now() + timezone.timedelta(seconds=expires_in),
        scope=scope,
    )
    set_token_value(token, raw)
    token.save()
    return token


# --- directory, access groups, gateways (H2 and H3) ----------------------------------------------

from hub.access.models import (  # noqa: E402
    AccessGroup,
    AccessGroupExclusion,
    AccessGroupMember,
    AccessGroupPosition,
    AccessGroupSite,
)
from hub.api.models import Scope, ServiceToken  # noqa: E402
from hub.directory.models import Person, Site  # noqa: E402
from hub.gateways.models import Gateway, GatewayEvent, PairingCode  # noqa: E402


class SiteFactory(ScopedFactory):
    class Meta:
        model = Site

    name = factory.Sequence(lambda n: f"Site {n}")
    address = "1 High Street"


class PersonFactory(ScopedFactory):
    class Meta:
        model = Person

    name = factory.Sequence(lambda n: f"Person {n}")
    work_email = factory.Sequence(lambda n: f"person{n}@example.test")


class AccessGroupFactory(ScopedFactory):
    class Meta:
        model = AccessGroup

    name = factory.Sequence(lambda n: f"Group {n}")


class AccessGroupMemberFactory(ScopedFactory):
    class Meta:
        model = AccessGroupMember

    access_group = factory.SubFactory(AccessGroupFactory, organisation=factory.SelfAttribute("..organisation"))
    person = factory.SubFactory(PersonFactory, organisation=factory.SelfAttribute("..organisation"))


class AccessGroupPositionFactory(ScopedFactory):
    class Meta:
        model = AccessGroupPosition

    access_group = factory.SubFactory(AccessGroupFactory, organisation=factory.SelfAttribute("..organisation"))
    position = factory.Sequence(lambda n: f"Position {n}")
    position_key = factory.LazyAttribute(lambda o: o.position.casefold())


class AccessGroupExclusionFactory(ScopedFactory):
    class Meta:
        model = AccessGroupExclusion

    access_group = factory.SubFactory(AccessGroupFactory, organisation=factory.SelfAttribute("..organisation"))
    person = factory.SubFactory(PersonFactory, organisation=factory.SelfAttribute("..organisation"))


class AccessGroupSiteFactory(ScopedFactory):
    class Meta:
        model = AccessGroupSite

    access_group = factory.SubFactory(AccessGroupFactory, organisation=factory.SelfAttribute("..organisation"))
    site = factory.SubFactory(SiteFactory, organisation=factory.SelfAttribute("..organisation"))


class PairingCodeFactory(ScopedFactory):
    class Meta:
        model = PairingCode

    site = factory.SubFactory(SiteFactory, organisation=factory.SelfAttribute("..organisation"))
    code_hash = factory.Sequence(lambda n: hash_token(f"CODE-{n:08d}"))
    expires_at = factory.LazyFunction(lambda: timezone.now() + timezone.timedelta(minutes=15))


class GatewayFactory(ScopedFactory):
    class Meta:
        model = Gateway

    site = factory.SubFactory(SiteFactory, organisation=factory.SelfAttribute("..organisation"))
    name = factory.Sequence(lambda n: f"Gateway {n}")
    credential_hash = factory.Sequence(lambda n: hash_token(f"hubgw_factory_{n}"))
    last_seen_at = factory.LazyFunction(timezone.now)


class GatewayEventFactory(ScopedFactory):
    class Meta:
        model = GatewayEvent

    site = factory.SubFactory(SiteFactory, organisation=factory.SelfAttribute("..organisation"))
    event_id = factory.LazyFunction(lambda: __import__("uuid").uuid4())
    type = "attendance.clock_in"
    occurred_at = factory.LazyFunction(timezone.now)


class ServiceTokenFactory(ScopedFactory):
    class Meta:
        model = ServiceToken

    name = factory.Sequence(lambda n: f"Service {n}")
    token_hash = factory.Sequence(lambda n: hash_token(f"hubsvc_factory_{n}"))
    scopes = factory.LazyFunction(lambda: list(Scope.values))


# --- connected products ---------------------------------------------------------------------------

from hub.products.models import ConnectedApp  # noqa: E402


class ConnectedAppFactory(ScopedFactory):
    class Meta:
        model = ConnectedApp

    product_key = "rostering"
    base_address = "https://rostering.example.test"


# --- the remote console ---------------------------------------------------------------------------

from hub.console.models import ConsoleSession  # noqa: E402


class ConsoleSessionFactory(ScopedFactory):
    class Meta:
        model = ConsoleSession

    gateway = factory.SubFactory(GatewayFactory, organisation=factory.SelfAttribute("..organisation"))
    user = factory.SubFactory(UserFactory)
    role = Role.OWNER
    origin = "https://console.example.test"
    started_at = factory.LazyFunction(timezone.now)
    expires_at = factory.LazyFunction(lambda: timezone.now() + timezone.timedelta(minutes=15))
    token_hash = factory.Sequence(lambda n: hash_token(f"handoff-{n}"))
    handoff_expires_at = factory.LazyFunction(lambda: timezone.now() + timezone.timedelta(seconds=60))
    browser_hash = factory.Sequence(lambda n: hash_token(f"browser-{n}"))


def open_console_tunnel(gateway, *, enabled: bool = True):
    """Put a gateway in the state the relay reports for an open tunnel, as the relay would."""
    from hub.console import services as console

    assert console.tunnel_opened(
        gateway.pk, protocol="pulsar-console.v1", software_version="1.5.0", console_enabled=enabled
    )
    gateway.refresh_from_db()
    return gateway
