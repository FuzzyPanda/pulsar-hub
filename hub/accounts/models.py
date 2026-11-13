"""Logins, and the OAuth models that bind a token to one organisation."""

import uuid

from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin
from django.db import models
from django.utils import timezone
from oauth2_provider.models import (
    AbstractAccessToken,
    AbstractApplication,
    AbstractGrant,
    AbstractIDToken,
    AbstractRefreshToken,
)


class UserManager(BaseUserManager):
    use_in_migrations = True

    def _create(self, email: str, password: str | None, **extra):
        if not email:
            raise ValueError("A user needs an email address.")
        user = self.model(email=self.normalize_email(email).lower(), **extra)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_user(self, email: str, password: str | None = None, **extra):
        extra.setdefault("is_staff", False)
        extra.setdefault("is_superuser", False)
        return self._create(email, password, **extra)

    def create_superuser(self, email: str, password: str | None = None, **extra):
        extra["is_staff"] = True
        extra["is_superuser"] = True
        extra.setdefault("is_platform_operator", True)
        return self._create(email, password, **extra)

    def get_by_natural_key(self, email):
        return self.get(email__iexact=email)


class User(AbstractBaseUser, PermissionsMixin):
    """One login. It holds no organisation: a person joins organisations through memberships.

    `id` is the stable public identifier (the OIDC `sub`). The email address can change and is
    never a join key.
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    email = models.EmailField(unique=True)
    name = models.CharField(max_length=200, blank=True)
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False, help_text="May open the Django admin.")
    # Pulsar's own staff. This alone opens no organisation: each visit needs a time-limited,
    # audited OperatorAccess row (hub.organisations).
    is_platform_operator = models.BooleanField(default=False)
    date_joined = models.DateTimeField(default=timezone.now)

    objects = UserManager()

    USERNAME_FIELD = "email"
    EMAIL_FIELD = "email"
    REQUIRED_FIELDS: list[str] = []

    class Meta:
        constraints = [
            models.UniqueConstraint(models.functions.Lower("email"), name="accounts_user_email_ci_unique"),
        ]

    def __str__(self) -> str:
        return self.email

    def save(self, *args, **kwargs):
        self.email = (self.email or "").strip().lower()
        super().save(*args, **kwargs)

    @property
    def display_name(self) -> str:
        return self.name or self.email


# --- OAuth models ---------------------------------------------------------------------------------
#
# A token is issued to one user, for one organisation (docs/CONTRACTS.md, "Hub and the app").
# The organisation is chosen on the authorisation screen, travels on the authorisation code, and
# is copied to the access and refresh tokens. `authenticated_at` is when the user last proved who
# they were in the browser; an organisation that requires single sign-on uses it to stop a refresh
# token outliving the account in the client's own directory.
#
# django-oauth-toolkit's models refer to each other, so swapping some means swapping all five.
# Application and IDToken are unchanged copies of the toolkit's.


class Application(AbstractApplication):
    """A product that signs in through the hub: the Pulsar app, Time Is Money 2."""

    class Meta(AbstractApplication.Meta):
        pass


class IDToken(AbstractIDToken):
    class Meta(AbstractIDToken.Meta):
        pass


class Grant(AbstractGrant):
    organisation = models.ForeignKey("organisations.Organisation", on_delete=models.CASCADE, related_name="+")
    authenticated_at = models.DateTimeField()
    via_sso = models.BooleanField(default=False)

    class Meta(AbstractGrant.Meta):
        pass


class AccessToken(AbstractAccessToken):
    organisation = models.ForeignKey("organisations.Organisation", on_delete=models.CASCADE, related_name="+")

    class Meta(AbstractAccessToken.Meta):
        pass


class RefreshToken(AbstractRefreshToken):
    organisation = models.ForeignKey("organisations.Organisation", on_delete=models.CASCADE, related_name="+")
    authenticated_at = models.DateTimeField()
    via_sso = models.BooleanField(default=False)

    class Meta(AbstractRefreshToken.Meta):
        pass
