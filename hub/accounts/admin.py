"""The Django admin holds two things: logins, and the OAuth applications that sign in through the
hub. Nothing else.

Third-party apps register their own admins for tokens, social accounts, email addresses and queued
jobs. Those are removed below: through them a staff login could read organisation-bound records
or edit the facts the sign-in rules rely on (a social account's tenant, an email's verified flag),
with no operator visit and no audit event. `tests/test_auth.py` fails if anything else appears.

No organisation-scoped model may be registered either. Organisations are run from `/operator/`.
"""

from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin

from hub.accounts.models import Application, User


@admin.register(User)
class UserAdmin(BaseUserAdmin):
    ordering = ["email"]
    list_display = ["email", "name", "is_active", "is_platform_operator", "is_staff"]
    list_filter = ["is_active", "is_platform_operator", "is_staff"]
    search_fields = ["email", "name"]
    readonly_fields = ["id", "date_joined", "last_login"]
    fieldsets = [
        (None, {"fields": ["id", "email", "name", "password"]}),
        ("Status", {"fields": ["is_active", "is_platform_operator", "is_staff", "is_superuser"]}),
        ("Dates", {"fields": ["date_joined", "last_login"]}),
    ]
    add_fieldsets = [(None, {"classes": ["wide"], "fields": ["email", "name", "password1", "password2"]})]
    filter_horizontal: list[str] = []


if admin.site.is_registered(Application):
    admin.site.unregister(Application)  # django-oauth-toolkit registered its own; this one replaces it


@admin.register(Application)
class ApplicationAdmin(admin.ModelAdmin):
    """The Pulsar app, Time Is Money 2. A client secret is shown once, when it is created."""

    list_display = ["name", "client_id", "client_type", "skip_authorization"]
    fields = [
        "name",
        "client_id",
        "client_type",
        "authorization_grant_type",
        "redirect_uris",
        "post_logout_redirect_uris",
        "allowed_origins",
        "algorithm",
        "skip_authorization",
        "client_secret",
        "hash_client_secret",
    ]

    def get_readonly_fields(self, request, obj=None):
        return ["client_id", "client_secret", "hash_client_secret"] if obj else []


ALLOWED_IN_ADMIN = {User, Application}


def restrict_admin_to_platform_records() -> None:
    for model in list(admin.site._registry):
        if model not in ALLOWED_IN_ADMIN:
            admin.site.unregister(model)
