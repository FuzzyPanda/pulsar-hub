"""The Django admin holds platform-level records only: logins and OAuth applications.

No organisation-scoped model is registered here, and none may be: the admin would read it through
a manager that has no current organisation. Organisations are run from `/operator/`.
"""

from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin

from hub.accounts.models import User


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
