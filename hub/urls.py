from allauth.account.decorators import secure_admin_login
from django.contrib import admin
from django.urls import include, path

from hub import health
from hub.accounts.admin import restrict_admin_to_platform_records

# The admin has its own login form, which would skip the hub's rate limits, MFA and audit trail.
# Send it through the one sign-in everyone else uses.
admin.site.login = secure_admin_login(admin.site.login)
# By now every installed app has registered its admins; keep only the hub's own.
restrict_admin_to_platform_records()

urlpatterns = [
    path("healthz", health.healthz, name="healthz"),
    path("readyz", health.readyz, name="readyz"),
    path("admin/", admin.site.urls),
    path("accounts/", include("allauth.urls")),
    path("oauth/", include("hub.accounts.oidc_urls")),
    path("api/v1/", include("hub.api.urls")),
    path("", include("hub.organisations.urls")),
]
