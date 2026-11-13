from django.contrib import admin
from django.urls import include, path

from hub import health

urlpatterns = [
    path("healthz", health.healthz, name="healthz"),
    path("readyz", health.readyz, name="readyz"),
    path("admin/", admin.site.urls),
    path("accounts/", include("allauth.urls")),
    path("oauth/", include("hub.accounts.oidc_urls")),
    path("api/v1/", include("hub.api.urls")),
    path("", include("hub.organisations.urls")),
]
