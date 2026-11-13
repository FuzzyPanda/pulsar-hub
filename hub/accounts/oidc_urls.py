"""Only the endpoints the hub offers. django-oauth-toolkit's own URL list also includes pages that
let any signed-in user register OAuth applications, token introspection and the device flow; none
of those are mounted. Applications are created by Pulsar staff in the admin."""

from django.urls import path, re_path
from oauth2_provider import views

from hub.accounts.oidc_views import AuthorizationView

app_name = "oauth2_provider"

urlpatterns = [
    path("authorize/", AuthorizationView.as_view(), name="authorize"),
    path("token/", views.TokenView.as_view(), name="token"),
    path("revoke_token/", views.RevokeTokenView.as_view(), name="revoke-token"),
    re_path(
        r"^\.well-known/openid-configuration/?$",
        views.ConnectDiscoveryInfoView.as_view(),
        name="oidc-connect-discovery-info",
    ),
    path(".well-known/jwks.json", views.JwksInfoView.as_view(), name="jwks-info"),
    path("userinfo/", views.UserInfoView.as_view(), name="user-info"),
    path("logout/", views.RPInitiatedLogoutView.as_view(), name="rp-initiated-logout"),
]
