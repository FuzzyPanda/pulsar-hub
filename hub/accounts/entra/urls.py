from allauth.socialaccount.providers.oauth2.urls import default_urlpatterns

from hub.accounts.entra.provider import EntraProvider

urlpatterns = default_urlpatterns(EntraProvider)
