from django.urls import path

from hub.api import views

urlpatterns = [
    path("me", views.MeView.as_view(), name="api_me"),
    path("organisation", views.OrganisationView.as_view(), name="api_organisation"),
    path("organisation/members", views.MemberListView.as_view(), name="api_members"),
]
