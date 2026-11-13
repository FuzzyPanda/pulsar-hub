from django.urls import path

from hub.api import views, views_machine

urlpatterns = [
    # People using the app (a user token, bound to one organisation).
    path("me", views.MeView.as_view(), name="api_me"),
    path("organisation", views.OrganisationView.as_view(), name="api_organisation"),
    path("organisation/members", views.MemberListView.as_view(), name="api_members"),
    # Pulsar Rostering and other systems (a service token).
    path("directory", views_machine.DirectoryView.as_view(), name="api_directory"),
    path("people", views_machine.PeopleView.as_view(), name="api_people"),
    path("sites", views_machine.SitesView.as_view(), name="api_sites"),
    path("events", views_machine.EventsView.as_view(), name="api_events"),
    # Gateways (the credential from pairing).
    path("gateways/pair", views_machine.GatewayPairView.as_view(), name="api_gateway_pair"),
    path("sites/<uuid:site_ref>/access", views_machine.GatewayAccessView.as_view(), name="api_gateway_access"),
    path(
        "sites/<uuid:site_ref>/access/ack", views_machine.GatewayAccessAckView.as_view(), name="api_gateway_access_ack"
    ),
    path("sites/<uuid:site_ref>/events", views_machine.GatewayEventsView.as_view(), name="api_gateway_events"),
    path("sites/<uuid:site_ref>/state", views_machine.GatewayStateView.as_view(), name="api_gateway_state"),
]
