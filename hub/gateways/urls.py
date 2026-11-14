from hub.gateways import views
from hub.organisations.routing import org_path

org_patterns = [
    org_path("sites/<uuid:site_id>/pairing-code/", views.gateway_pairing_code, name="gateway_pairing_code"),
    org_path("gateways/<uuid:gateway_id>/revoke/", views.gateway_revoke, name="gateway_revoke"),
    org_path(
        "gateways/<uuid:gateway_id>/console-address/", views.gateway_console_address, name="gateway_console_address"
    ),
    org_path("events/", views.event_list, name="event_list"),
]
