from django.urls import path

from hub.console import internal, views
from hub.organisations.routing import org_path

org_patterns = [
    org_path("gateways/<uuid:gateway_id>/console/open/", views.console_open, name="console_open"),
    org_path("console-sessions/<uuid:session_id>/extend/", views.console_extend, name="console_extend"),
    org_path("console-sessions/<uuid:session_id>/end/", views.console_end, name="console_end"),
]

# The relay's internal channel. Never routed by Caddy; see hub/console/internal.py.
internal_patterns = [
    path("started", internal.started, name="relay_started"),
    path("tunnel/authorize", internal.tunnel_authorize, name="relay_tunnel_authorize"),
    path("tunnel/refused", internal.tunnel_refused, name="relay_tunnel_refused"),
    path("tunnel/opened", internal.tunnel_opened, name="relay_tunnel_opened"),
    path("handoff/redeem", internal.handoff_redeem, name="relay_handoff_redeem"),
    path("event", internal.event, name="relay_event"),
    path("heartbeat", internal.heartbeat, name="relay_heartbeat"),
]
