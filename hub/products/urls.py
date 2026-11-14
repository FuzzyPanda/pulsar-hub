from hub.organisations.routing import org_path
from hub.products import views

org_patterns = [
    org_path("settings/apps/", views.app_connect, name="app_connect"),
    org_path("settings/apps/<uuid:app_id>/", views.app_update, name="app_update"),
    org_path("settings/apps/<uuid:app_id>/disconnect/", views.app_disconnect, name="app_disconnect"),
]
