from hub.directory import views
from hub.organisations.routing import org_path

org_patterns = [
    org_path("sites/", views.site_list, name="site_list"),
    org_path("sites/new/", views.site_create, name="site_create"),
    org_path("sites/<uuid:site_id>/", views.site_detail, name="site_detail"),
    org_path("sites/<uuid:site_id>/update/", views.site_update, name="site_update"),
    org_path("sites/<uuid:site_id>/access-mode/", views.site_access_mode, name="site_access_mode"),
    org_path("people/", views.person_list, name="person_list"),
    org_path("people/new/", views.person_create, name="person_create"),
    org_path("people/<uuid:person_id>/", views.person_detail, name="person_detail"),
    org_path("people/<uuid:person_id>/update/", views.person_update, name="person_update"),
    org_path("people/<uuid:person_id>/end/", views.person_end, name="person_end"),
    org_path("people/<uuid:person_id>/reactivate/", views.person_reactivate, name="person_reactivate"),
]
