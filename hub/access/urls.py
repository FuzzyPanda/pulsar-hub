from hub.access import views
from hub.organisations.routing import org_path

org_patterns = [
    org_path("access-groups/", views.group_list, name="group_list"),
    org_path("access-groups/new/", views.group_create, name="group_create"),
    org_path("access-groups/<uuid:group_id>/", views.group_detail, name="group_detail"),
    org_path("access-groups/<uuid:group_id>/update/", views.group_update, name="group_update"),
    org_path("access-groups/<uuid:group_id>/delete/", views.group_delete, name="group_delete"),
    org_path("access-groups/<uuid:group_id>/sites/", views.group_sites, name="group_sites"),
    org_path("access-groups/<uuid:group_id>/positions/", views.group_positions, name="group_positions"),
    org_path("access-groups/<uuid:group_id>/members/add/", views.group_member_add, name="group_member_add"),
    org_path("access-groups/<uuid:group_id>/members/remove/", views.group_member_remove, name="group_member_remove"),
]
