from django.urls import include, path

from hub.access.urls import org_patterns as access_patterns
from hub.directory.urls import org_patterns as directory_patterns
from hub.gateways.urls import org_patterns as gateway_patterns
from hub.organisations import views
from hub.organisations.routing import org_path

org_patterns = [
    org_path("", views.org_home, name="org_home"),
    org_path("members/", views.member_list, name="member_list"),
    org_path("members/<uuid:membership_id>/role/", views.member_role, name="member_role"),
    org_path("members/<uuid:membership_id>/remove/", views.member_remove, name="member_remove"),
    org_path("invitations/", views.invitation_create, name="invitation_create"),
    org_path("invitations/<uuid:invitation_id>/revoke/", views.invitation_revoke, name="invitation_revoke"),
    org_path("settings/", views.org_settings, name="org_settings"),
    org_path("settings/security/", views.org_security, name="org_security"),
    org_path("settings/identity-providers/", views.identity_provider_add, name="identity_provider_add"),
    org_path(
        "settings/identity-providers/<uuid:idp_id>/remove/",
        views.identity_provider_remove,
        name="identity_provider_remove",
    ),
    org_path("settings/export/", views.org_export, name="org_export"),
    org_path("audit/", views.audit_list, name="audit_list"),
    org_path("operator-access/<uuid:access_id>/end/", views.operator_access_end, name="operator_access_end"),
    org_path("settings/directory-source/", views.directory_source, name="directory_source"),
    org_path("settings/service-tokens/", views.service_token_create, name="service_token_create"),
    org_path(
        "settings/service-tokens/<uuid:token_id>/revoke/", views.service_token_revoke, name="service_token_revoke"
    ),
    *directory_patterns,
    *access_patterns,
    *gateway_patterns,
]

operator_patterns = [
    path("", views.operator_home, name="operator_home"),
    path("organisations/", views.operator_provision, name="operator_provision"),
    path("organisations/<uuid:org_ref>/access/", views.operator_open_access, name="operator_open_access"),
    path("organisations/<uuid:org_ref>/owner/", views.operator_invite_owner, name="operator_invite_owner"),
    path("organisations/<uuid:org_ref>/status/", views.operator_set_status, name="operator_set_status"),
    path("organisations/<uuid:org_ref>/delete/", views.operator_delete, name="operator_delete"),
]

urlpatterns = [
    path("", views.home, name="home"),
    path("invitations/<str:token>/", views.invitation_accept, name="invitation_accept"),
    path("org/<slug:org_slug>/", include(org_patterns)),
    path("operator/", include(operator_patterns)),
]
