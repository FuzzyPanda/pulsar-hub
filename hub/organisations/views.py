"""The web console. Views are thin: they read through the scoped managers and change things only
through `hub.organisations.services`.

Every view that takes `org_slug` runs after `OrganisationMiddleware` has checked the user's place
in that organisation and made it current.
"""

import json
from functools import wraps

from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.core.exceptions import PermissionDenied, ValidationError
from django.core.paginator import Paginator
from django.http import Http404, HttpResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.utils import timezone
from django.views.decorators.http import require_GET, require_http_methods, require_POST

from hub.accounts import invitations as invitation_session
from hub.accounts.stepup import step_up_required
from hub.audit.models import AuditEvent
from hub.organisations import services
from hub.organisations.models import IdentityProvider, Invitation, Membership, OperatorAccess, Organisation, Role
from hub.organisations.services import Actor


def role_required(minimum: Role):
    """The caller must hold at least `minimum` in the current organisation (operators act as Admin)."""

    def decorator(view):
        @wraps(view)
        def wrapper(request, *args, **kwargs):
            Actor.from_request(request).require(minimum)
            return view(request, *args, **kwargs)

        wrapper.minimum_role = minimum
        return wrapper

    return decorator


def _flash_errors(request, exc: Exception) -> None:
    text = "; ".join(exc.messages) if isinstance(exc, ValidationError) else (str(exc) or "You cannot do that.")
    messages.error(request, text)


def _grantable_roles(actor: Actor) -> list[Role]:
    return [role for role in Role if services._may_grant(actor, role)]


# --- Outside any organisation ---------------------------------------------------------------------


@login_required
@require_GET
def home(request):
    """Where a login lands: its organisations. With exactly one, go straight in."""
    after_mfa = request.session.pop("hub_after_mfa", None)
    memberships = list(services.memberships_for_user(request.user))
    if after_mfa and after_mfa.startswith(("/org/", "/oauth/authorize/")):
        return redirect(after_mfa)
    if len(memberships) == 1 and not request.user.is_platform_operator:
        return redirect("org_home", org_slug=memberships[0].organisation.slug)
    return render(request, "organisations/home.html", {"memberships": memberships})


@require_http_methods(["GET", "POST"])
def invitation_accept(request, token: str):
    """The page an invitation link opens.

    Opening it remembers the invitation in the session and marks the invited address as verified
    (the link reached it). A signed-in user whose email matches joins on POST. Anyone else is shown
    how to continue: create a login, sign in, or use the organisation's Microsoft or Google sign-in.
    """
    invitation = services.find_pending_invitation(token)
    if invitation is None:
        invitation_session.forget(request)
        return render(request, "organisations/invitation_invalid.html", status=404)

    invitation_session.remember(request, token)
    from allauth.account.adapter import get_adapter

    get_adapter(request).stash_verified_email(request, invitation.email)

    user = request.user
    matches = user.is_authenticated and user.email.lower() == invitation.email.lower()
    if request.method == "POST":
        if not matches:
            raise PermissionDenied
        try:
            services.accept_invitation(invitation, user=user, request=request)
        except ValidationError as exc:
            _flash_errors(request, exc)
            return redirect("home")
        invitation_session.forget(request)
        messages.success(request, f"You have joined {invitation.organisation.name}.")
        return redirect("org_home", org_slug=invitation.organisation.slug)

    from hub.accounts.models import User

    context = {
        "invitation": invitation,
        "invited_organisation": invitation.organisation,
        "role_label": Role(invitation.role).label,
        "matches": matches,
        "account_exists": User.objects.filter(email__iexact=invitation.email).exists(),
        "providers": services.sign_in_providers_for(invitation.organisation),
        "sso_required": invitation.organisation.sso_required,
    }
    return render(request, "organisations/invitation_accept.html", context)


# --- Inside an organisation -----------------------------------------------------------------------


@require_GET
def org_home(request, org_slug: str):
    from hub.products import services as products

    actor = Actor.from_request(request)
    context = {
        # The launcher: every Pulsar product this organisation has, as this person may use it.
        "app_tiles": products.launcher_tiles(actor=actor, request=request),
        "is_owner": actor.is_member_with(Role.OWNER),
        "member_count": Membership.objects.filter(is_active=True).count(),
        "pending_invitations": Invitation.objects.filter(
            accepted_at__isnull=True, revoked_at__isnull=True, expires_at__gt=timezone.now()
        ).count()
        if actor.has_role(Role.ADMIN)
        else None,
        "operator_visits": OperatorAccess.objects.active().select_related("operator")
        if actor.has_role(Role.ADMIN)
        else [],
        "role": actor.role,
        "can_manage": actor.has_role(Role.ADMIN),
    }
    return render(request, "organisations/org_home.html", context)


@require_GET
@role_required(Role.MANAGER)
def member_list(request, org_slug: str):
    actor = Actor.from_request(request)
    members = Membership.objects.filter(is_active=True).select_related("user").order_by("user__name", "user__email")
    pending = Invitation.objects.filter(
        accepted_at__isnull=True, revoked_at__isnull=True, expires_at__gt=timezone.now()
    ).select_related("invited_by")
    grantable = _grantable_roles(actor)
    rows = [
        {
            "membership": m,
            "is_self": m.user_id == request.user.pk,
            "editable": m.user_id != request.user.pk and m.role_enum in grantable,
        }
        for m in members
    ]
    context = {
        "rows": rows,
        "pending_invitations": pending if actor.has_role(Role.ADMIN) else [],
        "grantable_roles": grantable,
        "can_manage": actor.has_role(Role.ADMIN),
    }
    return render(request, "organisations/member_list.html", context)


@require_POST
@role_required(Role.ADMIN)
def invitation_create(request, org_slug: str):
    try:
        invitation, _token = services.invite_member(
            actor=Actor.from_request(request),
            email=request.POST.get("email", ""),
            role=request.POST.get("role", Role.STAFF),
            request=request,
        )
    except (ValidationError, PermissionDenied, ValueError) as exc:
        _flash_errors(request, exc)
    else:
        if invitation.email_sent:
            messages.success(request, "Invitation sent.")
        else:
            messages.error(request, "The invitation email could not be sent. Invite the person again in a few minutes.")
    return redirect("member_list", org_slug=org_slug)


@require_POST
@role_required(Role.ADMIN)
def invitation_revoke(request, org_slug: str, invitation_id):
    invitation = get_object_or_404(Invitation.objects, pk=invitation_id)
    try:
        services.revoke_invitation(invitation, actor=Actor.from_request(request), request=request)
    except (ValidationError, PermissionDenied) as exc:
        _flash_errors(request, exc)
    else:
        messages.success(request, "Invitation revoked.")
    return redirect("member_list", org_slug=org_slug)


@require_POST
@role_required(Role.ADMIN)
@step_up_required
def member_role(request, org_slug: str, membership_id):
    membership = get_object_or_404(Membership.objects.select_related("user", "organisation"), pk=membership_id)
    try:
        services.change_role(
            membership, actor=Actor.from_request(request), new_role=request.POST.get("role", ""), request=request
        )
    except (ValidationError, PermissionDenied, ValueError) as exc:
        _flash_errors(request, exc)
    else:
        messages.success(request, "Role changed.")
    return redirect("member_list", org_slug=org_slug)


@require_POST
@role_required(Role.ADMIN)
@step_up_required
def member_remove(request, org_slug: str, membership_id):
    membership = get_object_or_404(Membership.objects.select_related("user", "organisation"), pk=membership_id)
    try:
        services.remove_member(membership, actor=Actor.from_request(request), request=request)
    except (ValidationError, PermissionDenied) as exc:
        _flash_errors(request, exc)
    else:
        messages.success(request, "Member removed.")
    return redirect("member_list", org_slug=org_slug)


@require_http_methods(["GET", "POST"])
@role_required(Role.ADMIN)
def org_settings(request, org_slug: str):
    actor = Actor.from_request(request)
    if request.method == "POST":
        try:
            services.rename_organisation(actor=actor, name=request.POST.get("name", ""), request=request)
        except (ValidationError, PermissionDenied) as exc:
            _flash_errors(request, exc)
        else:
            messages.success(request, "Saved.")
        return redirect("org_settings", org_slug=org_slug)
    from hub.api.models import Scope, ServiceToken
    from hub.products import services as products
    from hub.products.addresses import HOST_PLACEHOLDER, browser_host

    app_rows, orphaned_apps = products.settings_rows(request=request)
    context = {
        "app_rows": app_rows,
        "orphaned_apps": orphaned_apps,
        "host_placeholder": HOST_PLACEHOLDER,
        "browser_host": browser_host(request),
        "identity_providers": IdentityProvider.objects.all(),
        "provider_choices": IdentityProvider.Provider.choices,
        "is_owner": actor.membership is not None and actor.membership.has_role(Role.OWNER),
        "directory_source_choices": Organisation.DirectorySource.choices,
        "service_tokens": ServiceToken.objects.live(),
        "scope_choices": Scope.choices,
        # The token itself, once, straight after it was made.
        "new_service_token": request.session.pop(NEW_SERVICE_TOKEN_KEY, None),
    }
    return render(request, "organisations/settings.html", context)


@require_POST
@role_required(Role.OWNER)
@step_up_required
def org_security(request, org_slug: str):
    try:
        services.update_security_settings(
            actor=Actor.from_request(request),
            staff_mfa_required=request.POST.get("staff_mfa_required") == "on",
            sso_required=request.POST.get("sso_required") == "on",
            request=request,
        )
    except (ValidationError, PermissionDenied) as exc:
        _flash_errors(request, exc)
    else:
        messages.success(request, "Sign-in rules saved.")
    return redirect("org_settings", org_slug=org_slug)


@require_POST
@role_required(Role.OWNER)
@step_up_required
def identity_provider_add(request, org_slug: str):
    try:
        services.add_identity_provider(
            actor=Actor.from_request(request),
            provider=request.POST.get("provider", ""),
            tenant=request.POST.get("tenant", ""),
            request=request,
        )
    except (ValidationError, PermissionDenied, ValueError) as exc:
        _flash_errors(request, exc)
    else:
        messages.success(request, "Identity provider added.")
    return redirect("org_settings", org_slug=org_slug)


@require_POST
@role_required(Role.OWNER)
@step_up_required
def identity_provider_remove(request, org_slug: str, idp_id):
    idp = get_object_or_404(IdentityProvider.objects, pk=idp_id)
    try:
        services.remove_identity_provider(idp, actor=Actor.from_request(request), request=request)
    except (ValidationError, PermissionDenied) as exc:
        _flash_errors(request, exc)
    else:
        messages.success(request, "Identity provider removed.")
    return redirect("org_settings", org_slug=org_slug)


@require_POST
@role_required(Role.OWNER)
@step_up_required
def directory_source(request, org_slug: str):
    try:
        services.set_directory_source(
            actor=Actor.from_request(request), source=request.POST.get("source", ""), request=request
        )
    except (ValidationError, PermissionDenied, ValueError) as exc:
        _flash_errors(request, exc)
    else:
        messages.success(request, "Saved.")
    return redirect("org_settings", org_slug=org_slug)


NEW_SERVICE_TOKEN_KEY = "hub_new_service_token"  # noqa: S105 (a session key name, not a secret)


@require_POST
@role_required(Role.OWNER)
@step_up_required
def service_token_create(request, org_slug: str):
    from hub.api import services as api_services

    try:
        row, token = api_services.create_service_token(
            actor=Actor.from_request(request),
            name=request.POST.get("name", ""),
            scopes=request.POST.getlist("scopes"),
            request=request,
        )
    except (ValidationError, PermissionDenied) as exc:
        _flash_errors(request, exc)
    else:
        # Shown once, on the next page, then gone: only its digest is stored.
        request.session[NEW_SERVICE_TOKEN_KEY] = {"id": str(row.pk), "name": row.name, "token": token}
    return redirect("org_settings", org_slug=org_slug)


@require_POST
@role_required(Role.OWNER)
@step_up_required
def service_token_revoke(request, org_slug: str, token_id):
    from hub.api import services as api_services
    from hub.api.models import ServiceToken

    row = get_object_or_404(ServiceToken.objects, pk=token_id)
    try:
        api_services.revoke_service_token(row, actor=Actor.from_request(request), request=request)
    except (ValidationError, PermissionDenied) as exc:
        _flash_errors(request, exc)
    else:
        messages.success(request, "Token revoked.")
    return redirect("org_settings", org_slug=org_slug)


@require_GET
@role_required(Role.ADMIN)
def audit_list(request, org_slug: str):
    events = AuditEvent.objects.select_related("actor")
    action = request.GET.get("action", "")
    if action:
        events = events.filter(action=action)
    page = Paginator(events, 50).get_page(request.GET.get("page"))
    actions = AuditEvent.objects.order_by("action").values_list("action", flat=True).distinct()
    return render(
        request, "organisations/audit_list.html", {"page": page, "actions": actions, "selected_action": action}
    )


@require_POST
@role_required(Role.OWNER)
def operator_access_end(request, org_slug: str, access_id):
    access = get_object_or_404(OperatorAccess.objects, pk=access_id)
    services.end_operator_access(access, ended_by=request.user, request=request)
    messages.success(request, "Operator access ended.")
    return redirect("org_home", org_slug=org_slug)


@require_POST
@role_required(Role.OWNER)
@step_up_required
def org_export(request, org_slug: str):
    if request.membership is None:
        raise PermissionDenied("Only an Owner can export the organisation.")
    data = services.export_organisation(request.organisation, actor_user=request.user, request=request)
    response = HttpResponse(json.dumps(data, indent=2, sort_keys=True), content_type="application/json")
    stamp = timezone.now().strftime("%Y%m%dT%H%M%SZ")
    response["Content-Disposition"] = f'attachment; filename="{request.organisation.slug}-export-{stamp}.json"'
    response["Cache-Control"] = "no-store"
    return response


# --- Pulsar operators -----------------------------------------------------------------------------
#
# `/operator/` is outside every organisation. AccountPolicyMiddleware has already required MFA.


def operator_required(view):
    @wraps(view)
    @login_required
    def wrapper(request, *args, **kwargs):
        if not request.user.is_platform_operator:
            raise Http404
        return view(request, *args, **kwargs)

    wrapper.operator_only = True
    return wrapper


@operator_required
@require_GET
def operator_home(request):
    """The list of organisations: name, address and status only. No organisation's data."""
    organisations = list(Organisation.objects.order_by("name"))
    ownerless = services.organisations_without_owner()
    for organisation in organisations:
        organisation.awaiting_owner = organisation.pk in ownerless
    return render(request, "organisations/operator_home.html", {"organisations": organisations})


@operator_required
@require_POST
@step_up_required
def operator_invite_owner(request, org_ref):
    organisation = get_object_or_404(Organisation, pk=org_ref)
    try:
        invitation, _token = services.invite_first_owner(
            organisation, owner_email=request.POST.get("owner_email", ""), operator=request.user, request=request
        )
    except (ValidationError, PermissionDenied) as exc:
        _flash_errors(request, exc)
    else:
        if invitation.email_sent:
            messages.success(request, f"Owner invitation for {organisation.name} sent.")
        else:
            messages.error(request, "The invitation email could not be sent. Check the mail settings and try again.")
    return redirect("operator_home")


@operator_required
@require_POST
@step_up_required
def operator_provision(request):
    try:
        organisation, invitation, _token = services.provision_organisation(
            name=request.POST.get("name", ""),
            owner_email=request.POST.get("owner_email", ""),
            operator=request.user,
            request=request,
        )
    except (ValidationError, PermissionDenied) as exc:
        _flash_errors(request, exc)
    else:
        if invitation.email_sent:
            messages.success(request, f"{organisation.name} created. The owner has been sent an invitation.")
        else:
            messages.error(
                request,
                f"{organisation.name} created, but the owner's invitation email could not be sent. "
                "Send it again from the list below.",
            )
    return redirect("operator_home")


@operator_required
@require_POST
@step_up_required
def operator_open_access(request, org_ref):
    organisation = get_object_or_404(Organisation, pk=org_ref)
    try:
        services.open_operator_access(
            organisation, operator=request.user, reason=request.POST.get("reason", ""), request=request
        )
    except (ValidationError, PermissionDenied) as exc:
        _flash_errors(request, exc)
        return redirect("operator_home")
    return redirect("org_home", org_slug=organisation.slug)


@operator_required
@require_POST
@step_up_required
def operator_set_status(request, org_ref):
    organisation = get_object_or_404(Organisation, pk=org_ref)
    try:
        if request.POST.get("action") == "suspend":
            services.suspend_organisation(
                organisation, operator=request.user, reason=request.POST.get("reason", ""), request=request
            )
            messages.success(request, f"{organisation.name} suspended.")
        elif request.POST.get("action") == "reactivate":
            services.reactivate_organisation(organisation, operator=request.user, request=request)
            messages.success(request, f"{organisation.name} reactivated.")
    except (ValidationError, PermissionDenied) as exc:
        _flash_errors(request, exc)
    return redirect("operator_home")


@operator_required
@require_POST
@step_up_required
def operator_delete(request, org_ref):
    organisation = get_object_or_404(Organisation, pk=org_ref)
    try:
        services.delete_organisation(
            organisation, operator=request.user, confirm_slug=request.POST.get("confirm_slug", ""), request=request
        )
    except (ValidationError, PermissionDenied) as exc:
        _flash_errors(request, exc)
    else:
        messages.success(request, "Organisation deleted.")
    return redirect("operator_home")
