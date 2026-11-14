"""Settings actions for connected products. Thin: every change goes through `hub.products.services`."""

from django.contrib import messages
from django.core.exceptions import PermissionDenied, ValidationError
from django.shortcuts import get_object_or_404, redirect
from django.urls import reverse
from django.views.decorators.http import require_POST

from hub.accounts.stepup import step_up_required
from hub.organisations.models import Role
from hub.organisations.services import Actor
from hub.organisations.views import _flash_errors, role_required
from hub.products import catalogue, services
from hub.products.models import ConnectedApp

ERRORS = (ValidationError, PermissionDenied, ValueError)


def _back(org_slug: str):
    return redirect(reverse("org_settings", kwargs={"org_slug": org_slug}) + "#apps")


def _name(product_key: str) -> str:
    product = catalogue.get_product(product_key)
    return product.name if product else "The app"


@require_POST
@role_required(Role.OWNER)
@step_up_required
def app_connect(request, org_slug: str):
    product_key = request.POST.get("product", "")
    try:
        services.connect_app(
            actor=Actor.from_request(request),
            product_key=product_key,
            base_address=request.POST.get("base_address", ""),
            launch_path=request.POST.get("launch_path", ""),
            request=request,
        )
    except ERRORS as exc:
        _flash_errors(request, exc)
    else:
        messages.success(request, f"{_name(product_key)} connected.")
    return _back(org_slug)


@require_POST
@role_required(Role.OWNER)
@step_up_required
def app_update(request, org_slug: str, app_id):
    app = get_object_or_404(ConnectedApp.objects, pk=app_id)
    try:
        services.update_app(
            app,
            actor=Actor.from_request(request),
            base_address=request.POST.get("base_address", ""),
            launch_path=request.POST.get("launch_path", ""),
            enabled=request.POST.get("enabled") == "on",
            request=request,
        )
    except ERRORS as exc:
        _flash_errors(request, exc)
    else:
        messages.success(request, f"{_name(app.product_key)} saved.")
    return _back(org_slug)


@require_POST
@role_required(Role.OWNER)
@step_up_required
def app_disconnect(request, org_slug: str, app_id):
    app = get_object_or_404(ConnectedApp.objects, pk=app_id)
    name = _name(app.product_key)
    try:
        services.disconnect_app(app, actor=Actor.from_request(request), request=request)
    except ERRORS as exc:
        _flash_errors(request, exc)
    else:
        messages.success(request, f"{name} disconnected.")
    return _back(org_slug)
