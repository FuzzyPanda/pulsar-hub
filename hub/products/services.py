"""Connecting products to an organisation, and working out what its launcher shows.

Connecting, changing and disconnecting are an Owner's to do, each is audited (rule 7), and views
never write `ConnectedApp` themselves. The read side (`launcher_tiles`, `settings_rows`) decides
what each role sees, so the template only draws what it is given.
"""

from dataclasses import dataclass, field

from django.core.exceptions import ValidationError
from django.db import IntegrityError, transaction
from django.urls import reverse

from hub.organisations.context import require_organisation
from hub.organisations.models import Role
from hub.organisations.services import Actor, _audit
from hub.products import catalogue
from hub.products.addresses import (
    browser_host,
    clean_base_address,
    clean_launch_path,
    launch_url,
)
from hub.products.models import ConnectedApp

# --- writes ---------------------------------------------------------------------------------------


def _clean(product: catalogue.Product, *, base_address: str, launch_path: str) -> tuple[str, str]:
    if product.kind == catalogue.SITES:
        # It is opened per site, through each gateway's remote console; the connection holds no address.
        return "", ""
    return clean_base_address(base_address), clean_launch_path(launch_path)


def _require_product(product_key: str) -> catalogue.Product:
    product = catalogue.get_product(product_key)
    if product is None:
        raise ValidationError("Choose a product from the list.")
    return product


@transaction.atomic
def connect_app(
    *, actor: Actor, product_key: str, base_address: str = "", launch_path: str = "", enabled: bool = True, request=None
) -> ConnectedApp:
    """Connect a product from the catalogue for the current organisation."""
    actor.require_member(Role.OWNER)
    product = _require_product(product_key)
    base_address, launch_path = _clean(product, base_address=base_address, launch_path=launch_path)
    if ConnectedApp.objects.filter(product_key=product.key).exists():
        raise ValidationError(f"{product.name} is already connected.")
    try:
        with transaction.atomic():
            app = ConnectedApp.objects.create(
                product_key=product.key,
                base_address=base_address,
                launch_path=launch_path,
                enabled=enabled,
                connected_by=actor.user,
            )
    except IntegrityError as exc:  # two Owners at the same moment
        raise ValidationError(f"{product.name} is already connected.") from exc
    _audit(
        actor,
        "app.connected",
        request=request,
        target=app,
        target_label=product.name,
        data={"product": product.key, "base_address": base_address, "launch_path": launch_path, "enabled": enabled},
    )
    return app


@transaction.atomic
def update_app(
    app: ConnectedApp,
    *,
    actor: Actor,
    base_address: str = "",
    launch_path: str = "",
    enabled: bool = True,
    request=None,
) -> None:
    """Change where a connected product lives, or turn it off without disconnecting it."""
    actor.require_member(Role.OWNER)
    product = _require_product(app.product_key)
    base_address, launch_path = _clean(product, base_address=base_address, launch_path=launch_path)
    changes = {}
    for name, value in (("base_address", base_address), ("launch_path", launch_path), ("enabled", enabled)):
        if getattr(app, name) != value:
            changes[name] = {"from": getattr(app, name), "to": value}
            setattr(app, name, value)
    if changes:
        app.save(update_fields=[*changes, "updated_at"])
        _audit(
            actor,
            "app.updated",
            request=request,
            target=app,
            target_label=product.name,
            data={"product": product.key, **changes},
        )


@transaction.atomic
def disconnect_app(app: ConnectedApp, *, actor: Actor, request=None) -> None:
    """Remove a product from the organisation's hub. Nothing in the product itself changes."""
    actor.require_member(Role.OWNER)
    product = catalogue.get_product(app.product_key)
    data = {"product": app.product_key, "base_address": app.base_address, "launch_path": app.launch_path}
    pk = app.pk
    app.delete()
    _audit(
        actor,
        "app.disconnected",
        request=request,
        target_label=product.name if product else app.product_key,
        data={**data, "connection": str(pk)},
    )


# --- read side ------------------------------------------------------------------------------------


@dataclass
class Link:
    label: str
    url: str


@dataclass
class SiteConsole:
    """One site's gateway on the Access Control tile: where its remote console stands, in words,
    and where the "Open" button posts for someone who may use it."""

    label: str
    state: str
    state_label: str
    open_url: str = ""
    site_url: str = ""


@dataclass
class Tile:
    """One product on the launcher, as one role sees it."""

    product: catalogue.Product
    icon_paths: tuple[str, ...]
    # `open`: there is at least one link. `needs_setup`: connected, but there is nothing to open
    # yet. `off`: connected and turned off. `not_connected`: in the catalogue only.
    state: str
    links: list[Link] = field(default_factory=list)
    # For a product that lives at each site: one row per site with a paired gateway.
    sites: list[SiteConsole] = field(default_factory=list)
    # What to do about a tile that cannot be opened, and where (shown to those who can do it).
    note: str = ""
    action_label: str = ""
    action_url: str = ""


def _site_consoles(*, actor: Actor, org_slug: str) -> list[SiteConsole]:
    """One row per site with a live gateway: the state of its remote console, and the address the
    "Open" button posts to when the console is available and this person is an Owner or an Admin.

    Never a link to a gateway's own address: the console is reached through the hub or not at all
    (the owner's decision of 2026-11-14).
    """
    from hub.console import services as console
    from hub.gateways.models import Gateway

    may_open = actor.is_member_with(Role.ADMIN)
    rows = []
    for gateway in Gateway.objects.live().select_related("site").order_by("site__name"):
        described = console.describe(gateway)
        rows.append(
            SiteConsole(
                label=gateway.site.name,
                state=described["state"],
                state_label=described["label"],
                open_url=reverse("console_open", kwargs={"org_slug": org_slug, "gateway_id": gateway.pk})
                if may_open and described["state"] == console.AVAILABLE
                else "",
                site_url=reverse("site_detail", kwargs={"org_slug": org_slug, "site_id": gateway.site_id}),
            )
        )
    return rows


def launcher_tiles(*, actor: Actor, request) -> list[Tile]:
    """The Apps launcher on the organisation's overview page.

    A member sees the connected, enabled products their role may use. An Owner also sees the rest
    of the catalogue, marked as not connected or turned off, because only an Owner can change that.
    """
    organisation = require_organisation()
    is_owner = actor.is_member_with(Role.OWNER)
    host = browser_host(request)
    settings_url = reverse("org_settings", kwargs={"org_slug": organisation.slug}) + "#apps"
    connected = {app.product_key: app for app in ConnectedApp.objects.all()}
    tiles = []
    for product in catalogue.CATALOGUE:
        if not actor.has_role(product.minimum_role):
            continue
        app = connected.get(product.key)
        tile = Tile(product=product, icon_paths=catalogue.icon_paths(product.icon), state="open")
        if app is None or not app.enabled:
            if not is_owner:
                continue
            tile.state = "not_connected" if app is None else "off"
            tile.action_label, tile.action_url = ("Connect" if app is None else "Turn on"), settings_url
        elif product.kind == catalogue.SITES:
            tile.sites = _site_consoles(actor=actor, org_slug=organisation.slug)
            if not tile.sites:
                tile.state = "needs_setup"
                tile.note = "No site has a gateway paired yet. An Admin can pair one on a site's page."
                tile.action_label = "Go to sites"
                tile.action_url = reverse("site_list", kwargs={"org_slug": organisation.slug})
        else:
            url = launch_url(
                app.base_address,
                app.launch_path or product.launch_path,
                host=host,
                org_slug=organisation.slug,
                org_ref=str(organisation.pk),
            )
            if url:
                tile.links = [Link("Open", url)]
            else:
                tile.state = "needs_setup"
                tile.note = "Its address needs attention. An Owner can correct it in Settings."
                if is_owner:
                    tile.action_label, tile.action_url = "Go to settings", settings_url
        tiles.append(tile)
    return tiles


def settings_rows(*, request) -> tuple[list[dict], list[ConnectedApp]]:
    """Every product in the catalogue with this organisation's connection, for Settings.

    Returns the rows, and any connection whose product has since left the catalogue (shown so
    that it can still be disconnected).
    """
    organisation = require_organisation()
    host = browser_host(request)
    connected = {app.product_key: app for app in ConnectedApp.objects.select_related("connected_by")}
    rows = []
    for product in catalogue.CATALOGUE:
        app = connected.pop(product.key, None)
        preview = ""
        if app is not None and product.kind == catalogue.ADDRESS:
            preview = launch_url(
                app.base_address,
                app.launch_path or product.launch_path,
                host=host,
                org_slug=organisation.slug,
                org_ref=str(organisation.pk),
            )
        rows.append(
            {
                "product": product,
                "icon_paths": catalogue.icon_paths(product.icon),
                "app": app,
                "needs_address": product.kind == catalogue.ADDRESS,
                "preview": preview,
            }
        )
    return rows, list(connected.values())
