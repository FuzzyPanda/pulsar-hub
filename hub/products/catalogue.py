"""The Pulsar products an organisation can open from the hub.

The catalogue is code, not data: a product exists for every organisation the moment it is listed
here, and an Owner then connects it for their own organisation (Settings, Apps), which is the one
per-organisation row (`hub.products.models.ConnectedApp`). Adding a product is one entry in
`CATALOGUE`; `docs/PRODUCTS.md` has the steps.

A product is one of two kinds:

* `ADDRESS`: the product runs at one address per organisation (Pulsar Rostering). The connection
  holds the base address and the launcher shows one "Open" link.
* `SITES`: the product runs at each site (Pulsar Access Control: every gateway has its own
  console). The connection holds no address; the launcher lists the sites whose gateway has a
  console address, set on the site's page.
"""

from dataclasses import dataclass

from hub.organisations.models import Role

ADDRESS = "address"
SITES = "sites"


@dataclass(frozen=True)
class Product:
    key: str
    name: str
    summary: str
    # A key of ICONS below. An unknown key draws the generic "app" icon.
    icon: str = "app"
    kind: str = ADDRESS
    # Appended to the connection's base address to make the "Open" link. `{org_slug}` is replaced
    # with the organisation's slug. An Owner can override it per connection.
    launch_path: str = "/"
    # The least role that sees the tile and may open the product.
    minimum_role: Role = Role.STAFF
    # Shown under the address field when an Owner connects the product.
    address_hint: str = ""


# Icons are drawn inline, so they need no request and follow the page's colours. Each is a list of
# SVG path data on a 24 by 24 grid, stroked with the current text colour (no fill).
ICONS: dict[str, tuple[str, ...]] = {
    "app": (
        "M4 4h7v7H4z",
        "M13 4h7v7h-7z",
        "M4 13h7v7H4z",
        "M13 13h7v7h-7z",
    ),
    "calendar": (
        "M4 6h16v14H4z",
        "M4 10h16",
        "M8 3v4",
        "M16 3v4",
        "M8 14h3",
        "M13 14h3",
        "M8 17h3",
    ),
    "door": (
        "M6 21V4a1 1 0 0 1 1-1h10a1 1 0 0 1 1 1v17",
        "M3 21h18",
        "M14.5 12v1.5",
    ),
    "activity": ("M3 12h4l3-8 4 16 3-8h4",),
}


CATALOGUE: tuple[Product, ...] = (
    Product(
        key="rostering",
        name="Pulsar Rostering",
        summary="Rosters, shifts and attendance.",
        icon="calendar",
        # Rostering's "sign in with Pulsar Hub": it sends the browser back through the hub's OIDC
        # screens and lands the person in this organisation, already signed in.
        launch_path="/api/v1/auth/hub/start?org={org_slug}",
        address_hint="Where this organisation opens Pulsar Rostering, such as https://rostering.example.com.",
    ),
    Product(
        key="access_control",
        name="Pulsar Access Control",
        summary="Door controller consoles at your sites.",
        icon="door",
        kind=SITES,
        # Sites, gateways and their pages are for Managers and above.
        minimum_role=Role.MANAGER,
    ),
)

_BY_KEY = {product.key: product for product in CATALOGUE}
if len(_BY_KEY) != len(CATALOGUE):  # pragma: no cover - a mistake caught at import
    raise RuntimeError("Two products in the catalogue share a key.")


def get_product(key: str) -> Product | None:
    return _BY_KEY.get(key)


def icon_paths(icon: str) -> tuple[str, ...]:
    return ICONS.get(icon) or ICONS["app"]
