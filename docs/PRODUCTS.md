# Products and the Apps launcher

The hub is the front door to every Pulsar product an organisation has. Its overview page opens
with **Apps**: one tile per product, each opening in a new tab. This file says how that is put
together and how to add a product.

## How it fits together

| Piece | Where | What it is |
|---|---|---|
| The catalogue | `hub/products/catalogue.py` | Code. Every product Pulsar offers: key, name, one-line summary, icon, default launch path, the least role that may use it |
| A connected app | `hub/products/models.py`, `ConnectedApp` | One row per organisation and product: the base address, an optional launch path of its own, whether it is shown, who connected it and when |
| Changes | `hub/products/services.py` | `connect_app`, `update_app`, `disconnect_app`. Owner only, each audited (`app.connected`, `app.updated`, `app.disconnected`) |
| The launcher | `launcher_tiles` in the same file; `hub/templates/products/_launcher.html` | What each role sees on the overview page |
| Settings, Apps | `hub/templates/products/_settings.html` | Where an Owner connects, changes and disconnects |
| Addresses | `hub/products/addresses.py` | Checking what was typed, and building each link |

A connected app holds no secret. The address is a link the person's own browser follows, and the
product keeps its own sign-in. The hub never calls a product, and never calls or links to a gateway
(rule 3 in `CLAUDE.md`): a gateway's console is reached down a connection the gateway itself keeps
open to the hub.

**Who sees what.** A member sees the connected products their role may use. An Owner also sees
the rest of the catalogue, marked "Not connected" (or "Turned off"), with a link to Settings. A
visiting Pulsar operator sees what an Admin sees and can change nothing.

**Addresses.** `http://` or `https://` only, with a host name; no user name or password, no `?`
and no `#`. The base address may use `{host}` as its whole host name. It is replaced, when the
page is drawn, with the host name the browser used to reach the hub (without its port), so
`http://{host}:8080` opens `http://192.168.1.143:8080` for someone who opened the hub by that LAN
address and `http://pulsar-hub.example.ts.net:8080` for someone who came by its mesh VPN name.
That host name is always one of `DJANGO_ALLOWED_HOSTS`.

**The link.** The base address, then the launch path: the connection's own if it has one,
otherwise the product's default from the catalogue. `{org_slug}` in the path becomes the
organisation's slug and `{org_ref}` its id (the `org_ref` of `CONTRACTS.md`); use the id wherever
the product has to recognise the organisation, because a slug is only this hub's name for it.
Pulsar Rostering's default is `/api/v1/auth/hub/start?hub_org={org_ref}`, its "sign in with Pulsar
Hub" (see `CONTRACTS.md`, "Opening a product from the hub"). Setting a connection's launch path to
`/` opens the product's front page instead.

**Two kinds of product.** Most products live at one address per organisation (`kind=ADDRESS`, the
default). Pulsar Access Control lives at each site (`kind=SITES`): its connection holds no
address, and its tile lists every site that has a paired gateway, with where that gateway's
**remote console** stands, in words: available, switched off on the gateway, gateway not
connected, or gateway software too old. For an Owner or an Admin an available console has an
**Open** button. It is a form, not a link: it posts to the hub, which asks for the authenticator
app or a passkey, starts a short session and opens the gateway's console in a new tab, on a
separate console address, relayed down the connection the gateway keeps open to the hub
(`hub/console/`, `relay/`; `CONTRACTS.md`, "Remote console"). The tile never shows an address on a
site's own network: that was the console-address link of 2026-11-13, removed the next day on the
owner's decision. With no gateway paired, the tile says what to do.

## Adding a product

Two steps. No migration, no new view and no new template.

1. **Add one entry to `CATALOGUE` in `hub/products/catalogue.py`.**

   ```python
   CATALOGUE: tuple[Product, ...] = (
       # ... the products already listed ...
       Product(
           key="gym",  # lower case letters, digits and _, at most 32; never reuse or rename a key
           name="Pulsar Gym",
           summary="Members, classes and check-in.",
           icon="activity",  # a key of ICONS in the same file; leave out for the generic icon
           launch_path="/",  # where on its address the product opens; may use {org_slug} and {org_ref}
           minimum_role=Role.STAFF,  # the least role that sees the tile
           address_hint="Where this organisation opens Pulsar Gym.",
       ),
   )
   ```

   For an icon of its own, add its SVG path data to `ICONS` under a new key (24 by 24 grid, drawn
   as outlines in the text colour). Deploy. Owners now see the product as "Not connected".

2. **Connect it for the organisation.** As an Owner: **Settings → Apps → Connect Pulsar Gym**,
   enter its address, and save. The tile appears on the overview page for everyone whose role may
   use it. Or from a shell on the hub (one line per organisation):

   ```bash
   docker compose exec web python manage.py connect_app <org-slug> gym "https://gym.example.com" --as owner@example.com
   ```

   `connect_app` goes through the same service as the Settings page, so the role check and the
   audit event are the same. Run it again with a new address to change it; add `--launch-path /x`
   to override the product's launch path, or `--disconnect` to remove the connection.

Update `tests/test_products.py::test_catalogue_lists_rostering_and_access_control` in the same
change: it pins the catalogue's keys so that a product cannot appear or vanish by accident.

A product that every site has its own copy of takes `kind=SITES` instead. Today that means a
gateway's remote console, and `_site_consoles` in `hub/products/services.py` is written for that
alone.

Retiring a product: remove its entry. Rows that still name it are ignored by the launcher and are
listed in Settings as "Retired" so an Owner can disconnect them.
