# Pulsar Hub — project context

Read `README.md` and `docs/PLAN.md` first. This file holds the rules and the starting point.

## What this is

A hosted, multi-organisation web service: identity, organisations, people, sites, Pulsar Access
Control gateway pairing, and access management across sites. It is the single front door for the
Pulsar app and the link between Pulsar Access Control (PAC) and Pulsar Rostering (which replaced
Time Is Money 2).

## Stack (match the sibling repos unless a decision says otherwise)

- Python 3.12, Django 5.2, Django REST Framework, PostgreSQL 16
- `django-allauth` for login, MFA (TOTP, passkeys, recovery codes) and social/OIDC sign-in
- An OIDC provider so the app (and, if decision D8 goes that way, Pulsar Rostering) signs in through
  the hub (`django-oauth-toolkit`)
- Background jobs on `django-q2` with the Postgres broker (no Redis), as PAC does
- Server-rendered Django templates with htmx for the web console; the app uses `/api/v1/`
- `pytest-django`, `ruff`, GitHub Actions; Docker Compose for local and production

## Rules that do not bend

1. **Organisation isolation is a security boundary.** Every business row carries an organisation.
   All access goes through an organisation-scoped manager. An isolation test suite proves that a
   user of organisation A gets nothing from organisation B on every route and API, and it gates CI.
2. **The hub never receives card numbers, PINs or credential hashes** from a gateway. The only
   credential it issues is its own rotating QR secret (phase H5).
3. **A gateway always dials out.** The hub never opens a connection to a client site.
4. **The hub being down never stops a door.** Gateways keep their last synced state. Design every
   gateway call so a missed poll or a restart converges without replay.
5. **Desired state, not commands**, for people and access. Remote door actions (phase H6) are the
   one exception and carry their own rules in `docs/PLAN.md`.
6. **Secrets come from the environment.** Never commit `.env`, keys, dumps or backups. Update
   `.env.example` with placeholders whenever a variable is added.
7. **Every sign-in, role change, access change, operator access and remote action is audited.**
8. **All timestamps are UTC** in storage and on the wire; convert only for display.
9. **Everything inbound is idempotent.** Events and writes carry a key; receiving one twice
   changes nothing.
10. **No gym or leisure management.** No memberships, class bookings, member billing or member
    apps. Staff and the building only.
    **At a site that runs PerfectGym, PerfectGym handles access:** the organisation gets
    rostering (Pulsar Rostering) and sign-in, and the Access module stays off
    for that site.
11. **Never return** pay rates, bank details, dates of birth, licence numbers or home addresses
    from any API.

## Sibling repos

| Repo | Why you might read it |
|---|---|
| `FuzzyPanda/Pulsar-Access-Control` | The gateway. Its `CLAUDE.md` rules (fail secure, `integration-sync` is the only caller of external systems, overseer vetting) apply to any work on that side. Its hub link is `services/integration-sync/internal/hublink` plus the Django models in `apps/django-web/api/models_hub.py`. |
| `FuzzyPanda/pulsar-rostering` | Rostering and attendance (replaced Time Is Money 2). A multi-tenant platform with its own organisations and logins. Its hub link lives in `backend/applications/access/`: it sends people and sites and reads attendance events, per `docs/CONTRACTS.md`. |
| `FuzzyPanda/pulsar-app` | The mobile app that will sign in through this service. |

A change to a wire contract is made in `docs/CONTRACTS.md` here first, then on the other side. Work in
a sibling repo follows that repo's own rules, not this file's.

## Where things are

H0 to H3 are built, with the intake half of H4 (events and door state). Next: the H4 alerts, then H5. Tick boxes in `docs/PLAN.md` as items
land, and update `docs/CONTRACTS.md` in the same change whenever an implementation differs from it.

| Path | What |
|---|---|
| `hub/settings.py` | Every setting; all environment-driven. `hub/test_settings.py` is the test overlay |
| `hub/organisations/` | Organisations, memberships, roles, invitations, operator visits, identity providers; the scoped manager (`scoping.py`), the current organisation (`context.py`), entry rules (`entry.py`, `middleware.py`), all writes (`services.py`), the web console (`views.py`) |
| `hub/accounts/` | The login (`User`), allauth adapters, MFA and step-up helpers, the Entra provider, the OIDC provider (`oidc.py`, `oidc_views.py`) and its organisation-bound token models |
| `hub/audit/` | The append-only audit log. Write with `audit.services.record(...)` |
| `hub/api/` | `/api/v1/`: three kinds of bearer credential (a user token, a service token, a gateway credential), each bound to one organisation; `views_machine.py` holds the gateway and service calls |
| `hub/directory/` | People and sites, and the snapshot Pulsar Rostering sends (`apply_rostering_snapshot`) |
| `hub/access/` | Access groups and `desired_access(site)`: the complete state a site's gateway should hold |
| `hub/gateways/` | Pairing, the gateway credential, acknowledgements, event and door-state intake, and each gateway's console address (a link only; rule 3 stands) |
| `hub/products/` | The Apps launcher: the product catalogue (`catalogue.py`, code), each organisation's connected apps, and the addresses they open. `docs/PRODUCTS.md` says how to add a product |
| `tests/isolation/` | The suite that gates CI (rule 1). `routes.py` lists every route |
| `scripts/check_unscoped_access.py` | The lint for cross-organisation access |

## How rule 1 is enforced, and what you must do

- **A new business model** inherits `hub.organisations.scoping.OrganisationScopedModel`. A system
  check fails otherwise. `Model.objects` returns only the current organisation's rows and raises
  when there is none; saves refuse another organisation's rows and foreign keys that cross
  organisations. Add a factory to `tests/factories.py` and to `FACTORIES` in
  `tests/isolation/test_models.py` (a test fails until you do), and give `make_world` in
  `tests/conftest.py` one row of it carrying the world's marker.
- **A new console route** is declared with `org_path(...)` under `/org/<org_slug>/` and added to
  `ORG_ROUTES` in `tests/isolation/routes.py`. **A new API route** goes in `API_ROUTES`. A test
  fails for any route that is in neither and not under a listed prefix.
- **Never** take an organisation from a URL, header or body in the API. The token decides.
- **A gateway or service payload is checked against a fixed list of allowed keys** and refused if it
  carries anything else (`EVENT_DATA_KEYS` in `hub/gateways/services.py`, the directory view). That
  is how rules 2 and 11 are enforced: add a key only after deciding it can never hold a credential or
  one of the fields rule 11 names.
- **Every `/api/v1/` refusal is `{"detail", "code"}`.** Use `hub.api.exceptions.refusal(...)` in a
  view, or put `code=` on the `ValidationError` a service raises. A new code is added to the table
  in `docs/CONTRACTS.md`, "Refusals", in the same change, and a code is never renamed: callers
  branch on it.
- **A directory snapshot is judged row by row** (`apply_rostering_snapshot`). A row the hub cannot
  take is reported in `rejected` and leaves whoever it names untouched; a removal is applied even
  from an otherwise bad row. Only a snapshot that is the wrong shape, carries a key outside the
  allow-list, or would leave nobody active is refused whole.
- **What a gateway is sent is a complete state with a version**, never a change (rule 5). Anything
  that alters who may enter a site must alter `desired_access(site)`, and nothing else may.
- **Reaching across organisations** (`.all_organisations`, `_base_manager`, raw SQL) needs
  `# unscoped: <reason>` on the same line or the line above, or CI fails. Use it only before an
  organisation is known (resolving a token or an invitation) or for a platform job.
- **Jobs, commands and tests** wrap work in `with organisation_context(org):`.
- **Changes go through `services.py`**, which checks the role and writes the audit event. Views
  and API endpoints do not write business models directly.
- **A Pulsar operator's visit is read-only.** In a service, `actor.require(role)` is for reading
  and `actor.require_member(role)` is for anything that changes the organisation.
- **No business model in the Django admin.** Organisations are run from `/operator/`.
- Sensitive actions take `@step_up_required`: the authenticator app or a passkey within the last
  five minutes. A password or recovery code does not pass it. H6 must use it.
- **An address that carries a secret in its path** (an invitation link, a reset link) is added to
  `_SECRET_PATHS` in `hub/middleware.py`, so the access log and error reports never hold it.
- **The audit log is append-only** in the model, in a database trigger and in the rights of the
  role the service runs as. Nothing updates or deletes an event; do not add a way to.

## Commands

```bash
# First time: Python 3.12 virtualenv and a local PostgreSQL 16 role that may create databases
python -m venv .venv && .venv/bin/pip install -r requirements.txt -r requirements-dev.txt
cp .env.example .env            # set DJANGO_SECRET_KEY, DATABASE_URL, DJANGO_DEBUG=True

python manage.py migrate && python manage.py createcachetable
python manage.py create_operator you@example.com     # the first Pulsar operator
python manage.py runserver

ruff check . && ruff format --check .
python scripts/check_unscoped_access.py
python manage.py makemigrations --check --dry-run
pytest                          # everything; uses hub.test_settings and its own test database
pytest -m isolation             # the organisation isolation suite on its own

docker compose up --build       # web, worker, Postgres and Caddy, as production runs them
# In Compose the service runs as a lesser database role. Commands that change the schema need the owner:
docker compose run --rm -e HUB_DATABASE_AS_OWNER=1 web python manage.py migrate
python -m hub.accounts.oidc_keys                      # a value for OIDC_RSA_PRIVATE_KEY (needs no settings)
python manage.py provision_organisation "Name" owner@example.com --operator you@example.com
```
