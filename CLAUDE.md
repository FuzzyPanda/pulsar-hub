# Pulsar Hub — project context

Read `README.md` and `docs/PLAN.md` first. This file holds the rules and the starting point.

## What this is

A hosted, multi-organisation web service: identity, organisations, people, sites, Pulsar Access
Control gateway pairing, and access management across sites. It is the single front door for the
Pulsar app and the link between Pulsar Access Control (PAC) and Time Is Money 2 (TIM2).

## Stack (match the sibling repos unless a decision says otherwise)

- Python 3.12, Django 5.2, Django REST Framework, PostgreSQL 16
- `django-allauth` for login, MFA (TOTP, passkeys, recovery codes) and social/OIDC sign-in
- An OIDC provider so TIM2 and the app sign in through the hub (`django-oauth-toolkit`)
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
    rostering (TIM2, which integrates with PerfectGym) and sign-in, and the Access module stays off
    for that site.
11. **Never return** pay rates, bank details, dates of birth, licence numbers or home addresses
    from any API.

## Sibling repos

| Repo | Why you might read it |
|---|---|
| `FuzzyPanda/Pulsar-Access-Control` | The gateway. Its `CLAUDE.md` rules (fail secure, `integration-sync` is the only caller of external systems, overseer vetting) apply to any work on that side. Plan: `docs/ecosystem-integration-plan.md`. |
| `FuzzyPanda/TimeIsMoney2` | Rostering and attendance. The product branch holds `docs/PRODUCT_PLAN.md`, an integrations framework with a Pulsar connector, the mobile API (`docs/api/mobile-v1.md`) and the Expo app in `mobile/`. |
| `FuzzyPanda/pulsar-app` | The mobile app that will sign in through this service. |

Do not change sibling repos from a session in this one; raise what is needed in their plans.

## Where to start

1. Read `docs/DECISIONS.md`. D1 (name) and D2 (hosting) do not block H0 or H1; D3 (TIM2 tenancy
   alignment) should be answered before H2.
2. Do phase **H0** in `docs/PLAN.md`: project scaffold, CI, Docker Compose, `.env.example`.
3. Then **H1** in this order: organisations and memberships, the scoped manager and isolation
   tests, login with MFA, then the OIDC provider.
4. Tick boxes in `docs/PLAN.md` as items land, and update `docs/CONTRACTS.md` in the same change
   whenever an implementation differs from it.

## Commands

To be filled in by the H0 session (`docker compose up`, `pytest`, `ruff check .`,
`python manage.py makemigrations --check --dry-run`).
