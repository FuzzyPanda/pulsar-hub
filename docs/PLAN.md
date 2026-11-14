# Plan

**Drafted 2026-11-13.** H0 to H3 are built, and the intake half of H4 (2026-11-13). H5 onward is not started. Tick items as they land.

## Phases at a glance

| Phase | Outcome | Depends on |
|---|---|---|
| H0 | A running, tested, empty service | — |
| H1 | Organisations, login, MFA, single sign-on | H0 |
| H2 | People and sites, shared with Pulsar Rostering | H1, decision D3 |
| H3 | Gateways paired; people and access synced to every site | H2, PAC items A0–A3 |
| H4 | Remote view: doors, events, who is on site, alerts | H3 |
| H5 | Hub-issued rotating QR credential | H3, PAC reader support |
| H6 | Remote door actions | H4, PAC fleet-control-plane sign-off |
| H7 | Compliance report, billing, hosting hardening | H4 |

H0 to H2 need nothing from PAC. H1 is the largest piece.

## H0 — Scaffold

- [x] Django project `hub/` with apps `organisations`, `accounts`, `directory`, `gateways`,
  `access`, `audit`, `api`.
- [x] Settings from the environment; `.env.example`; no secret in the image.
- [x] Docker Compose: web, worker (`qcluster`), Postgres, Caddy. Non-root containers, health
  checks, migrate-before-traffic entrypoint.
  The service runs as a second database role that cannot change the schema or rewrite the audit
  log; only the entrypoint's migration step uses the owning role.
- [x] CI on every pull request: `ruff`, `pytest`, `makemigrations --check`, secret scan.
  First run on GitHub passed on 2026-11-13 (lint, tests, isolation suite, secret scan, Compose config,
  Docker build). Still to do in the repository settings: make "Organisation isolation suite" and
  "Secret scan" required checks on `main`.
- [x] Structured JSON logs; error monitoring hook.

## H1 — Identity and organisations

**Organisations**

- [x] `Organisation`, `Membership` (user, organisation, role). One login can belong to several
  organisations; casual staff often work for two employers.
- [x] Roles: Owner, Admin, Manager, Staff. A separate platform-operator role for Pulsar, whose
  access to an organisation is time-limited and audited.
- [x] Organisation-scoped model manager and middleware; raw unscoped access is a lint failure.
- [x] Isolation test suite covering every route and API. Gates CI from the first model onward.
- [x] Provision, suspend, export and delete an organisation.

**Login and MFA**

- [x] Email login with verified email, password policy, rate limiting, session list and
  revocation, invite links.
- [x] MFA: authenticator app, passkeys, recovery codes. Required for Owner, Admin and Manager;
  per-organisation setting for Staff.
- [ ] Sign in with Microsoft Entra and Google, configured per organisation. A disabled account in
  the client's directory can no longer sign in.
  **Built, and tested against simulated provider responses; not yet run against a real tenant.**
  It needs Pulsar's Microsoft and Google application registrations (`MICROSOFT_CLIENT_ID`,
  `GOOGLE_CLIENT_ID`) and one live sign-in with each before this box is ticked. How it works is in
  `CONTRACTS.md`, "Sign-in".
- [x] Step-up: a fresh MFA check on demand, used later by H6.

H1 was reviewed independently for security on 2026-11-13. No path across organisations was found.
The twelve other defects it proved are fixed, each with a regression test in
`tests/test_hardening.py`. It could not cover live Microsoft or Google sign-in, or GitHub branch
protection (not yet set up).

**Hub as the sign-in for other products**

- [x] OIDC provider with PKCE for the Pulsar app (and for Pulsar Rostering, if decision D8 goes that way).
- [x] Token claims carry the user, the organisation and the role, nothing sensitive.
- [x] Audit log: sign-in, MFA changes, role changes, operator access.

**The hub as the front door (added 2026-11-14)**

- [x] Apps launcher on the organisation overview: a code-defined product catalogue and
  per-organisation connected apps, managed by an Owner in Settings. `docs/PRODUCTS.md`.
- [x] Each gateway can carry a console address, set by an Admin on the site page; the site page
  and the Access Control tile link to it. A link only: the hub still never calls a gateway.
- [ ] Pulsar Rostering's side of the link (`/api/v1/auth/hub/start`, "sign in with Pulsar Hub")
  is being built in `pulsar-rostering`. Until it is live there, an Owner can point the tile at
  Rostering's front page with a launch path of `/`. See decision D8, which this does not close.

## H2 — Directory

- [x] `Person` (`person_ref`, name, work email, status, optional link to a login).
- [x] `Site` (`site_ref`, name, address, timezone).
- [x] `AccessGroup` per organisation ("Managers", "Cleaners"), assigned to people. A group also names
  the sites it opens, which is what makes access multi-site.
- [x] Pulsar Rostering link, per decision D3: people and sites come from Rostering where an
  organisation rosters; the hub is the source where it does not. One direction per organisation,
  never both. Rostering sends a full snapshot with a service token (`PUT /api/v1/directory`).
- [ ] CSV import for organisations with neither.
- [x] Service tokens (hashed, scoped) and `/api/v1/` for other systems.

## H3 — Gateways and multi-site access

- [x] Pair a PAC gateway to a site with a one-time code; show last contact; revoke.
- [x] A site can be marked as access-managed elsewhere (a PerfectGym site). It cannot be paired,
  and cannot be added to an access group. Rostering and sign-in work as normal.
- [x] Desired access per site: people, active or not, access groups. The gateway pulls and
  acknowledges a version. Contract in `CONTRACTS.md`.
- [x] Per-site mapping from hub access groups to that gateway's own access levels, done once at
  commissioning. It lives on the gateway (its "Pulsar Hub" page), not in the hub.
- [x] Ending a person removes access at every site on each gateway's next pull; the hub shows
  access as unconfirmed until that site acknowledges.
- [x] Signed event intake with idempotency. Pulsar Rostering reads attendance events from the hub
  with a cursor (`GET /api/v1/events`); the hub does not call Rostering.
- [x] Stays local to each gateway, by design: doors, wiring, schedules, alarm areas,
  anti-passback, occupancy counts, and every card and PIN.

The gateway side is in `Pulsar-Access-Control` (`integration-sync/internal/hublink`) and the
Rostering side in `pulsar-rostering` (`applications/access`). **None of it has run against a real
gateway yet**: it is tested against each side's own fakes and against each other on one machine.

## H4 — Remote view

- [x] Per site: door state, recent events, who is on site, gateway health. The gateway posts a
  door-state snapshot and events; the hub shows them on the site's page and the events page.
- [ ] Across sites: one page for every site's doors and alerts.
- [ ] Alerts (door forced, held open, gateway out of contact) to email and to the app. The events
  arrive and are shown; nothing is sent yet.
- [x] Read-only. No action in this phase can change a door.

## H5 — Hub-issued credential

- [ ] Rotating QR credential: the hub creates a per-person secret, each gateway receives it only
  for its own people, the app shows the code. Works at every site without re-enrolment.
- [ ] Revocation follows the person's status. Screenshots must not work: short rotation, clock
  skew tolerance documented.
- [ ] Cards stay enrolled on each gateway. A shared per-organisation card key that would let one
  card work at every site is decision D5 and is not in this phase.

## H6 — Remote door actions

The highest-risk surface in the whole offering. Do not start it early.

- [ ] Only two actions: a timed unlock pulse on one door, and lockdown of a site.
  **Never remote emergency unlock.**
- [ ] Each action needs a fresh MFA step-up, a reason, and a role that allows it.
- [ ] The gateway pulls the request, checks its age and signature, runs it through its own door
  state machine, and reports the result. The hub shows "requested" until the gateway confirms.
- [ ] Every request, refusal and result is audited on both sides.
- [ ] Requires the PAC side to pass its `fleet-control-plane` rules, `/ship-check` and
  `security-reviewer`.

## H7 — Running it as a business

- [ ] Monthly per-organisation report: who can open which doors, after-hours entries, staff
  starts and ends.
- [ ] Australian hosting, wildcard TLS, encrypted backups with a tested restore, staging
  environment, uptime checks, status page.
- [ ] Privacy policy, terms, data-processing terms, breach procedure before the first client.
- [ ] Subscription billing through an off-the-shelf provider. Do not build invoicing.

## Order

H0 → H1 → H2 → H3 → H4 → H5 → H7 → H6.
