# Decisions

Open decisions first. Move an entry to "Made" with its date when it is settled.

## Open

| # | Decision | Recommendation | Blocks |
|---|---|---|---|
| D1 | Product name for the hub, the app and the rostering product | Choose before any domain, sender address or app bundle id is created; those are permanent or costly to change | Hosting, app store submission |
| D2 | Hosting | Australian region; AWS Melbourne, where the image registry already lives | H7; staging can start anywhere |
| D8 | Two sign-in systems. Pulsar Rostering was rebuilt as a platform with its own organisations, memberships, logins and mandatory two-step sign-in, and calls itself a hub; this hub has the same things plus single sign-on, passkeys and the OIDC provider. Today they are linked by a service token only, so a person who uses both signs in twice and an organisation exists in both | Choose one identity: either Rostering signs in through this hub (OIDC; this hub owns organisations and logins), or this hub's access and gateway features move into the Rostering platform and this repo is retired. Do not run two for long | Before a real client uses both; the app's sign-in |
| D5 | One card working at every site | Start with the hub-issued QR credential. A shared per-organisation card key means the hub holds credential hashes and one key covers every site; decide later, deliberately | Beyond H5 |
| D6 | Is MFA mandatory for Staff | Per-organisation setting, default off for Staff, always on for Manager and above. **H1 was built this way (2026-11-13); confirm to close** | H1 |
| D7 | PAC positioning | PAC's fleet rules still say "MSP-operated, not customer cloud". The owner directed the hub link to be built (2026-11-13) and it is recorded in PAC's backlog, but the wording of PAC's pitch and its fleet-control-plane skill has not been changed and needs the owner's words | Before remote door actions (H6) |

## Made

| Date | Decision |
|---|---|
| 2026-11-13 | The hub and the app are separate repos from rostering and PAC. |
| 2026-11-13 | Pulsar's internal tools (MSP Dashboard, pulsar-knowledge, Pulsar Ops Core) are not part of the client offering. |
| 2026-11-13 | Clients need remote management of access control, and multi-site access at least kept in sync. |
| 2026-11-13 | **PerfectGym sites get rostering only.** PerfectGym handles access there. Pulsar Rostering integrates with PerfectGym; Pulsar Access Control and the hub's door features (H3 to H6) are not offered at those sites. |

| 2026-11-13 | **D3: one product owns people and sites per organisation.** Pulsar Rostering where the organisation rosters, the hub otherwise; set per organisation in the hub (`directory_source`), never both. Built as recommended when the owner directed the links to be built. Rostering sends; the hub never calls Rostering. |
| 2026-11-13 | Time Is Money 2 is retired. Rostering is `pulsar-rostering`. |

## Assumed by this draft, not yet confirmed

| Assumption | Where it matters |
|---|---|
| A client can take access control without rostering, so the hub owns identity and organisations | H1, D3, D4 |
| Gateways dial out to the hub; no inbound access to client sites and no VPN for the integration | H3, `CONTRACTS.md` |
| Multi-site access is managed in the hub; gateways do not talk to each other | H3 |

## Chosen while building H1, to confirm

None of these was in the plan in so many words. Each is cheap to change now and costly later.

| Choice | Why | Change it by |
|---|---|---|
| An OIDC token is for one user in **one** organisation; a person with two employers holds two tokens | The plan says claims carry "the organisation and the role"; one token for every organisation would make every API call name its organisation | Reworking `CONTRACTS.md` "Sign-in" before the app integrates |
| There is no public sign-up. A login is created only by accepting an invitation | A hub of staff records should not hold accounts nobody vouched for | `AccountAdapter.is_open_for_signup` |
| Single sign-on uses **Pulsar's** Microsoft and Google registrations; an organisation only names its tenant or domain. No just-in-time provisioning | No per-organisation client secret in the database, and a directory cannot add people on its own | Adding per-organisation OIDC clients, with encrypted secrets |
| A Pulsar operator's visit is **read-only**: it sees what an Admin sees and changes nothing. An operator login cannot hold a membership. The one thing an operator does for an organisation is send the first Owner invitation, and only while there is no Owner | An independent review showed that an operator who could invite could invite itself, turning a time-limited visit into permanent access | `Actor.is_member_with` and `invite_first_owner` in `hub/organisations/services.py` |
| An operator visit lasts at most 8 hours; a browser session at most 12, however busy; an app stays signed in at most 90 days; an SSO organisation's refresh token 24 hours after the last directory sign-in | Bounds on how long access outlives the reason for it | `OPERATOR_ACCESS_MAX_HOURS`, `SESSION_MAX_AGE_HOURS`, `OIDC_SESSION_MAX_DAYS`, `SSO_REFRESH_MAX_AGE_HOURS` |
| Step-up, and every page that changes how a login is protected, needs the authenticator app or a passkey. A password, an emailed code or a recovery code is not enough once a login has a second factor | Otherwise a stolen session plus the password passes every check, including the ones H6 will rely on | `hub/accounts/stepup.py`, `hub/accounts/middleware.py` |
| Changing a password, removing a second factor, or an Owner changing the organisation's sign-in rules signs the affected people out of the app | Recovering an account should throw out whoever else was using it | `hub/accounts/signals.py`, `update_security_settings` |
| The running service uses a database role that cannot change the schema and can only add to and read the audit log | The audit log should survive a compromised web process, not only a careless one | `manage.py grant_app_role`, `docker-compose.yml` |
| Suspending an organisation closes the console and API to its members; it changes nothing for gateways | Rule 4: the hub never stops a door | Decide in H3 what a suspended organisation's gateways may still sync |
| Deleting an organisation also deletes its audit rows, leaving one platform record of the deletion | "Delete" should mean the client's data is gone | Keeping audit rows for a retention period instead |
