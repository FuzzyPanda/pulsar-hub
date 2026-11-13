# Decisions

Open decisions first. Move an entry to "Made" with its date when it is settled.

## Open

| # | Decision | Recommendation | Blocks |
|---|---|---|---|
| D1 | Product name for the hub, the app and the rostering product | Choose before any domain, sender address or app bundle id is created; those are permanent or costly to change | Hosting, app store submission |
| D2 | Hosting | Australian region; AWS Melbourne, where the image registry already lives | H7; staging can start anywhere |
| D3 | Who owns people and sites when an organisation uses both rostering and the hub | TIM2 is the source for organisations that roster; the hub is the source for access-only organisations. Never two-way | H2 |
| D4 | TIM2 multi-tenancy | Its product plan (decision D1 there) recommends one shared database with an organisation on every row. Align with it: TIM2 adopts the hub's `org_ref` and sign-in instead of building its own sign-up and identity | TIM2 Phase 2 |
| D5 | One card working at every site | Start with the hub-issued QR credential. A shared per-organisation card key means the hub holds credential hashes and one key covers every site; decide later, deliberately | Beyond H5 |
| D6 | Is MFA mandatory for Staff | Per-organisation setting, default off for Staff, always on for Manager and above. **H1 was built this way (2026-11-13); confirm to close** | H1 |
| D7 | PAC positioning | PAC's current pitch is "MSP-operated, not customer cloud". The hub makes it "runs on site, managed from anywhere". Needs an overseer decision in the PAC repo | H3 onward |

## Made

| Date | Decision |
|---|---|
| 2026-11-13 | The hub and the app are separate repos from TIM2 and PAC. |
| 2026-11-13 | Pulsar's internal tools (MSP Dashboard, pulsar-knowledge, Pulsar Ops Core) are not part of the client offering. |
| 2026-11-13 | Clients need remote management of access control, and multi-site access at least kept in sync. |
| 2026-11-13 | **PerfectGym sites get rostering only.** PerfectGym handles access there. TIM2 integrates with PerfectGym; Pulsar Access Control and the hub's door features (H3 to H6) are not offered at those sites. |

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
| An OIDC token is for one user in **one** organisation; a person with two employers holds two tokens | The plan says claims carry "the organisation and the role"; one token for every organisation would make every API call name its organisation | Reworking `CONTRACTS.md` "Sign-in" before the app or TIM2 integrates |
| There is no public sign-up. A login is created only by accepting an invitation | A hub of staff records should not hold accounts nobody vouched for | `AccountAdapter.is_open_for_signup` |
| Single sign-on uses **Pulsar's** Microsoft and Google registrations; an organisation only names its tenant or domain. No just-in-time provisioning | No per-organisation client secret in the database, and a directory cannot add people on its own | Adding per-organisation OIDC clients, with encrypted secrets |
| A visiting Pulsar operator acts as an **Admin**: can invite and manage Managers and Staff, cannot create Owners or Admins, change sign-in rules, or export | Enough to help, not enough to take over | `Actor.role` and `_may_grant` in `hub/organisations/services.py` |
| An operator visit lasts at most 8 hours; a browser session at most 12; an SSO organisation's refresh token 24 hours after the last directory sign-in | Bounds on how long access outlives the reason for it | `OPERATOR_ACCESS_MAX_HOURS`, `SESSION_MAX_AGE_HOURS`, `SSO_REFRESH_MAX_AGE_HOURS` |
| Suspending an organisation closes the console and API to its members; it changes nothing for gateways | Rule 4: the hub never stops a door | Decide in H3 what a suspended organisation's gateways may still sync |
| Deleting an organisation also deletes its audit rows, leaving one platform record of the deletion | "Delete" should mean the client's data is gone | Keeping audit rows for a retention period instead |
