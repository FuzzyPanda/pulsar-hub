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
| D6 | Is MFA mandatory for Staff | Per-organisation setting, default off for Staff, always on for Manager and above | H1 |
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
