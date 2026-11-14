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

## Made

| Date | Decision |
|---|---|
| 2026-11-13 | The hub and the app are separate repos from rostering and PAC. |
| 2026-11-13 | Pulsar's internal tools (MSP Dashboard, pulsar-knowledge, Pulsar Ops Core) are not part of the client offering. |
| 2026-11-13 | Clients need remote management of access control, and multi-site access at least kept in sync. |
| 2026-11-13 | **PerfectGym sites get rostering only.** PerfectGym handles access there. Pulsar Rostering integrates with PerfectGym; Pulsar Access Control and the hub's door features (H3 to H6) are not offered at those sites. |

| 2026-11-13 | **D3: one product owns people and sites per organisation.** Pulsar Rostering where the organisation rosters, the hub otherwise; set per organisation in the hub (`directory_source`), never both. Built as recommended when the owner directed the links to be built. Rostering sends; the hub never calls Rostering. |
| 2026-11-13 | Time Is Money 2 is retired. Rostering is `pulsar-rostering`. |
| 2026-11-14 | **Remote access to a gateway's console is relayed through the hub.** Asked how the hub should give remote access to a gateway's console from outside the site's network, the owner chose: "Relay through the hub: the gateway keeps an outbound connection open to the hub, and the hub relays the console to a signed-in hub user. Works from anywhere with only a hub login, for any client, and nothing is opened inbound at the site." This amends rule 3 of `CLAUDE.md` (the gateway still dials; the hub now answers down a connection the gateway keeps open) and nothing else. |
| 2026-11-14 | **A remote console may do everything, with safeguards.** Asked what a remote console may do, the owner chose: "Everything, with safeguards: the full console, but each remote session needs a fresh authenticator check at the hub, is limited to owners and admins, expires after a short time, and is recorded in the audit log on both the hub and the gateway." Built on the hub side as: Owner or Admin members only (never a Pulsar operator's visit), a step-up check to open and to extend, 15 minutes by default and never more than 60, three sessions per gateway, and an audit event for every start, end, refusal and extension. The gateway's switch for it is on the gateway and off by default; that part is the builder's choice, not the owner's words. The next day's decision D9 (below) says what "everything" means at a door. |
| 2026-11-14 | **The Access Control tile must not open a link to a local IP address.** The owner's words, earlier the same day. The console-address link built on 2026-11-13 is removed, not kept beside the remote console: the field, its form, service, command, route and tests are gone, with a migration. |
| 2026-11-15 | **D9, door actions in a remote console session: all but emergency unlock.** Asked what a remote session may do at a door, the owner chose "All but emergency unlock (Recommended)": "Remote sessions can unlock a door, lock down and change door modes, each with a typed reason that goes in the audit log. Emergency unlock (release every door) is refused remotely and must be done on site." This is the gateway's to enforce: it knows which requests are remote and for whom (`CONTRACTS.md`, "Remote console", "Door actions in a remote session"). The hub sends no door instruction of its own; `PLAN.md` H6 is unchanged and still not built. Not built on the gateway side yet. |
| 2026-11-15 | **D7, the gateway repository's fleet rule and the remote console: an exception until a client site.** The owner chose "Exception until a client site (Recommended)": "Record a dated exception in Access Control's documents: the pairing credential is enough for bench and pilot use, the switch stays off by default, and a client certificate on the tunnel is required before it is switched on at a paying client's site." So the tunnel as built here (the pairing credential over TLS) is accepted for bench and pilot use only. Two things follow and neither is done: the exception has to be written into Access Control's own documents, dated, by whoever works there; and a client certificate on the tunnel has to be designed into this contract and built on both sides before any paying client's gateway has its switch turned on. The wording of Access Control's pitch ("MSP-operated, not customer cloud") was the other half of the old D7 and is that repository's to bring into line when it records the exception. |

## Assumed by this draft, not yet confirmed

| Assumption | Where it matters |
|---|---|
| A client can take access control without rostering, so the hub owns identity and organisations | H1, D3, D4 |
| Gateways dial out to the hub; no inbound access to client sites and no VPN for the integration. Still so with the remote console (2026-11-14): it runs down a connection the gateway opened | H3, `CONTRACTS.md` |
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

## Chosen while building the remote console (2026-11-14), to confirm

| Choice | Why | Change it by |
|---|---|---|
| A separate small service, the relay, holds the tunnels; it has no database and decides nothing | The web workers are synchronous and cannot hold a connection open. Keeping every decision in the web service keeps one place to audit and one place to review | `relay/`, `hub/console/services.py` |
| One new dependency, `aiohttp`, pinned to an exact version | It is the relay's WebSocket server, streaming HTTP server and HTTP client in one maintained project. Pinned, unlike the rest, because it parses raw traffic from the internet | `requirements.txt` |
| A gateway's cookies are kept by the relay, per session, and never sent to the browser | The gateway's console reads no cookie from script (its CSRF token is in the page), so nothing is lost; and then a gateway's cookie cannot reach the hub, another gateway or another person, cannot outlive the session, and a console cannot plant a cookie on anything. Rewriting cookie names per gateway would have left them in the browser, on a bench under the hub's own host name | `relay/protocol.py`, `CookieJar` |
| A console may not send the browser off its own origin: redirects keep their path and lose their host | A redirect to a gateway's LAN address is useless from outside and is the link the owner ruled out; and a console should not be able to send an Owner's browser somewhere else | `relay/protocol.py`, `confine_location` |
| The gateway's switch is local and off by default, and the hub cannot turn it on | A site that never asked for remote access should not have it because its hub account was taken over | `CONTRACTS.md`; the gateway side |
| A hub session that ends, for any reason, ends the console sessions opened from it; so does any change of role, even a promotion | A console session should never be worth more than the sign-in it came from | `hub/console/services.py`, `_invalid_reason` |
| Three sessions per gateway, one per person; 15 minutes, extended only by another step-up, 60 at most | The owner's "short time", made exact | `MAX_SESSIONS_PER_GATEWAY`, `CONSOLE_SESSION_MINUTES` |
| The hub audits sessions, not the requests inside them | What was done is in the gateway's own log, where it can be attributed and where the hub cannot rewrite it. The relay logs no addresses: a console address can carry a secret | Adding a request log to the relay, with paths redacted |
| Every relayed response closes its connection (added after the security review, 2026-11-15) | How a response is framed comes from the gateway. Never reusing a connection that carried one means a gateway that lies about a length, or about having a body, has nothing to leave behind for the next request. It costs a new connection from the proxy to the relay per request, on one machine | `relay/server.py`, `_exchange` |
| The web service hears of a gateway's switch at most three times a minute, then only where it ended up; the relay itself acts on every change at once (2026-11-15) | Each change the hub hears is an audit event. A gateway may say it only every five seconds (the contract), and may also say it by reconnecting | `relay/outbox.py`; `console_report_burst`, `console_report_seconds` |
| Opening is rationed: 10 a minute per person, 20 per gateway, a minute's rest for a gateway that did not answer, and one Open waiting on a gateway at a time on the whole hub (2026-11-15) | An Open keeps a synchronous web worker waiting up to five seconds, and there are two. Without a ration a few Opens on silent gateways stall the hub, and with it the heartbeat that every console depends on. The price: while one person's Open waits on a silent gateway, someone else's is told to try again in a few seconds | `hub/console/services.py`, the constants at the top |
| On a plain-HTTP bench every console shares one origin on an extra port | The owner allowed it for the bench. Cookies stay apart there; web storage and "same-site" standing do not | `CONSOLE_ORIGIN_TEMPLATE`; refused outside the lab flag |
