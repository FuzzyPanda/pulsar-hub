# Contracts — ids, pairing, calls and events

**Proposed 2026-11-13.** "Identifiers", "Sign-in" and the `/api/v1/` calls marked H1 are built; the
gateway and TIM2 sections are still proposals. If an implementation differs from this file, change
this file in the same pull request.

## Identifiers

| Id | Format | Minted by | Also stored in |
|---|---|---|---|
| `org_ref` | UUID v4 | Hub | TIM2 organisation or instance; each paired gateway |
| `person_ref` | UUID v4 | Hub, or TIM2 where it is the source for that organisation | TIM2 employee; PAC `Person.external_ref` |
| `site_ref` | UUID v4 | Hub, or TIM2 where it is the source | TIM2 location; PAC `Site.external_ref`, set at pairing |

Names and email addresses are never join keys.

`org_ref` is the primary key of the hub's organisation row. A login has its own stable id, the
OIDC `sub` (UUID v4); it is not a `person_ref`. A person record (H2) may link to a login.

## Sign-in (built in H1)

The hub is an OpenID Connect provider. The Pulsar app and TIM2 are clients, registered by Pulsar
staff; there is no self-service client registration.

| Item | Value |
|---|---|
| Issuer | `{HUB_BASE_URL}/oauth` |
| Discovery | `{issuer}/.well-known/openid-configuration` |
| Endpoints | `/oauth/authorize/`, `/oauth/token/`, `/oauth/userinfo/`, `/oauth/revoke_token/`, `/oauth/logout/`, `/oauth/.well-known/jwks.json` |
| Flow | Authorisation code with PKCE (`S256` only). No implicit, password or device flow |
| Scopes | `openid` (required), `profile`, `email`, `offline_access` |
| Signing | RS256; keys published at the JWKS address |
| Lifetimes | Access and ID token 10 minutes. Refresh token: rotated on every use, dead after 30 days unused, and dead 90 days after the user signed in however much it was used. Reuse of an old refresh token revokes the whole family |
| Bearer tokens | In the `Authorization` header only, never in a query string. Stored by the hub as digests |

**A token is for one user in one organisation.** A person who works for two employers signs in
once and holds one token per organisation.

- The client may name the organisation with `org=<org_ref>` on the authorisation request. Without
  it, a user with one organisation gets that one and a user with several is asked to choose.
- To obtain a token the browser session must pass the same rules as the web console: an active
  membership, the organisation's single sign-on rule, and MFA where the role requires it.

| Claim | Scope | Meaning |
|---|---|---|
| `sub` | `openid` | The login's id |
| `org_ref` | `openid` | The organisation this token is for |
| `org_role` | `openid` | `owner`, `admin`, `manager` or `staff` in that organisation, at issue time |
| `name`, `org_name` | `profile` | Display names |
| `email`, `email_verified` | `email` | The login's email address |

Nothing else is ever a claim. A resource server must not treat `org_role` as live: the hub
re-checks the membership on every API call, and a role change or removal deletes that user's
tokens for the organisation, so a client learns of it within one access-token lifetime at most.

A token stops working immediately when the user leaves or is removed from the organisation, the
login is deactivated, or the organisation is suspended or deleted. The app is also signed out (its
tokens are deleted, so the next call fails and it must send the user through sign-in) when the
user's role changes, the user changes their password or removes a second factor, or an Owner
changes the organisation's sign-in rules. Clients must treat a `401` or a failed refresh as "sign in
again", not as an error. For an organisation that
requires single sign-on, a refresh token is honoured for 24 hours after the user last signed in
through the organisation's directory (`SSO_REFRESH_MAX_AGE_HOURS`); after that the app must send
the user through sign-in again.

**Single sign-on with Microsoft Entra or Google.** Pulsar holds one application registration with
each provider. An organisation lists which Entra tenant id or Google Workspace domain is its own;
that row holds no secret. A directory never creates a membership: people still join by
invitation, and a first sign-in through a directory is accepted only while accepting an invitation
from an organisation that lists that directory, for the invited address. A directory's email claim
is never used to match an existing login.

## Pairing a gateway

1. An organisation admin creates a one-time code for a site.
2. An installer enters the hub URL and the code on the gateway.
3. The gateway exchanges the code for a long-lived credential bound to one `org_ref` and one
   `site_ref`. The hub stores only a hash; the gateway stores it encrypted.
4. Either side can revoke. A revoked or unreachable gateway keeps its last synced people and
   follows its own fail policy.

## Gateway to hub (the gateway always initiates)

| Call | Purpose | Phase |
|---|---|---|
| `GET /api/v1/sites/{site_ref}/access?since=` | Desired access: people (`person_ref`, name, active), access groups, version | H3 |
| `POST /api/v1/sites/{site_ref}/access/ack` | Version applied, with per-person failures | H3 |
| `POST /api/v1/sites/{site_ref}/events` | Signed batch of events | H3 |
| `POST /api/v1/sites/{site_ref}/state` | Door states and gateway health snapshot | H4 |
| `GET /api/v1/sites/{site_ref}/credentials?since=` | Rotating-QR secrets for this site's people | H5 |
| `GET /api/v1/sites/{site_ref}/actions` | Pending remote actions | H6 |
| `POST /api/v1/sites/{site_ref}/actions/{id}/result` | Outcome of a remote action | H6 |

## Event envelope

```json
{"id": "<uuid>", "type": "attendance.clock_in", "occurred_at": "<RFC3339 UTC>",
 "org_ref": "<uuid>", "site_ref": "<uuid>", "person_ref": "<uuid>", "data": {}}
```

- `id` is the idempotency key.
- Batches are signed with HMAC-SHA256 over the raw body using the pairing credential.
- The gateway queues while the hub is unreachable and sends in order when it returns.
- The hub rejects an `org_ref` or `site_ref` that does not match the pairing.

| Event | Phase |
|---|---|
| `attendance.clock_in`, `attendance.clock_out` | H3 |
| `access.applied`, `access.revoked` | H3 |
| `door.forced`, `door.held_open`, `gateway.health` | H4 |
| `visitor.arrived` | later |

## Hub and TIM2

| Direction | Call | Purpose |
|---|---|---|
| TIM2 → hub | OIDC sign-in | One login across products |
| Either, per decision D3 | `GET /api/v1/people`, `GET /api/v1/sites` | The source product publishes; the other reads |
| Hub → TIM2 | Signed webhook to TIM2's inbound integration hook | Attendance events, in the envelope above |
| Hub → TIM2 | `POST /api/v1/roster-check` on TIM2 | "Is this person rostered at this site now?" for roster-gated doors |

TIM2's product branch already has a Pulsar connector that polls a gateway or receives its report
webhook directly. That keeps working for standalone installs; the hub path is added beside it as
another connector, not as a replacement.

## Hub and the app

- Sign-in: OIDC authorisation code with PKCE, as above. Tokens are per device and revocable.
- All app calls are under `/api/v1/` and scoped to the signed-in user and the organisation the
  token is for. The organisation cannot be named in a URL, header or body.
- Rostering screens call TIM2's mobile API (`TimeIsMoney2/docs/api/mobile-v1.md`) with a token the
  hub sign-in authorises.

| Call | Returns | Role | Phase |
|---|---|---|---|
| `GET /api/v1/me` | `user_ref`, `name`, `email`, `organisation`, `role` | any member | H1 |
| `GET /api/v1/organisation` | `org_ref`, `name`, `slug`, `status` | any member | H1 |
| `GET /api/v1/organisation/members` | `user_ref`, `name`, `email`, `role` for each active member | Manager and above | H1 |

## Failure behaviour

| Situation | Gateway | Hub |
|---|---|---|
| Hub unreachable | Keeps last synced people and credentials; queues events | — |
| Gateway silent | — | Site shown as out of contact; attendance for the gap flagged incomplete |
| Person ended while a gateway is offline | Access removed on next pull | Access shown as unconfirmed for that site |
| Remote action older than its time limit | Refused and reported | Shown as expired |
