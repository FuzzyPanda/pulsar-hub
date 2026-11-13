# Contracts — ids, pairing, calls and events

**Proposed 2026-11-13. Nothing is built.** If an implementation differs from this file, change
this file in the same pull request.

## Identifiers

| Id | Format | Minted by | Also stored in |
|---|---|---|---|
| `org_ref` | UUID v4 | Hub | TIM2 organisation or instance; each paired gateway |
| `person_ref` | UUID v4 | Hub, or TIM2 where it is the source for that organisation | TIM2 employee; PAC `Person.external_ref` |
| `site_ref` | UUID v4 | Hub, or TIM2 where it is the source | TIM2 location; PAC `Site.external_ref`, set at pairing |

Names and email addresses are never join keys.

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

- Sign-in: OIDC authorisation code with PKCE. Tokens are per device and revocable.
- All app calls are under `/api/v1/` and scoped to the signed-in user and the chosen organisation.
- Rostering screens call TIM2's mobile API (`TimeIsMoney2/docs/api/mobile-v1.md`) with a token the
  hub sign-in authorises.

## Failure behaviour

| Situation | Gateway | Hub |
|---|---|---|
| Hub unreachable | Keeps last synced people and credentials; queues events | — |
| Gateway silent | — | Site shown as out of contact; attendance for the gap flagged incomplete |
| Person ended while a gateway is offline | Access removed on next pull | Access shown as unconfirmed for that site |
| Remote action older than its time limit | Refused and reported | Shown as expired |
