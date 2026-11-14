# Contracts — ids, pairing, calls and events

**Proposed 2026-11-13; refusal codes, row-by-row directory and gateway health added 2026-11-14.** "Identifiers", "Sign-in" and the `/api/v1/` calls marked H1 are built; the
sections on gateways and Pulsar Rostering are built on the hub side. If an implementation differs from this file, change
this file in the same pull request.

## Identifiers

| Id | Format | Minted by | Also stored in |
|---|---|---|---|
| `org_ref` | UUID v4 | Hub | Each paired gateway |
| `person_ref` | UUID v4 | Hub, or Pulsar Rostering where it is the source for that organisation | Rostering's reference for the person; the gateway's `hub_people.person_ref` |
| `site_ref` | UUID v4 | Hub, or Pulsar Rostering where it is the source | Rostering's reference for the site; the gateway's `hub_link.site_ref`, set at pairing |

Names and email addresses are never join keys.

`org_ref` is the primary key of the hub's organisation row. A login has its own stable id, the
OIDC `sub` (UUID v4); it is not a `person_ref`. A person record (H2) may link to a login.

## Sign-in (built in H1)

The hub is an OpenID Connect provider. The Pulsar app is a client, registered by Pulsar
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

## Refusals (every `/api/v1/` call)

Every refusal, from any `/api/v1/` call, is JSON with two keys:

```json
{"detail": "This token does not have the directory:read scope.", "code": "missing_scope"}
```

`detail` is one sentence for a person and may be reworded at any time. `code` is for a program: it
is stable, and a caller decides what to do next from the HTTP status and the code, never from the
sentence. A caller must treat a code it does not know as it treats the status alone.

| Status | `code` | Meaning | What the caller does |
|---|---|---|---|
| 401 | `not_authenticated` | No bearer credential was sent | Send one |
| 401 | `token_not_accepted` | The credential is unknown, revoked, or its site or organisation is closed | Stop calling; a person must issue a new one |
| 403 | `missing_scope` | The service token is accepted but lacks the scope this call needs | Keep using its other scopes. A token's scopes are fixed when it is made, so a person creates a new token that has this one |
| 403 | `directory_source_is_hub` | `PUT /directory` for an organisation whose people and sites are managed in the hub | A person switches the directory source in the hub console |
| 403 | `role_too_low` | A user token whose role is below what the call needs | Nothing; hide the feature |
| 403 | `pairing_code_not_valid` | `POST /gateways/pair` refused, whatever the cause | A person makes a new code |
| 403 | `permission_denied` | Any other refusal of an accepted credential | Needs a person |
| 409 | `empty_snapshot` | `PUT /directory` would leave no active people while the hub holds some | Send `allow_empty: true` only when a person confirmed it |
| 400 | `unexpected_field` | A row carries a key outside the allowed list | Fix the sender; nothing was applied |
| 400 | `snapshot_too_large` | More than 20,000 people or sites | Nothing was applied |
| 400 | `invalid_signature` | `POST /sites/{ref}/events`: the signature does not match the body | Nothing was stored |
| 400 | `invalid_request` | The body, a parameter or a field is not what the call takes | Fix the request; repeating it unchanged will not help |
| 404 | `not_found` | A site this credential is not for. (An address that is no call at all also answers `404`, but not with this body) | |
| 405 | `method_not_allowed` | | |
| 429 | `rate_limited` | Too many calls | Wait (`Retry-After`) and try again |

Rows refused inside an accepted `PUT /directory` carry their own codes (`invalid_row`,
`duplicate_reference`, `reference_in_use`); see "Pulsar Rostering and hub". Events refused inside
an accepted batch carry a `reason` only.

## Gateway and hub (built: hub side H3, gateway side in `Pulsar-Access-Control`)

The gateway always initiates. Every call is HTTPS to `{HUB_BASE_URL}/api/v1/`, JSON in and out.
After pairing, every call carries `Authorization: Bearer <credential>`. The site in the path must
be the site the credential is paired to; anything else is `404`.

| Call | Purpose |
|---|---|
| `POST /gateways/pair` | Exchange a one-time code for a credential |
| `GET /sites/{site_ref}/access` | The state the gateway should hold |
| `POST /sites/{site_ref}/access/ack` | What the gateway has applied |
| `POST /sites/{site_ref}/events` | A signed batch of events |
| `POST /sites/{site_ref}/state` | Door states and gateway health, latest only |

A `401` on any call after pairing means the credential is no longer accepted (revoked, or the site
or organisation is closed). The gateway stops calling, keeps the people it last synced, and follows
its own fail policy. Nothing about its doors changes because the hub stopped answering.

### Pairing

1. An organisation Admin creates a one-time code for a site in the hub console. It is twelve
   characters shown as `XXXX-XXXX-XXXX`, valid for 15 minutes, usable once. Making another cancels it.
2. An installer enters the hub address and the code on the gateway.
3. The gateway calls `POST /gateways/pair` with no `Authorization` header:

```json
{"code": "K7QM-2XPA-9RTD", "name": "Front office R1100", "software_version": "1.4.0"}
```

`201`:

```json
{"gateway_id": "<uuid>", "credential": "hubgw_...", "org_ref": "<uuid>", "org_name": "Harbour Dental",
 "site_ref": "<uuid>", "site_name": "Main clinic", "site_timezone": "Australia/Melbourne", "poll_seconds": 60}
```

Any failure is `403 {"detail": "That pairing code is not valid."}`, whatever the cause. The
endpoint is limited to 10 attempts a minute per address. The hub stores only a digest of the
credential; the gateway stores it encrypted. A site has one live gateway: pairing another revokes
the one before. Either side can revoke.

### Desired access

`GET /sites/{site_ref}/access` returns the complete state, never a list of changes:

```json
{"org_ref": "<uuid>", "site_ref": "<uuid>", "version": "9f2c41d07a3be6c2a1f0b3d4e5f60718",
 "generated_at": "2026-11-13T05:00:00Z",
 "access_groups": ["Cleaners", "Managers"],
 "people": [
   {"person_ref": "<uuid>", "name": "Sam Lee", "active": true, "access_groups": ["Managers"]},
   {"person_ref": "<uuid>", "name": "Pat Kaur", "active": false, "access_groups": ["Cleaners"]}
 ]}
```

- A person is listed if they belong to an access group that includes this site. `access_groups` on
  a person names only the groups that apply at this site.
- `active: false` means the person has been ended: remove their access now.
- **Absence is removal.** A person the gateway holds from the hub who is not in the list must be
  treated as inactive.
- An access group is a name. What it means at this site (which doors, which hours) is the
  gateway's own mapping from group name to its local access levels. A group with no mapping grants
  nothing, and the gateway reports that in its acknowledgement.
- `version` changes when, and only when, the content does. Send `?version=<the one you hold>` and
  the hub answers `304` with no body if nothing changed.
- The hub never sends, and the gateway never needs, a card number, PIN or credential. Cards are
  enrolled on the gateway against the person.

`POST /sites/{site_ref}/access/ack`:

```json
{"version": "9f2c41d07a3be6c2a1f0b3d4e5f60718",
 "failures": [{"person_ref": "<uuid>", "reason": "access group Cleaners is not mapped at this site"}]}
```

`204`. The hub shows a site's access as unconfirmed until the acknowledged version equals the
current one. Acknowledge again whenever the list of failures changes (a mapping was added).

### Events

`POST /sites/{site_ref}/events` with header `X-Hub-Signature: sha256=<hex>`, the HMAC-SHA256 of the
raw request body keyed with the credential.

```json
{"events": [
  {"id": "<uuid>", "type": "attendance.clock_in", "occurred_at": "2026-11-13T05:01:07Z",
   "org_ref": "<uuid>", "site_ref": "<uuid>", "person_ref": "<uuid>",
   "data": {"door": "Staff entrance", "door_ref": "staff_entry"}}
]}
```

`200`:

```json
{"accepted": 1, "duplicates": 0, "rejected": [{"id": "<uuid>", "reason": "unknown type"}]}
```

- `id` is the idempotency key. An event the hub already holds is counted under `duplicates` and
  changes nothing, so a gateway that is unsure whether a batch arrived sends it again.
- Each event is judged alone. A rejected event will never be accepted: drop it, do not retry it.
  Everything not in `rejected` is safely held by the hub.
- At most 500 events a batch. The gateway queues while the hub is unreachable and sends oldest first.
- `org_ref` and `site_ref` must be the ones the gateway is paired to. `occurred_at` is RFC 3339
  with a zone, and not more than five minutes in the future.
- A bad signature, or a body that is not `{"events": [...]}`, is `400` and nothing is stored.

| Type | `person_ref` | `data` keys allowed |
|---|---|---|
| `attendance.clock_in`, `attendance.clock_out` | required | `door`, `door_ref` |
| `door.forced` | none | `door`, `door_ref` |
| `door.held_open` | none | `door`, `door_ref`, `seconds` (whole number) |
| `access.applied`, `access.revoked` | optional | `version` |
| `gateway.health` | none | `status`, `detail` |

Any other `data` key is refused. That is how rule 2 is enforced: there is no key a card number, a
PIN or a credential hash could travel in.

What the gateway sends today (Pulsar Access Control, `internal/hublink`): `attendance.clock_in`,
`attendance.clock_out`, `door.forced` and `door.held_open`. It does not yet send `seconds` on
`door.held_open`, nor `access.applied`, `access.revoked` or `gateway.health`; the hub accepts them
when it does. Applied versions reach the hub through the acknowledgement, and health through the
state call below.

### State

`POST /sites/{site_ref}/state` replaces the last snapshot. `204`.

```json
{"doors": [{"door_ref": "staff_entry", "name": "Staff entrance", "state": "locked", "mode": "normal"}],
 "health": {"status": "ok", "detail": "", "queued_events": 0}}
```

`state` is one of `locked`, `unlocked`, `open`, `held_open`, `forced`, `fault`, `lockdown`, `unknown`.
`mode` is the door's operating mode as the gateway holds it. `health.status` is `ok` or `degraded`
(`degraded` when the last hub call failed or events are waiting). The gateway sends every door it
has, and `software_version` at pairing may be empty.

## Pulsar Rostering and hub (built: hub side H2; Rostering side in `pulsar-rostering`)

Pulsar Rostering replaced Time Is Money 2. Decision D3: for an organisation that rosters,
Rostering owns people and sites and sends the hub a copy; the hub owns them otherwise. One
direction per organisation, set in the hub console (`directory_source`).

Rostering always initiates, with a **service token** an Owner creates in the hub console and
pastes into Rostering. The hub stores only its digest, holds no secret of Rostering's, and never
calls Rostering. Every call carries `Authorization: Bearer hubsvc_...`; the token decides the
organisation.

| Call | Scope | Purpose |
|---|---|---|
| `PUT /api/v1/directory` | `directory:write` | The full list of people and sites |
| `GET /api/v1/events?after=<cursor>` | `events:read` | Door and attendance events, oldest first |
| `GET /api/v1/people`, `GET /api/v1/sites` | `directory:read` | The hub's copy, and for each site the hub's view of its gateway (also open to Managers with a user token) |

A token for Pulsar Rostering needs `directory:write` and `events:read`. `directory:read` is
optional: with it Rostering also shows whether each site's gateway is in contact and checks that
what it sent is what the hub holds; without it those two calls answer `403 missing_scope` and
everything else carries on.

`PUT /api/v1/directory` is a snapshot. Sending it twice changes nothing; a missed one is repaired
by the next.

```json
{"people": [{"person_ref": "<uuid>", "name": "Sam Lee", "work_email": "sam@example.com", "status": "active"}],
 "sites":  [{"site_ref": "<uuid>", "name": "Main clinic", "address": "1 High St, Kew VIC 3101",
             "timezone": "Australia/Melbourne", "is_active": true}],
 "allow_empty": false}
```

- `person_ref` and `site_ref` are minted by Rostering and never change. They become the hub's ids.
- `status` is `active` or `ended`. A person missing from the list is ended; a missing site is made
  inactive. Nothing is deleted.
- Only these fields exist. Rostering must never send, and the hub has nowhere to keep, pay rates,
  bank details, dates of birth, licence numbers, phone numbers or home addresses (rule 11).
- `work_email` may be `null` or left out. `is_active` on a site and `allow_empty` are optional.

`200`:

```json
{"people_created": 0, "people_updated": 1, "people_ended": 1,
 "sites_created": 0, "sites_updated": 0, "sites_deactivated": 0,
 "rejected_count": 1,
 "rejected": [{"person_ref": "<uuid>", "code": "invalid_row", "reason": "A person needs a name."}]}
```

**Each row is judged alone, and a removal is never held back by another row.** A row the hub
cannot take is listed in `rejected` (with `person_ref` or `site_ref` as it was sent) and every other
row is applied. A sender must read `rejected`: a `200` no longer means every row was taken.
`rejected` holds at most 100 rows; `rejected_count` is the full number.

| Row | What the hub does |
|---|---|
| Valid | Applied |
| `status: ended` for a person the hub holds, anything else about the row invalid | **The person is ended.** The row is also listed in `rejected`, and the person's other details are left as they were |
| `is_active: false` for a site the hub holds, anything else invalid | **The site is made inactive.** Listed in `rejected`; its other details are left as they were |
| Invalid, and not such a removal (`invalid_row`: no name once cleaned, an unknown time zone, a status that is neither `active` nor `ended`, a reference that is not a UUID) | Not applied. A person or site the hub already holds under that reference is left exactly as it was: it is **not** ended or made inactive for being "missing" |
| The same reference on two rows (`duplicate_reference`) | Neither row is applied; what the hub holds is left as it was |
| A new reference that is already in use (`reference_in_use`: another organisation holds it) | Not created |

A person or site left out of the list altogether is still ended or made inactive, as before.

Refused as a whole, with nothing applied:

- `400 invalid_request`: the body is not JSON, `people` or `sites` is not a list, or a row is not
  an object.
- `400 unexpected_field`: a row carries a key outside the lists above. Refused, not ignored, so a
  sender that has started including more finds out before it sends something that must never
  leave it.
- `400 snapshot_too_large`.
- `409 empty_snapshot`: applying the list would leave no active people while the hub holds active
  people. It would remove everyone's access at every door, so the sender must say it means it with
  `allow_empty: true`. Rows in `rejected` leave their people as they were, so they count as
  whatever the hub already holds.
- `403 directory_source_is_hub` and `403 missing_scope` (see "Refusals").

`GET /api/v1/sites` (`directory:read`) lists every site with the hub's view of its gateway:

```json
[{"site_ref": "<uuid>", "name": "Main clinic", "address": "1 High St, Kew VIC 3101",
  "timezone": "Australia/Melbourne", "is_active": true, "access_managed_elsewhere": false,
  "gateway": {"status": "ok", "last_contact_at": "2026-11-14T05:00:10Z", "access_confirmed": true}}]
```

| `gateway.status` | Meaning |
|---|---|
| `none` | No gateway is paired to this site (or another system runs its doors). `last_contact_at` is `null` and `access_confirmed` is `false` |
| `out_of_contact` | The gateway has not called for five minutes (`GATEWAY_OUT_OF_CONTACT_SECONDS`). Door events from this site will arrive late; people ended meanwhile keep their access there until it calls again |
| `degraded` | In contact, and its last health report was not `ok` (its last call to the hub failed, or some people's access groups are not mapped at that site) |
| `ok` | In contact and healthy |

`access_confirmed` is `true` when the gateway has acknowledged the access the hub currently wants
at that site, whatever its `status`; `false` means a change (a person added, ended or moved between
groups) has not been confirmed at that site's doors yet. `last_contact_at` is the gateway's last
call of any kind, to the half minute. Nothing about a door is in this answer: no door names, states
or modes. It is read-only and tells a reader how far to trust door attendance from a site, not how
to change anything there. `GET /api/v1/people` is the hub's copy of the people, in the shape of
the `people` rows above; a sender can read both back to check that what it sent is what the hub
holds.

`GET /api/v1/events?after=<cursor>&limit=200&type=attendance` returns events with a cursor greater
than `after`, oldest first:

```json
{"events": [{"cursor": 4812, "id": "<uuid>", "type": "attendance.clock_in",
             "occurred_at": "2026-11-13T05:01:07Z", "org_ref": "<uuid>", "site_ref": "<uuid>",
             "person_ref": "<uuid>", "data": {"door": "Staff entrance", "door_ref": "staff_entry"}}],
 "next_cursor": 4812, "more": false}
```

Start with `after=0`. Store `next_cursor` once the batch is processed and send it next time.
`type` is a prefix filter (`attendance` matches both clock types). `id` is stable, so processing a
batch twice must be harmless on the reader's side too. Poll about once a minute.
Cursors only mean something for the organisation the token belongs to: a reader that is given a
token for a different organisation starts again from `0`. A new type under a prefix the reader
asked for will arrive without notice; skip what you do not know.

Sign-in to Rostering through the hub is not built: Rostering has its own logins and organisations
today, and whether the two merge is an open decision (D8).

## Hub and the app

- Sign-in: OIDC authorisation code with PKCE, as above. Tokens are per device and revocable.
- All app calls are under `/api/v1/` and scoped to the signed-in user and the organisation the
  token is for. The organisation cannot be named in a URL, header or body.
- Rostering screens call Pulsar Rostering's own API with Rostering's own sign-in for now (decision D8).

| Call | Returns | Role | Phase |
|---|---|---|---|
| `GET /api/v1/me` | `user_ref`, `name`, `email`, `organisation`, `role` | any member | H1 |
| `GET /api/v1/organisation` | `org_ref`, `name`, `slug`, `status` | any member | H1 |
| `GET /api/v1/organisation/members` | `user_ref`, `name`, `email`, `role` for each active member | Manager and above | H1 |

## Failure behaviour

| Situation | Gateway | Hub | Rostering |
|---|---|---|---|
| Hub unreachable | Keeps the people it last synced; queues events and sends them oldest first when the hub returns | — | Keeps polling; nothing is lost, events wait in the hub |
| Gateway silent | — | Site shown as out of contact after five minutes; access shown as unconfirmed | Attendance for the gap arrives when the gateway reconnects |
| Person ended while a gateway is offline | Access removed on its next pull | Access shown as unconfirmed for that site | — |
| Gateway revoked, or its site or organisation closed | Gets `401`; stops calling; keeps its last people; doors unchanged | Stops accepting its calls | — |
| Rostering sends nothing | — | Keeps the last copy; nothing expires | — |
| Rostering sends an empty list by mistake | — | Refuses it (`409`); no access is removed | Shows the error; a person must act |
| Rostering sends a list with a row the hub cannot take | — | Applies every other row and every removal; lists the row in `rejected` | Shows the rejected rows; a person fixes them. Nobody's removal waits for that |
| Access group has no mapping at a site | Grants nothing for it; reports it in the acknowledgement | Shows the site as applied with problems, naming the people | — |
