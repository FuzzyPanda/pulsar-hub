# Contracts — ids, pairing, calls and events

**Proposed 2026-11-13.** "Identifiers", "Sign-in" and the `/api/v1/` calls marked H1 are built; the
sections on gateways and Pulsar Rostering are built on the hub side, and "Remote console"
(2026-11-14) on the hub side only. If an implementation differs from this file, change
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
| `amr` | `openid` | `["mfa"]` when the browser session that asked for the token had passed a second factor (authenticator app, passkey or recovery code; enrolling the first factor counts). Absent otherwise |
| `name`, `org_name` | `profile` | Display names |
| `email`, `email_verified` | `email` | The login's email address |

Nothing else is ever a claim. `amr` is in the ID token only (issued with the code and again at each
refresh, which carries what the original sign-in proved); userinfo never has it. A client must read
its absence as "not proved", never as "no second factor". A resource server must not treat `org_role` as live: the hub
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

### Opening a product from the hub

The hub's Apps launcher links to each product an organisation has connected (`docs/PRODUCTS.md`).
For a product with an address the link is followed by the person's browser and the hub makes no
call of its own. Pulsar Access Control has no address to link to: its console is carried down the
connection each gateway keeps open to the hub.

| Product | Link | What the product does with it |
|---|---|---|
| Pulsar Rostering | `{base}/api/v1/auth/hub/start?hub_org={org_ref}` | Starts its "sign in with Pulsar Hub": an authorisation-code request to this hub as OIDC provider (above) with `org={org_ref}`, and lands the person signed in. Rostering registers its own client with the hub |
| Pulsar Access Control | None. An Owner or Admin presses "Open" for a site, passes a step-up check, and the hub opens the gateway's console through its relay on the console origin | See "Remote console" below. Since 2026-11-14 the hub never links to an address on a site's own network |

`{base}` is the address an Owner entered for the organisation. `org_ref` is this hub's id for the
organisation, the same value as the `org_ref` claim, so the link works whatever the organisation is
called in the product (the two slugs need not match). It is sent so that the hub's authorisation
screen is asked for the right organisation before anyone is signed in; it grants nothing, the hub
refuses it for a person who does not belong to that organisation, and Rostering must take the
organisation it trusts from the `org_ref` claim of the token it then receives. A launch path may use
`{org_slug}` (the hub's slug) as well or instead. An Owner can replace the path for one organisation
(for a product version that has no such endpoint yet) without a change here.

## Gateway and hub (built: hub side H3, gateway side in `Pulsar-Access-Control`)

The gateway always initiates: every call below, and the one long-lived connection of "Remote
console". The hub never opens a connection to a site. Every call is HTTPS to `{HUB_BASE_URL}/api/v1/`, JSON in and out.
After pairing, every call carries `Authorization: Bearer <credential>`. The site in the path must
be the site the credential is paired to; anything else is `404`.

| Call | Purpose |
|---|---|
| `POST /gateways/pair` | Exchange a one-time code for a credential |
| `GET /sites/{site_ref}/access` | The state the gateway should hold |
| `POST /sites/{site_ref}/access/ack` | What the gateway has applied |
| `POST /sites/{site_ref}/events` | A signed batch of events |
| `POST /sites/{site_ref}/state` | Door states and gateway health, latest only |
| `GET /gateways/tunnel` (WebSocket) | The remote-console tunnel; see "Remote console" |

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

## Remote console (built: hub side 2026-11-14; gateway side to be built in `Pulsar-Access-Control`)

**The owner's decision, 2026-11-14.** A gateway's own web console can be opened from outside the
site's network, through the hub: the gateway keeps one outbound connection open to the hub, and the
hub relays the console down it to a signed-in hub user. Nothing is opened inbound at the site. The
whole console is reachable this way, with safeguards: each remote session needs a fresh
authenticator check at the hub, is for an Owner or an Admin only, expires after a short time, and
is recorded in the audit log on both the hub and the gateway. It replaces the console-address link
of 2026-11-13: the hub no longer offers a link to an address on a site's own network.

This section is the whole contract for the gateway side. `tools/console_conformance.py` in this
repository plays the hub's end for a gateway under development, and `tools/fake_gateway.py` is a
complete, small gateway end to read beside it.

### What each side decides

| The hub decides | The gateway decides |
|---|---|
| Who may have a session: an active Owner or Admin of the gateway's organisation, after a step-up check; never a Pulsar operator, a Manager or Staff | Whether the remote console is on at all. A switch on the gateway, set by someone on site, **off unless they turned it on**. The hub can read it and cannot change it |
| When a session ends (the list is under "Sessions") | What a request reaches: its console's one fixed local address, from its own configuration. A frame carries a method, a path and headers, never a host, a port or a scheme |
| That a request which changes something came from the console's own pages (`Origin` check) | Whether to accept each session (`session.ack`), and whether to ask for its own sign-in as well |
| What the browser may keep: one cookie of the hub's own, nothing of the gateway's | What its console does, and its own audit record of every session and action |

Rule 4 holds throughout: the tunnel is not on the path of any door decision, the people sync or the
event queue. A gateway must behave at its doors exactly as before with the tunnel refused, hung,
flapping or sending nonsense, and with the remote console on or off.

### The tunnel

One WebSocket (RFC 6455) per gateway, opened by the gateway and kept open:

```
GET {HUB_BASE_URL}/api/v1/gateways/tunnel          (wss://; the scheme follows HUB_BASE_URL)
Authorization: Bearer hubgw_...                    the pairing credential, as on every other call
Sec-WebSocket-Protocol: pulsar-console.v1          every version the gateway speaks, comma-separated
X-Gateway-Version: 1.5.0                           optional
```

- **TLS is required.** Plain `ws://` is accepted only by a hub whose own lab flag for plain HTTP is
  on (`INSECURE_COOKIES`), and a gateway must refuse to use it unless its own lab flag is on
  (`HUB_LINK_ALLOW_INSECURE_HTTP=true`). Never at a site.
- **No `Origin` header.** A request that carries one is refused: nothing running in a browser may
  open a tunnel.
- No WebSocket compression is negotiated. Redirects are not followed.
- The credential binds the tunnel to the one gateway, organisation and site it was paired to. The
  gateway is not asked for, and must not send, an organisation or a site.
- A gateway **should** keep the tunnel open whether its remote console is on or off, so that the
  hub can tell people "switched off on the gateway" rather than "not connected". With the console
  off it refuses every session; it carries nothing.

The answer to the upgrade:

| Status | Meaning | What the gateway does |
|---|---|---|
| `101`, `Sec-WebSocket-Protocol: pulsar-console.v1` | Accepted | Sends `hello` |
| `401` | The credential is not accepted (revoked, or the site or organisation is closed). The same meaning as on every other call | Stops, as for any `401` |
| `403` | TLS is required, or the request carried `Origin` | A configuration fault: retry no more than once an hour |
| `404` | This hub has no remote console (older software, or not set up) | Retry no more than once an hour |
| `426`, body `{"detail": "...", "supported": ["pulsar-console.v1"]}` | No version in common | Retry no more than once an hour; say so on its own status page |
| `429` (`Retry-After`) | Too many attempts from this address (30 a minute) | Wait at least `Retry-After` |
| `503` (`Retry-After`) | The hub cannot check the credential just now. **Not** a statement about the credential | Back off and retry |

**Versions.** The subprotocol name is the version. The gateway offers every version it speaks; the
hub picks the newest it also speaks and names it in the `101`. With none in common the hub answers
`426` before any frame is exchanged, and shows the gateway as "gateway software too old". Within a
version, both sides **ignore frame types and fields they do not know**; anything that would break
an older peer needs a new version name.

**Frames.** A text message is one JSON object with a string `"t"` (the frame type), at most
131072 bytes. A binary message is body data for one stream: a 4-byte big-endian stream id, then 1
to 65536 bytes of data. Malformed frames, a first frame that is not `hello`, a `hello` later than
10 seconds, a `status` outside 200 to 599, or more data than a stream's window allows are protocol
errors: the hub closes the tunnel with `4000`.

| Frame | Direction | Fields |
|---|---|---|
| `hello` | gateway → hub, first, within 10 s | `console_enabled` (boolean, required), `software_version` (text, optional) |
| `welcome` | hub → gateway, in answer | `gateway_id`, `org_ref`, `site_ref`, `limits` (below), `ping_seconds` (20), `idle_seconds` (60) |
| `console` | gateway → hub | `enabled` (boolean): the local switch changed |
| `session.start` | hub → gateway | `session`, `user` {`id`, `email`, `name`, `role`}, `started_at`, `expires_at`, `console_origin`, `client_ip` |
| `session.ack` | gateway → hub, within 5 s | `session`, `ok` (boolean), and when not ok `reason`: `disabled` (the switch is off), `busy`, or anything else |
| `session.extend` | hub → gateway | `session`, `expires_at` |
| `session.end` | either way | `session`, `reason`; from the hub also `ended_at` |
| `req` | hub → gateway | `s`, `session`, `method`, `path`, `headers`, `body` (boolean) |
| `req.end` | hub → gateway | `s`: the request body is complete. Sent only when `body` was true |
| `res` | gateway → hub | `s`, `status` (200 to 599), `headers`, `body` (boolean) |
| `res.end` | gateway → hub | `s`: the response body is complete. Sent only when `body` was true |
| `win` | either way | `s`, `n`: the receiver of a body grants the sender `n` more bytes |
| `rst` | either way | `s`, `reason` (text, for logs): the stream is abandoned |

`limits` in `welcome`, which both sides hold to:

| Limit | Value | |
|---|---|---|
| `max_streams` | 32 | Requests in flight on one tunnel. The hub also allows one session at most 12 |
| `window` | 262144 | Bytes of body a sender may have outstanding on one stream, in each direction |
| `max_data` | 65536 | Bytes of data in one binary frame |
| `max_text_frame` | 131072 | Bytes in one JSON frame |
| `max_header_bytes` | 65536 | Names and values of one message's headers together; at most 200 headers |
| `max_request_body` | 16777216 | An upload (`CONSOLE_MAX_UPLOAD_MB` on the hub). Larger is refused by the hub with `413` |

**Keepalive.** The hub sends a WebSocket ping every `ping_seconds` and closes the tunnel if no pong
comes within half that. The gateway answers pings (any WebSocket library does) and may send its
own. A gateway that has received nothing at all, frame or ping, for `idle_seconds` must treat the
tunnel as dead, close it and reconnect.

**Closing.** Whoever closes, **every session on the tunnel is over** on both sides, without any
`session.end`. Sessions never move to a later connection.

| Close code | From the hub it means | What the gateway does |
|---|---|---|
| `1001` | The relay is restarting | Reconnect with back-off |
| `4000` | The gateway broke the protocol; the close reason says how | Reconnect with back-off; it is a bug to fix |
| `4001` | The same gateway opened a newer tunnel, which replaced this one | Wait at least 30 seconds before reconnecting (two instances are fighting) |
| `4003` | The credential is no longer accepted. The hub sends `session.end` (`gateway_revoked`) for each open session first | Stops, as for a `401` |
| `4004` | The hub cannot check anything just now | Reconnect with back-off |
| anything else, or the connection just dropping | | Reconnect with back-off |

**Reconnecting.** After the n-th failure in a row wait `min(300, 2^(n-1))` seconds, times a random
factor between 0.5 and 1. A tunnel that reached `welcome` and stayed open 60 seconds resets n.
`401` and `4003` end the attempts until the gateway is paired again; `403`, `404` and `426` are
retried no more than hourly. None of this may delay, or share a failure counter with, the people
sync or the event queue.

### Sessions

A session is one hub user, on one gateway, in one browser, for a short time. The hub starts one
only for an Owner or Admin who has just passed a step-up check, at most three at a time per gateway
and one per person. It lasts `CONSOLE_SESSION_MINUTES` (15 by default, never more than 60) and is
extended only by another step-up.

```json
{"t": "session.start", "session": "6b1f...", "started_at": "2026-11-14T05:00:00Z", "expires_at": "2026-11-14T05:15:00Z",
 "user": {"id": "<the login's id, the OIDC sub>", "email": "sam@example.com", "name": "Sam Lee", "role": "owner"},
 "console_origin": "https://0f8fad5bd9cb469fa16570867728950e.console.example.net", "client_ip": "203.0.113.9"}
```

- `role` is `owner` or `admin`. `client_ip` is the browser's address as the hub saw it, and may be
  empty. Times are RFC 3339, UTC.
- The gateway answers `{"t": "session.ack", "session": "...", "ok": true}` within 5 seconds. The
  session exists only from then: the hub sends no request before it. Without an answer in time the
  hub tells the person the gateway did not answer and sends `session.end` (reason `not_started`).
- With its switch off the gateway answers `ok: false`, `reason: "disabled"`. It may refuse for any
  reason of its own.
- **Every `req` names its session.** The gateway must refuse (with `rst`, or a `res` of its own
  making) a request for a session it did not accept, one that has ended, and one whose `expires_at`
  passed more than 60 seconds ago by its own clock. The hub ends sessions on time; the 60 seconds
  is room for clock difference, and the check is there so that a hub that failed to say "ended"
  cannot keep a session alive.
- `session.extend` moves `expires_at`. It is sent only after another step-up at the hub.
- The hub's reasons in `session.end`: `expired`, `user` (the person ended it), `admin` (another
  Owner or Admin did), `replaced` (the same person opened a new one), `gateway_revoked`,
  `membership_changed` (their role changed or they left), `signed_out`, `hub_session_ended` (their
  hub sign-in ended some other way), `organisation_closed`, `not_opened` (the browser never arrived
  within a minute), `gateway_ended`, `not_started`. New reasons may appear: any `session.end` ends
  the session.
- The gateway ends a session itself by sending `session.end`. It must do so for every session when
  its switch is turned off, and then send `console` with `enabled: false`.
- **The gateway records, in its own audit log,** each session's start (who, role, from what
  address, until when), its end and the reason, and each action taken in it, attributed to the hub
  user. The hub records every start, end, refusal and extension on its side.

### Requests

```json
{"t": "req", "s": 7, "session": "6b1f...", "method": "POST", "path": "/ui/doors/3/?tab=schedule",
 "headers": [["accept", "text/html"], ["content-type", "application/x-www-form-urlencoded"],
             ["origin", "https://0f8f...950e.console.example.net"], ["x-forwarded-for", "203.0.113.9"],
             ["x-forwarded-proto", "https"], ["x-forwarded-host", "0f8f...950e.console.example.net"],
             ["x-hub-console-session", "6b1f..."], ["cookie", "sessionid=...; csrftoken=..."],
             ["content-length", "58"]],
 "body": true}
```

- `s` is the stream id: a whole number from 1, chosen by the hub, never reused on a connection.
- `method` is one of `GET`, `HEAD`, `POST`, `PUT`, `PATCH`, `DELETE`, `OPTIONS`.
- `path` is the path and query exactly as the browser sent them. The hub does not send one that
  does not begin with a single `/`, and **the gateway must refuse one all the same** (so not
  `//host/...`, not `http://...`), and must build the address it calls from its own configured
  console address and this path, and from nothing else. That is what keeps the tunnel from
  reaching anything but the console, and it is the gateway's check that counts.
- With `body: true` the body follows as binary frames and ends with `req.end`. **The gateway reads
  every request body to its end**, granting credit as it goes, even when it has already answered.
- The gateway answers with `res`, then binary frames and `res.end` when `body` is true. It never
  sends a `1xx` status; `HEAD`, `204` and `304` have `body: false`. If it cannot answer it sends
  `rst`, and the browser gets a `502`.
- Either side abandons a stream with `rst`. Frames for a stream that is not open are ignored (they
  cross on the wire), except that body data for a stream the hub does hold, outside its response,
  is a protocol error.
- **Flow control.** Each direction of each stream starts with `window` bytes of credit. A sender
  never has more than its credit outstanding; the receiver gives credit back with `win` as it
  passes the bytes on (the hub does so in steps of at least half a window, once they have reached
  the browser). Credit never exceeds `window`. This is what lets a slow browser or a slow console
  hold up its own stream and no other, with nothing buffered without limit. A gateway that sends
  beyond its credit loses its tunnel (`4000`).
- **Time limits at the hub.** 60 seconds for `res` once the request is sent (then `rst` and a
  `504`); 60 seconds of silence in the middle of a body (then `rst`); 10 seconds waiting for a free
  stream (then `503`). A browser that goes away gets its stream an `rst`.

**Headers the hub sends.** Names are lower case. What the browser sent, without: hop-by-hop headers
(RFC 9110 7.6.1, and any named in `Connection`), `host`, `cookie`, `authorization`, `forwarded`,
`via`, `x-real-ip`, `expect`, and every header beginning `x-forwarded-`, `x-hub-`, `x-pulsar-`,
`proxy-`, `x-ssl-`, `x-client-cert` or `sec-websocket-`. Then, written by the hub:

| Header | Value |
|---|---|
| `x-forwarded-for` | One address: the browser's, as the hub saw it |
| `x-forwarded-proto`, `x-forwarded-host` | The scheme and host of `console_origin` |
| `x-hub-console-session` | The session id, the same as the frame's `session` |
| `cookie` | Only the cookies this session's console has set (below). Absent when there are none |
| `content-length` | The body's length, on every request with a body and on every `POST`, `PUT` and `PATCH` |

`origin` and `referer` arrive as the browser sent them. For every method except `GET`, `HEAD` and
`OPTIONS` the hub has already refused the request unless `Origin` (or, without one, `Referer`) is
exactly `console_origin`.

**What the gateway does with them** before calling its console:

1. Sets `Host` itself, to what its console expects.
2. Replaces `origin`, when it equals `console_origin`, with its console's own local origin, and
   the same prefix of `referer`; drops an `origin` that is anything else. The console's own CSRF
   check then passes for a form posted remotely and for no other.
3. Adds whatever tells its console who the hub user is, after removing any header of that name
   that arrived.
4. Trusts `x-forwarded-*` and `x-hub-*` **only because they came down the tunnel**. Its own proxy
   must strip them, and its client-certificate headers, from every request that arrives any other
   way, as it does for the client-certificate headers today.

**Cookies.** The gateway's console sets cookies as for any browser. The hub keeps them, per
session, and sends them back with that session's requests; the browser never receives them. So:
`Domain`, `Secure`, `HttpOnly` and `SameSite` have no effect; `Path`, `Max-Age` and `Expires` are
honoured; at most 50 cookies of 4096 bytes each; they are gone when the session ends. **Script in
a console page cannot read or set the console's cookies** (`document.cookie` is empty), so a
console must carry its CSRF token in the page, as Pulsar Access Control's does, and must not read
it from a cookie in script. A gateway should end its console's own sign-in when the hub session it
was made in ends.

**What the hub does to a response.** Removes hop-by-hop headers, `set-cookie` (to the jar),
`strict-transport-security`, `public-key-pins`, `alt-svc`, `clear-site-data`,
`service-worker-allowed`, `nel`, `report-to`, `reporting-endpoints`, `expect-ct`,
`origin-agent-cluster`, `date` and `server`. Sets `referrer-policy: same-origin` and
`cross-origin-resource-policy: same-origin`, and `x-content-type-options: nosniff` and
`cross-origin-opener-policy: same-origin` unless the console set its own. **Keeps the browser on
the console origin:** in `location`, `content-location`, `refresh`, `hx-redirect`, `hx-location`,
`hx-push-url` and `hx-replace-url`, the scheme and host of an absolute address are discarded and
the path, query and fragment kept. So a console that redirects to its own local address lands on
the right page of the console origin, and no console can send the browser anywhere else. The body
is passed through untouched; `content-encoding` is the console's business.

**What a console cannot do through the hub.** WebSocket upgrades (`501`), registering a service
worker (`403` for the script), a streamed response that is silent for more than 60 seconds, an
upload over the limit, and any path beginning `/__hub__/`, which the hub answers itself (the
hand-off, "end this session", and the page shown when a session has ended). Pulsar Access
Control's console uses polling only, so nothing it does today is affected except push
notifications, which need a service worker.

### The console origin

A console is never served from the hub's own origin. `CONSOLE_ORIGIN_TEMPLATE` gives each gateway
its own: `https://{gateway}.console.example.net`, where `{gateway}` is the gateway's id without
dashes. **The domain must be a different registrable domain from the hub's**, so that nothing a
console serves is same-site with the hub. The browser reaches it from the hub by a form `POST`
carrying a single-use token that is valid for 60 seconds, is stored only as a digest, is never in
an address and is never logged; the relay exchanges it for the session's cookie
(`__Host-pulsar_console`: `Secure`, `HttpOnly`, `SameSite=Strict`, host-only, no lifetime of its
own), whose value is random and means nothing without the hub's record of the session.

On a plain-HTTP bench only, one shared origin on an extra port is accepted
(`http://{host}:8081`). The cookie rules still hold there, because a gateway's cookies never reach
the browser at all and the browser's never reach a gateway; responses are sent `no-store`, because
the browser's cache would be shared between gateways. What does **not** hold on a bench is origin
isolation itself: consoles share web storage with each other, and their pages are same-site with
the hub. That is one of the reasons a bench is not a deployment.

### What each side relies on

| The gateway relies on the hub for | The hub relies on the gateway for |
|---|---|
| A session only for an Owner or Admin with a fresh second factor, and its end when any of the listed things happens | Refusing every session while its switch is off, and never treating the hub's word as enough to switch it on |
| The `Origin` check on every request that changes something | Sending each request to its console and nowhere else |
| The identity in `session.start` being the person at the hub | Refusing a request for a session it did not accept or that has ended |
| The four forwarding headers, and nothing forged in their place | Its own audit record, complete without the hub's |
| Nothing: its doors, its people and its events do not depend on any of this | Keeping its credential secret; the tunnel is as trusted as the credential |

The tunnel authenticates with the same bearer credential as the rest of the hub link. The gateway
repository's fleet-control-plane rules ask for a client certificate on anything that changes a
site; `docs/DECISIONS.md` D7 records that this has not been reconciled.

### Inside the hub

Not part of the gateway contract. The relay (`relay/`, an asynchronous service beside the web
workers) holds the tunnels and carries the bytes; it has no database and decides nothing. It asks
the web service (`/internal/relay/...`: Docker network only, refused by Caddy, shared secret
compared in constant time, refused if it came through a proxy) whether a credential or a hand-off
token is valid, reports tunnels opening and closing, and every ten seconds lists the tunnels and
sessions it holds and is told which to drop. The web service tells the relay at once when a
session starts, is extended or ends and when a gateway is revoked (`relay:8003`, never routed by
Caddy). If the relay cannot reach the web service it stops relaying within about 35 seconds; if it
restarts, every session is over. There is one relay; running several is not built.

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
| `GET /api/v1/people`, `GET /api/v1/sites` | `directory:read` | The hub's copy (also open to Managers with a user token) |

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
- A snapshot with no active people while the hub holds active people is refused (`409`) unless
  `allow_empty` is true: it would remove everyone's access at every door.
- `403` if the organisation's directory source is the hub, and also if the token lacks the scope.
  `200` with counts of what changed.
- `work_email` may be `null` or left out. `is_active` on a site and `allow_empty` are optional.
- Every refusal is `{"detail": "<one sentence>"}`. There is no machine-readable code yet, so a
  caller cannot tell the two `403` cases apart; treat both as "needs a person".

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
| Gateway revoked, or its site or organisation closed | Gets `401`; stops calling; keeps its last people; doors unchanged | Stops accepting its calls; closes its tunnel (`4003`) and ends its remote console sessions at once | — |
| Tunnel refused, dropped or hung | Reconnects with back-off. Doors, the people sync and the event queue are not affected | Shows the remote console as not connected; ends the sessions that were on it | — |
| Hub's relay or web service down | As above | No remote console. Nothing else changes | — |
| Rostering sends nothing | — | Keeps the last copy; nothing expires | — |
| Rostering sends an empty list by mistake | — | Refuses it (`409`); no access is removed | Shows the error; a person must act |
| Access group has no mapping at a site | Grants nothing for it; reports it in the acknowledgement | Shows the site as applied with problems, naming the people | — |
