# PDR: job positions and rostered access — Pulsar Hub

**Status:** proposed 2026-11-14 by the Pulsar Rostering side. **For:** the engineers who own Pulsar
Hub. **Companion:** the same-named PDR for Pulsar Access Control (the gateway). Nothing here has been
built in the hub; Rostering's side is built and **switched off** until the hub says it accepts each
part (section 4.1).

## 1. The problem, and the owner's decisions (14 November 2026)

Today Pulsar Rostering sends the hub its people and sites (`PUT /api/v1/directory`: `person_ref`,
`name`, `work_email`, `status`) and reads door attendance back (`GET /api/v1/events`). Who may enter
which site is set **only in the hub console** (access groups and their memberships). So a new starter
has a shift tomorrow but no door access until somebody also adds them to an access group in the hub.

The owner decided:

1. **Door access is managed in Pulsar Access Control or in the hub, not in Rostering.** Rostering
   tells the hub about changes *to the person*: a termination (already sent: `status: ended`) and a
   change of **job positions** (Guard, Supervisor, Instructor…), so that the hub or the gateway can
   **map positions to access groups**.
2. **Access limited to rostered hours** ("the card only works while rostered"): Rostering builds its
   side now, switched off, and the hub and the gateway decide whether and how to act on it.
3. Gateway health and door alarms stay in the hub (no change asked of the hub here).

Rostering is never in the path of a door decision: it sends snapshots; the gateway decides, locally,
with its own fail policy, and keeps working when the hub or Rostering is down.

## 2. What Rostering will send

### 2.1 Positions on each person (an added key in the existing directory call)

`PUT /api/v1/directory`, unchanged except that each person may carry `positions`:

```json
{"people": [
   {"person_ref": "7c0e…", "name": "Sam Lee", "work_email": "sam@example.com", "status": "active",
    "positions": ["Guard", "Supervisor"]},
   {"person_ref": "91ab…", "name": "Pat Kaur", "work_email": null, "status": "ended", "positions": []}],
 "sites": [{"site_ref": "…", "name": "Main clinic", "address": "1 High St, Kew VIC 3101",
            "timezone": "Australia/Melbourne", "is_active": true}],
 "allow_empty": false}
```

| Field | Meaning |
|---|---|
| `positions` | The names of the person's **current job positions**, sorted, distinct, each at most 60 characters. Rostering keeps no "positions a person is set up for" on the person: a position exists only on a shift. So "current" means **the positions on the person's published shifts from 30 days ago to 30 days ahead**. A person with no shift in that span has `[]`. An ended person always has `[]` |

Sent **only** when the hub advertises it (4.1) and an owner switched it on. The list is a full
snapshot like the rest of the directory: the positions in the latest snapshot are the person's
positions; a position missing from it is no longer theirs.

### 2.2 Rostered windows (a new call)

`PUT /api/v1/rostered-windows`, a **full snapshot** of the published roster for a rolling horizon,
sent when it changes and at least hourly:

```json
{"generated_at": "2026-11-14T05:00:00Z",
 "horizon_start": "2026-11-14T04:30:00Z",
 "horizon_end": "2026-11-17T05:00:00Z",
 "margin_minutes": 30,
 "windows": [
   {"person_ref": "7c0e…", "site_ref": "a41f…", "starts_at": "2026-11-14T21:30:00Z",
    "ends_at": "2026-11-15T07:30:00Z", "position": "Guard"}]}
```

| Field | Meaning |
|---|---|
| `generated_at` | When Rostering built the snapshot (UTC) |
| `horizon_start`, `horizon_end` | The span the snapshot is complete for: now minus the margin, until now plus the horizon (default 72 hours, at most 336). **Outside it the snapshot says nothing** (it does not mean "not rostered") |
| `margin_minutes` | Already applied to every window (default 30, at most 240): a window opens that long before the published start and closes that long after the published end |
| `windows[].person_ref`, `site_ref` | References the hub already holds from the directory |
| `windows[].starts_at`, `ends_at` | UTC instants, already widened by the margin. Overnight shifts are one window |
| `windows[].position` | The position's name on that shift (may be empty) |

Only **published** shifts (never a draft), only people still employed, only sites the hub knows. Two
shifts of one person at one site are two windows (they may touch or overlap after the margin).

### 2.3 Never sent

Pay and charge rates, client names, shift or assignment ids, shift notes, names in the windows call,
phone numbers, home addresses, dates of birth, gender, licence or qualification numbers, leave or
availability, anything about why a shift changed. The directory keeps its explicit allow-list
(the hub already refuses any other key — please keep refusing).

## 3. Latency and what a roster change does at a door (for the hub to state in its contract)

Rostering sends a changed snapshot on its next per-minute run. A shift published at 08:55 for 09:00
is in the hub by about 08:56; a gateway then needs its own poll (60 s) to get it. **The margin is
what absorbs this**; a shorter margin than the end-to-end latency means a late-published person
waits at the door. A shift swap removes the old person's window in the next snapshot: if the hub and
the gateway enforce windows, the swapped-out person loses access within a couple of minutes, even
mid-shift. Rostering cannot make this faster than its schedule plus the gateway's poll.

## 4. Changes requested of the hub, smallest first (each ships on its own)

### 4.1 Capability advertisement (needed before anything else)

`GET /api/v1/capabilities`, authenticated by the same service token (no extra scope):

```json
{"contract": 2,
 "directory": {"person_fields": ["person_ref", "name", "work_email", "status", "positions"],
               "site_fields": ["site_ref", "name", "address", "timezone", "is_active"]},
 "rostered_windows": {"version": 1, "max_horizon_hours": 336}}
```

Rostering reads it hourly. It sends `positions` only while `directory.person_fields` contains
`"positions"`, and windows only while `rostered_windows.version` is `1`. A `404` means "nothing beyond
today's contract" (what the hub answers now). If the hub later refuses what it advertised (a `400`
on the directory with positions, any refusal on windows), Rostering switches that part off, records
when, and sends the directory as today **in the same run**: the base sync never depends on an
extension.

### 4.2 Accept `positions` on a person

- Add `positions` to the directory's person allow-list (`DirectoryView`: today `{"person_ref",
  "name", "work_email", "status"}`), optional, a list of at most 20 strings.
- Clean each with the same `plain_text()` as names (at most 60 characters), drop blanks and
  duplicates; a value that is not a list of strings refuses the snapshot (`400`), as other malformed
  rows do.
- Store it on `directory.Person` (e.g. `positions` JSON, default `[]`). Show it on the person's page.
- The snapshot audit event should count position changes like other changes.

### 4.3 Map positions to access groups (in the hub)

- An organisation-level mapping: position name → access group(s) ("Guard" → "Guards").
- Memberships derived from it are kept apart from hand-made ones (e.g. `AccessGroupMember.source`
  `positions` vs `manual`), recomputed whenever a directory snapshot or the mapping changes, so a
  position removed from a person removes only the derived membership, never one a person added.
- The gateway needs no change for this: it receives access groups as today and maps groups to its
  own access levels.
- **Recommendation:** do it here, not on the gateway: access groups are the hub's concept and span
  sites, and one mapping serves every gateway of the organisation.

### 4.4 Accept rostered windows

- `PUT /api/v1/rostered-windows`, scope `directory:write` (or a new `roster:write`; the hub's call).
- Snapshot semantics as the directory: the windows in the latest snapshot replace all earlier ones
  for the organisation; sending it twice changes nothing.
- Validate: every `person_ref` and `site_ref` is the organisation's; `ends_at` after `starts_at`; no
  window longer than 26 hours plus twice the margin; `horizon_end - horizon_start` within
  `max_horizon_hours`; at most 50,000 windows. A malformed snapshot is applied in no part (`400` with
  `{"detail"}`).
- Keep `generated_at` and `horizon_end`; show per site "rostered windows received at …, valid until …".
- Only for organisations whose directory source is Rostering.

### 4.5 Carry windows to the gateway (only once a gateway says it understands them)

In `GET /sites/{site_ref}/access`, for a gateway that advertised support (see the gateway PDR):

```json
{"…": "as today",
 "windows_valid_until": "2026-11-17T05:00:00Z",
 "roster_limited_groups": ["Guards"],
 "people": [{"person_ref": "7c0e…", "name": "Sam Lee", "active": true, "access_groups": ["Guards"],
             "windows": [{"starts_at": "2026-11-14T21:30:00Z", "ends_at": "2026-11-15T07:30:00Z"}]}]}
```

- `roster_limited_groups`: access groups the organisation has marked "only while rostered" (a new
  flag on `AccessGroup`, off by default). Windows limit **only** access that comes from those groups;
  everything else is as today.
- `windows`: that person's windows **at this site** only. The version digest must include them.
- `windows_valid_until`: the `horizon_end` of the snapshot the windows came from. The gateway decides
  what to do when it passes (gateway PDR).
- A gateway that did not advertise support never receives these keys (it would refuse unknown keys or
  ignore them; either is wrong for a safety decision).

## 5. Failure behaviour (questions for the hub to decide, with a recommendation)

| Situation | Question | Recommendation |
|---|---|---|
| Rostering stops sending windows (its link is switched off, removed, failing, or the organisation is suspended) | Do the hub's windows age out? | Keep serving the last windows with their `windows_valid_until`; never extend it. Show "rostered windows are stale" on the site after `horizon_end` |
| The rostered-windows switch is turned off in Rostering | Should the hub drop the windows? | Rostering will stop sending; propose an explicit `DELETE /api/v1/rostered-windows` that Rostering calls when the switch goes off, so "not limited any more" is a deliberate signal, not silence |
| A snapshot fails validation | Keep the previous one? | Yes, unchanged, and record the error (as the directory does) |
| An access group is roster-limited but the organisation sends no windows | Deny everyone in it? | That is the gateway's fail policy (gateway PDR); the hub should warn when a roster-limited group exists and no windows have arrived |

## 6. Security and privacy

- Position names and shift times are operational data about staff, not credentials. They reveal
  when someone will be on site: treat the windows like the access snapshot (only to the paired
  gateway of that site; never in logs; not in the events API).
- No card, PIN or credential travels in either direction (rule 2 holds).
- The windows call is a snapshot of the published roster only; a draft never leaves Rostering.

## 7. Acceptance tests the hub could adopt

1. `GET /api/v1/capabilities` with a service token returns the shape in 4.1; without a token 401.
2. A directory snapshot with `positions` is accepted once advertised; positions are cleaned, stored
   and shown; a second identical snapshot changes nothing; `positions: "Guard"` (not a list) is `400`.
3. Mapping "Guard" → "Guards": a person sent with `["Guard"]` becomes a derived member; sent with
   `[]` stops being one; a hand-made membership in the same group survives both.
4. Rostered windows: a valid snapshot is stored; the same one again changes nothing; a window for a
   person of another organisation, an inverted window, or an oversized horizon refuses the whole
   snapshot and keeps the previous one.
5. The access snapshot for a gateway that advertised support carries only that site's windows and
   `roster_limited_groups`; for one that did not, no new key appears; the version changes when a
   window changes and not otherwise.

## 8. Open questions

- New scope `roster:write`, or reuse `directory:write`?
- Should the hub accept windows for an organisation whose directory source is the hub (no
  Rostering)? Proposed: no.
- Decision D8 (one identity) may move people into one system; the references stay stable either way.
