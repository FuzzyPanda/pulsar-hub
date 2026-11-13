# Candidates — not in the plan yet

**Drafted 2026-11-13.** Ideas only. Nothing here is committed or scheduled; move an item into
`PLAN.md` when it is chosen. None of it is gym or leisure management.

## Features (reuse what exists)

| # | Idea | Built on | Notes |
|---|---|---|---|
| F1 | Licence-gated access | Pulsar Rostering qualification expiry + PAC access | Expired ticket blocks the relevant door; warn the manager first. Recommended first |
| F2 | Contractor and visitor kiosk | PAC visitor passes | Tablet sign-in, induction acknowledgement, time-boxed pass |
| F3 | Alarm tied to the roster | PAC alarm areas, first-person-in unlock | First rostered in disarms, last out arms, alert if left unarmed |
| F4 | Lone-worker check-in in the app | PAC lone-worker timers and duress alerts | Clinics, after-hours staff |
| F5 | Staff asset register | Hub people | Laptop, keys, card, uniform per person; drives the offboarding list |
| F6 | Plain-English reports and weekly digest | Hub events | "Who was on site after 10pm last week?" |

## New platforms (separate products that join through the hub)

Each would use the hub's sign-in, organisations, people and sites, and appear as a module in the
app. Take on at most one at a time.

**Shortlisted by the owner 2026-11-13: P1, P2 (built on Gorelo) and P4.** P3 is not shortlisted.

| # | Platform | What it is | Why it fits | Watch out for |
|---|---|---|---|---|
| P1 | Monitoring ("Sense") | Sensors with logging and alerts: fridge and cold-room temperature, server room, water leak, power loss, door left open | Own hardware plus recurring revenue; clinics, pharmacies and food businesses must keep temperature logs; sells without rostering or access | Needs a board and enclosure; sensor accuracy claims; established data-logger vendors |
| P2 | Client IT portal (on Gorelo) | The managed IT service as a product: staff onboarding requests, device list, security score, tickets, approvals, with Gorelo as the system behind it | Productises the core business; gives every MSP client a reason to sign in to the hub | Sits on top of the PSA and Microsoft tooling; do not rebuild a helpdesk |
| P3 | Unstaffed paid entry | Book and pay online, receive a code, door opens: self-storage, co-working day passes, studio and room hire | PAC already enforces an external system's decision at the door | Close to the leisure boundary; keep to storage, co-working and room hire. Payments mean refunds and disputes |
| P4 | Vehicle and gate access | Number-plate cameras and gate relays for depots, car parks, storage yards | Extends PAC to a second kind of entrance | Camera hardware and installation are resold and installed by others |

## Wider horizons (unvetted)

**New things to sense**

| # | Idea | What it is | Link to the shortlist |
|---|---|---|---|
| W1 | On-device vision | People counting, tailgating, after-hours presence, queue length, processed on the device so no video leaves the site | Same cameras and AI-accelerated boards as P4; a module of P1 |
| W2 | Energy and plant | Power metering, lights and air conditioning that follow occupancy and the roster, equipment run-hours | Extends P1 from alerting to control |
| W3 | Long-range sensors (LoRaWAN) | Tank level, pumps, gates, cool rooms across a large or rural property | Extends P1 beyond one building |

**New places to sell**

| # | Idea | What it is | Watch out for |
|---|---|---|---|
| W4 | Construction and temporary sites | Portable 4G access and attendance kit, hired by the month; entry gated on induction and licence (F1) | Large incumbents; needs rugged hardware |
| W5 | Strata and apartments | Entry, lifts, visitor codes, parcel lockers for small blocks | Different buyer (strata managers); residents are not staff |
| W6 | Schools and childcare premises | Staff and contractor sign-in, working-with-children check at the door, lockdown | Sell the building layer only, not student or child management |

**New ways to sell**

| # | Idea | What it is | Watch out for |
|---|---|---|---|
| W7 | Partner tier | Other MSPs and licensed installers resell the hub under their own client list | Needs a second level of tenancy; support load |
| W8 | Hardware for other vendors | Controllers and sensors sold to software companies, as with PerfectGym | Certification; one-customer dependence |
| W9 | Public API and webhooks | Clients and third parties connect their own systems | An API is a promise to keep |

**IT-side products (extend P2)**

| # | Idea | What it is | Watch out for |
|---|---|---|---|
| W10 | Essential Eight and cyber-insurance pack | Monthly evidence pack from Gorelo and Microsoft data plus physical access records | Never claim certification; evidence only |
| W11 | Staff-identity Wi-Fi | Per-person Wi-Fi keys issued from the staff record; visitor pass includes guest Wi-Fi; offboarding removes both | Depends on the network vendor's API |
| W12 | Private AI appliance | An on-site box that answers questions over the client's own documents without sending them to the cloud | Hardware cost; support; accuracy expectations |
| W13 | AI front desk | Answers the phone and the door intercom, knows who is rostered, takes messages, issues visitor passes | Crowded market; call quality |

## Resell or integrate, do not build

- Cameras and video, payroll and award interpretation, HR (reviews, recruitment), safety
  inspections and inductions software, room and desk booking.
