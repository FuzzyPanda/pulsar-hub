# Pulsar Hub

**Status: phases H0 and H1 are built** (a running, tested service with organisations, sign-in, MFA
and sign-in for other products). H2 onward is planned, not started. Working name; the product name
is an open decision.

Pulsar Hub is the hosted service that joins a client's Pulsar products around one record, the staff
member. A client business signs in once and manages its people, sites and door access from
anywhere, across every site. It needs no server of its own.

| Product | Where it runs | How it joins |
|---|---|---|
| **Pulsar Hub** (this repo) | Hosted by Pulsar, one organisation per client | Identity, organisations, people, sites, gateways, access |
| **Pulsar Access Control** | A gateway on each client site | Pairs with the hub and dials out to it; keeps deciding locally |
| **Time Is Money 2** (rostering) | Hosted, or standalone for existing installs | Signs in through the hub; reads people and sites; receives door events |
| **Pulsar app** (`pulsar-app`) | Staff and managers' phones | One app over all of the above |
| Managed IT | Pulsar service | Joins through single sign-on with the client's Microsoft or Google identity |

A client can take access control without rostering, or rostering without access control. That is
why the hub is its own service and not a feature of either product.

## Run it

```bash
cp .env.example .env        # then fill in the values marked change-me
docker compose up --build   # web, worker, Postgres, Caddy on http://localhost
docker compose exec web python manage.py create_operator you@example.com
```

Sign in at `/operator/`, set up two-step sign-in, and create the first organisation. Day-to-day
commands for development are in [`CLAUDE.md`](CLAUDE.md).

## Read next

- [`docs/PLAN.md`](docs/PLAN.md) — phases and checklists
- [`docs/CONTRACTS.md`](docs/CONTRACTS.md) — ids, gateway pairing, calls and events
- [`docs/DECISIONS.md`](docs/DECISIONS.md) — open decisions that block work
- [`docs/CANDIDATES.md`](docs/CANDIDATES.md) — ideas not yet in the plan
- [`CLAUDE.md`](CLAUDE.md) — rules and where a coding session should start

## Not part of this

Pulsar's internal tools (MSP Dashboard, pulsar-knowledge, Pulsar Ops Core) are not client-facing
and nothing here depends on them.
