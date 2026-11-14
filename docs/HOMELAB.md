# Running it on a homelab

How to stand the hub up on a machine at home or in a lab, pair a Pulsar Access Control gateway
with it, and connect Pulsar Rostering. This is for testing. For a real client, use
`docker-compose.prod.yml`, a public domain and HTTPS.

Everything below assumes one machine for the hub (called `hubhost` here; use its LAN address), a
gateway on the same network or your mesh VPN, and Rostering wherever you run it. The gateway and
Rostering both call the hub; the hub calls neither, so only the hub needs to be reachable. That
includes the remote console (step 6): it runs down a connection the gateway opens.

## 1. The hub

```bash
git clone https://github.com/FuzzyPanda/pulsar-hub && cd pulsar-hub
cp .env.example .env
```

Edit `.env`. The values that matter for a plain-HTTP lab:

| Variable | Value |
|---|---|
| `POSTGRES_PASSWORD`, `POSTGRES_APP_PASSWORD` | two different values from `openssl rand -hex 24` |
| `DJANGO_SECRET_KEY` | `python3 -c "import secrets; print(secrets.token_urlsafe(50))"` |
| `DJANGO_ALLOWED_HOSTS` | `hubhost` (the name or address you will type in the browser) |
| `HUB_BASE_URL` | `http://hubhost` |
| `CSRF_TRUSTED_ORIGINS` | `http://hubhost` |
| `INSECURE_COOKIES` | `True` (plain HTTP only; never on the internet) |
| `EMAIL_BACKEND` | `django.core.mail.backends.console.EmailBackend` (invitation links appear in the web log) |
| `OIDC_RSA_PRIVATE_KEY` | see below |

```bash
docker compose build
docker compose run --rm --entrypoint python web -m hub.accounts.oidc_keys
```

Put the key in `.env` on one line, in single quotes, with `\n` between its lines, as the comment
in `.env.example` shows. Then:

```bash
docker compose up -d
docker compose exec web python manage.py create_operator you@example.com
```

Open `http://hubhost/operator/`, sign in, set up two-step sign-in with an authenticator app
(passkeys need HTTPS, so they are not available in this set-up), and create an organisation. The
owner's invitation link is in `docker compose logs web`. Open it, create the owner's login, set up
two-step sign-in, and you are in the organisation's console.

## 2. Decide where people and sites come from

In the organisation's **Settings → People and sites**:

- **Pulsar Hub** if you are testing access control alone. Add sites and people in the hub.
- **Pulsar Rostering** if you are testing the two together. Leave the hub's lists empty; they
  fill from Rostering (step 4). This can only be chosen while the hub has no people or sites.

## 3. Pair the gateway

On the hub: **Sites →** the site **→ Create a pairing code**. It is shown once and lasts 15 minutes.

On the gateway (see `docs/hub-link-design.md` in `Pulsar-Access-Control`):

1. Because this lab hub is plain HTTP, set `HUB_LINK_ALLOW_INSECURE_HTTP=true` in the gateway's
   `.env` and restart `integration-sync` and `django-web`. Without it the gateway refuses anything
   but `https://`, which is what you want everywhere else.
2. **Setup → Pulsar Hub**: enter `http://hubhost` and the code, and confirm.

Within a few seconds the page shows the organisation and site it paired to, and the hub's site
page shows the gateway in contact.

Then, in the hub, make an **access group**, add people, and tick the site. On the gateway's Pulsar
Hub page the group appears with "grants nothing at this site" until you **map it to one or more
access levels**. People from the hub then appear under People with a Pulsar Hub badge; enrol a
card on one as usual. The hub's site page turns from "waiting for the gateway" to confirmed.

To see attendance, give a door on the gateway the attendance role "clock in" (and another "clock
out"), and badge. The event appears on the hub's **Events** page within a poll (about a minute).

## 4. Connect Pulsar Rostering

On the hub: **Settings → Connected systems → create a token** with "Send people and sites" and
"Read door and attendance events". It is shown once.

In Rostering (`backend/applications/access/README.md` there has the detail):

1. Run its migrations, and give the organisation the access application:
   `manage.py set_entitlements --org <slug> --applications rostering,attendance,access`.
2. Because this lab hub is plain HTTP, set `HUB_LINK_ALLOW_INSECURE_HTTP=true`.
3. Have its scheduler and worker running (`manage.py run_scheduler`, `manage.py run_worker`): the
   link is a job that runs once a minute.
4. As an owner or admin, open the **Access** page and fill in the Pulsar Hub panel: the hub
   address `http://hubhost` and the token. Or `PUT /api/v1/orgs/<slug>/access/hub-link`.

Rostering then sends its people and sites about once a minute, and reads attendance events back.
Its people and sites appear in the hub with Rostering's own references, so pair the gateway
(step 3) to the site **as Rostering sent it**, and put Rostering's people in the access group.
A badge at a clock-in door is recorded in Rostering as a presence event for that person, marked as
coming from the hub. It does not create a timesheet entry.

## 5. Open the products from the hub

The organisation's overview page starts with **Apps**. As an Owner, in **Settings → Apps**:

- **Connect Pulsar Rostering** and enter where it runs. On a bench where Rostering is on the same
  machine as the hub, on port 8080, enter `http://{host}:8080`: `{host}` becomes whichever name
  you opened the hub with, so the link works by LAN address and by mesh VPN name alike.
- **Connect Pulsar Access Control.** It has no address to enter. Its tile then lists each site
  with a paired gateway and says where that gateway's remote console stands (step 6).

Both can also be done from a shell: `docker compose exec web python manage.py connect_app --help`.

## 6. The remote console

A gateway's own web console, opened through the hub. Add to `.env` and start again
(`docker compose up -d`):

| Variable | Value on a plain-HTTP bench |
|---|---|
| `CONSOLE_ORIGIN_TEMPLATE` | `http://{host}:8081` (every console on one extra port of the hub's own host; accepted only because `INSECURE_COOKIES` is `True`) |
| `RELAY_INTERNAL_SECRET` | `openssl rand -hex 32` |

The site's page and the Access Control tile now show **Remote console** with one of: available,
switched off on the gateway, gateway not connected, gateway software too old. A gateway whose
software has no remote console (every released gateway, as of 2026-11-14) shows "too old".

To see it work without one, run the fake gateway that the hub's tests use. Create a pairing code
for a site with no gateway, then, on any machine that can reach the hub and has Python and aiohttp:

```bash
python tools/fake_gateway.py --hub http://hubhost --pair XXXX-XXXX-XXXX
```

The site's page says **Available**. As an Owner or Admin press **Open remote console**, enter a
code from your authenticator app, and a small stand-in console opens in a new tab on port 8081.
The page lists the session, with **End**; `--console-off` starts the fake gateway with its switch
off. For someone building the gateway side, `python tools/console_conformance.py --help` plays the
hub instead and checks a gateway against the contract.

## What to check, and what "working" looks like

| Do this | Expect |
|---|---|
| End a person (in whichever product owns people) | Denied at the door within about two polls; the hub's site page says confirmed again |
| Stop the hub (`docker compose stop web`) and badge | Doors behave exactly as before. Events queue on the gateway and arrive, once, when the hub is back |
| Revoke the gateway on the hub's site page | The gateway's page says revoked. Nobody's access changes |
| Block a person on the gateway's Pulsar Hub page | Denied, whatever the hub says, until unblocked there |
| Remove a group's mapping on the gateway | Those people lose that access on the next poll; the hub's site page lists them as applied with problems |

## Limits of this set-up

- Plain HTTP on a LAN: anyone on that network can read the traffic, including the gateway's
  credential. Fine for a bench; not for anything real.
- No email is sent. Links are in the log.
- The remote console's bench mode puts every gateway's console on one origin that shares the hub's
  host name. A gateway's cookies and the hub's are still kept apart (the relay holds the
  gateway's), but the consoles share the browser's storage with each other and are "same-site"
  with the hub: cookies ignore ports, so script on a console page can set cookies the hub is
  then sent, and could read any hub cookie that script may read (none today: they are all
  `HttpOnly`). Production gives each gateway its own origin on a separate domain; do not put the
  bench mode on the internet. The hub refuses to start in bench mode if `HUB_BASE_URL` is https.
- Passkeys and sign-in with Microsoft or Google need HTTPS and a real address.
