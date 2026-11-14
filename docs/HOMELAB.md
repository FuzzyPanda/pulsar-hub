# Running it on a homelab

How to stand the hub up on a machine at home or in a lab, pair a Pulsar Access Control gateway
with it, and connect Pulsar Rostering. This is for testing. For a real client, use
`docker-compose.prod.yml`, a public domain and HTTPS.

Everything below assumes one machine for the hub (called `hubhost` here; use its LAN address), a
gateway on the same network or your mesh VPN, and Rostering wherever you run it. The gateway and
Rostering both call the hub; the hub calls neither, so only the hub needs to be reachable.

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
"Read door and attendance events". Tick "Read people and sites" as well if Rostering should show
whether each site's gateway is in contact and check that the hub holds what it sent; without it
those two things are skipped and the rest works. It is shown once, and its permissions cannot be
changed afterwards: make a new token to add one.

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
- **Connect Pulsar Access Control.** It has no address of its own. As an Admin, open the site's
  page and, under **Gateway → Door controller console**, enter the gateway's own address (for
  example `https://192.168.1.50/ui/`). The site page then has **Open door controller console**,
  and the Access Control tile lists the site. The console opens from the site's network and asks
  for the gateway's own sign-in.

Both can also be done from a shell: `docker compose exec web python manage.py connect_app --help`.

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
- Passkeys and sign-in with Microsoft or Google need HTTPS and a real address.
