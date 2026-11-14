"""The product launcher: the catalogue, connected apps, gateway console addresses, and the
recovery codes page that used to leave a new user with nowhere to go."""

import re

import pytest
from allauth.mfa.models import Authenticator
from allauth.mfa.recovery_codes.internal.auth import RecoveryCodes
from django.core.exceptions import PermissionDenied, ValidationError
from django.urls import reverse

from hub.audit.models import AuditEvent
from hub.gateways import services as gateway_services
from hub.gateways.models import Gateway
from hub.organisations.context import organisation_context
from hub.organisations.models import Role
from hub.organisations.services import Actor
from hub.products import catalogue, services
from hub.products.addresses import browser_host, clean_base_address, clean_launch_path, launch_url, resolve_address
from hub.products.models import ConnectedApp
from tests import factories as f

pytestmark = pytest.mark.django_db


def actor(world, role):
    return Actor(world.user(role), world.memberships[role])


def audit_events(world, action):
    return list(AuditEvent.all_organisations.filter(organisation=world.organisation, action=action))


def page(client, name, world, **kwargs):
    response = client.get(reverse(name, kwargs={"org_slug": world.organisation.slug, **kwargs}))
    assert response.status_code == 200, response.status_code
    return response.content.decode()


# --- the catalogue --------------------------------------------------------------------------------


def test_catalogue_lists_rostering_and_access_control():
    keys = [product.key for product in catalogue.CATALOGUE]
    assert keys == ["rostering", "access_control"]
    rostering = catalogue.get_product("rostering")
    assert rostering.kind == catalogue.ADDRESS and rostering.minimum_role == Role.STAFF
    assert rostering.launch_path == "/api/v1/auth/hub/start?org={org_slug}"
    assert catalogue.get_product("access_control").kind == catalogue.SITES
    assert catalogue.get_product("nothing") is None


def test_every_catalogue_entry_is_well_formed():
    for product in catalogue.CATALOGUE:
        assert re.fullmatch(r"[a-z][a-z0-9_]{1,31}", product.key)
        assert product.name and product.summary
        assert product.kind in (catalogue.ADDRESS, catalogue.SITES)
        assert clean_launch_path(product.launch_path) == product.launch_path
        assert catalogue.icon_paths(product.icon)
    assert catalogue.icon_paths("no-such-icon") == catalogue.ICONS["app"]


# --- addresses ------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "typed, stored",
    [
        ("http://{host}:8080", "http://{host}:8080"),
        ("http://{host}:8080/", "http://{host}:8080"),
        ("  https://rostering.example.com  ", "https://rostering.example.com"),
        ("https://rostering.example.com/", "https://rostering.example.com"),
        ("https://apps.example.com/rostering", "https://apps.example.com/rostering"),
        ("https://192.168.1.211/ui/", "https://192.168.1.211/ui/"),
        ("http://[::1]:8080", "http://[::1]:8080"),
    ],
)
def test_base_addresses_that_are_accepted(typed, stored):
    assert clean_base_address(typed) == stored


@pytest.mark.parametrize(
    "typed",
    [
        "",
        "rostering.example.com",
        "ftp://rostering.example.com",
        "javascript:alert(1)",
        "//rostering.example.com",
        "https://",
        "https://user:secret@rostering.example.com",
        "https://user@rostering.example.com",
        "https://rostering.example.com?next=1",
        "https://rostering.example.com/?",
        "https://rostering.example.com/#top",
        "https://rostering example.com",
        "https://rostering.example.com/a b",
        "https://rostering.example.com\\@evil.example",
        "https://rostering.example.com:99999",
        "https://rostering.example.com:port",
        "https://rostеring.example.com",  # a Cyrillic letter that looks like a Latin one
        "https://rostering.example.com/‮",  # an invisible direction mark
        "http://{host}.example.com",
        "http://rostering.{host}",
        "http://rostering.example.com/{host}",
        "http://{host}:8080/{host}",
        "http://{org_slug}.example.com",
        "https://" + "a" * 300 + ".example.com",
    ],
)
def test_base_addresses_that_are_refused(typed):
    with pytest.raises(ValidationError):
        clean_base_address(typed)


def test_a_gateway_console_address_cannot_use_the_host_placeholder():
    with pytest.raises(ValidationError):
        clean_base_address("https://{host}/ui/", allow_host_placeholder=False)
    assert clean_base_address("https://192.168.1.211/ui/", allow_host_placeholder=False) == "https://192.168.1.211/ui/"


@pytest.mark.parametrize("typed", ["", "/", "/login", "/api/v1/auth/hub/start?org={org_slug}"])
def test_launch_paths_that_are_accepted(typed):
    assert clean_launch_path(typed) == typed


@pytest.mark.parametrize(
    "typed", ["login", "//evil.example/x", "https://evil.example/", "/a b", "/x#y", "/{host}", "/x\\y", "/" + "a" * 300]
)
def test_launch_paths_that_are_refused(typed):
    with pytest.raises(ValidationError):
        clean_launch_path(typed)


def test_launch_url_fills_in_the_host_and_the_organisation():
    path = "/api/v1/auth/hub/start?org={org_slug}"
    assert (
        launch_url("http://{host}:8080", path, host="192.168.1.143", org_slug="gym")
        == "http://192.168.1.143:8080/api/v1/auth/hub/start?org=gym"
    )
    assert (
        launch_url("http://{host}:8080", path, host="pulsar-hub.example.ts.net", org_slug="security")
        == "http://pulsar-hub.example.ts.net:8080/api/v1/auth/hub/start?org=security"
    )
    assert launch_url("https://apps.example.com/rostering/", "/login", host="x", org_slug="gym") == (
        "https://apps.example.com/rostering/login"
    )
    assert launch_url("https://rostering.example.com", "", host="x", org_slug="gym") == "https://rostering.example.com/"
    assert (
        launch_url("https://rostering.example.com", "/", host="x", org_slug="gym") == "https://rostering.example.com/"
    )
    # Nothing is offered as a link unless it is a safe one.
    assert launch_url("javascript:alert(1)", "/", host="x", org_slug="gym") == ""
    assert launch_url("http://{host}:8080", "/", host="", org_slug="gym") == ""
    assert launch_url("https://rostering.example.com", "//evil.example", host="x", org_slug="gym") == ""
    assert resolve_address("", host="x") == ""


def test_browser_host_is_the_name_the_browser_used_without_its_port(rf):
    assert browser_host(rf.get("/", HTTP_HOST="hub.test:8443")) == "hub.test"
    assert browser_host(rf.get("/", HTTP_HOST="hub.test")) == "hub.test"


# --- connecting, changing and disconnecting -------------------------------------------------------


def test_an_owner_connects_changes_and_disconnects_an_app(world_a):
    owner = actor(world_a, "owner")
    with organisation_context(world_a.organisation):
        app = services.connect_app(actor=owner, product_key="access_control", base_address="ignored")
        # A product that lives at each site keeps no address of its own.
        assert (app.product_key, app.base_address, app.launch_path, app.enabled) == ("access_control", "", "", True)
        assert app.connected_by == world_a.owner and app.connected_at is not None
        assert app.organisation_id == world_a.organisation.pk

        rostering = world_a.connected_app
        services.update_app(rostering, actor=owner, base_address="http://{host}:8080/", launch_path="/", enabled=False)
        rostering.refresh_from_db()
        assert (rostering.base_address, rostering.launch_path, rostering.enabled) == ("http://{host}:8080", "/", False)
        # Saving the same values again is not a change.
        services.update_app(rostering, actor=owner, base_address="http://{host}:8080", launch_path="/", enabled=False)

        services.disconnect_app(rostering, actor=owner)
        assert not ConnectedApp.objects.filter(product_key="rostering").exists()

    assert [e.data["product"] for e in audit_events(world_a, "app.connected")] == ["access_control"]
    (updated,) = audit_events(world_a, "app.updated")
    assert updated.data["base_address"]["to"] == "http://{host}:8080" and updated.data["enabled"] == {
        "from": True,
        "to": False,
    }
    (gone,) = audit_events(world_a, "app.disconnected")
    assert gone.data["product"] == "rostering" and gone.actor == world_a.owner


@pytest.mark.parametrize("role", ["admin", "manager", "staff"])
def test_only_an_owner_connects_changes_or_disconnects(world_a, role):
    with organisation_context(world_a.organisation):
        with pytest.raises(PermissionDenied):
            services.connect_app(actor=actor(world_a, role), product_key="access_control")
        with pytest.raises(PermissionDenied):
            services.update_app(
                world_a.connected_app, actor=actor(world_a, role), base_address="https://x.example.test"
            )
        with pytest.raises(PermissionDenied):
            services.disconnect_app(world_a.connected_app, actor=actor(world_a, role))
        assert ConnectedApp.objects.count() == 1
    assert not audit_events(world_a, "app.connected") and not audit_events(world_a, "app.disconnected")


def test_a_visiting_operator_cannot_connect_an_app(world_a):
    visiting = Actor(world_a.operator_access.operator, None, world_a.operator_access)
    with organisation_context(world_a.organisation):
        with pytest.raises(PermissionDenied):
            services.connect_app(actor=visiting, product_key="access_control")
        with pytest.raises(PermissionDenied):
            gateway_services.set_console_address(world_a.gateway, actor=visiting, address="https://x.example.test")


def test_connecting_refuses_bad_input(world_a):
    owner = actor(world_a, "owner")
    with organisation_context(world_a.organisation):
        with pytest.raises(ValidationError):
            services.connect_app(actor=owner, product_key="payroll", base_address="https://x.example.test")
        with pytest.raises(ValidationError):  # already connected in this organisation
            services.connect_app(actor=owner, product_key="rostering", base_address="https://x.example.test")
        services.disconnect_app(world_a.connected_app, actor=owner)
        for bad in ("", "rostering.example.test", "javascript:alert(1)", "https://u:p@x.example.test"):
            with pytest.raises(ValidationError):
                services.connect_app(actor=owner, product_key="rostering", base_address=bad)
        with pytest.raises(ValidationError):
            services.connect_app(
                actor=owner, product_key="rostering", base_address="https://x.example.test", launch_path="//evil"
            )
        assert not ConnectedApp.objects.exists()


def test_each_organisation_connects_the_same_product_separately(world_a, world_b):
    with organisation_context(world_a.organisation):
        a = ConnectedApp.objects.get()
    with organisation_context(world_b.organisation):
        b = ConnectedApp.objects.get()
    assert a.product_key == b.product_key == "rostering" and a.base_address != b.base_address


# --- the gateway's console address ----------------------------------------------------------------


def test_an_admin_sets_and_clears_a_gateway_console_address(world_a):
    admin = actor(world_a, "admin")
    with organisation_context(world_a.organisation):
        gateway = world_a.gateway
        gateway_services.set_console_address(gateway, actor=admin, address=" https://192.168.1.211/ui/ ")
        assert Gateway.objects.get(pk=gateway.pk).console_address == "https://192.168.1.211/ui/"
        for bad in ("https://{host}/ui/", "192.168.1.211", "ftp://192.168.1.211", "https://a:b@192.168.1.211/"):
            with pytest.raises(ValidationError):
                gateway_services.set_console_address(gateway, actor=admin, address=bad)
        with pytest.raises(PermissionDenied):
            gateway_services.set_console_address(gateway, actor=actor(world_a, "manager"), address="")
        gateway_services.set_console_address(gateway, actor=admin, address="")
        assert Gateway.objects.get(pk=gateway.pk).console_address == ""
        gateway_services.revoke_gateway(gateway, actor=admin)
        with pytest.raises(ValidationError):
            gateway_services.set_console_address(gateway, actor=admin, address="https://192.168.1.211/ui/")
    changes = [(e.data["from"], e.data["to"]) for e in audit_events(world_a, "gateway.console_address_changed")]
    assert sorted(changes) == sorted(
        [
            ("https://zzamarkerzz-gateway.example.test/ui/", "https://192.168.1.211/ui/"),
            ("https://192.168.1.211/ui/", ""),
        ]
    )


def test_a_console_address_is_not_part_of_what_a_gateway_is_sent(world_a):
    """It is a link for people. It must never change the access state a gateway pulls (rule 5)."""
    from hub.access.services import desired_access

    with organisation_context(world_a.organisation):
        before = desired_access(world_a.site)
        gateway_services.set_console_address(
            world_a.gateway, actor=actor(world_a, "admin"), address="https://10.0.0.9/ui/"
        )
        assert desired_access(world_a.site) == before
        assert "console" not in str(before)


# --- the launcher on the overview page ------------------------------------------------------------

ROSTERING_LINK = 'href="https://rostering.zzamarkerzz.example.test/api/v1/auth/hub/start?org=world-a"'
CONSOLE_LINK = 'href="https://zzamarkerzz-gateway.example.test/ui/"'


def test_staff_see_the_apps_they_may_use_and_nothing_else(client, world_a):
    f.sign_in(client, world_a.staff)
    body = page(client, "org_home", world_a)
    assert body.index('id="apps-heading"') < body.index("Active members of this organisation")  # the first thing
    assert "Pulsar Rostering" in body and ROSTERING_LINK in body
    assert 'target="_blank" rel="noopener noreferrer"' in body
    assert "Pulsar Access Control" not in body and "Not connected" not in body and "Manage apps" not in body


def test_an_owner_also_sees_what_is_not_connected(client, world_a):
    f.sign_in(client, world_a.owner, mfa=True)
    body = page(client, "org_home", world_a)
    assert ROSTERING_LINK in body
    assert "Pulsar Access Control" in body and "Not connected" in body and "Manage apps" in body
    assert CONSOLE_LINK not in body  # not connected, so no link, whatever the gateway holds
    for role in ("admin", "manager"):
        f.sign_in(client, world_a.user(role), mfa=True)
        body = page(client, "org_home", world_a)
        assert ROSTERING_LINK in body and "Pulsar Access Control" not in body and "Not connected" not in body


def test_access_control_lists_each_site_with_a_console_or_says_what_to_do(client, world_a):
    with organisation_context(world_a.organisation):
        services.connect_app(actor=actor(world_a, "owner"), product_key="access_control")
    f.sign_in(client, world_a.manager, mfa=True)
    body = page(client, "org_home", world_a)
    assert "Pulsar Access Control" in body and CONSOLE_LINK in body and f"{world_a.marker} Clinic" in body
    # Staff do not get the tile, or the site names in it.
    f.sign_in(client, world_a.staff)
    assert "Pulsar Access Control" not in page(client, "org_home", world_a)

    with organisation_context(world_a.organisation):
        gateway_services.set_console_address(world_a.gateway, actor=actor(world_a, "admin"), address="")
    f.sign_in(client, world_a.manager, mfa=True)
    body = page(client, "org_home", world_a)
    assert "Pulsar Access Control" in body and "No site has a door controller console address yet" in body
    assert "Needs setting up" in body and "-gateway.example.test" not in body
    assert reverse("site_list", kwargs={"org_slug": world_a.organisation.slug}) in body


def test_a_revoked_gateways_console_is_not_offered(client, world_a):
    with organisation_context(world_a.organisation):
        services.connect_app(actor=actor(world_a, "owner"), product_key="access_control")
        gateway_services.revoke_gateway(world_a.gateway, actor=actor(world_a, "admin"))
    f.sign_in(client, world_a.manager, mfa=True)
    assert CONSOLE_LINK not in page(client, "org_home", world_a)


def test_the_host_placeholder_follows_the_name_the_browser_used(client, world_a):
    with organisation_context(world_a.organisation):
        services.update_app(world_a.connected_app, actor=actor(world_a, "owner"), base_address="http://{host}:8080")
    f.sign_in(client, world_a.staff)
    url = reverse("org_home", kwargs={"org_slug": world_a.organisation.slug})
    by_name = client.get(url, HTTP_HOST="hub.test").content.decode()
    assert 'href="http://hub.test:8080/api/v1/auth/hub/start?org=world-a"' in by_name
    by_other_name = client.get(url, HTTP_HOST="localhost:8000").content.decode()
    assert 'href="http://localhost:8080/api/v1/auth/hub/start?org=world-a"' in by_other_name
    # A host name the hub does not answer to never reaches a link.
    assert client.get(url, HTTP_HOST="evil.example").status_code == 400


def test_a_launch_path_override_replaces_the_default(client, world_a):
    with organisation_context(world_a.organisation):
        services.update_app(
            world_a.connected_app, actor=actor(world_a, "owner"), base_address="https://r.example.test", launch_path="/"
        )
    f.sign_in(client, world_a.staff)
    body = page(client, "org_home", world_a)
    assert 'href="https://r.example.test/"' in body and "auth/hub/start" not in body


def test_an_app_that_is_turned_off_shows_only_to_owners(client, world_a):
    with organisation_context(world_a.organisation):
        services.update_app(
            world_a.connected_app,
            actor=actor(world_a, "owner"),
            base_address=world_a.connected_app.base_address,
            enabled=False,
        )
    f.sign_in(client, world_a.staff)
    body = page(client, "org_home", world_a)
    assert "Pulsar Rostering" not in body and "No apps are connected" in body
    f.sign_in(client, world_a.owner, mfa=True)
    body = page(client, "org_home", world_a)
    assert "Pulsar Rostering" in body and "Turned off" in body and ROSTERING_LINK not in body


# --- Settings and the site page -------------------------------------------------------------------


def test_settings_lets_an_owner_manage_apps_and_shows_an_admin_what_is_connected(client, world_a):
    slug = world_a.organisation.slug
    f.sign_in(client, world_a.owner, mfa=True)
    body = page(client, "org_settings", world_a)
    assert 'id="apps"' in body and "https://rostering.zzamarkerzz.example.test" in body
    assert reverse("app_connect", kwargs={"org_slug": slug}) in body
    assert reverse("app_update", kwargs={"org_slug": slug, "app_id": world_a.connected_app.pk}) in body
    assert reverse("app_disconnect", kwargs={"org_slug": slug, "app_id": world_a.connected_app.pk}) in body
    f.sign_in(client, world_a.admin, mfa=True)
    body = page(client, "org_settings", world_a)
    assert "https://rostering.zzamarkerzz.example.test" in body and "Only an Owner can connect" in body
    assert reverse("app_connect", kwargs={"org_slug": slug}) not in body


def test_an_owner_connects_changes_and_disconnects_through_settings(client, world_a):
    slug = world_a.organisation.slug
    back = reverse("org_settings", kwargs={"org_slug": slug}) + "#apps"
    f.sign_in(client, world_a.owner, mfa=True)
    response = client.post(reverse("app_connect", kwargs={"org_slug": slug}), {"product": "access_control"})
    assert response.status_code == 302 and response["Location"] == back
    update = reverse("app_update", kwargs={"org_slug": slug, "app_id": world_a.connected_app.pk})
    # A bad address is refused with a message and changes nothing.
    assert client.post(update, {"base_address": "javascript:alert(1)", "enabled": "on"}).status_code == 302
    assert "must start with http:// or https://" in client.get(back).content.decode()
    assert client.post(update, {"base_address": "http://{host}:8080", "launch_path": "/"}).status_code == 302
    with organisation_context(world_a.organisation):
        assert {a.product_key for a in ConnectedApp.objects.all()} == {"rostering", "access_control"}
        app = ConnectedApp.objects.get(product_key="rostering")
        assert (app.base_address, app.launch_path, app.enabled) == ("http://{host}:8080", "/", False)
    disconnect = reverse("app_disconnect", kwargs={"org_slug": slug, "app_id": app.pk})
    assert client.post(disconnect).status_code == 302
    with organisation_context(world_a.organisation):
        assert not ConnectedApp.objects.filter(product_key="rostering").exists()
    # Not an Owner: refused outright.
    f.sign_in(client, world_a.admin, mfa=True)
    assert client.post(reverse("app_connect", kwargs={"org_slug": slug}), {"product": "rostering"}).status_code == 403


def test_the_site_page_opens_the_console_and_lets_an_admin_set_it(client, world_a):
    slug = world_a.organisation.slug
    site_page = {"site_id": world_a.site.pk}
    form = reverse("gateway_console_address", kwargs={"org_slug": slug, "gateway_id": world_a.gateway.pk})
    f.sign_in(client, world_a.manager, mfa=True)
    body = page(client, "site_detail", world_a, **site_page)
    assert "Open door controller console" in body and CONSOLE_LINK in body
    assert form not in body  # a Manager opens it; an Admin sets it
    assert client.post(form, {"console_address": "https://10.0.0.9/ui/"}).status_code == 403

    f.sign_in(client, world_a.admin, mfa=True)
    assert form in page(client, "site_detail", world_a, **site_page)
    assert client.post(form, {"console_address": "https://10.0.0.9/ui/"}).status_code == 302
    assert 'href="https://10.0.0.9/ui/"' in page(client, "site_detail", world_a, **site_page)
    assert client.post(form, {"console_address": "https://{host}/ui/"}).status_code == 302  # refused, with a message
    assert client.post(form, {"console_address": ""}).status_code == 302
    body = page(client, "site_detail", world_a, **site_page)
    assert "Open door controller console" not in body and "10.0.0.9" not in body
    # A site without a gateway has neither the button nor the form.
    body = page(client, "site_detail", world_a, site_id=world_a.pairing_code.site_id)
    assert "Open door controller console" not in body and "console-address" not in body


# --- the recovery codes page ----------------------------------------------------------------------

INLINE_SCRIPT = re.compile(r"<script(?![^>]*\bsrc=)(?![^>]*application/json)", re.IGNORECASE)


# Enrolling commits (allauth sends its signals on commit), so this test uses real commits.
@pytest.mark.django_db(transaction=True)
def test_a_new_user_gets_from_enrolling_to_the_organisation(client, world_a):
    """The whole path that used to strand a new user: sent to set up two-step sign-in, shown the
    recovery codes once, and then on, through "Continue", to the page first asked for."""
    from allauth.mfa.totp.internal import auth as totp
    from django.core.cache import cache

    user = world_a.manager
    client.post("/accounts/login/", {"login": user.email, "password": f.PASSWORD})
    org_home = reverse("org_home", kwargs={"org_slug": world_a.organisation.slug})
    assert client.get(org_home)["Location"] == reverse("mfa_index")
    response = client.get(reverse("mfa_activate_totp"))
    if response.status_code == 302:  # allauth wants a recent password first
        client.post(response["Location"].split("?")[0], {"password": f.PASSWORD})
        response = client.get(reverse("mfa_activate_totp"))
    secret = client.session[totp.SECRET_SESSION_KEY]
    cache.clear()
    code = totp.format_hotp_value(totp.hotp_value(secret, next(totp.yield_hotp_counters_from_time())))
    response = client.post(reverse("mfa_activate_totp"), {"code": code})
    assert response.status_code == 302 and response["Location"] == reverse("mfa_view_recovery_codes")

    response = client.get(reverse("mfa_view_recovery_codes"))
    assert response.status_code == 200
    body = response.content.decode()
    codes = RecoveryCodes(Authenticator.objects.get(user=user, type="recovery_codes")).get_unused_codes()
    assert len(codes) == 10 and all(code in body for code in codes)
    # A real form to the home page: the box is required, so it holds without JavaScript too.
    assert '<form method="get" action="/" id="codes_form">' in body
    assert '<input id="codes_saved" type="checkbox" required>' in body
    assert 'id="codes_continue" type="submit">Continue</button>' in body
    # Download carries the codes itself; allauth's own download refuses once they have been shown.
    assert 'download="recovery-codes.txt"' in body and "data:text/plain;charset=utf-8," + codes[0] in body
    assert client.get(reverse("mfa_download_recovery_codes")).status_code == 403
    # The script comes from the hub's own static files, as the Content-Security-Policy requires.
    assert 'src="/static/hub/js/recovery_codes.js"' in body and not INLINE_SCRIPT.search(body)
    assert "default-src 'self'" in response["Content-Security-Policy"]

    # "Continue" goes home, and home goes on to the page that asked for two-step sign-in.
    response = client.get("/")
    assert response.status_code == 302 and response["Location"] == org_home
    assert client.get(org_home).status_code == 200

    # Shown once: a second visit holds no codes, and still offers a way on.
    again = client.get(reverse("mfa_view_recovery_codes")).content.decode()
    assert not any(code in again for code in codes)
    assert '<a class="btn" href="/">Continue</a>' in again
    assert reverse("mfa_generate_recovery_codes") in again and reverse("mfa_index") in again


def test_the_recovery_codes_script_is_a_static_file():
    from django.contrib.staticfiles import finders

    assert finders.find("hub/js/recovery_codes.js") and finders.find("hub/js/webauthn_notice.js")
    # The stock page's own scripts are collected too; the hub's layout has the block they load in.
    assert finders.find("mfa/js/recovery_codes.js") and finders.find("account/js/onload.js")


def test_other_two_step_pages_offer_a_way_back(client, world_a):
    """The confirm pages had one button each and no way to change your mind; the security key
    page had a button that could silently do nothing."""
    user = world_a.manager
    f.sign_in(client, user, mfa=True)
    # These pages want a second-factor check made as a re-authentication, moments ago.
    session = client.session
    session["account_authentication_methods"][-1]["reauthenticated"] = True
    session.save()
    back = f'<a href="{reverse("mfa_index")}">Cancel and go back to two-step sign-in</a>'
    for name in ("mfa_deactivate_totp", "mfa_generate_recovery_codes", "mfa_add_webauthn"):
        response = client.get(reverse(name))
        assert response.status_code == 200, name
        assert back in response.content.decode(), name
    body = client.get(reverse("mfa_add_webauthn")).content.decode()
    assert 'id="webauthn_notice" role="alert" hidden' in body and "hub/js/webauthn_notice.js" in body
    assert "mfa/js/webauthn.js" in body and not INLINE_SCRIPT.search(body)


def test_remove_security_key_page_offers_a_way_back(rf, world_a):
    from types import SimpleNamespace

    from django.template.loader import render_to_string

    request = rf.get("/")
    request.user = world_a.manager
    body = render_to_string(
        "mfa/webauthn/authenticator_confirm_delete.html", {"authenticator": SimpleNamespace(pk=1)}, request=request
    )
    assert "Are you sure you want to remove this security key?" in body  # allauth's own page is still there
    assert f'<a href="{reverse("mfa_list_webauthn")}">Cancel and go back to security keys</a>' in body


# --- the same changes from a shell ----------------------------------------------------------------


def test_connect_app_command_goes_through_the_service(world_a):
    import io

    from django.core.management import CommandError, call_command

    slug, owner, admin = world_a.organisation.slug, world_a.owner.email, world_a.admin.email
    call_command("connect_app", slug, "access_control", "--as", owner, stdout=io.StringIO())
    call_command("connect_app", slug, "rostering", "http://{host}:8080", "--as", owner, stdout=io.StringIO())
    with organisation_context(world_a.organisation):
        assert ConnectedApp.objects.get(product_key="rostering").base_address == "http://{host}:8080"
        assert ConnectedApp.objects.filter(product_key="access_control", enabled=True).exists()
    for refused in (
        [slug, "rostering", "https://x.example.test", "--as", admin],  # not an Owner
        [slug, "rostering", "javascript:alert(1)", "--as", owner],
        ["no-such-org", "rostering", "https://x.example.test", "--as", owner],
        [slug, "rostering", "https://x.example.test", "--as", "nobody@example.test"],
    ):
        with pytest.raises(CommandError):
            call_command("connect_app", *refused, stdout=io.StringIO())
    call_command("connect_app", slug, "rostering", "--launch-path", "/", "--off", "--as", owner, stdout=io.StringIO())
    with organisation_context(world_a.organisation):
        app = ConnectedApp.objects.get(product_key="rostering")
        assert (app.base_address, app.launch_path, app.enabled) == ("http://{host}:8080", "/", False)
    call_command("connect_app", slug, "rostering", "--disconnect", "--as", owner, stdout=io.StringIO())
    with organisation_context(world_a.organisation):
        assert not ConnectedApp.objects.filter(product_key="rostering").exists()
    assert len(audit_events(world_a, "app.connected")) == 1 and len(audit_events(world_a, "app.disconnected")) == 1


def test_set_console_address_command_goes_through_the_service(world_a):
    import io

    from django.core.management import CommandError, call_command

    slug, admin = world_a.organisation.slug, world_a.admin.email
    call_command(
        "set_console_address", slug, world_a.site.name, "https://10.0.0.9/ui/", "--as", admin, stdout=io.StringIO()
    )
    with organisation_context(world_a.organisation):
        assert Gateway.objects.get(pk=world_a.gateway.pk).console_address == "https://10.0.0.9/ui/"
    call_command("set_console_address", slug, str(world_a.site.pk), "", "--as", admin, stdout=io.StringIO())
    with organisation_context(world_a.organisation):
        assert Gateway.objects.get(pk=world_a.gateway.pk).console_address == ""
    depot = f"{world_a.marker} Depot"  # a site with no gateway
    for refused in (
        [slug, world_a.site.name, "https://10.0.0.9/ui/", "--as", world_a.manager.email],
        [slug, world_a.site.name, "https://{host}/ui/", "--as", admin],
        [slug, depot, "https://10.0.0.9/ui/", "--as", admin],
        [slug, "No such site", "https://10.0.0.9/ui/", "--as", admin],
    ):
        with pytest.raises(CommandError):
            call_command("set_console_address", *refused, stdout=io.StringIO())
