"""Phase H0: the empty service behaves like a service."""

import io
import json
import logging
import subprocess
import sys
from pathlib import Path

import pytest
from django.core.management import call_command

from hub.accounts.models import User
from hub.logging import JsonFormatter, RequestContextFilter
from hub.organisations.models import Invitation, Organisation
from tests import factories as f

ROOT = Path(__file__).resolve().parent.parent


def test_liveness_needs_nothing(client, settings):
    settings.ALLOWED_HOSTS = ["hub.example"]  # the container health check calls localhost
    response = client.get("/healthz", HTTP_HOST="localhost:8000")
    assert response.status_code == 200 and response.json() == {"status": "ok"}


@pytest.mark.django_db
def test_readiness_checks_the_database(client):
    assert client.get("/readyz").json() == {"status": "ok"}


@pytest.mark.django_db
def test_every_response_carries_a_request_id(client):
    generated = client.get("/accounts/login/")["X-Request-ID"]
    assert len(generated) == 32
    assert client.get("/accounts/login/", HTTP_X_REQUEST_ID="trace-abc-12345")["X-Request-ID"] == "trace-abc-12345"
    # Something that is not a plausible id is replaced, not echoed into logs.
    assert client.get("/accounts/login/", HTTP_X_REQUEST_ID="<script>")["X-Request-ID"] != "<script>"


def test_logs_are_json_lines_with_context():
    stream = io.StringIO()
    handler = logging.StreamHandler(stream)
    handler.setFormatter(JsonFormatter("%(asctime)s %(levelname)s %(name)s %(message)s"))
    handler.addFilter(RequestContextFilter())
    logger = logging.getLogger("hub.test_platform")
    logger.addHandler(handler)
    try:
        logger.warning("door %s", "left open", extra={"site": "north"})
    finally:
        logger.removeHandler(handler)
    line = json.loads(stream.getvalue())
    assert line["message"] == "door left open" and line["level"] == "WARNING" and line["logger"] == "hub.test_platform"
    assert line["site"] == "north" and line["request_id"] == "-" and line["time"].endswith("Z")


def _settings_import(env: dict) -> subprocess.CompletedProcess:
    base = {"PATH": "/usr/bin:/bin", "DATABASE_URL": "postgres://u:p@localhost/x", "HOME": "/nonexistent"}
    return subprocess.run(  # noqa: S603
        [sys.executable, "-c", "import os; os.chdir('/'); import hub.settings as s; print(s.DEBUG)"],
        env=base | env | {"PYTHONPATH": str(ROOT)},
        capture_output=True,
        text=True,
        cwd="/",
    )


@pytest.mark.skipif((ROOT / ".env").exists(), reason="a developer .env would supply the missing values")
def test_settings_refuse_to_start_without_secrets():
    assert "DJANGO_SECRET_KEY" in _settings_import({}).stderr
    assert "OIDC_RSA_PRIVATE_KEY" in _settings_import({"DJANGO_SECRET_KEY": "x"}).stderr
    assert _settings_import({"DJANGO_SECRET_KEY": "x", "DJANGO_DEBUG": "True"}).stdout.strip() == "True"


def test_env_example_lists_every_setting():
    import re

    names = set(re.findall(r"env(?:\.\w+)?\(\s*\"([A-Z0-9_]+)\"", (ROOT / "hub" / "settings.py").read_text()))
    documented = set(re.findall(r"^#?\s*([A-Z0-9_]+)=", (ROOT / ".env.example").read_text(), flags=re.M))
    assert names and not (names - documented), f"add to .env.example: {sorted(names - documented)}"


def test_no_secret_looking_values_in_env_example():
    for line in (ROOT / ".env.example").read_text().splitlines():
        assert "BEGIN" not in line or "PRIVATE KEY" not in line or "..." in line or "change" in line.lower(), line


@pytest.mark.django_db
def test_generate_oidc_key_command():
    out = io.StringIO()
    call_command("generate_oidc_key", stdout=out)
    assert out.getvalue().startswith("-----BEGIN PRIVATE KEY-----")


@pytest.mark.django_db
def test_create_operator_and_provision_commands(monkeypatch):
    monkeypatch.setattr("getpass.getpass", lambda prompt="": f.PASSWORD)
    call_command("create_operator", "Ops@Pulsar.Test", name="Ops", stdout=io.StringIO())
    operator = User.objects.get(email="ops@pulsar.test")
    assert operator.is_platform_operator and not operator.is_staff and operator.check_password(f.PASSWORD)

    out = io.StringIO()
    call_command(
        "provision_organisation", "Harbour Dental", "owner@harbour.test", operator="ops@pulsar.test", stdout=out
    )
    organisation = Organisation.objects.get(slug="harbour-dental")
    assert str(organisation.pk) in out.getvalue()
    assert Invitation.all_organisations.filter(organisation=organisation, email="owner@harbour.test").exists()


@pytest.mark.django_db
def test_sign_in_buttons_only_for_configured_providers(client, world_a, settings):
    """An organisation may list a directory before Pulsar has registered with that provider.
    That shows as a message, never as an error page."""
    from django.urls import reverse

    Organisation.objects.filter(pk=world_a.organisation.pk).update(sso_required=True)
    f.sign_in(client, world_a.staff)
    url = reverse("org_home", kwargs={"org_slug": world_a.organisation.slug})
    assert b"microsoft/login" in client.get(url).content
    settings.SOCIALACCOUNT_PROVIDERS = {}
    response = client.get(url)
    assert response.status_code == 403 and b"microsoft/login" not in response.content
