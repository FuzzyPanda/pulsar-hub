"""The error monitoring hook. Called from settings only when SENTRY_DSN is set."""

from urllib.parse import urlsplit, urlunsplit

import sentry_sdk

from hub.middleware import redact_path


def _scrub(event, hint):
    """Drop request bodies, cookies, query strings, auth headers and secret-bearing paths before an
    event leaves the process."""
    request = event.get("request") or {}
    request.pop("data", None)
    request.pop("cookies", None)
    request.pop("query_string", None)
    if request.get("url"):
        parts = urlsplit(request["url"])
        request["url"] = urlunsplit((parts.scheme, parts.netloc, redact_path(parts.path), "", ""))
    headers = request.get("headers") or {}
    for name in list(headers):
        if name.lower() in {"authorization", "cookie", "x-csrftoken", "x-hub-signature"}:
            headers[name] = "[removed]"
    return event


def init_error_monitoring(*, dsn: str, environment: str, release: str = "") -> None:
    sentry_sdk.init(
        dsn=dsn,
        environment=environment,
        release=release or None,
        send_default_pii=False,
        traces_sample_rate=0.0,
        before_send=_scrub,
    )
