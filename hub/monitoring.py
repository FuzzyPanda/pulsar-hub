"""The error monitoring hook. Called from settings only when SENTRY_DSN is set."""

import sentry_sdk


def _scrub(event, hint):
    """Drop request bodies, cookies and auth headers before an event leaves the process."""
    request = event.get("request") or {}
    request.pop("data", None)
    request.pop("cookies", None)
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
