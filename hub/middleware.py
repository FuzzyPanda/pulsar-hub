"""Request-wide context: a request id on every log line and response, and the access log."""

import logging
import re
import time
import uuid

from hub.logging import org_ref_var, request_id_var, user_ref_var

access_log = logging.getLogger("hub.access")

_SAFE_REQUEST_ID = re.compile(r"^[A-Za-z0-9._-]{8,64}$")

# Addresses that carry a secret in the path: whoever reads one can use it. They are redacted
# wherever an address is recorded (the access log, error reports). Query strings are never
# recorded at all: OAuth codes and state travel there.
_SECRET_PATHS = [
    re.compile(r"^(/invitations/)[^/]+(/?)"),
    re.compile(r"^(/accounts/confirm-email/)[^/]+(/?)"),
    re.compile(r"^(/accounts/password/reset/key/)[^/]+(/?)"),
]


def redact_path(path: str) -> str:
    for pattern in _SECRET_PATHS:
        path, replaced = pattern.subn(r"\1[redacted]\2", path, count=1)
        if replaced:
            break
    return path


class RequestContextMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        supplied = request.headers.get("X-Request-ID", "")
        request_id = supplied if _SAFE_REQUEST_ID.match(supplied) else uuid.uuid4().hex
        request.request_id = request_id
        tokens = (request_id_var.set(request_id), user_ref_var.set(""), org_ref_var.set(""))
        started = time.monotonic()
        status = 500
        try:
            response = self.get_response(request)
            status = response.status_code
        finally:
            access_log.info(
                "%s %s %s",
                request.method,
                redact_path(request.path),
                status,
                extra={
                    "method": request.method,
                    "path": redact_path(request.path),
                    "status": status,
                    "duration_ms": round((time.monotonic() - started) * 1000),
                },
            )
            request_id_var.reset(tokens[0])
            user_ref_var.reset(tokens[1])
            org_ref_var.reset(tokens[2])
        response["X-Request-ID"] = request_id
        return response


# Scripts, styles, fonts and frames only from the hub itself; nothing inline. Images may also be
# data: URLs (the authenticator-app QR code is one). The hub's own templates and django-allauth's
# pages keep to this: page data travels in `<script type="application/json">` blocks, which are
# not executed.
CONTENT_SECURITY_POLICY = (
    "default-src 'self'; img-src 'self' data:; object-src 'none'; base-uri 'self'; frame-ancestors 'none'"
)


class ContentSecurityPolicyMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        response = self.get_response(request)
        response.headers.setdefault("Content-Security-Policy", CONTENT_SECURITY_POLICY)
        return response
