"""Request-wide context: a request id on every log line and response."""

import re
import uuid

from hub.logging import org_ref_var, request_id_var, user_ref_var

_SAFE_REQUEST_ID = re.compile(r"^[A-Za-z0-9._-]{8,64}$")


class RequestContextMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        supplied = request.headers.get("X-Request-ID", "")
        request_id = supplied if _SAFE_REQUEST_ID.match(supplied) else uuid.uuid4().hex
        request.request_id = request_id
        tokens = (request_id_var.set(request_id), user_ref_var.set(""), org_ref_var.set(""))
        try:
            response = self.get_response(request)
        finally:
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
