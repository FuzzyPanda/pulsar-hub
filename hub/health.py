"""Liveness and readiness. Neither needs a login and neither reveals anything."""

from django.db import connection
from django.http import JsonResponse


def healthz(request):
    """The process is up. Used by the container health check."""
    return JsonResponse({"status": "ok"})


def readyz(request):
    """The process can reach its database. Used by the proxy and by uptime checks."""
    try:
        with connection.cursor() as cursor:  # unscoped: SELECT 1, reads no table
            cursor.execute("SELECT 1")
            cursor.fetchone()
    except Exception:
        return JsonResponse({"status": "unavailable"}, status=503)
    return JsonResponse({"status": "ok"})


class HealthCheckMiddleware:
    """Answers the two probes before anything else runs.

    It sits first in MIDDLEWARE so the container health check, which calls `localhost:8000`, does
    not depend on `localhost` being in DJANGO_ALLOWED_HOSTS. The production proxy does not forward
    these paths from the internet.
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if request.method in ("GET", "HEAD"):
            if request.path == "/healthz":
                return healthz(request)
            if request.path == "/readyz":
                return readyz(request)
        return self.get_response(request)
