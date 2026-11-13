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
