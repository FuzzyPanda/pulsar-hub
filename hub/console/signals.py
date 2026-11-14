"""Signing out of the hub ends the console sessions that were opened from that sign-in."""

from django.contrib.auth.signals import user_logged_out
from django.dispatch import receiver


@receiver(user_logged_out)
def _end_console_sessions(request, user, **kwargs):
    # Django sends this before it flushes the session, so the key is still the one the console
    # sessions were bound to.
    from hub.console import services

    session = getattr(request, "session", None)
    key = getattr(session, "session_key", None)
    if key:
        services.end_for_browser(key, request=request)
