"""Writing audit events. Call `record(...)`; never build an AuditEvent by hand."""

import logging

from hub.audit.models import AuditEvent
from hub.logging import request_id_var
from hub.organisations.context import current_organisation

logger = logging.getLogger("hub.audit")

_UNSET = object()


def client_ip(request) -> str | None:
    """The client address as seen through NUM_PROXIES trusted proxies."""
    if request is None:
        return None
    from django.conf import settings

    forwarded = [part.strip() for part in request.META.get("HTTP_X_FORWARDED_FOR", "").split(",") if part.strip()]
    proxies = settings.NUM_PROXIES
    if proxies and len(forwarded) >= proxies:
        return forwarded[-proxies]
    return request.META.get("REMOTE_ADDR") or None


def record(
    action: str,
    *,
    request=None,
    actor=_UNSET,
    actor_kind: str | None = None,
    organisation=_UNSET,
    target=None,
    target_label: str = "",
    data: dict | None = None,
    save: bool = True,
) -> AuditEvent:
    """Append one event.

    `organisation` defaults to the current one; pass `None` for an account-level or platform
    event. `actor` defaults to the request's user. `target` is any model instance; its class name
    and primary key are stored, never the object itself.
    """
    if organisation is _UNSET:
        organisation = current_organisation()
    if actor is _UNSET:
        user = getattr(request, "user", None)
        actor = user if getattr(user, "is_authenticated", False) else None
    if actor_kind is None:
        if actor is None:
            actor_kind = AuditEvent.ActorKind.SYSTEM
        elif getattr(request, "operator_access", None) is not None:
            actor_kind = AuditEvent.ActorKind.OPERATOR
        else:
            actor_kind = AuditEvent.ActorKind.USER

    ip = client_ip(request)
    event = AuditEvent(
        organisation=organisation,
        action=action,
        actor=actor,
        actor_kind=actor_kind,
        actor_label=(getattr(actor, "email", "") or "")[:254],
        target_type=type(target).__name__ if target is not None else "",
        target_ref=str(getattr(target, "pk", "") or "")[:64],
        target_label=(target_label or "")[:254],
        ip_address=ip,
        user_agent=(request.META.get("HTTP_USER_AGENT", "")[:255] if request is not None else ""),
        request_id=getattr(request, "request_id", None) or request_id_var.get("") or "",
        data=data or {},
    )
    if not save:
        return event
    event.save(force_insert=True)
    _log(event)
    return event


def _log(event: AuditEvent) -> None:
    logger.info(
        "audit %s",
        event.action,
        extra={"audit_action": event.action, "audit_id": str(event.pk), "actor_kind": event.actor_kind},
    )


def record_many(rows: list[dict], *, request=None, actor=_UNSET, actor_kind: str | None = None) -> None:
    """Append several events by one actor in one statement. Each row is the keyword arguments
    `record` takes for one event (`action`, `target`, `target_label`, `data`).

    For a change that touches many people at once (a list of people in, a list of access changes
    out): every one of them is still its own event, and writing them costs one insert, not one
    each, inside a transaction that is holding locks.
    """
    events = [record(request=request, actor=actor, actor_kind=actor_kind, save=False, **row) for row in rows]
    AuditEvent.objects.bulk_create(events, batch_size=500)
    for event in events:
        _log(event)
