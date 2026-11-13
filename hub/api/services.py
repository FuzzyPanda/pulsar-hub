"""Service tokens."""

from django.core.exceptions import PermissionDenied, ValidationError
from django.db import transaction
from django.utils import timezone

from hub.api.models import Scope, ServiceToken, new_service_token
from hub.organisations.models import Role, hash_token
from hub.organisations.services import Actor, _audit


@transaction.atomic
def create_service_token(*, actor: Actor, name: str, scopes: list[str], request=None) -> tuple[ServiceToken, str]:
    """Returns the row and the token. The token is shown once and stored only as a digest."""
    if not actor.is_member_with(Role.OWNER):
        raise PermissionDenied("Only an Owner can connect another system.")
    name = (name or "").strip()
    if not name:
        raise ValidationError("Give the token a name that says what uses it.")
    scopes = sorted(set(scopes))
    if not scopes or any(scope not in Scope.values for scope in scopes):
        raise ValidationError("Choose what the token may do.")
    token = new_service_token()
    row = ServiceToken.objects.create(
        name=name[:100], token_hash=hash_token(token), scopes=scopes, created_by=actor.user
    )
    _audit(actor, "service_token.created", request=request, target=row, target_label=row.name, data={"scopes": scopes})
    return row, token


@transaction.atomic
def revoke_service_token(row: ServiceToken, *, actor: Actor, request=None) -> None:
    if not actor.is_member_with(Role.OWNER):
        raise PermissionDenied("Only an Owner can disconnect another system.")
    if row.revoked_at is None:
        row.revoked_at = timezone.now()
        row.save(update_fields=["revoked_at"])
        _audit(actor, "service_token.revoked", request=request, target=row, target_label=row.name)


def find_service_token(token: str) -> ServiceToken | None:
    if not token or not token.startswith("hubsvc_"):
        return None
    row = (
        ServiceToken.all_organisations.filter(  # unscoped: looked up by its secret value
            token_hash=hash_token(token), revoked_at__isnull=True
        )
        .select_related("organisation")
        .first()
    )
    if row is None or not row.organisation.is_active:
        return None
    return row
