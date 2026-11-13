"""The current organisation.

Organisation isolation is a security boundary (CLAUDE.md rule 1). Every query for a business row
is filtered by the organisation held here, and a query made while nothing is held here fails
instead of returning every organisation's rows.

The value is set in exactly three places:

* `OrganisationMiddleware`, for a console request under `/org/<slug>/`, after it has checked
  that the signed-in user is a member;
* `hub.api.authentication`, for an API request, from the organisation the token is bound to;
* `organisation_context(...)`, explicitly, in jobs, commands, services and tests.
"""

from collections.abc import Iterator
from contextlib import contextmanager
from contextvars import ContextVar, Token
from typing import TYPE_CHECKING

from hub.logging import org_ref_var

if TYPE_CHECKING:
    from hub.organisations.models import Organisation


class NoOrganisationContext(RuntimeError):
    """A business row was read or written while no organisation was current."""


class CrossOrganisationAccess(RuntimeError):
    """A write tried to touch, or point at, a row of an organisation other than the current one."""


_current: ContextVar["Organisation | None"] = ContextVar("hub_current_organisation", default=None)


def current_organisation() -> "Organisation | None":
    return _current.get()


def require_organisation() -> "Organisation":
    organisation = _current.get()
    if organisation is None:
        raise NoOrganisationContext(
            "No organisation is current. Business rows can only be reached inside a request that has "
            "resolved an organisation, or inside `organisation_context(...)`."
        )
    return organisation


def set_current_organisation(organisation: "Organisation | None") -> tuple[Token, Token]:
    """Low-level setter for middleware. Pair every call with `reset_current_organisation`."""
    return _current.set(organisation), org_ref_var.set(str(organisation.pk) if organisation else "")


def reset_current_organisation(tokens: tuple[Token, Token]) -> None:
    _current.reset(tokens[0])
    org_ref_var.reset(tokens[1])


@contextmanager
def organisation_context(organisation: "Organisation") -> Iterator["Organisation"]:
    """Make `organisation` current for the duration of the block."""
    if organisation is None:
        raise NoOrganisationContext("organisation_context() needs an organisation.")
    tokens = set_current_organisation(organisation)
    try:
        yield organisation
    finally:
        reset_current_organisation(tokens)
