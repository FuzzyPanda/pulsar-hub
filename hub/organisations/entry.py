"""The one decision about whether a signed-in session may enter an organisation.

The console middleware and the OIDC authorisation screen both ask here, so a token can never be
obtained on easier terms than the console.
"""

from dataclasses import dataclass
from enum import Enum

from hub.accounts.mfa import has_mfa, mfa_satisfied, session_sso_identity
from hub.organisations.models import Membership, OperatorAccess, Organisation
from hub.organisations.services import identity_providers_for, resolve_access


class Entry(Enum):
    OK = "ok"
    NOT_FOUND = "not_found"  # no such organisation, or no place in it: indistinguishable on purpose
    SUSPENDED = "suspended"
    SSO_REQUIRED = "sso_required"
    MFA_ENROL = "mfa_enrol"  # the role needs MFA and the user has no second factor yet
    MFA_CHALLENGE = "mfa_challenge"  # the user has a second factor but this session has not used it


@dataclass
class EntryDecision:
    outcome: Entry
    organisation: Organisation | None = None
    membership: Membership | None = None
    operator_access: OperatorAccess | None = None

    @property
    def ok(self) -> bool:
        return self.outcome is Entry.OK


def sso_satisfied(request, organisation: Organisation) -> bool:
    identity = session_sso_identity(request)
    if identity is None:
        return False
    return identity in {(idp.provider, idp.tenant) for idp in identity_providers_for(organisation)}


def evaluate_entry(request, organisation: Organisation | None, *, allow_operator: bool = True) -> EntryDecision:
    if organisation is None or organisation.status == Organisation.Status.DELETING:
        return EntryDecision(Entry.NOT_FOUND)
    membership, operator_access = resolve_access(request.user, organisation)
    if not allow_operator:
        operator_access = None
    if membership is None and operator_access is None:
        return EntryDecision(Entry.NOT_FOUND)
    decision = EntryDecision(Entry.OK, organisation, membership, operator_access)

    if membership is not None:
        if not organisation.is_active:
            decision.outcome = Entry.SUSPENDED
            return decision
        if organisation.sso_required and not sso_satisfied(request, organisation):
            decision.outcome = Entry.SSO_REQUIRED
            return decision
        needs_mfa = membership.mfa_required
    else:
        needs_mfa = True  # a Pulsar operator, always

    if needs_mfa and not mfa_satisfied(request):
        decision.outcome = Entry.MFA_CHALLENGE if has_mfa(request.user) else Entry.MFA_ENROL
    return decision
