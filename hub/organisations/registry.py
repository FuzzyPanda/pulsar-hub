"""Hub models that are deliberately not organisation-scoped, each with its reason.

`hub.organisations.checks` fails the build for any hub model that is neither an
`OrganisationScopedModel` nor listed here. Adding a line is a security decision: review it as one.
"""

GLOBAL_MODELS: dict[str, str] = {
    "accounts.User": "A login is global; one person can belong to several organisations.",
    "organisations.Organisation": "The organisation itself.",
    "audit.AuditEvent": (
        "Carries an optional organisation: account-level events (sign-in, MFA change) have none. "
        "Its default manager is organisation-scoped; platform-wide reads use `all_organisations`."
    ),
    "accounts.Application": "An OAuth client (the Pulsar app, TIM2). Platform-level; created by Pulsar staff.",
    "accounts.IDToken": "Record of an issued ID token; holds no claims. Reached only through its access token.",
    "accounts.Grant": "OAuth authorisation code. Bound to an organisation; looked up by code before one is known.",
    "accounts.AccessToken": "OAuth token. Bound to an organisation; looked up by token before one is known.",
    "accounts.RefreshToken": "OAuth token. Bound to an organisation; looked up by token before one is known.",
}
