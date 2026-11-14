"""Settings for Pulsar Hub.

Every value that differs between environments, and every secret, comes from the environment
(CLAUDE.md rule 6). `.env.example` lists each variable with a placeholder; add to it whenever a
variable is added here.
"""

from pathlib import Path

import environ
from django.core.exceptions import ImproperlyConfigured

BASE_DIR = Path(__file__).resolve().parent.parent

env = environ.Env(
    DJANGO_DEBUG=(bool, False),
)
# A local `.env` is a developer convenience only. Containers get their environment from Compose.
if (BASE_DIR / ".env").exists():
    environ.Env.read_env(BASE_DIR / ".env")

SECRET_KEY = env("DJANGO_SECRET_KEY")
DEBUG = env("DJANGO_DEBUG")
ALLOWED_HOSTS = env.list("DJANGO_ALLOWED_HOSTS", default=["localhost", "127.0.0.1"])

# The public address of the hub, without a trailing slash. It is the OIDC issuer and the base of
# every link sent by email, so it must be the address clients actually use.
HUB_BASE_URL = env("HUB_BASE_URL", default="http://localhost:8000").rstrip("/")
PRODUCT_NAME = env("PRODUCT_NAME", default="Pulsar Hub")  # working name, decision D1

# --- Applications -------------------------------------------------------------------------------

INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "django.contrib.humanize",
    "django.contrib.postgres",
    # Third party
    "rest_framework",
    "django_htmx",
    "django_q",
    "allauth",
    "allauth.account",
    "allauth.mfa",
    "allauth.usersessions",
    "allauth.socialaccount",
    "allauth.socialaccount.providers.google",
    "hub.accounts.entra",  # Microsoft Entra, with the tenant id (replaces allauth's microsoft provider)
    "oauth2_provider",
    # Hub
    "hub.accounts",
    "hub.organisations",
    "hub.audit",
    "hub.directory",
    "hub.gateways",
    "hub.access",
    "hub.api",
    "hub.products",
]

MIDDLEWARE = [
    "hub.health.HealthCheckMiddleware",
    "django.middleware.security.SecurityMiddleware",
    "whitenoise.middleware.WhiteNoiseMiddleware",
    "hub.middleware.RequestContextMiddleware",
    "hub.middleware.ContentSecurityPolicyMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "allauth.usersessions.middleware.UserSessionsMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
    "django_htmx.middleware.HtmxMiddleware",
    "allauth.account.middleware.AccountMiddleware",
    "hub.accounts.middleware.AccountPolicyMiddleware",
    "hub.organisations.middleware.OrganisationMiddleware",
]

ROOT_URLCONF = "hub.urls"
WSGI_APPLICATION = "hub.wsgi.application"
ASGI_APPLICATION = "hub.asgi.application"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [BASE_DIR / "hub" / "templates"],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
                "hub.context_processors.hub",
            ],
        },
    },
]

# --- Database and cache -------------------------------------------------------------------------

# The running service connects as a role with only the rights it needs (DATABASE_URL). Migrations
# and `grant_app_role` need the owning role: the entrypoint runs those with HUB_DATABASE_AS_OWNER=1,
# which selects DATABASE_OWNER_URL, and the web and worker processes never see that URL. Where no
# owner URL is set (development, CI) one role does both.
_AS_OWNER = env.bool("HUB_DATABASE_AS_OWNER", default=False) and bool(env("DATABASE_OWNER_URL", default=""))
DATABASES = {"default": env.db("DATABASE_OWNER_URL" if _AS_OWNER else "DATABASE_URL")}
DATABASES["default"]["CONN_MAX_AGE"] = env.int("DATABASE_CONN_MAX_AGE", default=60)
DATABASES["default"]["CONN_HEALTH_CHECKS"] = True
DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

# Rate limits and login throttles need a cache shared by every web process. The database cache
# keeps the stack free of Redis, like the job broker. `createcachetable` runs in the entrypoint.
CACHES = {
    "default": {
        "BACKEND": "django.core.cache.backends.db.DatabaseCache",
        "LOCATION": "hub_cache",
    }
}

# --- Time ---------------------------------------------------------------------------------------

# Rule 8: UTC in storage and on the wire. Templates convert for display only.
USE_TZ = True
TIME_ZONE = "UTC"
LANGUAGE_CODE = "en-au"
USE_I18N = True

# --- Static files -------------------------------------------------------------------------------

STATIC_URL = "static/"
STATIC_ROOT = BASE_DIR / "staticfiles"
STATICFILES_DIRS = [BASE_DIR / "hub" / "static"]
STORAGES = {
    "default": {"BACKEND": "django.core.files.storage.FileSystemStorage"},
    "staticfiles": {"BACKEND": "whitenoise.storage.CompressedManifestStaticFilesStorage"},
}

# --- Proxy and transport security ---------------------------------------------------------------

# Caddy terminates TLS and is the only thing that can reach the web container.
SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https")
NUM_PROXIES = env.int("NUM_PROXIES", default=1)
CSRF_TRUSTED_ORIGINS = env.list("CSRF_TRUSTED_ORIGINS", default=[])
INSECURE_COOKIES = env.bool("INSECURE_COOKIES", default=DEBUG)  # plain-HTTP local development only
SESSION_COOKIE_SECURE = not INSECURE_COOKIES
CSRF_COOKIE_SECURE = not INSECURE_COOKIES
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = "Lax"
CSRF_COOKIE_SAMESITE = "Lax"
SECURE_CONTENT_TYPE_NOSNIFF = True
SECURE_REFERRER_POLICY = "same-origin"
X_FRAME_OPTIONS = "DENY"
if not INSECURE_COOKIES:
    SECURE_HSTS_SECONDS = env.int("SECURE_HSTS_SECONDS", default=31536000)
    SECURE_HSTS_INCLUDE_SUBDOMAINS = True

# --- Sessions -----------------------------------------------------------------------------------

# Database sessions, so a session can be listed and revoked (allauth.usersessions).
SESSION_ENGINE = "django.contrib.sessions.backends.db"
# An absolute lifetime, not a sliding one. It bounds how long a login survives after the account
# is disabled in the client's own directory (Microsoft Entra or Google).
SESSION_COOKIE_AGE = env.int("SESSION_MAX_AGE_HOURS", default=12) * 3600
SESSION_SAVE_EVERY_REQUEST = False

# --- Accounts (django-allauth) ------------------------------------------------------------------

AUTH_USER_MODEL = "accounts.User"
AUTHENTICATION_BACKENDS = ["allauth.account.auth_backends.AuthenticationBackend"]
LOGIN_URL = "account_login"
LOGIN_REDIRECT_URL = "home"

AUTH_PASSWORD_VALIDATORS = [
    {"NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator"},
    {"NAME": "django.contrib.auth.password_validation.MinimumLengthValidator", "OPTIONS": {"min_length": 12}},
    {"NAME": "django.contrib.auth.password_validation.CommonPasswordValidator"},
    {"NAME": "django.contrib.auth.password_validation.NumericPasswordValidator"},
]
PASSWORD_HASHERS = [
    "django.contrib.auth.hashers.Argon2PasswordHasher",
    "django.contrib.auth.hashers.PBKDF2PasswordHasher",
]

ACCOUNT_ADAPTER = "hub.accounts.adapters.AccountAdapter"
ACCOUNT_USER_MODEL_USERNAME_FIELD = None
ACCOUNT_LOGIN_METHODS = {"email"}
ACCOUNT_SIGNUP_FIELDS = ["email*", "password1*", "password2*"]
ACCOUNT_SIGNUP_FORM_CLASS = "hub.accounts.forms.SignupForm"
ACCOUNT_EMAIL_VERIFICATION = "mandatory"
ACCOUNT_UNIQUE_EMAIL = True
ACCOUNT_MAX_EMAIL_ADDRESSES = 2  # the current address plus one being changed to (allauth requires 2)
ACCOUNT_CHANGE_EMAIL = True
ACCOUNT_PREVENT_ENUMERATION = True
ACCOUNT_EMAIL_UNKNOWN_ACCOUNTS = False
ACCOUNT_LOGIN_ON_EMAIL_CONFIRMATION = False
ACCOUNT_LOGIN_ON_PASSWORD_RESET = False
ACCOUNT_LOGOUT_ON_PASSWORD_CHANGE = True
ACCOUNT_SESSION_REMEMBER = False  # sessions end at SESSION_COOKIE_AGE; no "remember me"
ACCOUNT_EMAIL_NOTIFICATIONS = True  # tell the user when a password, email or MFA setting changes
ACCOUNT_REAUTHENTICATION_REQUIRED = True
ACCOUNT_REAUTHENTICATION_TIMEOUT = 300
ACCOUNT_EMAIL_SUBJECT_PREFIX = f"[{PRODUCT_NAME}] "
ACCOUNT_DEFAULT_HTTP_PROTOCOL = "http" if INSECURE_COOKIES else "https"
# allauth's defaults already limit failed logins (5 per 5 minutes per account, 10 a minute per IP),
# password resets, signups and email confirmation. Tightened or added here where the hub differs.
ACCOUNT_RATE_LIMITS = {
    "login_failed": "10/m/ip,5/300s/key",
    "reauthenticate": "10/m/user",
}
ALLAUTH_TRUSTED_PROXY_COUNT = NUM_PROXIES

MFA_ADAPTER = "hub.accounts.adapters.MFAAdapter"
MFA_SUPPORTED_TYPES = ["totp", "webauthn", "recovery_codes"]
MFA_PASSKEY_LOGIN_ENABLED = True
MFA_TOTP_ISSUER = PRODUCT_NAME
MFA_RECOVERY_CODE_COUNT = 10
MFA_RECOVERY_CODES_SHOW_ONCE = True
MFA_WEBAUTHN_ALLOW_INSECURE_ORIGIN = INSECURE_COOKIES
# A step-up (see hub.accounts.stepup) is "fresh" for this long.
MFA_STEP_UP_MAX_AGE = env.int("MFA_STEP_UP_MAX_AGE_SECONDS", default=300)

USERSESSIONS_TRACK_ACTIVITY = True

# Sign in with Microsoft Entra and Google. Pulsar registers one multi-tenant application with
# each; which tenant or Workspace domain may sign in to which organisation is per-organisation
# data (hub.organisations.models.IdentityProvider), so no client secret is ever stored in a row.
SOCIALACCOUNT_ADAPTER = "hub.accounts.adapters.SocialAccountAdapter"
SOCIALACCOUNT_AUTO_SIGNUP = True
SOCIALACCOUNT_EMAIL_AUTHENTICATION = False  # never match a social login to a local user by email alone
SOCIALACCOUNT_LOGIN_ON_GET = False
SOCIALACCOUNT_STORE_TOKENS = False
SOCIALACCOUNT_PROVIDERS = {}
if env("MICROSOFT_CLIENT_ID", default=""):
    SOCIALACCOUNT_PROVIDERS["microsoft"] = {
        "APPS": [
            {
                "client_id": env("MICROSOFT_CLIENT_ID"),
                "secret": env("MICROSOFT_CLIENT_SECRET"),
                "settings": {"tenant": "organizations"},  # work and school accounts only
            }
        ],
    }
if env("GOOGLE_CLIENT_ID", default=""):
    SOCIALACCOUNT_PROVIDERS["google"] = {
        "APPS": [{"client_id": env("GOOGLE_CLIENT_ID"), "secret": env("GOOGLE_CLIENT_SECRET")}],
        "SCOPE": ["openid", "email", "profile"],
    }

# For an organisation that requires single sign-on: how long after the user last came through its
# directory a refresh token is still honoured. Bounds how long the app keeps working after the
# account is disabled there.
SSO_REFRESH_MAX_AGE_HOURS = env.int("SSO_REFRESH_MAX_AGE_HOURS", default=24)
# However often a refresh token is used, the app must send the user through sign-in again this
# long after they last signed in.
OIDC_SESSION_MAX_DAYS = env.int("OIDC_SESSION_MAX_DAYS", default=90)
# Gateways (Pulsar Access Control). A pairing code is typed on site within minutes of being made.
PAIRING_CODE_MINUTES = env.int("PAIRING_CODE_MINUTES", default=15)
# A gateway polls about once a minute. After this long without a call it is shown as out of contact.
GATEWAY_OUT_OF_CONTACT_SECONDS = env.int("GATEWAY_OUT_OF_CONTACT_SECONDS", default=300)
INVITATION_EXPIRY_DAYS = env.int("INVITATION_EXPIRY_DAYS", default=7)
# How long a Pulsar operator may hold access to an organisation before it must be granted again.
OPERATOR_ACCESS_MAX_HOURS = env.int("OPERATOR_ACCESS_MAX_HOURS", default=8)

# --- The hub as OIDC provider (django-oauth-toolkit) --------------------------------------------

OIDC_RSA_PRIVATE_KEY = env.str("OIDC_RSA_PRIVATE_KEY", default="", multiline=True)
if not OIDC_RSA_PRIVATE_KEY:
    if not DEBUG:
        raise ImproperlyConfigured(
            "OIDC_RSA_PRIVATE_KEY is not set. Generate one with `python -m hub.accounts.oidc_keys`."
        )
    # Development only: a key that lasts until the process exits, so every token dies with it.
    from hub.accounts.oidc_keys import generate_rsa_private_key_pem

    OIDC_RSA_PRIVATE_KEY = generate_rsa_private_key_pem()

OAUTH2_PROVIDER_APPLICATION_MODEL = "accounts.Application"
OAUTH2_PROVIDER_ID_TOKEN_MODEL = "accounts.IDToken"
OAUTH2_PROVIDER_ACCESS_TOKEN_MODEL = "accounts.AccessToken"
OAUTH2_PROVIDER_REFRESH_TOKEN_MODEL = "accounts.RefreshToken"
OAUTH2_PROVIDER_GRANT_MODEL = "accounts.Grant"
OAUTH2_PROVIDER = {
    "OIDC_ENABLED": True,
    "OIDC_ISS_ENDPOINT": f"{HUB_BASE_URL}/oauth",
    "OIDC_RSA_PRIVATE_KEY": OIDC_RSA_PRIVATE_KEY,
    "OIDC_RSA_PRIVATE_KEYS_INACTIVE": [
        k for k in env.str("OIDC_RSA_PRIVATE_KEYS_INACTIVE", default="", multiline=True).split("\n\n") if k.strip()
    ],
    "OAUTH2_VALIDATOR_CLASS": "hub.accounts.oidc.HubOAuth2Validator",
    "PKCE_REQUIRED": True,
    "SCOPES": {
        "openid": "Confirm who you are",
        "profile": "Your name",
        "email": "Your email address",
        "offline_access": "Stay signed in on this device",
    },
    "DEFAULT_SCOPES": ["openid"],
    "ALLOWED_REDIRECT_URI_SCHEMES": env.list("OIDC_ALLOWED_REDIRECT_URI_SCHEMES", default=["https"]),
    "ALLOWED_GRANT_TYPES": ["authorization_code", "refresh_token"],
    "AUTHORIZATION_CODE_EXPIRE_SECONDS": 60,
    "ACCESS_TOKEN_EXPIRE_SECONDS": env.int("OIDC_ACCESS_TOKEN_SECONDS", default=600),
    "ID_TOKEN_EXPIRE_SECONDS": env.int("OIDC_ACCESS_TOKEN_SECONDS", default=600),
    "REFRESH_TOKEN_EXPIRE_SECONDS": env.int("OIDC_REFRESH_TOKEN_DAYS", default=30) * 86400,
    "ROTATE_REFRESH_TOKEN": True,
    "REFRESH_TOKEN_REUSE_PROTECTION": True,
    "REFRESH_TOKEN_GRACE_PERIOD_SECONDS": 0,
    "OIDC_RESPONSE_TYPES_SUPPORTED": ["code"],
    # RFC 9700 (OAuth 2.0 Security Best Current Practice). The toolkit keeps these off by default
    # until its 4.0 release so that upgrades do not change behaviour; a new service has nothing to
    # keep compatible with. Tokens are stored as digests, are never accepted in a query string,
    # and an insecure configuration fails `check --deploy`.
    "COMPLIANT_BCP_RFC9700_IMPLICIT_GRANT": True,
    "COMPLIANT_BCP_RFC9700_PASSWORD_GRANT": True,
    "COMPLIANT_BCP_RFC9700_PKCE_METHOD": True,
    "COMPLIANT_BCP_RFC9700_ACCESS_TOKEN_TRANSPORT": True,
    "COMPLIANT_BCP_RFC9700_AUTHZ_RESPONSE_ISS": True,
    "COMPLIANT_BCP_RFC9700_TOKEN_STORAGE": True,
    "COMPLIANT_BCP_RFC9700_REFRESH_TOKEN": True,
    "COMPLIANT_BCP_RFC9700_REDIRECT_URI_SCHEME": True,
    "COMPLIANT_BCP_RFC9700_REDIRECT_URI_MATCHING": True,
    "COMPLIANT_BCP_RFC9700_PKCE_REQUIRED": True,
    "OIDC_RP_INITIATED_LOGOUT_ENABLED": True,
    "OIDC_RP_INITIATED_LOGOUT_ALWAYS_PROMPT": True,
}

# --- API (Django REST Framework) ----------------------------------------------------------------

REST_FRAMEWORK = {
    # Authenticated and organisation-scoped unless a view says otherwise.
    "DEFAULT_AUTHENTICATION_CLASSES": ["hub.api.authentication.OrganisationTokenAuthentication"],
    "DEFAULT_PERMISSION_CLASSES": ["hub.api.permissions.IsOrganisationMember"],
    "DEFAULT_RENDERER_CLASSES": ["rest_framework.renderers.JSONRenderer"],
    "DEFAULT_PARSER_CLASSES": ["rest_framework.parsers.JSONParser"],
    "DEFAULT_THROTTLE_CLASSES": [
        "rest_framework.throttling.AnonRateThrottle",
        "rest_framework.throttling.UserRateThrottle",
    ],
    "DEFAULT_THROTTLE_RATES": {
        "anon": env("API_THROTTLE_ANON", default="30/min"),
        "user": env("API_THROTTLE_USER", default="600/min"),
        # Guessing a pairing code: twelve characters from a 31-letter alphabet, valid 15 minutes.
        "gateway_pair": env("API_THROTTLE_GATEWAY_PAIR", default="10/min"),
    },
    "NUM_PROXIES": NUM_PROXIES,
    "EXCEPTION_HANDLER": "hub.api.exceptions.exception_handler",
    "UNAUTHENTICATED_USER": None,
}

# --- Background jobs (django-q2, Postgres broker) -----------------------------------------------

Q_CLUSTER = {
    "name": "hub",
    "orm": "default",
    "workers": env.int("Q_CLUSTER_WORKERS", default=2),
    "timeout": env.int("Q_CLUSTER_TIMEOUT", default=60),
    "retry": env.int("Q_CLUSTER_RETRY", default=120),
    "max_attempts": 5,
    "catch_up": False,
    "ack_failures": True,
}

# --- Email --------------------------------------------------------------------------------------

EMAIL_BACKEND = env("EMAIL_BACKEND", default="django.core.mail.backends.console.EmailBackend")
EMAIL_HOST = env("EMAIL_HOST", default="localhost")
EMAIL_PORT = env.int("EMAIL_PORT", default=587)
EMAIL_HOST_USER = env("EMAIL_HOST_USER", default="")
EMAIL_HOST_PASSWORD = env("EMAIL_HOST_PASSWORD", default="")
EMAIL_USE_TLS = env.bool("EMAIL_USE_TLS", default=True)
DEFAULT_FROM_EMAIL = env("DEFAULT_FROM_EMAIL", default="hub@localhost")
SERVER_EMAIL = DEFAULT_FROM_EMAIL

# --- Logging and error monitoring ---------------------------------------------------------------

LOG_LEVEL = env("LOG_LEVEL", default="info").upper()
LOG_FORMAT = env("LOG_FORMAT", default="text" if DEBUG else "json")

LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "filters": {"request_context": {"()": "hub.logging.RequestContextFilter"}},
    "formatters": {
        "json": {
            "()": "hub.logging.JsonFormatter",
            "format": "%(asctime)s %(levelname)s %(name)s %(message)s",
        },
        "text": {"format": "%(asctime)s %(levelname)-7s %(name)s [%(request_id)s] %(message)s"},
    },
    "handlers": {
        "console": {
            "class": "logging.StreamHandler",
            "formatter": "json" if LOG_FORMAT == "json" else "text",
            "filters": ["request_context"],
        },
    },
    "root": {"handlers": ["console"], "level": LOG_LEVEL},
    "loggers": {
        "django": {"handlers": ["console"], "level": "INFO", "propagate": False},
        # Django's own "Not Found: <path>" lines would print secret-bearing paths in full; the hub's
        # access log (hub.access) records every request with those redacted. Errors still show.
        "django.request": {"handlers": ["console"], "level": "ERROR", "propagate": False},
        "hub": {"handlers": ["console"], "level": LOG_LEVEL, "propagate": False},
    },
}

# The error monitoring hook. Nothing is sent anywhere unless SENTRY_DSN is set.
SENTRY_DSN = env("SENTRY_DSN", default="")
if SENTRY_DSN:
    from hub.monitoring import init_error_monitoring

    init_error_monitoring(
        dsn=SENTRY_DSN,
        environment=env("SENTRY_ENVIRONMENT", default="production"),
        release=env("HUB_RELEASE", default=""),
    )
