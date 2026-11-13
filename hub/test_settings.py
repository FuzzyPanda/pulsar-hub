"""Test overlay. Supplies the environment a test run needs, then loads the real settings."""

import os

os.environ.setdefault("DJANGO_SECRET_KEY", "test-only-not-a-secret")
os.environ.setdefault("DATABASE_URL", "postgres://hub:hub-dev-only@127.0.0.1:5432/hub")
os.environ.setdefault("HUB_BASE_URL", "https://hub.test")
os.environ.setdefault("DJANGO_ALLOWED_HOSTS", "hub.test,testserver,localhost")
os.environ.setdefault("MICROSOFT_CLIENT_ID", "test-microsoft-client")
os.environ.setdefault("MICROSOFT_CLIENT_SECRET", "test-microsoft-secret")
os.environ.setdefault("GOOGLE_CLIENT_ID", "test-google-client")
os.environ.setdefault("GOOGLE_CLIENT_SECRET", "test-google-secret")
os.environ["DJANGO_DEBUG"] = "False"

from hub.accounts.oidc_keys import generate_rsa_private_key_pem  # noqa: E402

os.environ.setdefault("OIDC_RSA_PRIVATE_KEY", generate_rsa_private_key_pem())

from hub.settings import *  # noqa: E402

PASSWORD_HASHERS = ["django.contrib.auth.hashers.MD5PasswordHasher"]
EMAIL_BACKEND = "django.core.mail.backends.locmem.EmailBackend"
CACHES = {"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}}
STORAGES["staticfiles"] = {"BACKEND": "django.contrib.staticfiles.storage.StaticFilesStorage"}
Q_CLUSTER = {**Q_CLUSTER, "sync": True}
OAUTH2_PROVIDER["OIDC_RSA_PRIVATE_KEY"] = os.environ["OIDC_RSA_PRIVATE_KEY"]
MIDDLEWARE = [m for m in MIDDLEWARE if "whitenoise" not in m]
