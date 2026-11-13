"""RSA key generation for the OIDC provider. Imported by settings, so it must not import Django."""

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa


def generate_rsa_private_key_pem() -> str:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()


if __name__ == "__main__":
    # `python -m hub.accounts.oidc_keys` works before any setting exists, which matters because the
    # settings refuse to load without this very key.
    import sys

    sys.stdout.write(generate_rsa_private_key_pem())
