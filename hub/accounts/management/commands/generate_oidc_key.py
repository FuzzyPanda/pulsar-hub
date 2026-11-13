from django.core.management.base import BaseCommand

from hub.accounts.oidc_keys import generate_rsa_private_key_pem


class Command(BaseCommand):
    help = "Print a new RSA private key for OIDC_RSA_PRIVATE_KEY. Store it as a secret; never commit it."

    def handle(self, *args, **options):
        self.stdout.write(generate_rsa_private_key_pem())
