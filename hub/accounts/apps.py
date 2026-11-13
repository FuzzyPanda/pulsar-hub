from django.apps import AppConfig


class AccountsConfig(AppConfig):
    name = "hub.accounts"
    label = "accounts"
    verbose_name = "Accounts and sign-in"

    def ready(self):
        from hub.accounts import signals  # noqa: F401
