from django.apps import AppConfig


class ConsoleConfig(AppConfig):
    name = "hub.console"
    label = "console"
    verbose_name = "Remote console"

    def ready(self):
        from hub.console import signals  # noqa: F401
