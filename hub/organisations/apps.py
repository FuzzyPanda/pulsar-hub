from django.apps import AppConfig


class OrganisationsConfig(AppConfig):
    name = "hub.organisations"
    label = "organisations"

    def ready(self):
        from hub.organisations import checks  # noqa: F401
