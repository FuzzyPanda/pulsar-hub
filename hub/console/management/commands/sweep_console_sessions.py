from django.core.management.base import BaseCommand

from hub.console import services


class Command(BaseCommand):
    help = (
        "End every remote console session that should no longer be running (time limit reached, person removed, "
        "gateway revoked, hub sign-in over) and record it. The relay's heartbeat does the same every few seconds; "
        "the worker runs this each minute so that it still happens while the relay is down."
    )

    def handle(self, *args, **options):
        self.stdout.write(f"{services.sweep()} sessions ended.")
