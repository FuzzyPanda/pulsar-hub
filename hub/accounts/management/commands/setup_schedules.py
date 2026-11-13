from django.core.management.base import BaseCommand
from django_q.models import Schedule

# Housekeeping the worker runs. Idempotent: the entrypoint calls this on every start.
SCHEDULES = [
    # (name, management command, what it removes)
    ("clear-expired-sessions", "clearsessions", "browser sessions past their lifetime"),
    ("clear-expired-oauth-tokens", "cleartokens", "OAuth codes and tokens past their lifetime"),
]


class Command(BaseCommand):
    help = "Create or update the worker's daily housekeeping schedules."

    def handle(self, *args, **options):
        for name, command, _what in SCHEDULES:
            Schedule.objects.update_or_create(
                name=name,
                defaults={
                    "func": "django.core.management.call_command",
                    "args": repr(command),
                    "schedule_type": Schedule.DAILY,
                },
            )
        Schedule.objects.filter(name__startswith="clear-").exclude(name__in=[s[0] for s in SCHEDULES]).delete()
        self.stdout.write(f"{len(SCHEDULES)} schedules in place.")
