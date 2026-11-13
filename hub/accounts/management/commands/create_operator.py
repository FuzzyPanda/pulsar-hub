import getpass

from allauth.account.models import EmailAddress
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError
from django.core.management.base import BaseCommand, CommandError
from django.db import transaction

from hub.accounts.models import User
from hub.audit import services as audit
from hub.audit.models import AuditEvent


class Command(BaseCommand):
    help = (
        "Create a Pulsar operator login (the first one, or another). The operator must set up "
        "two-step sign-in before the operator console opens, and still needs a time-limited "
        "visit to enter any organisation."
    )

    def add_arguments(self, parser):
        parser.add_argument("email")
        parser.add_argument("--name", default="")
        parser.add_argument(
            "--staff", action="store_true", help="Also allow the Django admin (logins and OAuth applications)."
        )
        parser.add_argument(
            "--no-password",
            action="store_true",
            help="Create the login without a password; the operator sets one with 'Forgot password'.",
        )

    @transaction.atomic
    def handle(self, *args, email, name, staff, no_password, **options):
        email = email.strip().lower()
        if User.objects.filter(email__iexact=email).exists():
            raise CommandError(f"A login already exists for {email}.")
        password = None
        if not no_password:
            password = getpass.getpass("Password: ")
            if password != getpass.getpass("Password (again): "):
                raise CommandError("The passwords do not match.")
            try:
                validate_password(password, User(email=email, name=name))
            except ValidationError as exc:
                raise CommandError(" ".join(exc.messages)) from exc
        user = User.objects.create_user(
            email=email, password=password, name=name, is_platform_operator=True, is_staff=staff, is_superuser=staff
        )
        EmailAddress.objects.create(user=user, email=email, verified=True, primary=True)
        audit.record(
            "operator.created",
            actor=None,
            actor_kind=AuditEvent.ActorKind.SYSTEM,
            organisation=None,
            target=user,
            target_label=email,
            data={"staff": staff, "via": "create_operator command"},
        )
        self.stdout.write(self.style.SUCCESS(f"Operator {email} created."))
