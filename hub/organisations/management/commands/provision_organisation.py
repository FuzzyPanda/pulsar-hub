from django.core.exceptions import PermissionDenied, ValidationError
from django.core.management.base import BaseCommand, CommandError

from hub.accounts.models import User
from hub.organisations import services


class Command(BaseCommand):
    help = "Create an organisation and email its first Owner an invitation. Same as the operator console."

    def add_arguments(self, parser):
        parser.add_argument("name")
        parser.add_argument("owner_email")
        parser.add_argument("--operator", required=True, help="Email of the Pulsar operator doing this (audited).")
        parser.add_argument("--slug", default="", help="Address under /org/. Derived from the name if omitted.")

    def handle(self, *args, name, owner_email, operator, slug, **options):
        operator_user = User.objects.filter(email__iexact=operator, is_platform_operator=True, is_active=True).first()
        if operator_user is None:
            raise CommandError(f"{operator} is not an active Pulsar operator.")
        try:
            organisation, invitation, _token = services.provision_organisation(
                name=name, owner_email=owner_email, operator=operator_user, slug=slug
            )
        except (ValidationError, PermissionDenied) as exc:
            raise CommandError("; ".join(getattr(exc, "messages", [str(exc)]))) from exc
        if not invitation.email_sent:
            self.stderr.write(
                self.style.WARNING(
                    f"{organisation.name} was created, but the invitation email to {invitation.email} could not be "
                    "sent. Check the EMAIL_* settings, then send it again from the operator console."
                )
            )
            return
        self.stdout.write(
            self.style.SUCCESS(
                f"{organisation.name} created at /org/{organisation.slug}/ (org_ref {organisation.pk}). "
                f"Invitation sent to {invitation.email}; it expires {invitation.expires_at:%Y-%m-%d %H:%M} UTC."
            )
        )
