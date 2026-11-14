import uuid

from django.core.exceptions import PermissionDenied, ValidationError
from django.core.management.base import BaseCommand, CommandError

from hub.accounts.models import User
from hub.directory.models import Site
from hub.gateways import services
from hub.gateways.models import Gateway
from hub.organisations.context import organisation_context
from hub.organisations.models import Organisation
from hub.organisations.services import Actor, resolve_access


class Command(BaseCommand):
    help = (
        "Record where a site's paired gateway serves its own web console, or clear it with an empty address. "
        "Same as the site page: the person named with --as must be an Admin or Owner, and the change is audited "
        "as theirs. The hub only links to the address; it never connects to it."
    )

    def add_arguments(self, parser):
        parser.add_argument("org_slug")
        parser.add_argument("site", help="The site's name, exactly, or its site_ref.")
        parser.add_argument("address", help='Such as https://192.168.1.50/ui/. Use "" to remove the link.')
        parser.add_argument("--as", dest="as_email", required=True, help="Email of the Admin doing this (audited).")

    def handle(self, *args, org_slug, site, address, as_email, **options):
        organisation = Organisation.objects.filter(slug=org_slug).first()
        if organisation is None:
            raise CommandError(f"There is no organisation at /org/{org_slug}/.")
        user = User.objects.filter(email__iexact=as_email, is_active=True).first()
        membership = resolve_access(user, organisation)[0] if user is not None else None
        if membership is None:
            raise CommandError(f"{as_email} is not an active member of {organisation.name}.")
        with organisation_context(organisation):
            try:
                sites = Site.objects.filter(pk=uuid.UUID(site))
            except ValueError:
                sites = Site.objects.filter(name=site)
            if sites.count() != 1:
                raise CommandError(f"{organisation.name} has no single site called {site!r}.")
            gateway = Gateway.objects.live().filter(site=sites.get()).select_related("site").first()
            if gateway is None:
                raise CommandError(f"No gateway is paired with {sites.get().name}. Pair one first.")
            try:
                services.set_console_address(gateway, actor=Actor(user, membership), address=address)
            except (ValidationError, PermissionDenied) as exc:
                raise CommandError("; ".join(getattr(exc, "messages", [str(exc)]))) from exc
        if gateway.console_address:
            self.stdout.write(self.style.SUCCESS(f"{gateway.site.name}: console address is {gateway.console_address}."))
        else:
            self.stdout.write(self.style.SUCCESS(f"{gateway.site.name}: console address removed."))
