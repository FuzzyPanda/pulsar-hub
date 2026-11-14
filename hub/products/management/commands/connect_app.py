from django.core.exceptions import PermissionDenied, ValidationError
from django.core.management.base import BaseCommand, CommandError

from hub.accounts.models import User
from hub.organisations.context import organisation_context
from hub.organisations.models import Organisation
from hub.organisations.services import Actor, resolve_access
from hub.products import catalogue, services
from hub.products.models import ConnectedApp


class Command(BaseCommand):
    help = (
        "Connect a product from the catalogue to an organisation's hub, change its address, or disconnect it. "
        "Same as Settings, Apps: the person named with --as must be an Owner, and the change is audited as theirs."
    )

    def add_arguments(self, parser):
        parser.add_argument("org_slug")
        parser.add_argument("product_key", choices=[product.key for product in catalogue.CATALOGUE])
        parser.add_argument(
            "base_address",
            nargs="?",
            default="",
            help="Where the organisation opens the product, such as https://rostering.example.com or "
            "http://{host}:8080. Not used for a product that lives at each site (access_control).",
        )
        parser.add_argument("--as", dest="as_email", required=True, help="Email of the Owner doing this (audited).")
        parser.add_argument("--launch-path", default=None, help="Override the product's launch path, such as /.")
        parser.add_argument("--off", action="store_true", help="Keep the connection but hide it from the launcher.")
        parser.add_argument("--disconnect", action="store_true", help="Remove the connection.")

    def handle(self, *args, org_slug, product_key, base_address, as_email, launch_path, off, disconnect, **options):
        organisation = Organisation.objects.filter(slug=org_slug).first()
        if organisation is None:
            raise CommandError(f"There is no organisation at /org/{org_slug}/.")
        user = User.objects.filter(email__iexact=as_email, is_active=True).first()
        membership = resolve_access(user, organisation)[0] if user is not None else None
        if membership is None:
            raise CommandError(f"{as_email} is not an active member of {organisation.name}.")
        actor = Actor(user, membership)
        try:
            with organisation_context(organisation):
                app = ConnectedApp.objects.filter(product_key=product_key).first()
                if disconnect:
                    if app is None:
                        raise CommandError(f"{product_key} is not connected to {organisation.name}.")
                    services.disconnect_app(app, actor=actor)
                    outcome = "disconnected from"
                elif app is None:
                    services.connect_app(
                        actor=actor,
                        product_key=product_key,
                        base_address=base_address,
                        launch_path=launch_path or "",
                        enabled=not off,
                    )
                    outcome = "connected to"
                else:
                    services.update_app(
                        app,
                        actor=actor,
                        base_address=base_address or app.base_address,
                        launch_path=app.launch_path if launch_path is None else launch_path,
                        enabled=not off,
                    )
                    outcome = "updated for"
        except (ValidationError, PermissionDenied) as exc:
            raise CommandError("; ".join(getattr(exc, "messages", [str(exc)]))) from exc
        self.stdout.write(
            self.style.SUCCESS(f"{product_key} {outcome} {organisation.name} (/org/{organisation.slug}/).")
        )
