"""Which Pulsar products an organisation has connected to its hub.

The products themselves are listed in code (`hub.products.catalogue`). A row here says that one
organisation uses one of them, and where it lives. It holds no secret: an address is a link, and
the product has its own sign-in (Pulsar Rostering signs in through the hub's OIDC provider).
"""

import uuid

from django.conf import settings
from django.db import models

from hub.organisations.scoping import OrganisationScopedModel
from hub.products.addresses import MAX_ADDRESS_LENGTH


class ConnectedApp(OrganisationScopedModel):
    """One product, connected for one organisation by an Owner."""

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    # A key of hub.products.catalogue.CATALOGUE. A row whose product has left the catalogue is
    # ignored by the launcher and can still be disconnected in Settings.
    product_key = models.CharField(max_length=32)
    # Where the organisation opens the product. May use `{host}` for the host name the browser
    # used to reach the hub. Blank for a product that lives at each site (its links come from the
    # sites' gateways).
    base_address = models.CharField(max_length=MAX_ADDRESS_LENGTH, blank=True)
    # Overrides the product's own launch path for this organisation. Blank means the default.
    launch_path = models.CharField(max_length=MAX_ADDRESS_LENGTH, blank=True)
    enabled = models.BooleanField(default=True)
    connected_by = models.ForeignKey(settings.AUTH_USER_MODEL, null=True, on_delete=models.SET_NULL, related_name="+")
    connected_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["connected_at"]
        constraints = [
            models.UniqueConstraint(fields=["organisation", "product_key"], name="products_one_connection_per_product"),
        ]

    def __str__(self) -> str:
        return f"{self.product_key} connection {self.id}"
