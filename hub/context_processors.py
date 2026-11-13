from django.conf import settings


def hub(request):
    """Values every template needs. The organisation is set by OrganisationMiddleware."""
    return {
        "product_name": settings.PRODUCT_NAME,
        "organisation": getattr(request, "organisation", None),
        "membership": getattr(request, "membership", None),
    }
