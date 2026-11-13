from django.urls import path

from hub.organisations.middleware import organisation_view


def org_path(route: str, view, name: str):
    """A route under `/org/<org_slug>/`. Use this, never `path`, for organisation routes."""
    return path(route, organisation_view(view), name=name)
