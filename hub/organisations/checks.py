"""System checks that keep rule 1 true as models are added."""

from django.apps import apps
from django.core.checks import Error, Tags, register

from hub.organisations.registry import GLOBAL_MODELS
from hub.organisations.scoping import AllOrganisationsManager, OrganisationManager, OrganisationScopedModel


def _hub_models():
    for model in apps.get_models():
        if model.__module__.startswith("hub.") and not model._meta.proxy:
            yield model


@register(Tags.models)
def check_every_model_is_scoped(app_configs, **kwargs):
    errors = []
    for model in _hub_models():
        label = model._meta.label
        scoped = issubclass(model, OrganisationScopedModel)
        if scoped and label in GLOBAL_MODELS:
            errors.append(
                Error(f"{label} is organisation-scoped and also listed in GLOBAL_MODELS.", obj=model, id="hub.E004")
            )
        if not scoped and label not in GLOBAL_MODELS:
            errors.append(
                Error(
                    f"{label} is not organisation-scoped.",
                    hint=(
                        "Inherit hub.organisations.scoping.OrganisationScopedModel, or add the model to "
                        "hub.organisations.registry.GLOBAL_MODELS with the reason it is global."
                    ),
                    obj=model,
                    id="hub.E001",
                )
            )
        if not scoped:
            continue
        if not isinstance(model._default_manager, OrganisationManager):
            errors.append(
                Error(
                    f"{label}: the default manager must be an OrganisationManager.",
                    hint="Subclass OrganisationManager for custom managers and keep it named `objects`.",
                    obj=model,
                    id="hub.E002",
                )
            )
        if not isinstance(getattr(model, "all_organisations", None), AllOrganisationsManager):
            errors.append(Error(f"{label}: `all_organisations` was replaced or removed.", obj=model, id="hub.E002"))
        for field in model._meta.local_many_to_many:
            through = field.remote_field.through
            if not issubclass(through, OrganisationScopedModel):
                errors.append(
                    Error(
                        f"{label}.{field.name}: a many-to-many between business rows needs an "
                        "organisation-scoped `through` model.",
                        obj=model,
                        id="hub.E003",
                    )
                )
    return errors
