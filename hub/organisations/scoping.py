"""The organisation-scoped base model and its managers.

Every business model inherits `OrganisationScopedModel`. A system check (`hub.organisations.checks`)
fails the build if a hub model neither inherits it nor appears, with a reason, in
`hub.organisations.registry.GLOBAL_MODELS`.

* `Model.objects` is the default manager. It returns only the current organisation's rows and
  raises `NoOrganisationContext` when no organisation is current.
* `Model.all_organisations` is the escape hatch for the few places that must look across
  organisations: resolving a token or an invitation before any organisation is known, platform
  jobs, and organisation export and deletion. Each use needs a `# unscoped: <reason>` comment;
  `scripts/check_unscoped_access.py` fails CI without one.
"""

from django.db import models

from hub.organisations.context import (
    CrossOrganisationAccess,
    NoOrganisationContext,
    current_organisation,
    require_organisation,
)


class OrganisationQuerySet(models.QuerySet):
    def update(self, **kwargs):
        if "organisation" in kwargs or "organisation_id" in kwargs:
            raise CrossOrganisationAccess("A row cannot be moved to another organisation.")
        return super().update(**kwargs)

    def bulk_create(self, objs, *args, **kwargs):
        objs = list(objs)
        for obj in objs:
            obj._bind_to_current_organisation()
            obj._check_related_organisations()
        return super().bulk_create(objs, *args, **kwargs)

    def bulk_update(self, objs, fields, *args, **kwargs):
        if "organisation" in fields or "organisation_id" in fields:
            raise CrossOrganisationAccess("A row cannot be moved to another organisation.")
        objs = list(objs)
        for obj in objs:
            obj._bind_to_current_organisation()
            obj._check_related_organisations()
        return super().bulk_update(objs, fields, *args, **kwargs)


class OrganisationManager(models.Manager.from_queryset(OrganisationQuerySet)):
    """Only the current organisation's rows. Fails closed when there is no current organisation."""

    def get_queryset(self):
        organisation = require_organisation()
        return super().get_queryset().filter(organisation_id=organisation.pk)


class AllOrganisationsManager(models.Manager.from_queryset(OrganisationQuerySet)):
    """Rows of every organisation. Reads only; writes still go through the current organisation."""

    # Django must never pick this manager for related-object access or migrations.
    use_in_migrations = False


class OrganisationScopedModel(models.Model):
    organisation = models.ForeignKey(
        "organisations.Organisation",
        on_delete=models.CASCADE,
        related_name="+",
        editable=False,
    )

    objects = OrganisationManager()
    all_organisations = AllOrganisationsManager()

    class Meta:
        abstract = True
        default_manager_name = "objects"

    # -- writes ----------------------------------------------------------------------------------

    def _bind_to_current_organisation(self) -> None:
        """Set the organisation on a new row, and refuse a row that belongs to another one."""
        organisation = current_organisation()
        if organisation is None:
            raise NoOrganisationContext(f"{type(self).__name__} cannot be written while no organisation is current.")
        if self.organisation_id is None:
            self.organisation = organisation
        elif self.organisation_id != organisation.pk:
            raise CrossOrganisationAccess(
                f"{type(self).__name__} belongs to another organisation than the current one."
            )

    def _check_related_organisations(self) -> None:
        """Every foreign key to another business row must stay inside this organisation."""
        for field in self._meta.concrete_fields:
            if not field.is_relation or field.name == "organisation":
                continue
            related_model = field.remote_field.model
            if not (isinstance(related_model, type) and issubclass(related_model, OrganisationScopedModel)):
                continue
            related_pk = getattr(self, field.attname)
            if related_pk is None:
                continue
            if field.is_cached(self):
                related_org_id = getattr(self, field.name).organisation_id
            else:
                related_org_id = (
                    related_model.all_organisations.filter(pk=related_pk)  # unscoped: integrity check of own FK
                    .values_list("organisation_id", flat=True)
                    .first()
                )
            if related_org_id != self.organisation_id:
                raise CrossOrganisationAccess(
                    f"{type(self).__name__}.{field.name} points at a row of another organisation."
                )

    def save(self, *args, **kwargs):
        self._bind_to_current_organisation()
        self._check_related_organisations()
        return super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        self._bind_to_current_organisation()
        return super().delete(*args, **kwargs)
