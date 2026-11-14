"""Who may enter where.

An access group ("Managers", "Cleaners") is a set of people and a set of sites: everyone in the
group may enter every site in the group. That one idea covers multi-site access. What a group
means at a particular door (which doors, which hours) is decided on that site's own gateway,
which maps each group name to its local access levels once, at commissioning.

The hub sends each gateway the state it should be in, never a list of changes (rule 5).
"""

import uuid

from django.db import models

from hub.organisations.scoping import OrganisationScopedModel


class AccessGroup(OrganisationScopedModel):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=100)
    description = models.CharField(max_length=255, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["name"]
        constraints = [
            models.UniqueConstraint(fields=["organisation", "name"], name="access_accessgroup_name_unique"),
        ]

    def __str__(self) -> str:
        return self.name


class AccessGroupMember(OrganisationScopedModel):
    """One person in one group. `source` says who put them there: a person in the console
    (`manual`), or one of the group's positions that the person holds (`positions`). A membership
    is one or the other, never both: a hand-made one is never touched by the positions, and one
    that came from a position goes when the position does."""

    class Source(models.TextChoices):
        MANUAL = "manual", "Added by a person"
        POSITIONS = "positions", "From a job position"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    access_group = models.ForeignKey(AccessGroup, on_delete=models.CASCADE, related_name="memberships")
    person = models.ForeignKey("directory.Person", on_delete=models.CASCADE, related_name="access_memberships")
    source = models.CharField(max_length=16, choices=Source.choices, default=Source.MANUAL)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(fields=["access_group", "person"], name="access_groupmember_unique"),
        ]

    def __str__(self) -> str:
        return f"{self.person_id} in {self.access_group_id}"


class AccessGroupPosition(OrganisationScopedModel):
    """A job position that puts whoever holds it in the group: "Guard" gives "Guards".

    Positions are names sent by Pulsar Rostering on each person (docs/CONTRACTS.md). The match
    ignores case (`position_key`), because the name is typed here by one person and in Rostering
    by another.
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    access_group = models.ForeignKey(AccessGroup, on_delete=models.CASCADE, related_name="position_links")
    position = models.CharField(max_length=60)
    position_key = models.CharField(max_length=120, editable=False)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["position"]
        constraints = [
            models.UniqueConstraint(fields=["access_group", "position_key"], name="access_groupposition_unique"),
        ]

    def __str__(self) -> str:
        return f"{self.position} gives {self.access_group_id}"


class AccessGroupSite(OrganisationScopedModel):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    access_group = models.ForeignKey(AccessGroup, on_delete=models.CASCADE, related_name="site_links")
    site = models.ForeignKey("directory.Site", on_delete=models.CASCADE, related_name="access_group_links")
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(fields=["access_group", "site"], name="access_groupsite_unique"),
        ]

    def __str__(self) -> str:
        return f"{self.access_group_id} at {self.site_id}"
