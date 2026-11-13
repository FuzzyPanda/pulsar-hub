"""API output. Serializers list their fields explicitly; nothing is exposed by default, and the
fields named in rule 11 (pay rates, bank details, dates of birth, licence numbers, home addresses)
are never added to one."""

from rest_framework import serializers

from hub.organisations.models import Membership, Organisation


class OrganisationSerializer(serializers.ModelSerializer):
    org_ref = serializers.UUIDField(source="pk", read_only=True)

    class Meta:
        model = Organisation
        fields = ["org_ref", "name", "slug", "status"]
        read_only_fields = fields


class MemberSerializer(serializers.ModelSerializer):
    user_ref = serializers.UUIDField(source="user_id", read_only=True)
    name = serializers.CharField(source="user.name", read_only=True)
    email = serializers.EmailField(source="user.email", read_only=True)

    class Meta:
        model = Membership
        fields = ["user_ref", "name", "email", "role"]
        read_only_fields = fields
