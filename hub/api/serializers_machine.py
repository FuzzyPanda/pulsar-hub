"""Shapes for the gateway and service APIs. Explicit field lists only (rule 11)."""

from rest_framework import serializers

from hub.directory.models import Person, Site
from hub.gateways.models import GatewayEvent


class PersonSerializer(serializers.ModelSerializer):
    person_ref = serializers.UUIDField(source="pk", read_only=True)

    class Meta:
        model = Person
        fields = ["person_ref", "name", "work_email", "status", "positions"]
        read_only_fields = fields


class SiteSerializer(serializers.ModelSerializer):
    """A site, with the hub's view of its gateway when the view supplies one (the `gateways`
    context: site id to `hub.gateways.services.gateway_summary`)."""

    site_ref = serializers.UUIDField(source="pk", read_only=True)
    gateway = serializers.SerializerMethodField()

    class Meta:
        model = Site
        fields = ["site_ref", "name", "address", "timezone", "is_active", "access_managed_elsewhere", "gateway"]
        read_only_fields = fields

    def get_gateway(self, site) -> dict:
        from hub.gateways.services import NO_GATEWAY

        return self.context.get("gateways", {}).get(site.pk, dict(NO_GATEWAY))


class EventSerializer(serializers.ModelSerializer):
    cursor = serializers.IntegerField(source="pk", read_only=True)
    id = serializers.UUIDField(source="event_id", read_only=True)
    org_ref = serializers.UUIDField(source="organisation_id", read_only=True)
    site_ref = serializers.UUIDField(source="site_id", read_only=True)
    person_ref = serializers.UUIDField(source="person_id", read_only=True, allow_null=True)
    occurred_at = serializers.DateTimeField(format="%Y-%m-%dT%H:%M:%SZ", read_only=True)

    class Meta:
        model = GatewayEvent
        fields = ["cursor", "id", "type", "occurred_at", "org_ref", "site_ref", "person_ref", "data"]
        read_only_fields = fields
