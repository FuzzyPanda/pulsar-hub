"""The calls a gateway makes, and the calls Pulsar Rostering makes. See docs/CONTRACTS.md."""

import json

from django.core.exceptions import PermissionDenied, ValidationError
from django.http import Http404
from rest_framework import status
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework.throttling import ScopedRateThrottle
from rest_framework.views import APIView

from hub.access.services import desired_access
from hub.api.authentication import GatewayAuthentication, OrganisationTokenAuthentication, ServiceTokenAuthentication
from hub.api.models import Scope
from hub.api.permissions import HasScope, IsGateway
from hub.api.serializers_machine import EventSerializer, PersonSerializer, SiteSerializer
from hub.directory import services as directory
from hub.directory.models import Person, Site
from hub.gateways import services as gateways
from hub.gateways.models import GatewayEvent
from hub.organisations.models import Role


def _problem(exc: Exception, code: int = status.HTTP_400_BAD_REQUEST) -> Response:
    detail = "; ".join(exc.messages) if isinstance(exc, ValidationError) else (str(exc) or "Refused.")
    return Response({"detail": detail}, status=code)


def _json_object(request) -> dict:
    """The request body as a JSON object. Parsed here, from the raw bytes, so that the events call
    can check its signature over exactly what was sent."""
    try:
        payload = json.loads(request.body or b"{}")
    except (ValueError, UnicodeDecodeError) as exc:
        raise ValidationError("The body is not JSON.") from exc
    if not isinstance(payload, dict):
        raise ValidationError("The body must be a JSON object.")
    return payload


# --- gateway --------------------------------------------------------------------------------------


class GatewayPairView(APIView):
    """A gateway exchanges a one-time code for its credential. The only gateway call without one."""

    authentication_classes: list = []
    permission_classes = [AllowAny]
    throttle_classes = [ScopedRateThrottle]
    throttle_scope = "gateway_pair"

    def post(self, request):
        try:
            payload = _json_object(request)
            gateway, credential = gateways.pair_gateway(
                code=str(payload.get("code") or ""),
                name=str(payload.get("name") or ""),
                software_version=str(payload.get("software_version") or ""),
                request=request._request,
            )
        except (PermissionDenied, ValidationError):
            # One answer for every failure: the endpoint never says which codes exist.
            return Response({"detail": "That pairing code is not valid."}, status=status.HTTP_403_FORBIDDEN)
        site, organisation = gateway.site, gateway.organisation
        return Response(
            {
                "gateway_id": str(gateway.pk),
                "credential": credential,
                "org_ref": str(organisation.pk),
                "org_name": organisation.name,
                "site_ref": str(site.pk),
                "site_name": site.name,
                "site_timezone": site.timezone,
                "poll_seconds": 60,
            },
            status=status.HTTP_201_CREATED,
            headers={"Cache-Control": "no-store"},
        )


class GatewayView(APIView):
    authentication_classes = [GatewayAuthentication]
    permission_classes = [IsGateway]

    @property
    def gateway(self):
        return self.request._request.gateway

    def initial(self, request, *args, **kwargs):
        super().initial(request, *args, **kwargs)
        gateways.touch(self.gateway, software_version=request.headers.get("X-Gateway-Version", ""))


class GatewayAccessView(GatewayView):
    def get(self, request, site_ref):
        snapshot = desired_access(self.gateway.site)
        if request.query_params.get("version") == snapshot["version"]:
            return Response(status=status.HTTP_304_NOT_MODIFIED)
        return Response(snapshot, headers={"Cache-Control": "no-store"})


class GatewayAccessAckView(GatewayView):
    def post(self, request, site_ref):
        try:
            payload = _json_object(request)
            gateways.record_ack(self.gateway, version=payload.get("version"), failures=payload.get("failures") or [])
        except ValidationError as exc:
            return _problem(exc)
        return Response(status=status.HTTP_204_NO_CONTENT)


class GatewayEventsView(GatewayView):
    def post(self, request, site_ref):
        body = request.body
        if not gateways.verify_signature(
            credential=request._request.gateway_credential,
            body=body,
            header=request.headers.get("X-Hub-Signature", ""),
        ):
            return Response({"detail": "The signature does not match the body."}, status=status.HTTP_400_BAD_REQUEST)
        try:
            payload = _json_object(request)
            result = gateways.ingest_events(self.gateway, payload.get("events"))
        except ValidationError as exc:
            return _problem(exc)
        return Response(result)


class GatewayStateView(GatewayView):
    def post(self, request, site_ref):
        try:
            gateways.record_state(self.gateway, _json_object(request))
        except ValidationError as exc:
            return _problem(exc)
        return Response(status=status.HTTP_204_NO_CONTENT)


# --- Pulsar Rostering and other systems -----------------------------------------------------------


class ServiceView(APIView):
    authentication_classes = [ServiceTokenAuthentication, OrganisationTokenAuthentication]
    permission_classes = [HasScope]


class DirectoryView(ServiceView):
    """`PUT /api/v1/directory`: the full list of people and sites from Pulsar Rostering."""

    authentication_classes = [ServiceTokenAuthentication]
    required_scope = Scope.DIRECTORY_WRITE

    def put(self, request):
        try:
            payload = _json_object(request)
            people, sites = payload.get("people"), payload.get("sites")
            if not isinstance(people, list) or not isinstance(sites, list):
                raise ValidationError("people and sites must both be lists.")
            if not all(isinstance(row, dict) for row in [*people, *sites]):
                raise ValidationError("Every person and site must be an object.")
            allowed_person = {"person_ref", "name", "work_email", "status"}
            allowed_site = {"site_ref", "name", "address", "timezone", "is_active"}
            if any(set(row) - allowed_person for row in people) or any(set(row) - allowed_site for row in sites):
                # Refused, not ignored: a sender that has started including more than these fields
                # must find out now, before it sends something that should never leave it.
                raise ValidationError(
                    "A person may carry only person_ref, name, work_email and status; "
                    "a site only site_ref, name, address, timezone and is_active."
                )
            counts = directory.apply_rostering_snapshot(
                people=people,
                sites=sites,
                allow_empty=payload.get("allow_empty") is True,
                token=request._request.service_token,
            )
        except PermissionDenied as exc:
            return _problem(exc, status.HTTP_403_FORBIDDEN)
        except ValidationError as exc:
            conflict = "would end everyone" in " ".join(exc.messages)
            return _problem(exc, status.HTTP_409_CONFLICT if conflict else status.HTTP_400_BAD_REQUEST)
        return Response(counts)


class PeopleView(ServiceView):
    required_scope = Scope.DIRECTORY_READ
    minimum_role = Role.MANAGER

    def get(self, request):
        return Response(PersonSerializer(Person.objects.order_by("name", "pk"), many=True).data)


class SitesView(ServiceView):
    required_scope = Scope.DIRECTORY_READ
    minimum_role = Role.MANAGER

    def get(self, request):
        return Response(SiteSerializer(Site.objects.order_by("name", "pk"), many=True).data)


class EventsView(ServiceView):
    """`GET /api/v1/events?after=<cursor>`: events oldest first, for a reader that keeps a cursor."""

    required_scope = Scope.EVENTS_READ
    minimum_role = Role.MANAGER

    def get(self, request):
        try:
            after = int(request.query_params.get("after", "0"))
            limit = max(1, min(int(request.query_params.get("limit", "200")), 500))
        except ValueError:
            return Response({"detail": "after and limit must be whole numbers."}, status=status.HTTP_400_BAD_REQUEST)
        events = GatewayEvent.objects.filter(pk__gt=max(after, 0)).order_by("pk")
        prefix = request.query_params.get("type", "")
        if prefix:
            events = events.filter(type__startswith=prefix)
        page = list(events[: limit + 1])
        more = len(page) > limit
        page = page[:limit]
        return Response(
            {
                "events": EventSerializer(page, many=True).data,
                "next_cursor": page[-1].pk if page else max(after, 0),
                "more": more,
            }
        )


def not_found(request, *args, **kwargs):
    raise Http404
