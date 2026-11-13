from rest_framework.generics import ListAPIView
from rest_framework.response import Response
from rest_framework.views import APIView

from hub.api.serializers import MemberSerializer, OrganisationSerializer
from hub.organisations.models import Membership, Role


class MeView(APIView):
    """Who the token is for: the user, the organisation and the role held there."""

    def get(self, request):
        membership = request._request.membership
        return Response(
            {
                "user_ref": str(request.user.pk),
                "name": request.user.name,
                "email": request.user.email,
                "organisation": OrganisationSerializer(request._request.organisation).data,
                "role": membership.role,
            }
        )


class OrganisationView(APIView):
    def get(self, request):
        return Response(OrganisationSerializer(request._request.organisation).data)


class MemberListView(ListAPIView):
    """Active members of the token's organisation. Managers and above."""

    minimum_role = Role.MANAGER
    serializer_class = MemberSerializer
    pagination_class = None

    def get_queryset(self):
        return Membership.objects.filter(is_active=True).select_related("user").order_by("user__email")
