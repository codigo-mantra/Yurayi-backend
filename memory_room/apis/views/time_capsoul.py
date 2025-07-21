import boto3

from django.shortcuts import get_object_or_404
from rest_framework import generics, permissions, status
from rest_framework.response import Response

from userauth.models import Assets
from userauth.apis.views.views import SecuredView


from memory_room.apis.serializers.memory_room import (
    AssetSerializer,
)

from memory_room.models import TimeCapSoulTemplateDefault, TimeCapSoul
from memory_room.apis.serializers.time_capsoul import TimeCapSoulTemplateDefaultReadOnlySerializer

class TimeCapSoulCoverView(generics.ListAPIView):
    """
    API endpoint to list all assets of type 'Time CapSoul Cover'.
    Only authenticated users can access this.
    """
    permission_classes = [permissions.IsAuthenticated]
    serializer_class = AssetSerializer

    def get_queryset(self):
        """
        Returns all Time CapSoul Cover assets ordered by creation date.
        """
        return Assets.objects.filter(asset_types='Time CapSoul Cover').order_by('-created_at')


class TimeCapSoulDefaultTemplateAPI(SecuredView):

    def get_memory_room(self, user, time_capsoul_id):
        """
        Utility method to get a memory room owned by the user.
        """
        return get_object_or_404(TimeCapSoul, id=time_capsoul_id, user=user)


    def get(self, request, format=None):
        default_templates = TimeCapSoulTemplateDefault.objects.filter(is_deleted = False)
        serializer = TimeCapSoulTemplateDefaultReadOnlySerializer(default_templates, many=True)
        return Response(serializer.data)

