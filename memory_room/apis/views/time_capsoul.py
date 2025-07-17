import boto3
from botocore.exceptions import ClientError
from django.conf import settings
from django.http import StreamingHttpResponse, Http404

from django.shortcuts import get_object_or_404
from rest_framework import generics, permissions, status
from rest_framework.response import Response
from rest_framework.parsers import MultiPartParser

from userauth.models import Assets
from userauth.apis.views.views import SecuredView


from memory_room.apis.serializers.memory_room import (
    AssetSerializer,
)

from memory_room.models import TimeCapSoulTemplateDefault
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
        return Assets.objects.filter(asset_types='Time CapSoul Cover').order_by('-is_created')


class TimeCapSoulDefaultTemplateAPI(SecuredView):

    def get(self, request, format=None):
        default_templates = TimeCapSoulTemplateDefault.objects.filter(is_deleted = False)
        serializer = TimeCapSoulTemplateDefaultReadOnlySerializer(default_templates, many=True)
        return Response(serializer.data)

