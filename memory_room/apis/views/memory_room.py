# views.py
from rest_framework import viewsets
from userauth.models import Assets
from userauth.apis.views.views import SecuredView

from rest_framework import status
from rest_framework.response import Response

from memory_room.apis.serializers.memory_room import AssetSerializer

from rest_framework import generics, permissions
from memory_room.models import MemoryRoom,MemoryRoomTemplateDefault

from memory_room.apis.serializers.serailizers import MemoryRoomSerializer
from memory_room.apis.serializers.memory_room import (
    MemoryRoomCreationSerializer, MemoryRoomTemplateDefaultSerializer
    )

class MemoryRoomCoverView(generics.ListAPIView): 
    permission_classes = [permissions.IsAuthenticated]
    queryset = Assets.objects.all()
    serializer_class = AssetSerializer

    def get_queryset(self):
        return Assets.objects.filter(asset_types = 'Memory Room Cover')
        

class UserMemoryRoomListView(generics.ListAPIView):
    serializer_class = MemoryRoomSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        return MemoryRoom.objects.filter(user=self.request.user, is_deleted=False)

class MemoryRoomTemplateDefaultViewSet(generics.ListAPIView):
    permission_classes = [permissions.IsAuthenticated]
    queryset = MemoryRoomTemplateDefault.objects.filter(is_deleted = False)
    serializer_class = MemoryRoomTemplateDefaultSerializer


class CreateMemoryRoomView(SecuredView):
    def post(self, request, format=None):
        user = self.get_current_user(request)
        serializer = MemoryRoomCreationSerializer(data=request.data, context={'user': user})
        serializer.is_valid(raise_exception=True)
        memory_room = serializer.validated_data.get('memory_room')
        serialized_data = MemoryRoomSerializer(memory_room).data if memory_room else {}

        return Response({'message': 'Memory created successfully', 'memory_room': serialized_data})
