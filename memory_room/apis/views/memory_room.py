from userauth.models import Assets
from userauth.apis.views.views import SecuredView

from rest_framework.views import APIView
from rest_framework import status
from rest_framework.response import Response

from memory_room.apis.serializers.memory_room import AssetSerializer

from rest_framework import generics, permissions
from memory_room.models import MemoryRoom,MemoryRoomTemplateDefault, MemoryRoomMediaFile, MemoryRoomDetail

from memory_room.apis.serializers.serailizers import MemoryRoomSerializer
from memory_room.apis.serializers.memory_room import (
    MemoryRoomCreationSerializer, MemoryRoomTemplateDefaultSerializer, MemoryRoomMediaFileSerializer
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

class MemoryRoomMediaFileListCreateAPI(SecuredView):

    def get(self, request, memory_room_id: int):
        user = self.get_current_user(request)
        media_files = MemoryRoomMediaFile.objects.filter(
            memory_room_details__memory_room__id=memory_room_id,
            memory_room_details__memory_room__user=user
        ).distinct()

        serializer = MemoryRoomMediaFileSerializer(media_files, many=True)
        return Response(serializer.data)

    def post(self, request, memory_room_id: int):
        serializer = MemoryRoomMediaFileSerializer(data=request.data)
        if serializer.is_valid():
            media_file = serializer.save()

            # Attach to memory room if it exists and belongs to the user
            try:
                memory_room_detail = MemoryRoomDetail.objects.get(
                    memory_room__id=memory_room_id,
                    memory_room__user=self.get_current_user(request)
                )
                memory_room_detail.media_files.add(media_file)
                return Response(serializer.data, status=status.HTTP_201_CREATED)
            except MemoryRoomDetail.DoesNotExist:
                media_file.delete()
                return Response(
                    {"error": "Memory room not found or unauthorized"},
                    status=status.HTTP_404_NOT_FOUND
                )

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
