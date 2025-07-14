from userauth.models import Assets
from userauth.apis.views.views import SecuredView

from rest_framework.views import APIView
from rest_framework import status
from rest_framework.response import Response
from django.shortcuts import get_object_or_404


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
        media_files = MemoryRoomMediaFile.objects.filter(memory_room_id=memory_room_id, user=user)
        serializer = MemoryRoomMediaFileSerializer(media_files, many=True)
        print(media_files, user, memory_room_id)
        return Response(serializer.data)

    def post(self, request, memory_room_id: int):
        user = self.get_current_user(request)

        # Ensure memory room exists and belongs to user
        memory_room = get_object_or_404(MemoryRoom, id=memory_room_id, user=user)

        data = request.data.copy()
        data['user'] = user.id
        data['memory_room'] = memory_room.id

        serializer = MemoryRoomMediaFileSerializer(data=data, context={'user': user})
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
        
    def delete(self, request, memory_room_id, media_file_id):
        user = self.get_current_user(request)

        media_file = get_object_or_404(
            MemoryRoomMediaFile,
            id=media_file_id,
            user=user,
            memory_room_id=memory_room_id
        )
        print(f'Media file deleted: {media_file} user: {user}')

        media_file.delete()

        return Response({'message': 'Media file deleted successfully'}, status=status.HTTP_204_NO_CONTENT)
