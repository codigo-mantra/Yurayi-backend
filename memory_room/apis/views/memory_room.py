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
    MemoryRoomCreationSerializer, MemoryRoomTemplateDefaultSerializer,MemoryRoomUpdationSerializer, MemoryRoomMediaFileSerializer
    
    )


class MemoryRoomCoverView(generics.ListAPIView): 
    permission_classes = [permissions.IsAuthenticated]
    queryset = Assets.objects.all()
    serializer_class = AssetSerializer

    def get_queryset(self):
        return Assets.objects.filter(asset_types = 'Memory Room Cover').order_by('-is_created')
        

class UserMemoryRoomListView(generics.ListAPIView):
    serializer_class = MemoryRoomSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        return MemoryRoom.objects.filter(user=self.request.user, is_deleted=False).order_by('-is_created')

class MemoryRoomTemplateDefaultViewSet(generics.ListAPIView):
    permission_classes = [permissions.IsAuthenticated]
    queryset = MemoryRoomTemplateDefault.objects.filter(is_deleted = False).order_by('-is_created')
    serializer_class = MemoryRoomTemplateDefaultSerializer


class CreateMemoryRoomView(SecuredView):
    def post(self, request, format=None):
        user = self.get_current_user(request)
        serializer = MemoryRoomCreationSerializer(data=request.data, context={'user': user})
        serializer.is_valid(raise_exception=True)
        memory_room = serializer.validated_data.get('memory_room')
        serialized_data = MemoryRoomSerializer(memory_room).data if memory_room else {}

        return Response({'message': 'Memory created successfully', 'memory_room': serialized_data})
    
    def delete(self, request,memory_room_id, format=None):
        """Delete memory room"""
        user = self.get_current_user(request)
        memory_room = get_object_or_404(MemoryRoom, id=memory_room_id, user=user)
        memory_room_name = memory_room.room_template.name
        memory_room.delete()
        return Response({'message': f'Memory deleted successfully named as : {memory_room_name}'}, status=status.HTTP_204_NO_CONTENT)
    
    def patch(self, request, memory_room_id):
        user = self.get_current_user(request)
        try:
            memory_room = MemoryRoom.objects.get(id=memory_room_id, user=user)
        except MemoryRoom.DoesNotExist:
            return Response({"detail": "MemoryRoom not found."}, status=status.HTTP_404_NOT_FOUND)

        serializer = MemoryRoomUpdationSerializer(instance = memory_room, data=request.data, partial=True)
        if serializer.is_valid():
            memory_room = serializer.save()
            memory_room_serializer = MemoryRoomSerializer(memory_room)
            
            return Response(memory_room_serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)



class MemoryRoomMediaFileListCreateAPI(SecuredView):

    def get(self, request, memory_room_id: int):
        """List All Media Files of Memory Room """
        user = self.get_current_user(request)
        memory_room = get_object_or_404(MemoryRoom, id=memory_room_id, user=user)
        media_files = MemoryRoomMediaFile.objects.filter(memory_room=memory_room, user=user).order_by('-is_created')
        serializer = MemoryRoomMediaFileSerializer(media_files, many=True)
        return Response(serializer.data)

    def post(self, request, memory_room_id: int):
        """Post Media Files in Memory Room"""

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
    
    def patch(self, request, memory_room_id, media_file_id):
        """Move Media File to another Memory room"""
        user  = self.get_current_user(request)
        # moved to memory room 
        memory_room = get_object_or_404(
            MemoryRoom,
            id=memory_room_id,
            user=user,
        )
        media_file = get_object_or_404(
            MemoryRoomMediaFile,
            id=media_file_id,
            user=user,

        )

        media_file.memory_room = memory_room
        media_file.save()
        return Response({'message': "Media files moved successfully"}, status=status.HTTP_200_OK)

    
        
    def delete(self, request, memory_room_id, media_file_id):
        """Delete Media file"""
        user = self.get_current_user(request)
        memory_room = get_object_or_404(MemoryRoom, id=memory_room_id, user=user)


        media_file = get_object_or_404(
            MemoryRoomMediaFile,
            id=media_file_id,
            user=user,
            memory_room=memory_room
        )
        media_file.delete()
        return Response({'message': 'Media file deleted successfully'}, status=status.HTTP_204_NO_CONTENT)
    
