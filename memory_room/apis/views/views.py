# views.py
from rest_framework import generics, permissions
from memory_room.models import MemoryRoom, TimeCapSoul
from memory_room.apis.serializers.serailizers import MemoryRoomSerializer, TimeCapSoulSerializer

class UserMemoryRoomListView(generics.ListAPIView):
    serializer_class = MemoryRoomSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        return MemoryRoom.objects.filter(user=self.request.user, is_deleted=False)

