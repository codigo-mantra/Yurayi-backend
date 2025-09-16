from rest_framework import generics, permissions
from memory_room.models import MemoryRoom, TimeCapSoul
from memory_room.apis.serializers.serailizers import MemoryRoomSerializer, TimeCapSoulSerializer
import logging

logger = logging.getLogger(__name__)

class UserMemoryRoomListView(generics.ListAPIView):
    serializer_class = MemoryRoomSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        logger.info("UserMemoryRoomListView.get_queryset called")
        return MemoryRoom.objects.filter(user=self.request.user, is_deleted=False)

