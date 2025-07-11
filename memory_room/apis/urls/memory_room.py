from django.urls import path
from memory_room.apis.views.memory_room import (
    UserMemoryRoomListView,MemoryRoomCoverView ,
    MemoryRoomTemplateDefaultViewSet, CreateMemoryRoomView

    )

urlpatterns = [
    path('covers-images/list/', MemoryRoomCoverView.as_view(), name='memory-room-cover'),
    path('create-new/', CreateMemoryRoomView.as_view(), name='create-memory-rooms'),
    path('list/', UserMemoryRoomListView.as_view(), name='user-memory-rooms'),
    path('default-templates/', MemoryRoomTemplateDefaultViewSet.as_view(), name='default-memory-templates'),

]
