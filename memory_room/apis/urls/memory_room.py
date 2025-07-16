from django.urls import path
from memory_room.apis.views.memory_room import (
    UserMemoryRoomListView,MemoryRoomCoverView ,
    MemoryRoomTemplateDefaultViewSet, CreateMemoryRoomView, MemoryRoomMediaFileListCreateAPI

    )

urlpatterns = [
    path('covers-images/list/', MemoryRoomCoverView.as_view(), name='memory-room-cover'),
    path('create-new/', CreateMemoryRoomView.as_view(), name='create-memory-rooms'),
    path('<int:memory_room_id>/', CreateMemoryRoomView.as_view(), name='updte-memory-room'),
    path('list/', UserMemoryRoomListView.as_view(), name='user-memory-rooms'),
    path('media-files/<int:memory_room_id>/list', MemoryRoomMediaFileListCreateAPI.as_view(), name='memory-room-media-files'),
    path('media-files/<int:memory_room_id>/<int:media_file_id>/', MemoryRoomMediaFileListCreateAPI.as_view(), name='memory-room-media-files-delete'),
    path('default-templates/', MemoryRoomTemplateDefaultViewSet.as_view(), name='default-memory-templates'),

]
