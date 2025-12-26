from django.urls import path
from memory_room.apis.views.memory_room import (
    UserMemoryRoomListView,MemoryRoomCoverView ,MediaFileDownloadView,SetMemoryRoomCoverImageAPIView,
    MemoryRoomTemplateDefaultViewSet, CreateMemoryRoomView, MemoryRoomMediaFileListCreateAPI, MemoryRoomMediaFileFilterView,UpdateMediaFileDescriptionView, ServeMedia,RefreshMediaURL,
    MemoryRoomDuplicationApiView,ChunkedMediaUploadView

    )

urlpatterns = [
    path('covers-images/list/', MemoryRoomCoverView.as_view(), name='memory-room-cover'),
    path('set/memory-room/<int:memory_room_id>/cover-image/<int:media_file_id>/', SetMemoryRoomCoverImageAPIView.as_view(), name='memory-room-set-cover-images'),
    path('create-new/', CreateMemoryRoomView.as_view(), name='create-memory-rooms'),
    path('<int:memory_room_id>/', CreateMemoryRoomView.as_view(), name='updte-memory-room'),
    path('duplicator/<int:memory_room_id>/', MemoryRoomDuplicationApiView.as_view(), name='memory-room-duplicator'),
    
    path('list/', UserMemoryRoomListView.as_view(), name='user-memory-rooms'),
    path('media-files/<int:memory_room_id>/list', MemoryRoomMediaFileListCreateAPI.as_view(), name='memory-room-media-files'),
    path('media-files/<int:memory_room_id>/chunked/upload/<str:action>', ChunkedMediaUploadView.as_view(), name='media_upload'),

    path('media-files/<int:memory_room_id>/<int:media_file_id>/', MemoryRoomMediaFileListCreateAPI.as_view(), name='memory-room-media-files-delete'),
    path('media-files/filter/', MemoryRoomMediaFileFilterView.as_view(), name='memory-media-filter'),
    path('default-templates/', MemoryRoomTemplateDefaultViewSet.as_view(), name='default-memory-templates'),
    path('media-file/<int:media_file_id>/memory-room/<int:memory_room_id>/download/', MediaFileDownloadView.as_view(), name='media-file-download'),
    path('media-file/<int:media_file_id>/memory_room/<int:memory_room_id>/update-description/', UpdateMediaFileDescriptionView.as_view(), name='update-media-file-description'),
     
    # media files
    path("api/media/<int:media_file_id>/serve/<path:s3_key>", ServeMedia.as_view(), name="serve-media"),
    path("media/refresh/access-token/", RefreshMediaURL.as_view(), name="refresh_media",),




]
