from django.urls import path
from memory_map.apis.views.media import MemoryMapChunkedUploadView,MemoryMapMediaListView,MemoryMapMediaEditDeleteView,ServeMemoryMapMedia,MemoryMapMediaDownloadAPIView

urlpatterns = [
    # POST /memory-map/media/<location_id>/<action>/
    # action = "init" | "upload" | "complete" | "abort"
    path("<int:location_id>/media/<str:action>/", 
         MemoryMapChunkedUploadView.as_view(),
         name="memory-map-chunked-upload"),

    path("media/<int:location_id>/list/", 
        MemoryMapMediaListView.as_view(),
        name="memory-map-media-list"),

    path("memory-map/media/<int:location_id>/<int:media_id>/",
        MemoryMapMediaEditDeleteView.as_view(),
        name="memory-map-media-edit-delete",
    ),

    path("media/<int:media_id>/serve/",
         ServeMemoryMapMedia.as_view(),
         name='serve-memory-map-media',
    ),

    path(
    "memory-map/media/<int:media_id>/download/",
    MemoryMapMediaDownloadAPIView.as_view(),
    name="memory-map-media-download"
)

]

    

