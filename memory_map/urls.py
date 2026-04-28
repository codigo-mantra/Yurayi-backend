from django.urls import path, include

urlpatterns = [
    path("", include("memory_map.apis.urls.memory_map")),     # memory-map core apis
    path("", include("memory_map.apis.urls.media")),          # memory-map media upload apis
    path("", include("memory_map.apis.urls.bucket")),         # memory-map bucket list apis
    path("", include("memory_map.apis.urls.recipients")),     # memory-map recipients/sharing apis
    
]