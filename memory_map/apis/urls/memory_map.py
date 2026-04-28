from django.urls import path
from memory_map.apis.views.memory_map import MemoryMapAPIView , MemoryMapLocationCreateAPIView,MemoryMapLocationListAPIView

urlpatterns = [
    path("", MemoryMapAPIView.as_view(), name="memory-map"),
    path("location/", MemoryMapLocationCreateAPIView.as_view(), name="memory-map-location-create"),
    path("location/list/",MemoryMapLocationListAPIView.as_view(), name="memory-map-location-list"),
    
]