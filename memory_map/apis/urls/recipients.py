from django.urls import path
from memory_map.apis.views.recipients import MemoryMapRecipientsAPIView

urlpatterns = [
    path("recipients/", MemoryMapRecipientsAPIView.as_view(), name="memory-map-recipients"),
]