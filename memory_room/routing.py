from django.urls import re_path
from memory_room.consumers import DownloadProgressConsumer

websocket_urlpatterns = [
    re_path(r'ws/download-progress/(?P<file_id>\w+)/$', DownloadProgressConsumer.as_asgi()),
]
