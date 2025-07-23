
from django.urls import path, include
from django.urls import include, path, re_path
from .views import testing_view


urlpatterns = [
    path('testing/', testing_view, name='test'),

    # --- memory-room-apis ---
    path('', include('memory_room.apis.urls.urls')), 
    path('memory-rooms/', include('memory_room.apis.urls.memory_room')), 
    path('time-capsoul/', include('memory_room.apis.urls.time_capsoul'))


]
