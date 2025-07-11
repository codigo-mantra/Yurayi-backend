
from django.urls import path, include
from django.urls import include, path, re_path


urlpatterns = [

    # --- memory-room-apis ---
    path('', include('memory_room.apis.urls.urls')), 

]
