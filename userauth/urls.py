
from django.urls import path, include
from django.urls import include, path, re_path


urlpatterns = [

    # --- authentication-apis ---
    path('', include('userauth.apis.urls.urls')), 

    # --- memory-room-apis ---
    path('', include('memory_room.urls')), 


]
