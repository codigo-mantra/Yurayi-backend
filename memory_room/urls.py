
from django.urls import path, include
from django.urls import include, path, re_path
from .views import testing_view, S3FileUploadView, UploadFileView


urlpatterns = [
    path('testing/', testing_view, name='test'),
    # path('testing/upload/files/', UploadFileView, name='upload'),
    
    path('upload/', S3FileUploadView.as_view(), name='test'),


    # --- memory-room-apis ---
    path('', include('memory_room.apis.urls.urls')), 
    path('memory-rooms/', include('memory_room.apis.urls.memory_room')), 
    path('time-capsoul/', include('memory_room.apis.urls.time_capsoul')),
    
    # notification apis here
    path('', include('memory_room.apis.urls.notification'))
    
    


]
