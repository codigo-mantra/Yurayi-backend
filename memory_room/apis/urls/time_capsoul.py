from django.urls import path
from memory_room.apis.views.time_capsoul import (
    TimeCapSoulCoverView, TimeCapSoulDefaultTemplateAPI, CreateTimeCapSoulView,TimeCapSoulUpdationView,
    TimeCapSoulMediaFilesView, TimeCapSoulMediaFileUpdationView
)

urlpatterns = [
    path('', CreateTimeCapSoulView.as_view(), name='create_time_capsoul'),
    path('cover-images/', TimeCapSoulCoverView.as_view(), name='time_capsoul_cover_images'),
    path('default-templates/', TimeCapSoulDefaultTemplateAPI.as_view(), name='default_timecapsoul_templates'),
    path('<int:time_capsoul_id>/settings/updation/', TimeCapSoulUpdationView.as_view(), name='time_capsoul_updation'),
    path('<int:time_capsoul_id>/media-file/upload/', TimeCapSoulMediaFilesView.as_view(), name='time_capsoul_media_files'),
    path('<int:time_capsoul_id>/media-file/<int:media_file_id>/updation/', TimeCapSoulMediaFileUpdationView.as_view(), name='time_capsoul_media_files_updation'),

]