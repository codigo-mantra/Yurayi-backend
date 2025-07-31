from django.urls import path
from memory_room.apis.views.time_capsoul import (
    TimeCapSoulCoverView, TimeCapSoulDefaultTemplateAPI, CreateTimeCapSoulView,TimeCapSoulUpdationView,
    TimeCapSoulMediaFilesView, TimeCapSoulMediaFileUpdationView, TimeCapSoulUnlockView, MoveTimeCapSoulMediaFile,TimeCapSoulMediaFileDownloadView
)

urlpatterns = [
    path('', CreateTimeCapSoulView.as_view(), name='create_time_capsoul'),
    path('<int:time_capsoul_id>/unlock/', TimeCapSoulUnlockView.as_view(), name='unlock'),
    path('cover-images/', TimeCapSoulCoverView.as_view(), name='time_capsoul_cover_images'),
    path('default-templates/', TimeCapSoulDefaultTemplateAPI.as_view(), name='default_timecapsoul_templates'),
    path('<int:time_capsoul_id>/settings/updation/', TimeCapSoulUpdationView.as_view(), name='time_capsoul_updation'),
    path('<int:time_capsoul_id>/media/upload/', TimeCapSoulMediaFilesView.as_view(), name='time_capsoul_media_files'),
    path('<int:time_capsoul_id>/media/<int:media_file_id>/updation/', TimeCapSoulMediaFileUpdationView.as_view(), name='time_capsoul_media_files_updation'),
    path('<int:old_cap_soul_id>/media/<int:media_file_id>/move-to/<int:new_capsoul_id>/',MoveTimeCapSoulMediaFile.as_view(), name='move_timecapsoul_media_file'),
    path('<int:timecapsoul_id>/media/<int:media_file_id>/download/',TimeCapSoulMediaFileDownloadView.as_view(), name='download_timecapsoul_media')


]