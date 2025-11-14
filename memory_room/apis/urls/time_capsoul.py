from django.urls import path
from memory_room.apis.views.time_capsoul import (
    TimeCapSoulCoverView, TimeCapSoulDefaultTemplateAPI, CreateTimeCapSoulView,TimeCapSoulUpdationView,
    TimeCapSoulMediaFilesView, TimeCapSoulMediaFileUpdationView, TimeCapSoulUnlockView, MoveTimeCapSoulMediaFile,TimeCapSoulMediaFileDownloadView,RecipientsDetailCreateOrUpdateView,TimeCapsoulMediaFileFilterView, TimeCapsoulFilterView,
    ServeTimeCapSoulMedia,SetTimeCapSoulCover,TaggedCapsoulTracker, UserStorageTracker, TimeCapsoulDuplicationApiView, ServeCoverTimecapsoulImages,
)

urlpatterns = [
    path('', CreateTimeCapSoulView.as_view(), name='create_time_capsoul'),
    path('<int:time_capsoul_id>/unlock/', TimeCapSoulUnlockView.as_view(), name='unlock'),
    path('duplicator/<int:time_capsoul_id>/', TimeCapsoulDuplicationApiView.as_view(), name='timecapsoul_duplicator'),
    
    path('cover-images/', TimeCapSoulCoverView.as_view(), name='time_capsoul_cover_images'),
    path('default-templates/', TimeCapSoulDefaultTemplateAPI.as_view(), name='default_timecapsoul_templates'),
    path('<int:time_capsoul_id>/settings/updation/', TimeCapSoulUpdationView.as_view(), name='time_capsoul_updation'),
    path('<int:time_capsoul_id>/media/upload/', TimeCapSoulMediaFilesView.as_view(), name='time_capsoul_media_files'),
    path('<int:time_capsoul_id>/media/<int:media_file_id>/updation/', TimeCapSoulMediaFileUpdationView.as_view(), name='time_capsoul_media_files_updation'),
    path('<int:old_cap_soul_id>/media/<int:media_file_id>/move-to/<int:new_capsoul_id>/',MoveTimeCapSoulMediaFile.as_view(), name='move_timecapsoul_media_file'),
    path('set-as-cover/media/<int:media_file_id>/<int:capsoul_id>/',SetTimeCapSoulCover.as_view(), name='set_as_cover'),
    path('<int:timecapsoul_id>/media/<int:media_file_id>/download/',TimeCapSoulMediaFileDownloadView.as_view(), name='download_timecapsoul_media'),
    path('<int:time_capsoul_id>/recipients/', RecipientsDetailCreateOrUpdateView.as_view(), name='recipients-crud'),
    path('media/filter/', TimeCapsoulMediaFileFilterView.as_view(), name='timecapsoul-media-filter'),
    path('filter/', TimeCapsoulFilterView.as_view(), name='timecapsoul-filter'),
    path("api/media/time-capsoul/<int:media_file_id>/serve/<path:s3_key>/", ServeTimeCapSoulMedia.as_view(), name="serve-media"),
    path("api/serve/cover-image/<int:cover_image_id>/",  ServeCoverTimecapsoulImages.as_view(), name="serve-media-list-view"),
    
    path('recipients/tracker/<int:capsoul_id>/', TaggedCapsoulTracker.as_view()),
    path('user/storage/tracker/', UserStorageTracker.as_view()),

    
]