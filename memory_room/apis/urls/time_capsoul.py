from django.urls import path
from memory_room.apis.views.time_capsoul import TimeCapSoulCoverView, TimeCapSoulDefaultTemplateAPI

urlpatterns = [
    path('cover-images/list/', TimeCapSoulCoverView.as_view(), name='time_capsoul_cover_images'),
    path('default-templates/list/', TimeCapSoulDefaultTemplateAPI.as_view(), name='default_timecapsoul_templates'),

]