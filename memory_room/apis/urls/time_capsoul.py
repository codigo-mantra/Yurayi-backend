from django.urls import path
from memory_room.apis.views.time_capsoul import (
    TimeCapSoulCoverView, TimeCapSoulDefaultTemplateAPI, CreateTimeCapSoulView,
)

urlpatterns = [
    path('cover-images/', TimeCapSoulCoverView.as_view(), name='time_capsoul_cover_images'),
    path('default-templates/', TimeCapSoulDefaultTemplateAPI.as_view(), name='default_timecapsoul_templates'),
    path('create/time-capsoul/', CreateTimeCapSoulView.as_view(), name='create_time_capsoul'),

]