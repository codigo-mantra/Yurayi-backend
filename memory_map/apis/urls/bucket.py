from django.urls import path
from memory_map.apis.views.bucket import BucketListCreateAPIView,BucketListAPIView

urlpatterns = [
    path("bucket/", BucketListCreateAPIView.as_view(), name="bucket-create"),
    path("bucket/list/", BucketListAPIView.as_view(), name="bucket-list"),

]

