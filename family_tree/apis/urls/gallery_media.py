from django.urls import path
from family_tree.apis.views.gallery_media import ( 
    FamilyTreeGalaryView, FamilyTreeGallerySearchAPIView,  FamilyTreeGalleryEditDeleteAPIView,FamilyTreeGalleryDownloadAPIView, ChunkedMediaFileUploadView
    ,ServeGalleryMedia,
)

urlpatterns = [
    path('<uuid:family_tree_id>/gallery-list/', FamilyTreeGalaryView.as_view(),),
    path("<uuid:family_tree_id>/gallery/search/", FamilyTreeGallerySearchAPIView.as_view()),
    path("<uuid:family_tree_id>/edit-gallery/<uuid:gallery_id>/", FamilyTreeGalleryEditDeleteAPIView.as_view()),
    path("<uuid:family_tree_id>/gallery/<uuid:media_id>/download/",FamilyTreeGalleryDownloadAPIView.as_view(),name="family-tree-gallery-download"),
    path(
        "<uuid:family_tree>/media/<str:action>/",
        ChunkedMediaFileUploadView.as_view(),
        name="chunked-media-upload"
    ),
      path(
        "gallery/<uuid:media_id>/stream/",
        ServeGalleryMedia.as_view(),
        name="serve-gallery-media",
    ),
]
