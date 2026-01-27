from django.urls import path
from family_tree.apis.views.gallery_media import ( 
    FamilyTreeGalaryView, FamilyTreeGallerySearchAPIView

)

urlpatterns = [
    path('<uuid:family_tree_id>/gallery-list/', FamilyTreeGalaryView.as_view(),),
    path("gallery/search/<uuid:family_tree_id>/", FamilyTreeGallerySearchAPIView.as_view()),


]
