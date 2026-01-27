from django.urls import path
from family_tree.apis.views.gallery_media import ( 
    FamilyTreeGalaryView

)

urlpatterns = [
    path('<uuid:family_tree>/gallery/media/list/', FamilyTreeGalaryView.as_view(),),

]
