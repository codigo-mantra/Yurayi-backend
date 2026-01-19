from django.urls import path

from family_tree.apis.views.family_tree  import (
    FamilyTreeUpdateAPIView,FamilyTreeCreateAPIView, AddFamilyMemberAPIView, FamilyTreeFilteredView, FamilyTreeListAPIView

)


urlpatterns = [
    path("create/new/family-tree/", FamilyTreeCreateAPIView.as_view(), name='user_family'),
    path("<str:family_tree_id>/add/new/member/", AddFamilyMemberAPIView.as_view(), name='add_member'),
    path("filter/<str:tree_id>/", FamilyTreeFilteredView.as_view(), name='user_family'),
    path("tree-list/", FamilyTreeListAPIView.as_view(), name='owner_family_tree'),
    path("<uuid:tree_id>/update/",FamilyTreeUpdateAPIView.as_view(),name="family-tree-update"),
]
