from django.urls import path

from family_tree.apis.views.family_tree  import (
    FamilyTreeUpdateAPIView,FamilyTreeCreateAPIView, AddFamilyMemberAPIView, FamilyTreeFilteredView, FamilyTreeListAPIView,FamilyTreeRecipientInviteAPIView,
    UploadProgressSSEView, ReplaceExistingMemberAPIView, UpdatePartnerMaritalStatusApiView)

urlpatterns = [
    path("create/new/family-tree/", FamilyTreeCreateAPIView.as_view(), name='user_family'),
    path("tree-list/", FamilyTreeListAPIView.as_view(), name='owner_family_tree'),
    path("filter/<str:tree_id>/", FamilyTreeFilteredView.as_view(), name='user_family'),
    path("<str:family_tree_id>/add/new/member/", AddFamilyMemberAPIView.as_view(), name='add_member'),
    path("<uuid:tree_id>/update/",FamilyTreeUpdateAPIView.as_view(),name="family-tree-update"),
    path("<uuid:family_tree_id>/recipients/",FamilyTreeRecipientInviteAPIView.as_view(),name="family-tree-invite-recipients"),
    path("upload/progress/", UploadProgressSSEView.as_view(), name="member-gallery-upload-status"),   # ← new
    path("<str:family_tree_id>/member/replace/", ReplaceExistingMemberAPIView.as_view(), name = "replace-existing-member"),
    path("<str:family_tree_id>/partner/<str:parent_node_id>/status/", UpdatePartnerMaritalStatusApiView.as_view(), name ="update-parent-node-marital-status"),
]
