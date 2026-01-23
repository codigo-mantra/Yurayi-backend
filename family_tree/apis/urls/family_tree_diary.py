# familytree/urls/diary_urls.py
from django.urls import path
from family_tree.apis.views.family_tree_diary import (
    FamilyTreeDiaryAPIView,  FamilyTreeDiaryCategoryAPIView, FamilyTreeDiaryCategoryAPIView, FamilyTreeDiaryUpdationView,
    FamilyTreeDiarySearchAPIView,
)

urlpatterns = [
    path("diary-categories/", FamilyTreeDiaryCategoryAPIView.as_view()),
    path("<uuid:family_tree_id>/diaries/", FamilyTreeDiaryAPIView.as_view()),
    path("diary/updation/<uuid:tree_diary_id>/", FamilyTreeDiaryUpdationView.as_view()),
    path("diary/search/<uuid:family_tree_id>/", FamilyTreeDiarySearchAPIView.as_view()),
]

