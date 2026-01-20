
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from django.shortcuts import get_object_or_404
from userauth.apis.views.views import SecuredView

from family_tree.models import FamilyTreeDiaryCategory, FamilyTreeDiary, FamilyMember, FamilyTree
from family_tree.apis.serializers.family_tree_diary import FamilyTreeDiaryCategorySerializer, FamilyTreeDiarySerializer,FamilyTreeDiaryCreateSerializer,FamilyTreeDiaryUpdationSerializer


class FamilyTreeDiaryCategoryAPIView(APIView):

    def get(self, request):
        queryset = FamilyTreeDiaryCategory.objects.filter(is_deleted=False)
        serializer = FamilyTreeDiaryCategorySerializer(queryset, many=True)
        return Response(serializer.data)


class FamilyTreeDiaryAPIView(APIView):


    def get(self, request, family_tree_id):
        family_tree_diary = FamilyTreeDiary.objects.filter(
            is_deleted = False,
            family_tree__id = family_tree_id
        )
        serializer = FamilyTreeDiarySerializer(family_tree_diary, many=True)
        return Response(serializer.data)

    def post(self, request, family_tree_id):
        user = None
        family_tree = get_object_or_404(FamilyTree, id=family_tree_id, is_deleted=False)
        serializer = FamilyTreeDiaryCreateSerializer(data=request.data, context = {'user': user, 'family_tree': family_tree})
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class FamilyTreeDiaryUpdationView(APIView):
   
    def patch(self, request, tree_diary_id):
        tree_diary = get_object_or_404(
            FamilyTreeDiary,
            id=tree_diary_id,
            is_deleted=False
        )
        serializer = FamilyTreeDiaryUpdationSerializer(
            tree_diary,
            data=request.data,
            partial=True
        )
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request, tree_diary_id):
        tree_diary = get_object_or_404(
            FamilyTreeDiary,
            id=tree_diary_id,
            is_deleted=False
        )
        tree_diary.is_deleted =True
        tree_diary.save()
        return Response(status=status.HTTP_204_NO_CONTENT)
