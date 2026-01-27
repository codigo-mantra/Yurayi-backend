
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from django.shortcuts import get_object_or_404
from userauth.apis.views.views import SecuredView
from django.db.models import Q
from django.db.models.functions import Cast
from django.db import models
from userauth.models import User

from family_tree.utils.pagination import (
    FamilyTreeDiaryPagination
)
from family_tree.models import FamilyTreeDiaryCategory, FamilyTreeDiary, FamilyMember, FamilyTree
from family_tree.apis.serializers.family_tree_diary import FamilyTreeDiaryCategorySerializer, FamilyTreeDiarySerializer,FamilyTreeDiaryCreateSerializer,FamilyTreeDiaryUpdationSerializer

def user_has_tree_edit_permission(user, family_tree):
    """
    Returns True if user can EDIT this family tree
    """
    return FamilyTree.objects.filter(
        Q(id=family_tree.id, owner=user, is_deleted=False)
        |
        Q(
            id=family_tree.id,
            family_tree_recipients__recipient_email=user.email,
            family_tree_recipients__permissions="edit",
            family_tree_recipients__is_deleted=False,
            is_deleted=False
        )
    ).exists()


def get_test_user(email):
    return User.objects.get(email = email)

class FamilyTreeDiaryCategoryAPIView(SecuredView):

    def get(self, request):
        queryset = FamilyTreeDiaryCategory.objects.filter(is_deleted=False)
        serializer = FamilyTreeDiaryCategorySerializer(queryset, many=True)
        return Response(serializer.data)


class FamilyTreeDiaryAPIView(SecuredView):


    def get(self, request, family_tree_id):
        user = self.get_current_user(request)

        family_tree = FamilyTree.objects.filter(
            Q(id=family_tree_id, owner=user, is_deleted=False)
            |
            Q(
                id=family_tree_id,
                family_tree_recipients__recipient_email=user.email,
                family_tree_recipients__is_deleted=False,
                is_deleted=False
            )
        ).distinct().first()

        if not family_tree:
            return Response(
                {"detail": "You do not have access to this family tree."},
                status=status.HTTP_403_FORBIDDEN
            )

        queryset = family_tree.diaries.filter(is_deleted=False).order_by("-created_at")

        paginator = FamilyTreeDiaryPagination()
        page = paginator.paginate_queryset(queryset, request)

        serializer = FamilyTreeDiarySerializer(page, many=True)
        return paginator.get_paginated_response(serializer.data)

    def post(self, request, family_tree_id):
        """Create new diary via owner or shared member who have edit permisison """
        user = self.get_current_user(request)

        family_tree = FamilyTree.objects.filter(
                    Q(id=family_tree_id, owner=user, is_deleted=False)
                    |
                    Q(
                        id=family_tree_id,
                        family_tree_recipients__recipient_email=user.email,
                        family_tree_recipients__is_deleted=False,
                        family_tree_recipients__permissions='edit',
                        is_deleted=False
                    )
            ).distinct().first()

        if not family_tree:
            return Response(
                {"detail": "You do not have access to this family tree."},
                status=status.HTTP_403_FORBIDDEN
            )
        serializer = FamilyTreeDiaryCreateSerializer(data=request.data, context = {'user': user, 'family_tree': family_tree})
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class FamilyTreeDiaryUpdationView(SecuredView):
   
    def patch(self, request, tree_diary_id):
        user = self.get_current_user(request)
        tree_diary = get_object_or_404(
            FamilyTreeDiary,
            id=tree_diary_id,
            is_deleted=False
        )
        if not user_has_tree_edit_permission(user, tree_diary.family_tree):
            return Response(
                {"detail": "You do not have permission to edit this diary."},
                status=status.HTTP_403_FORBIDDEN
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
        user = self.get_current_user(request)
        tree_diary = get_object_or_404(
            FamilyTreeDiary,
            id=tree_diary_id,
            is_deleted=False
        )
        if not user_has_tree_edit_permission(user, tree_diary.family_tree):
            return Response(
                {"detail": "You do not have permission to edit this diary."},
                status=status.HTTP_403_FORBIDDEN
            )
        tree_diary.is_deleted =True
        tree_diary.save()
        return Response(status=status.HTTP_204_NO_CONTENT)
    

class FamilyTreeDiarySearchAPIView(SecuredView):
    """
    Case-insensitive paginated search API for FamilyTreeDiary
    """

    pagination_class = FamilyTreeDiaryPagination

    def get(self, request, family_tree_id):
        user = self.get_current_user(request)

        family_tree = FamilyTree.objects.filter(
            Q(id=family_tree_id, owner=user, is_deleted=False)
            |
            Q(
                id=family_tree_id,
                family_tree_recipients__recipient_email=user.email,
                family_tree_recipients__is_deleted=False,
                is_deleted=False
            )
        ).distinct().first()

        if not family_tree:
            return Response(
                {"detail": "You do not have access to this family tree."},
                status=status.HTTP_403_FORBIDDEN
            )

        #  Query params (all case-insensitive)
        keyword = request.query_params.get("query")
        category = request.query_params.get("category")
        author = request.query_params.get("author")
        created = request.query_params.get("created")  # YYYY / YYYY-MM / YYYY-MM-DD

        #  Base queryset
        queryset = family_tree.diaries.select_related(
            "category", "author"
        ).filter(is_deleted=False)

        #  Title + description
        if keyword:
            queryset = queryset.filter(
                Q(title__icontains=keyword) |
                Q(description__icontains=keyword)
            )

        # Category name contains
        if category:
            queryset = queryset.filter(
                category__name__icontains=category
            )

        #  Author name / username contains
        if author:
            queryset = queryset.filter(
                Q(author__first_name__icontains=author) |
                Q(author__last_name__icontains=author) |
                Q(author__username__icontains=author)
            )

        # created_at "date contains"
        if created:
            queryset = queryset.annotate(
                created_str=Cast("created_at", models.CharField())
            ).filter(created_str__icontains=created)

        queryset = queryset.order_by("-created_at")

        #  Pagination
        paginator = self.pagination_class()
        page = paginator.paginate_queryset(queryset, request)

        serializer = FamilyTreeDiarySerializer(page, many=True)
        return paginator.get_paginated_response(serializer.data)