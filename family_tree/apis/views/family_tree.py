from rest_framework.response import Response
from django.shortcuts import get_object_or_404
from uuid import UUID


from family_tree.apis.serializers.family_tree import (
    FamilyTreeUpdateSerializer,
)

from rest_framework import status
from rest_framework.response import Response
from django.db import transaction
from userauth.apis.views.views import SecuredView
from django.db.models import Q
from collections import defaultdict, deque
from rest_framework.views import APIView



from family_tree.utils.tree_filter import get_filtered_tree
from family_tree.utils.tree_hierarchy import get_full_hierarchy_from_member

from family_tree.models import FamilyTree, FamilyMember, ParentalRelationship,Partnership,FamilyTreeRecipient

from family_tree.apis.serializers.family_tree import (
    FamilyTreeNodeSerializer,FamilyTreeCreateSerializer, AddNewFamilyMemberSerializer, FamilyTreeSerializer,
    FamilyTreeRecipientBulkSerializer,FamilyTreeRecipientListSerializer, FamilyTreeRecipientManageSerializer
)

from userauth.models import User


class FamilyTreeListAPIView(SecuredView):
    """Get all family tree members for the logged-in user"""


    def get(self, request):
        user = self.get_current_user(request)  
        family_tree = FamilyTree.objects.filter(owner=user, is_deleted=False).order_by('-created_at')
        if not family_tree:
            return Response([])

        serializer = FamilyTreeSerializer(family_tree, many=True, context ={'user': user})
        return Response(serializer.data, status=status.HTTP_200_OK)


class FamilyTreeCreateAPIView(SecuredView):
    """Create new family tree"""

    def post(self, request):
        user = self.get_current_user(request)
        serializer = FamilyTreeCreateSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data

        # Check if tree already exists
        if FamilyTree.objects.filter(owner=user, is_deleted=False).exists():
            return Response(
                {"detail": "Family tree already exists."},
                status=status.HTTP_400_BAD_REQUEST
            )

        with transaction.atomic():
            # Create family tree
            family_tree = FamilyTree.objects.create(
                owner=user,
                is_deleted=False
            )

            # Create root member
            family_member = FamilyMember.objects.create(
                family_tree=family_tree,
                author=user,
                first_name=data.get("first_name"),
                last_name=data.get("last_name", ""),
                gender=data.get("gender"),
                is_married=data.get("is_married", False),
                married_date=data.get("married_date",None),
                is_person_alive=data.get("is_person_alive", True),
                death_date=data.get("death_date",None),
                email_address=data.get("email_address"),
                profession=data.get("profession", None),
                birth_date=data.get("birth_date"),
                profile_image_s3_key=data.get("profile_image_s3_key"),
            )

            # Assign root member
            family_tree.root_member = family_member
            family_tree.save(update_fields=["root_member"])

        return Response(
            {
                "family_tree_id": family_tree.id,
                "root_member_id": family_member.id,
            },
            status=status.HTTP_201_CREATED
        )


class AddFamilyMemberAPIView(SecuredView):
    """Add new member in existing family tree and handle different relationships"""

    def post(self, request, family_tree_id):
        user = self.get_current_user(request)

        try:
            family_tree = FamilyTree.objects.get(
                id=family_tree_id,
                owner=user,
                is_deleted=False
            )
        except FamilyTree.DoesNotExist:
            return Response(
                {"detail": "Family tree not found"},
                status=status.HTTP_404_NOT_FOUND
            )

        serializer = AddNewFamilyMemberSerializer(
            data=request.data,
            context={
                "family_tree": family_tree,
                "user": user
            }
        )
        serializer.is_valid(raise_exception=True)
        member = serializer.save()

        return Response( status=status.HTTP_201_CREATED )


class FamilyTreeFilteredView(SecuredView):
    """
    Optimized Family Tree View with prefetched relationships
    Minimal database queries using relationship maps
    """


    def get_full_hierarchy_from_member(self, start_member, family_tree, view_type="all"):
        """
        Returns hierarchy starting from a member.
        
        view_type:
            - all
            - maternal
            - paternal
        """

        visited = set()
        queue = deque([start_member])
        result = []

        while queue:
            member = queue.popleft()

            if not member or member.id in visited:
                continue

            visited.add(member.id)
            result.append(member)

            
            parent_rel = (
                ParentalRelationship.objects
                .filter(child=member, is_deleted=False, family_tree = family_tree)
                .select_related("father")
                .first()
            )

            if parent_rel:
                if view_type in ("all", "paternal") and parent_rel.father:
                    queue.append(parent_rel.father)

                if view_type in ("all", "maternal") and parent_rel.mother:
                    queue.append(parent_rel.mother)

            # =====================
            # Children
            # =====================
            if view_type == "maternal":
                children_rels = ParentalRelationship.objects.filter(
                    mother=member,
                    is_deleted=False
                    , family_tree = family_tree
                ).select_related("child")

            elif view_type == "paternal":
                children_rels = ParentalRelationship.objects.filter(
                    father=member,
                    is_deleted=False
                    , family_tree = family_tree
                ).select_related("child")

            else:  # all
                children_rels = ParentalRelationship.objects.filter(
                    Q(father=member) | Q(mother=member),
                    is_deleted=False
                    , family_tree = family_tree
                ).select_related("child")

            for rel in children_rels:
                queue.append(rel.child)

            # =====================
            # Spouse (always included)
            # =====================
            partnership = Partnership.objects.filter(
                Q(husband=member) | Q(wife=member),
                is_deleted=False
                , family_tree = family_tree
            ).select_related("husband", "wife").first()

            if partnership:
                spouse = partnership.wife if partnership.husband == member else partnership.husband
                queue.append(spouse)

            # =====================
            # Siblings (respect lineage)
            # =====================
            if parent_rel:
                sibling_filter = Q()

                if view_type in ("all", "paternal") and parent_rel.father:
                    sibling_filter |= Q(father=parent_rel.father)

                if view_type in ("all", "maternal") and parent_rel.mother:
                    sibling_filter |= Q(mother=parent_rel.mother)

                sibling_rels = ParentalRelationship.objects.filter(
                    sibling_filter,
                    is_deleted=False
                    , family_tree = family_tree
                ).exclude(child=member).select_related("child")

                for rel in sibling_rels:
                    queue.append(rel.child)

        return result

    def get(self, request, tree_id):

        try:
            UUID(str(tree_id))
        except (ValueError, TypeError):
            return Response("Invalid family tree id", status=status.HTTP_404_NOT_FOUND)

        view_type = request.GET.get("view_type", "all")

        if view_type not in ("all", "paternal", "maternal"):
            return Response(
                {"detail": "Invalid view_type. Must be 'all', 'paternal', or 'maternal'."},
                status=status.HTTP_400_BAD_REQUEST
            )

        try:
            family_tree = FamilyTree.objects.select_related("root_member").get(
                id=tree_id,
                is_deleted=False
            )
        except FamilyTree.DoesNotExist:
            return Response(
                {"detail": "Family tree not found"},
                status=status.HTTP_404_NOT_FOUND
            )

        if not family_tree.root_member:
            return Response(
                {"detail": "Root member not assigned to tree"},
                status=status.HTTP_400_BAD_REQUEST
            )
        members = [family_tree.root_member]

        if view_type == 'all':
                members = get_full_hierarchy_from_member(family_tree.root_member, family_tree,view_type)

        else:
            root_member = family_tree.root_member

            paternal_member = root_member.primary_father
            maternal_member = root_member.primary_mother

            if view_type == 'maternal' and not maternal_member and paternal_member:
                partnership =  family_tree.partnerships.filter(husband = paternal_member,is_deleted = False).first()

                if partnership and partnership.wife:
                    maternal_member = partnership.wife
           
            elif view_type =='paternal' and not paternal_member and maternal_member:
                partnership =  family_tree.partnerships.filter(wife = maternal_member,is_deleted = False).first()

                if partnership and partnership.husband:
                    paternal_member = partnership.husband


            if view_type == "maternal" and  maternal_member:
                start_member = maternal_member
                members = get_full_hierarchy_from_member(start_member, family_tree,view_type)

            elif view_type == "paternal" and paternal_member:
                start_member = paternal_member
                members = get_full_hierarchy_from_member(start_member,family_tree, view_type)
       
        serializer = FamilyTreeNodeSerializer(
            members,
            many=True,
            context={
                "root_node_id": family_tree.get_root_node_id(),
                "view_type": view_type,
                "family_tree": family_tree,
            },
        )

        return Response(serializer.data, status=status.HTTP_200_OK)


class FamilyTreeUpdateAPIView(SecuredView):

    def patch(self, request, tree_id):
        user = self.get_current_user(request)
        tree = get_object_or_404(
            FamilyTree,
            id=tree_id,
            owner = user,
            is_deleted=False
        )

        serializer = FamilyTreeUpdateSerializer(
            tree,
            data=request.data,
            partial=True,
            context={"user": user}
        )

        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_200_OK)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class FamilyTreeRecipientInviteAPIView(APIView):
    """
    Invite multiple recipients to a family tree
    """

    def get(self, request, family_tree_id):
        """Get all recipient of specific family-tree """
        family_tree = get_object_or_404(
            FamilyTree,
            id=family_tree_id,
            is_deleted=False
        )
        tree_recipients = family_tree.family_tree_recipients.filter(is_deleted = False).order_by('-created_at')
        serializer =  FamilyTreeRecipientListSerializer(tree_recipients, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)
        

    def post(self, request, family_tree_id):
        """Add recipeints to family-tree"""
        family_tree = get_object_or_404(
            FamilyTree,
            id=family_tree_id,
            is_deleted=False
        )

        serializer = FamilyTreeRecipientBulkSerializer(
            data=request.data,
            context={
                "family_tree": family_tree,
                "request": request
            }
        )
        serializer.is_valid(raise_exception=True)
        serializer.save()

        return Response(
            {
                "message": "Invitations sent successfully"
            },
            status=status.HTTP_201_CREATED
        )
    
    def patch(self, request, family_tree_id):
        family_tree = get_object_or_404(
            FamilyTree,
            id=family_tree_id,
            is_deleted=False
        )

        serializer = FamilyTreeRecipientManageSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        recipient_payloads = serializer.validated_data["recipients"]

        recipient_ids = [item["recipient_id"] for item in recipient_payloads]
        recipients_qs = family_tree.family_tree_recipients.filter(is_deleted =False)


        recipients_map = {r.id: r for r in recipients_qs}

        updated_ids = []
        removed_ids = []
        recipients_to_update = []

        for item in recipient_payloads:
            recipient = recipients_map.get(item["recipient_id"])
            if not recipient:
                continue  # or raise error if you want strict validation

            if item["operation"] == "update":
                recipient.permissions = item["permissions"]
                # recipient.is_deleted = False
                updated_ids.append(recipient.id)
                recipient.save()

            elif item["operation"] == "remove":
                recipient.is_deleted = True

                removed_ids.append(recipient.id)

            recipients_to_update.append(recipient)

        if recipients_to_update:
            FamilyTreeRecipient.objects.bulk_update(
                recipients_to_update,
                fields=["permissions", "is_deleted"]
            )

        return Response(
            {
                "message": "Recipients processed successfully",
                "updated_ids": updated_ids,
                "removed_ids": removed_ids
            },
            status=status.HTTP_200_OK
        )
   