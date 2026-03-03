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
from django.db.models import Q
import json
import time

from family_tree.utils.tree_filter import get_filtered_tree
from family_tree.utils.tree_hierarchy import get_full_hierarchy_from_member

from family_tree.models import FamilyTree, FamilyMember, ParentalRelationship,Partnership,FamilyTreeRecipient,UploadSession

from family_tree.apis.serializers.family_tree import (
    FamilyTreeNodeSerializer,FamilyTreeCreateSerializer, AddNewFamilyMemberSerializer, FamilyTreeSerializer,
    FamilyTreeRecipientBulkSerializer,FamilyTreeRecipientListSerializer, FamilyTreeRecipientManageSerializer,
    UploadSessionSerializer
)

from userauth.models import User
from django.http import StreamingHttpResponse
from django.core.cache import cache
from family_tree.tasks import process_encrypted_upload
import os 
from django.conf import settings
from django.utils.text import get_valid_filename


class FamilyTreeListAPIView(SecuredView):
    """Get all family tree members for the logged-in user"""


    def get(self, request):
        user = self.get_current_user(request)  
        owner_family_tree = FamilyTree.objects.filter(owner=user, is_deleted=False).order_by('-created_at')
        shared_trees = FamilyTree.objects.filter(
            family_tree_recipients__recipient_email=user.email,
            family_tree_recipients__is_deleted=False,
            is_deleted=False
        )
        combined_tree = owner_family_tree | shared_trees
        if not combined_tree:
            return Response([])

        serializer = FamilyTreeSerializer(combined_tree, many=True, context ={'user': user})
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
                profile_image=data.get("profile_image", None)
            )

            # Assign root member
            family_tree.root_member = family_member
            family_tree.save(update_fields=["root_member"])
            upload_sessions = []
            gallery_media = data.get("gallery_media",[])
            if gallery_media is not None:
                files = gallery_media if isinstance(gallery_media, list) else [gallery_media]
            else:
                files = []

            family_tree_obj = FamilyTree.objects.get(id=UUID(str(family_tree.id)))

            for file in files:
                if not file:
                    continue

                session = UploadSession.objects.create(
                    user=user,
                    member=family_member,
                    target_type="gallery_media",
                    status="pending",
                    family_tree=family_tree_obj,
                )
                upload_id = str(session.id)
                set_upload_filename(upload_id, get_valid_filename(file.name))
                temp_path = os.path.join(
                    settings.MEDIA_ROOT,
                    str(family_tree.id),
                    "temp_uploads",
                    upload_id,
                )
                os.makedirs(temp_path, exist_ok=True)

                file_path = os.path.join(temp_path, get_valid_filename(file.name))
                with open(file_path, "wb+") as destination:
                    for chunk in file.chunks():
                        destination.write(chunk)
                process_encrypted_upload.delay(upload_id)

                upload_sessions.append(session)
            session_serializer = UploadSessionSerializer(upload_sessions, many=True)
        return Response(
            {
                "family_tree_id": family_tree.id,
                "root_member_id": family_member.id,
                "upload_sesions": session_serializer.data
            },
            status=status.HTTP_201_CREATED
        )


class AddFamilyMemberAPIView(SecuredView):
    """Add new member in existing family tree and handle different relationships"""

    def post(self, request, family_tree_id):
        user = self.get_current_user(request)

        try:
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
        sessions = getattr(serializer, "_upload_sessions", None)
        session_serializer = UploadSessionSerializer(sessions, many = True)

        return Response({"message":"member created successfully","member_id":member.id,"upload_id":session_serializer.data}, status=status.HTTP_201_CREATED )


class FamilyTreeFilteredView(SecuredView):
    """
    Optimized Family Tree View with prefetched relationships
    Minimal database queries using relationship maps
    """

    def get(self, request, tree_id):
        try:
            UUID(str(tree_id))
        except (ValueError, TypeError):
            return Response("Invalid family tree id", status=status.HTTP_404_NOT_FOUND)

        user = self.get_current_user(request)
        view_type = request.GET.get("view_type", "all")

        if view_type not in ("all", "paternal", "maternal"):
            return Response(
                {"detail": "Invalid view_type. Must be 'all', 'paternal', or 'maternal'."},
                status=status.HTTP_400_BAD_REQUEST
            )

        try:
            family_tree = FamilyTree.objects.filter(
                    Q(id=tree_id, owner=user, is_deleted=False)
                    |
                    Q(
                        id=tree_id,
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
        except FamilyTree.DoesNotExist:
            pass

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
                members = get_full_hierarchy_from_member(start_member, family_tree, start_member.id)

            elif view_type == "paternal" and paternal_member:
                start_member = paternal_member
                members = get_full_hierarchy_from_member(start_member,family_tree, start_member.id)
       
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
        family_tree = FamilyTree.objects.filter(
                    Q(id=tree_id, owner=user, is_deleted=False)
                    |
                    Q(
                        id=tree_id,
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

        serializer = FamilyTreeUpdateSerializer(
            family_tree,
            data=request.data,
            partial=True,
            context={"user": user}
        )

        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_200_OK)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class FamilyTreeRecipientInviteAPIView(SecuredView):
    """
    Invite multiple recipients to a family tree
    """

    def get(self, request, family_tree_id):
        """Get all recipient of specific family-tree """
        user = self.get_current_user(request)
        family_tree = get_object_or_404(
            FamilyTree,
            id=family_tree_id,
            is_deleted=False,
            owner = user
        )
        tree_recipients = family_tree.family_tree_recipients.filter(is_deleted = False).order_by('-created_at')
        serializer =  FamilyTreeRecipientListSerializer(tree_recipients, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)
        

    def post(self, request, family_tree_id):
        """Add recipeints to family-tree"""
        user = self.get_current_user(request)
        family_tree = get_object_or_404(
            FamilyTree,
            id=family_tree_id,
            is_deleted=False,
            owner = user
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
        user = self.get_current_user(request)
        family_tree = get_object_or_404(
            FamilyTree,
            id=family_tree_id,
            is_deleted=False,
            owner = user
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
   

POLL_INTERVAL       = 1.0
SSE_TIMEOUT         = 600
PROGRESS_KEY_PREFIX = "upload_progress"
TERMINAL_STATUSES   = {"Aborted"}


def _get_redis_progress(uid: str) -> int:
    return cache.get(f"{PROGRESS_KEY_PREFIX}:{uid}", 0)


class UploadProgressSSEView(SecuredView):
    """
    SSE endpoint — streams progress for in-flight uploads only.

    GET /api/upload/progress/?session_ids=<id1>,<id2>,...

    Progress is read from Redis (updated per chunk — no DB hits).
    Status is read from DB (written only on transitions).

    When a session row disappears from DB it means the upload Completed
    and the row was deleted — the SSE sends one final 100% event and
    drops the session from the stream.

    Each event:
    {
        "sessionId": "<uuid>",
        "fileName":  "holiday.mp4",   // from Redis
        "status":    "Initialized" | "Pending" | "Uploading" | "Aborted" | "Completed",
        "progress":  0–100
    }

    Final event when all sessions are done:
    { "type": "done" }
    """
    def get(self, request):
        user = self.get_current_user(request)
        raw_ids     = request.GET.get("session_ids", "")
        session_ids = [s.strip() for s in raw_ids.split(",") if s.strip()]

        if not session_ids:
            return Response(
                {"detail": "session_ids query param is required."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        owned_ids = set(str(i) for i in UploadSession.objects.filter(
            id__in=session_ids, user=user
        ).values_list("id", flat=True))

        if not owned_ids:
            return Response(
                {"detail": "No matching sessions found."},
                status=status.HTTP_404_NOT_FOUND,
            )

        return StreamingHttpResponse(
            self._stream(list(owned_ids), user),
            content_type="text/event-stream",
            headers={
                "Cache-Control":     "no-cache",
                "X-Accel-Buffering": "no",
            },
        )

    @staticmethod
    def _event(payload: dict) -> str:
        return f"data: {json.dumps(payload)}\n\n"

    def _stream(self, session_ids: list[str], user):
        deadline   = time.time() + SSE_TIMEOUT
        active_ids = set(session_ids)

        yield ": heartbeat\n\n"

        while time.time() < deadline and active_ids:
            # Single DB query for all active sessions
            db_rows = UploadSession.objects.filter(
                id__in=active_ids, user=user
            ).only("id", "status")

            db_map = {str(r.id): r for r in db_rows}

            newly_finished = set()

            for sid in list(active_ids):
                progress = _get_redis_progress(sid)

                if sid not in db_map:
                    yield self._event({
                        "sessionId": sid,
                        "fileName":  _get_redis_filename(sid),
                        "status":    "Completed",
                        "progress":  100,
                    })
                    newly_finished.add(sid)
                    continue

                db_session = db_map[sid]
                db_status  = db_session.status

                if db_status == "Aborted":
                    yield self._event({
                        "sessionId": sid,
                        "fileName":  _get_redis_filename(sid),
                        "status":    "Aborted",
                        "progress":  progress,
                    })
                    newly_finished.add(sid)
                    continue

                # Clamp progress to the band that matches status
                if db_status == "Initialized":
                    progress = max(0,  min(progress, 4))
                elif db_status == "Pending":
                    progress = max(5,  min(progress, 9))
                elif db_status == "Uploading":
                    progress = max(10, min(progress, 95))

                yield self._event({
                    "sessionId": sid,
                    "fileName":  _get_redis_filename(sid),
                    "status":    db_status,
                    "progress":  progress,
                })

            active_ids -= newly_finished

            if not active_ids:
                yield self._event({"type": "done", "message": "All uploads finished."})
                return

            time.sleep(POLL_INTERVAL)

        yield self._event({"type": "timeout", "message": "SSE connection timed out."})


FILENAME_KEY_PREFIX = "upload_filename"
FILENAME_TTL        = 2 * 60 * 60


def set_upload_filename(upload_session_id: str, file_name: str):
    cache.set(f"{FILENAME_KEY_PREFIX}:{upload_session_id}", file_name, FILENAME_TTL)


def _get_redis_filename(upload_session_id: str) -> str:
    return cache.get(f"{FILENAME_KEY_PREFIX}:{upload_session_id}", "")

