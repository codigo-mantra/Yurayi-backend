import os
import json
import time
import uuid
import threading
from django.conf import settings
from django.http import JsonResponse, StreamingHttpResponse
from django.core.cache import cache
from django.core.files.base import ContentFile
from django.shortcuts import get_object_or_404
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

from rest_framework import status
from rest_framework.views import APIView
from rest_framework.response import Response

from userauth.models import User
from django.db.models.functions import Cast
from userauth.apis.views.views import SecuredView

from family_tree.models import FamilyTree, FamilyTreeGallery
from django.db.models import Q
from django.db import models


from memory_room.utils import get_file_category
from family_tree.apis.serializers.galery_media import FamilyTreeGallerySerializer, GalleryUpdateSerializer
from memory_room.upload_helper import ChunkedUploadSession,truncate_filename, s3, kms, AWS_KMS_KEY_ID

from family_tree.utils.pagination import FamilyTreeGalleryPagination

email = 'krishna234@gmail.com'
def get_current_user(email):
    return User.objects.get(email = email)
    

from family_tree.apis.views.family_tree_diary import user_has_tree_edit_permission

def get_local_upload_path(family_tree_id, upload_id, filename):
    return os.path.join(
        settings.MEDIA_ROOT,
        "media_uploads",
        str(family_tree_id),
        upload_id,
        filename
    )


def ensure_dir(path):
    os.makedirs(os.path.dirname(path), exist_ok=True)


def get_family_tree(user, family_tree_id):
    """
    Returns True if user can EDIT this family tree
    """
    family_tree =  FamilyTree.objects.filter(
        Q(id=family_tree_id, owner=user, is_deleted=False)
        |
        Q(
            id=family_tree_id,
            family_tree_recipients__recipient_email=user.email,
            family_tree_recipients__permissions="edit",
            family_tree_recipients__is_deleted=False,
            is_deleted=False
        )
    ).first()
    return family_tree



class ChunkedMediaFileUploadView(APIView):

    CACHE_PREFIX = "chunked_upload"
    SESSION_TIMEOUT = 3600
    MAX_CHUNK_SIZE = 50 * 1024 * 1024
    SMALL_FILE_THRESHOLD = 5 * 1024 * 1024

    def _key(self, upload_id):
        return f"{self.CACHE_PREFIX}:{upload_id}"

    def _percent(self, value):
        try:
            return int(min(max(round(float(value)), 0), 100))
        except Exception:
            return 0

    def get_session(self, upload_id):
        data = cache.get(self._key(upload_id))
        return ChunkedUploadSession.from_dict(json.loads(data)) if data else None

    def save_session(self, session):
        session.last_activity = time.time()
        cache.set(
            self._key(session.upload_id),
            json.dumps(session.to_dict()),
            self.SESSION_TIMEOUT
        )

    def delete_session(self, upload_id):
        cache.delete(self._key(upload_id))

    # ----------------------------------------------------
    # MAIN ENTRY
    # ----------------------------------------------------
    def post(self, request, family_tree, action):
        # user = self.get_current_user(request)
        user = get_current_user(email)

        family_tree = get_object_or_404(FamilyTree, id=family_tree)
        if not user_has_tree_edit_permission(user, family_tree):
            return Response(
                {"detail": "You do not have permission to edit this diary."},
                status=status.HTTP_403_FORBIDDEN
            )

        if action == "init":
            return self.initialize_uploads(request, user, family_tree)
        if action == "upload":
            return self.upload_chunk(request, user)
        if action == "complete":
            return self.complete_upload_streaming(request, user, family_tree)
        if action == "abort":
            return self.abort_upload(request, user)

        return JsonResponse({"error": "Invalid action"}, status=400)

    # ----------------------------------------------------
    # INIT
    # ----------------------------------------------------
    def initialize_uploads(self, request, user, family_tree):
        files_data = json.loads(request.POST.get("filesData", "[]"))
        if not files_data:
            return JsonResponse({"error": "No files provided"}, status=400)

        initialized_files = []

        for file_data in files_data:
            file_name = file_data["fileName"]
            file_size = int(file_data["fileSize"])
            total_chunks = int(file_data["totalChunks"])
            chunk_size = int(file_data["chunkSize"])

            upload_id = str(uuid.uuid4())
            clean_name = file_name.replace(" ", "_")

            local_path = get_local_upload_path(
                family_tree.id, upload_id, clean_name
            )

            session = ChunkedUploadSession(
                upload_id=upload_id,
                user_id=user.id,
                time_capsoul_id=family_tree.id,
                file_name=clean_name,
                file_size=file_size,
                file_type=get_file_category(clean_name),
                total_chunks=total_chunks,
                chunk_size=chunk_size,
                s3_key=None,  # unused in local
            )

            session.local_path = local_path
            session.temp_file_path = f"{local_path}.part"
            session.is_small_file = file_size < self.SMALL_FILE_THRESHOLD

            ensure_dir(session.temp_file_path)

            self.save_session(session)

            initialized_files.append({
                "uploadId": upload_id,
                "fileName": file_name,
                "totalChunks": total_chunks,
                "percentage": 5,
            })

        return JsonResponse({"files": initialized_files})

    # ----------------------------------------------------
    # CHUNK UPLOAD
    # ----------------------------------------------------
    def upload_chunk(self, request, user):
        upload_id = request.POST.get("uploadId")
        chunk_index = int(request.POST.get("chunkIndex", -1))
        chunk_file = request.FILES.get("chunk")
        iv = request.POST.get("iv")

        if not upload_id or not chunk_file:
            return JsonResponse({"error": "Invalid chunk"}, status=400)

        def stream():
            session = self.get_session(upload_id)
            if not session:
                yield self._event(upload_id, "error", 0, "Session expired")
                return

            decrypted = self._decrypt_chunk(chunk_file, iv)

            ensure_dir(session.temp_file_path)
            with open(session.temp_file_path, "ab") as f:
                f.write(decrypted)

            with session.lock:
                session.uploaded_chunks.add(chunk_index)

            self.save_session(session)

            percent = (len(session.uploaded_chunks) / session.total_chunks) * 90
            yield self._event(upload_id, "uploaded", self._percent(percent))

        return StreamingHttpResponse(
            stream(),
            content_type="text/event-stream",
            headers={"Cache-Control": "no-cache"}
        )

    # ----------------------------------------------------
    # COMPLETE
    # ----------------------------------------------------
    def complete_upload_streaming(self, request, user, family_tree):
        upload_ids = request.POST.getlist("uploadIds[]")

        def stream():
            for upload_id in upload_ids:
                session = self.get_session(upload_id)
                if not session:
                    yield self._event(upload_id, "error", 0)
                    continue

                final_path = session.local_path
                temp_path = session.temp_file_path

                with open(temp_path, "rb") as f:
                    content = ContentFile(f.read(), name=os.path.basename(final_path))

                media = FamilyTreeGallery.objects.create(
                    author=user,
                    family_tree=family_tree,
                    title=session.file_name,
                    file_size=session.file_size,
                    file_type=session.file_type,
                )

                media.file.save(
                    os.path.basename(final_path),
                    content,
                    save=True
                )

                os.remove(temp_path)
                self.delete_session(upload_id)

                yield self._event(upload_id, "complete", 100)

        return StreamingHttpResponse(
            stream(),
            content_type="text/event-stream",
            headers={"Cache-Control": "no-cache"}
        )

    # ----------------------------------------------------
    # ABORT
    # ----------------------------------------------------
    def abort_upload(self, request, user):
        upload_id = request.POST.get("uploadId")
        session = self.get_session(upload_id)

        if session and os.path.exists(session.temp_file_path):
            os.remove(session.temp_file_path)

        self.delete_session(upload_id)
        return JsonResponse({"status": "aborted"})

    # ----------------------------------------------------
    # HELPERS
    # ----------------------------------------------------
    def _event(self, upload_id, stage, percentage, error=None):
        payload = {
            "uploadId": upload_id,
            "stage": stage,
            "percentage": percentage
        }
        if error:
            payload["error"] = error
        return f"data: {json.dumps(payload)}\n\n"

    def _decrypt_chunk(self, chunk_file, iv_str):
        iv = bytes.fromhex(iv_str)
        encrypted = chunk_file.read()

        key = settings.ENCRYPTION_KEY
        cipher = Cipher(
            algorithms.AES(key),
            modes.GCM(iv, encrypted[-16:]),
            backend=default_backend()
        )
        decryptor = cipher.decryptor()
        return decryptor.update(encrypted[:-16]) + decryptor.finalize()


class FamilyTreeGalaryView(SecuredView):
    pagination_class = FamilyTreeGalleryPagination

    def get(self, request, family_tree_id):
        user = self.get_current_user(request)

        family_tree = get_family_tree(
            user=user,
            family_tree_id=family_tree_id
        )

        if not family_tree:
            return Response(
                {"detail": "You do not have permission to access this gallery."},
                status=status.HTTP_403_FORBIDDEN
            )

        queryset = family_tree.gallery_items.filter(
            is_deleted=False
        ).order_by("-created_at")

        paginator = self.pagination_class()
        page = paginator.paginate_queryset(queryset, request)

        serializer = FamilyTreeGallerySerializer(page, many=True)
        return paginator.get_paginated_response(serializer.data)


class FamilyTreeGallerySearchAPIView(SecuredView):
    """
    Case-insensitive paginated search API for FamilyTreeGallery
    """

    pagination_class = FamilyTreeGalleryPagination

    def get(self, request, family_tree_id):
        user = self.get_current_user(request)

        family_tree = get_family_tree(
            user=user,
            family_tree_id=family_tree_id
        )

        if not family_tree:
            return Response(
                {"detail": "You do not have access to this family tree."},
                status=status.HTTP_403_FORBIDDEN
            )

        # ---- Query params ----
        keyword = request.query_params.get("query")
        file_type = request.query_params.get("file_type")   
        author = request.query_params.get("author")
        created = request.query_params.get("created")       

        # ---- Base queryset ----
        queryset = family_tree.gallery_items.select_related(
            "author"
        ).filter(is_deleted=False)

        # ---- Title + description search ----
        if keyword:
            queryset = queryset.filter(
                Q(title__icontains=keyword) |
                Q(description__icontains=keyword)
            )

        # ---- File type filter ----
        if file_type:
            queryset = queryset.filter(file_type__iexact=file_type)

        # ---- Author name / email ----
        if author:
            queryset = queryset.filter(
                Q(author__first_name__icontains=author) |
                Q(author__last_name__icontains=author) |
                Q(author__email__icontains=author)
            )

        # ---- Created date (string contains) ----
        if created:
            queryset = queryset.annotate(
                created_str=Cast("created_at", models.CharField())
            ).filter(created_str__icontains=created)

        queryset = queryset.order_by("-created_at")

        # ---- Pagination ----
        paginator = self.pagination_class()
        page = paginator.paginate_queryset(queryset, request)

        serializer = FamilyTreeGallerySerializer(page, many=True)
        return paginator.get_paginated_response(serializer.data)



class FamilyTreeGalleryEditDeleteAPIView(SecuredView):
    """
    PUT / PATCH -> Edit gallery metadata
    DELETE      -> Soft delete gallery item
    """

    def delete(self, request, family_tree_id, gallery_id):
        user = get_current_user(email)

        family_tree = get_family_tree(
            user=user,
            family_tree_id=family_tree_id
        )

        if not family_tree:
            return Response(
                {"detail": "You do not have permission to delete this gallery."},
                status=status.HTTP_403_FORBIDDEN
            )

        gallery = family_tree.gallery_items.filter(is_deleted = False, family_tree = family_tree, id = gallery_id).first()
        gallery.is_deleted = True
        gallery.save()

        return Response(
            {"detail": "Gallery item deleted successfully."},
            status=status.HTTP_204_NO_CONTENT
        )
    
    def patch(self, request, family_tree_id, gallery_id):
        user = get_current_user(email)

        family_tree = get_family_tree(
            user=user,
            family_tree_id=family_tree_id
        )

        if not family_tree:
            return Response(
                {"detail": "You do not have permission to delete this gallery."},
                status=status.HTTP_403_FORBIDDEN
            )

        gallery = family_tree.gallery_items.filter(is_deleted = False, family_tree = family_tree, id = gallery_id).first()
        serializer = GalleryUpdateSerializer(gallery, data = request.data, partial = True)
        serializer.is_valid(raise_exception=True)
        serializer.save()

        return Response(
            {"detail": "Gallery item deleted successfully."},
            status=status.HTTP_204_NO_CONTENT,
        )