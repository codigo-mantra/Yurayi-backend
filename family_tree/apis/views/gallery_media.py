import os
import mimetypes
import json
import time
import uuid
import threading
from django.conf import settings
from django.http import FileResponse, Http404, HttpResponse
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
import struct

from memory_room.utils import get_file_category
from family_tree.apis.serializers.galery_media import FamilyTreeGallerySerializer, GalleryUpdateSerializer
# from memory_room.upload_helper import ChunkedUploadSession,truncate_filename, s3, kms, AWS_KMS_KEY_ID
from timecapsoul.utils import MediaThumbnailExtractor
from family_tree.utils.pagination import FamilyTreeGalleryPagination
from family_tree.utils.upload_helper import ChunkedUploadSession


email = 'krishna234@gmail.com'
def get_current_user(email):
    """Method to getting the test user"""
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
    Returns owner or shared family tree if user has permission
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



def get_shared_family_tree(user, family_tree_id):
    """
    Returns shared family tree
    """
    family_tree =  FamilyTree.objects.filter(
        Q(id=family_tree_id, owner=user, is_deleted=False)
        |
        Q(
            id=family_tree_id,
            family_tree_recipients__recipient_email=user.email,
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
        key = self._key(upload_id)
        data = cache.get(key)
        return ChunkedUploadSession.from_dict(json.loads(data)) if data else None

    def save_session(self, session):
        session.last_activity = time.time()
        key = self._key(str(session.upload_id))
        cache.set(
            key,
            json.dumps(session.to_dict(), default=str),
            self.SESSION_TIMEOUT
        )

    def delete_session(self, upload_id):
        cache.delete(self._key(str(upload_id)))


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
                gallery_media_id=family_tree.id,
                file_name=clean_name,
                file_size=file_size,
                file_type=get_file_category(clean_name),
                total_chunks=total_chunks,
                chunk_size=chunk_size,
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
            encrypted = chunk_file.read()
            ensure_dir(session.temp_file_path)
            with open(session.temp_file_path, "ab") as f:
                f.write(bytes.fromhex(iv))
                f.write(struct.pack(">I", len(encrypted)))
                f.write(encrypted)   

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
        from django.core.files import File
        upload_ids = request.POST.getlist("uploadIds[]")

        def stream():
            for upload_id in upload_ids:
                session = self.get_session(upload_id)
                if not session:
                    yield self._event(upload_id, "error", 0)
                    continue

                final_path = session.local_path
                temp_path = session.temp_file_path

                os.replace(temp_path, final_path)

                media = FamilyTreeGallery.objects.create(
                    author=user,
                    family_tree=family_tree,
                    title=session.file_name,
                    file_size=session.file_size,
                    file_type=session.file_type,
                )

                media.file.save(
                    os.path.basename(final_path),
                    File(open(final_path, "rb")),
                    save=True
                )

                extension = os.path.splitext(final_path)[1].lower()
                from family_tree.utils.upload_helper import UniversalThumbnailService
                # MIN_PREVIEW_BYTES = 1024 * 1024

                # chunks = []
                # total = 0
                # for chunk in self.decrypt_full_file(final_path):
                #     chunks.append(chunk)
                #     total += len(chunk)

                #     if total >= MIN_PREVIEW_BYTES:
                #         break
                # decrypted_preview = b"".join(chunks)

                thumbnail_bytes = UniversalThumbnailService.generate(
                    final_path,
                    self.decrypt_full_file,
                    extension=extension
                )
                # print(decrypted_preview[:10])
                # print(decrypted_preview[-10:])
                # print("Preview size:", len(decrypted_preview))
                # print("Thumbnail bytes:", thumbnail_bytes)

                if thumbnail_bytes:
                    media.thumbnail_preview.save(
                        f"{upload_id}_thumb.jpg",
                        ContentFile(thumbnail_bytes),
                        save=True
                    )

                # os.remove(temp_path)
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
    

        



    def decrypt_full_file(self, file_path):

        import struct

        key = settings.ENCRYPTION_KEY

        with open(file_path, "rb") as f:

            while True:

                iv = f.read(12)
                if not iv:
                    break

                length_bytes = f.read(4)
                if not length_bytes:
                    break

                encrypted_length = struct.unpack(">I", length_bytes)[0]

                encrypted = f.read(encrypted_length)

                tag = encrypted[-16:]
                ciphertext = encrypted[:-16]

                cipher = Cipher(
                    algorithms.AES(key),
                    modes.GCM(iv, tag),
                    backend=default_backend()
                )

                decryptor = cipher.decryptor()

                yield decryptor.update(ciphertext) + decryptor.finalize()


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
    

class FamilyTreeGalleryDownloadAPIView(SecuredView):
    """
    Securely download gallery media files with progress support
    """

    CHUNK_SIZE = 1024 * 1024  # 1 MB

    # ------------------------------------------------------------
    # Stream decrypted chunks (memory safe)
    # ------------------------------------------------------------
    def _stream_decrypted_chunks(self, file_path):
        key = settings.ENCRYPTION_KEY

        with open(file_path, "rb") as f:

            while True:
                iv = f.read(12)
                if not iv:
                    break

                size_data = f.read(4)
                if not size_data:
                    break

                encrypted_size = struct.unpack(">I", size_data)[0]
                encrypted = f.read(encrypted_size)
                tag = encrypted[-16:]
                ciphertext = encrypted[:-16]

                cipher = Cipher(
                    algorithms.AES(key),
                    modes.GCM(iv, tag),
                    backend=default_backend()
                )

                decryptor = cipher.decryptor()

                decrypted = decryptor.update(ciphertext) + decryptor.finalize()
                offset = 0
                total = len(decrypted)

                while offset < total:
                    yield decrypted[offset:offset+self.DOWNLOAD_CHUNK_SIZE]
                    offset += self.DOWNLOAD_CHUNK_SIZE
                    time.sleep(0.01)  
                    
    # ------------------------------------------------------------
    # Calculate decrypted size (for progress bar support)
    # ------------------------------------------------------------
    def _get_decrypted_file_size(self, file_path):

        key = settings.ENCRYPTION_KEY
        total_size = 0

        with open(file_path, "rb") as f:

            while True:

                iv = f.read(12)
                if not iv:
                    break

                size_data = f.read(4)
                if not size_data:
                    break

                encrypted_size = struct.unpack(">I", size_data)[0]

                encrypted = f.read(encrypted_size)

                tag = encrypted[-16:]
                ciphertext = encrypted[:-16]

                cipher = Cipher(
                    algorithms.AES(key),
                    modes.GCM(iv, tag),
                    backend=default_backend()
                )

                decryptor = cipher.decryptor()

                decrypted = decryptor.update(ciphertext) + decryptor.finalize()

                total_size += len(decrypted)

        return total_size


    # ------------------------------------------------------------
    # Main GET endpoint
    # ------------------------------------------------------------
    def get(self, request, family_tree_id, media_id):
        user = self.get_current_user(request)

        if not user:
            return Response(status=status.HTTP_401_UNAUTHORIZED)


        family_tree = get_shared_family_tree(
            user=user,
            family_tree_id=family_tree_id
        )

        if not family_tree:
            return Response(
                {"detail": "You do not have permission to access this gallery."},
                status=status.HTTP_403_FORBIDDEN
            )

        try:
            media = FamilyTreeGallery.objects.get(
                id=media_id,
                family_tree=family_tree,
                is_deleted=False
            )

        except FamilyTreeGallery.DoesNotExist:
            raise Http404("Media file not found")

        if not media.file:
            raise Http404("File not available")

        file_path = media.file.path
        if not os.path.exists(file_path):
            raise Http404("File missing on server")

        # file_size = os.path.getsize(file_path)
        filename = os.path.basename(file_path)

        content_type, _ = mimetypes.guess_type(filename)
        content_type = content_type or "application/octet-stream"

        file_size = self._get_decrypted_file_size(file_path)

        response = StreamingHttpResponse(
            streaming_content=self._stream_decrypted_chunks(file_path),
            content_type=content_type
        )

        response["Content-Disposition"] = f'attachment; filename="{filename}"'
        response["Content-Length"] = str(file_size)
        response["Cache-Control"] = "no-cache, no-store, must-revalidate"
        response["X-Content-Type-Options"] = "nosniff"
        response["Access-Control-Expose-Headers"] = (
            "Content-Length, Content-Disposition"
        )

        return response



class ServeGalleryMedia(SecuredView):
    """
    Securely stream decrypted gallery media with range support
    """

    CACHE_TIMEOUT = 60 * 60 * 24 * 7
    STREAMING_CHUNK_SIZE = 64 * 1024

    IMAGE_EXTENSIONS = {'.jpg', '.jpeg', '.png', '.gif', '.webp'}
    VIDEO_EXTENSIONS = {'.mp4', '.webm', '.mov', '.mkv'}
    AUDIO_EXTENSIONS = {'.mp3', '.wav', '.aac', '.ogg'}

    # -------------------------
    # HELPERS
    # -------------------------

    def _get_extension(self, filename):
        return '.' + filename.lower().rsplit('.', 1)[-1] if '.' in filename else ''

    def _categorize(self, filename):
        ext = self._get_extension(filename)

        if ext in self.IMAGE_EXTENSIONS:
            return "image"

        if ext in self.VIDEO_EXTENSIONS:
            return "video"

        if ext in self.AUDIO_EXTENSIONS:
            return "audio"

        return "other"

    def _guess_type(self, filename):
        import mimetypes
        content_type, _ = mimetypes.guess_type(filename)
        return content_type or "application/octet-stream"

    # -------------------------
    # RANGE STREAMING
    # -------------------------

    def _stream_bytes(self, request, file_bytes, content_type, filename):

        file_size = len(file_bytes)
        range_header = request.headers.get("Range")

        if range_header:
            import re
            m = re.match(r"bytes=(\d+)-(\d*)", range_header)
            start = int(m.group(1))
            end = int(m.group(2)) if m.group(2) else file_size - 1
            status = 206
        else:
            start = 0
            end = file_size - 1
            status = 200

        end = min(end, file_size - 1)

        def stream():
            pos = start
            while pos <= end:
                chunk_end = min(pos + self.STREAMING_CHUNK_SIZE, end + 1)
                yield file_bytes[pos:chunk_end]
                pos = chunk_end

        response = StreamingHttpResponse(
            stream(),
            status=status,
            content_type=content_type
        )

        response["Accept-Ranges"] = "bytes"
        response["Content-Length"] = str(end - start + 1)

        if status == 206:
            response["Content-Range"] = f"bytes {start}-{end}/{file_size}"

        response["Content-Disposition"] = "inline"
        response["Cache-Control"] = "no-store"

        response["Access-Control-Allow-Origin"] = "*"
        response["Access-Control-Expose-Headers"] = (
            "Accept-Ranges, Content-Range, Content-Length"
        )

        return response

    # -------------------------
    # STREAM CHUNKED DECRYPT
    # -------------------------

    def _stream_chunked_decrypt(self, file_path):

        import struct
        key = settings.ENCRYPTION_KEY

        with open(file_path, "rb") as f:

            while True:

                iv = f.read(12)

                if not iv:
                    break

                length_bytes = f.read(4)

                if not length_bytes:
                    break

                encrypted_length = struct.unpack(">I", length_bytes)[0]

                encrypted = f.read(encrypted_length)

                tag = encrypted[-16:]
                ciphertext = encrypted[:-16]

                cipher = Cipher(
                    algorithms.AES(key),
                    modes.GCM(iv, tag),
                    backend=default_backend()
                )

                decryptor = cipher.decryptor()

                decrypted = decryptor.update(ciphertext)
                decrypted += decryptor.finalize()

                yield decrypted

    # -------------------------
    # MAIN GET
    # -------------------------

    def get(self, request, media_id):

        user = self.get_current_user(request)

        media = get_object_or_404(
            FamilyTreeGallery,
            id=media_id,
            # family_tree_id=family_tree_id,
            is_deleted=False
        )

        file_path = media.file.path

        filename = os.path.basename(file_path)

        category = self._categorize(filename)

        content_type = self._guess_type(filename)

        cache_key = f"gallery_bytes_{media_id}"

        file_bytes = cache.get(cache_key)
        # extension = self._get_extension(filename)
        # if extension == '.doc':
        #     from memory_room.utils import convert_doc_to_docx_bytes
        #     cache_key = f'{media_id}_docx_preview'
        #     file_bytes = cache.get(cache_key) or convert_doc_to_docx_bytes(file_bytes, media_id, user.email)
        #     cache.set(cache_key, file_bytes, timeout=self.CACHE_TIMEOUT)
        #     content_type = "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
        #     filename = filename.replace(".doc", ".docx")
            

        # -------------------------
        # VIDEO / AUDIO
        # -------------------------

        if category in ["video", "audio"]:

            if not file_bytes:

                decrypted = bytearray()

                for chunk in self._stream_chunked_decrypt(file_path):
                    decrypted.extend(chunk)

                file_bytes = bytes(decrypted)

                cache.set(cache_key, file_bytes, self.CACHE_TIMEOUT)

            return self._stream_bytes(
                request,
                file_bytes,
                content_type,
                filename
            )

        # -------------------------
        # IMAGE (PROGRESSIVE)
        # -------------------------

        if category == "image":

            return StreamingHttpResponse(
                self._stream_chunked_decrypt(file_path),
                content_type=content_type
            )

        # -------------------------
        # OTHER FILES
        # -------------------------

        if not file_bytes:

            decrypted = bytearray()

            for chunk in self._stream_chunked_decrypt(file_path):
                decrypted.extend(chunk)

            file_bytes = bytes(decrypted)

            cache.set(cache_key, file_bytes, self.CACHE_TIMEOUT)

        return HttpResponse(
            file_bytes,
            content_type=content_type
        )

        