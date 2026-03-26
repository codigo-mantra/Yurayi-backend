import os
import mimetypes
import json
import time
import uuid
import threading
import re
import hmac
import hashlib
import struct
import logging
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

from memory_room.utils import get_file_category
from family_tree.apis.serializers.galery_media import FamilyTreeGallerySerializer, GalleryUpdateSerializer
# from memory_room.upload_helper import ChunkedUploadSession,truncate_filename, s3, kms, AWS_KMS_KEY_ID
from memory_room.utils import convert_doc_to_docx_bytes
from family_tree.utils.pagination import FamilyTreeGalleryPagination
from family_tree.utils.upload_helper import ChunkedUploadSession



logger = logging.getLogger(__name__)

email = 'test@test.com'
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
            # family_tree_recipients__permissions="edit",        #changeddd so that view-only access viewers or family memebers can also access 
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

class ChunkedMediaFileUploadView(SecuredView):

    CACHE_PREFIX = "chunked_upload"
    SESSION_TIMEOUT = 3600
    MAX_CHUNK_SIZE = 50 * 1024 * 1024
    SMALL_FILE_THRESHOLD = 5 * 1024 * 1024

    def _key(self, upload_id):
        return f"{self.CACHE_PREFIX}:{str(upload_id)}"

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
        user = self.get_current_user(request)
        # user = get_current_user(email)

        family_tree = get_object_or_404(FamilyTree, id=family_tree)
        if not user_has_tree_edit_permission(user, family_tree):
            return Response(
                {"detail": "You do not have permission to edit this family tree."},
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
        MAX_FILE_SIZE = 2 * 1024 * 1024 * 1024  # example 2GB

        for file_data in files_data:
            file_name = file_data["fileName"]
            file_size = int(file_data["fileSize"])
            if file_size <= 0 or file_size > MAX_FILE_SIZE:
                return JsonResponse({"error": "Invalid file size"}, status=400)
            total_chunks = int(file_data["totalChunks"])
            chunk_size = int(file_data["chunkSize"])

            upload_id = str(uuid.uuid4())
            # clean_name = file_name.replace(" ", "_")
            from django.utils.text import get_valid_filename
            import os

            base_name = os.path.basename(file_name)
            clean_name = get_valid_filename(base_name)

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
            return JsonResponse({"error": "Invalid request"}, status=400)
        def stream():
            session = self.get_session(upload_id)
            if not session :
                yield self._event(upload_id, "error", 0, "Unauthorized session")
                return
            if time.time() - session.last_activity > self.SESSION_TIMEOUT:
                self.delete_session(upload_id)
                yield self._event(upload_id, "error", 0, "Session expired")
                return
            if chunk_index < 0 or chunk_index >= session.total_chunks:
                yield self._event(upload_id, "error", 0, "Invalid chunk index")
                return

            if chunk_index in session.uploaded_chunks:
                yield self._event(upload_id, "error", 0, "Duplicate chunk")
                return
            encrypted = chunk_file.read()
            chunk_size = len(encrypted)

            if chunk_size > self.MAX_CHUNK_SIZE:
                yield self._event(upload_id, "error", 0, "Chunk too large")
                return
            if not iv:
                yield self._event(upload_id, "error", 0, "Missing IV")
                return

            try:
                iv_bytes = bytes.fromhex(iv)
            except ValueError:
                yield self._event(upload_id, "error", 0, "Invalid IV format")
                return

            if len(iv_bytes) != 12:
                yield self._event(upload_id, "error", 0, "Invalid IV length")
                return

            session.received_bytes += chunk_size
            ensure_dir(session.temp_file_path)
            with open(session.temp_file_path, "ab") as f:
                f.write(iv_bytes)
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
                if len(session.uploaded_chunks) != session.total_chunks:
                    yield self._event(upload_id, "error", 0, "Incomplete upload")
                    continue

                try:
                    os.replace(temp_path, final_path)
                except Exception:
                    yield self._event(upload_id, "error", 0, "File move failed")
                    continue
                media = FamilyTreeGallery.objects.create(
                    author=user,
                    family_tree=family_tree,
                    title=session.file_name,
                    file_size=session.file_size,
                    file_type=session.file_type,
                )

                with open(final_path, "rb") as f:
                    media.file.save(
                        os.path.basename(final_path),
                        File(f),
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
                try:
                    thumbnail_bytes = UniversalThumbnailService.generate(
                        final_path,
                        self.decrypt_full_file,
                        extension=extension
                    )
                except Exception:
                    if os.path.exists(final_path):
                        os.remove(final_path)

                    media.delete()
                    self.delete_session(upload_id)
                    yield self._event(upload_id, "error", 0, "File corrupted")
                    continue
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
                if len(encrypted) < 16:
                    raise ValueError("Invalid encrypted data")
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
        )

        file_type = request.query_params.get("file_type")

        if file_type:
            queryset = queryset.filter(file_type__iexact=file_type)

        queryset = queryset.order_by("-created_at")

        paginator = self.pagination_class()
        page = paginator.paginate_queryset(queryset, request)

        serializer = FamilyTreeGallerySerializer(page, many=True,context={"request": request})
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

        serializer = FamilyTreeGallerySerializer(page, many=True,context={"request": request})
        return paginator.get_paginated_response(serializer.data)



class FamilyTreeGalleryEditDeleteAPIView(SecuredView):
    """
    PUT / PATCH -> Edit gallery metadata
    DELETE      -> Soft delete gallery item
    """

    def delete(self, request, family_tree_id, gallery_id):
        user = self.get_current_user(request)

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
        user = self.get_current_user(request)

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

                try:
                    decrypted = decryptor.update(ciphertext) + decryptor.finalize()
                except Exception:
                    raise Http404("Corrupted encrypted file")

                for i in range(0, len(decrypted), self.CHUNK_SIZE):
                    yield decrypted[i:i+self.CHUNK_SIZE]
    
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
        # filename = os.path.basename(file_path)
        #changedd FIX: use user-renamed title instead of raw disk filename while user downloads the file
        disk_filename = os.path.basename(file_path)
        extension = os.path.splitext(disk_filename)[1]
        user_title = media.title or disk_filename
        if not user_title.lower().endswith(extension.lower()):
            user_title = f"{user_title}{extension}"
        filename = user_title

        content_type, _ = mimetypes.guess_type(filename)
        content_type = content_type or "application/octet-stream"

        response = StreamingHttpResponse(
            self._stream_decrypted_chunks(file_path),
            content_type=content_type
        )

        response["Content-Disposition"] = f'attachment; filename="{filename}"'
        response["Cache-Control"] = "no-store"
        response["X-Content-Type-Options"] = "nosniff"

        return response



class ServeGalleryMedia(SecuredView):

    CACHE_TIMEOUT = 60 * 60 * 24 * 7  # 7 days
    STREAMING_CHUNK_SIZE = 64 * 1024  # 1 mb

    IMAGE_EXTENSIONS = {
        '.jpg', '.jpeg', '.png', '.gif', '.webp', '.bmp', 
        '.tiff', '.tif', '.heic', '.heif', '.raw', '.cr2', '.nef', '.arw'
    }
    VIDEO_EXTENSIONS = {
        '.mp4', '.webm', '.mov', '.mkv', '.avi', '.wmv', 
        '.flv', '.m4v', '.3gp', '.mpeg', '.mpg', '.ts'
    }
    AUDIO_EXTENSIONS = {
        '.mp3', '.wav', '.aac', '.ogg', '.flac', '.m4a', '.wma', '.opus'
    }
    PDF_EXTENSIONS = {'.pdf'}
    DOCUMENT_EXTENSIONS = {
        '.doc', '.docx', '.xls', '.xlsx', '.csv', 
        '.json', '.txt', '.odt', '.ods', '.pdf'
    }

    NEEDS_CONVERSION = {
        '.heic', '.heif', '.raw', '.cr2', '.nef', '.arw', 
        '.tiff', '.tif',                                    
        '.doc',                                             
        '.mkv', '.avi', '.wmv', '.flv', '.mov', '.ts', 
        '.m4v', '.3gp', '.mpeg', '.mpg',                 
    }

    # ---------------------------------------------------
    # SECURITY
    # ---------------------------------------------------

    def _validate_signature(self, media_id, exp, sig):
        data = f"{media_id}:{exp}"
        expected_sig = hmac.new(
            settings.SECRET_KEY.encode(),
            data.encode(),
            hashlib.sha256
        ).hexdigest()
        return hmac.compare_digest(expected_sig, sig)

    # ---------------------------------------------------
    # HELPERS
    # ---------------------------------------------------

    def _get_extension(self, filename):
        return '.' + filename.lower().rsplit('.', 1)[-1] if '.' in filename else ''

    def _categorize(self, filename):
        ext = self._get_extension(filename)
        if ext in {'.heic', '.heif', '.raw', '.cr2', '.nef', '.arw', '.tiff', '.tif'}:
            return "image"
        if ext in self.IMAGE_EXTENSIONS:
            return "image"
        if ext in {'.mkv', '.avi', '.wmv', '.flv', '.mov', '.ts', '.m4v', '.3gp', '.mpeg', '.mpg'}:
            return "video"
        if ext in self.VIDEO_EXTENSIONS:
            return "video"
        if ext in self.AUDIO_EXTENSIONS:
            return "audio"
        if ext in self.PDF_EXTENSIONS:
            return "pdf"
        if ext in self.DOCUMENT_EXTENSIONS:
            return "document"
        return "other"

    def _guess_type(self, filename, converted_ext=None):
        """Guess content type, optionally for converted format."""
        ext = converted_ext or self._get_extension(filename)
        
        type_map = {
            '.mp4': 'video/mp4', '.webm': 'video/webm', '.mov': 'video/quicktime',
            '.mp3': 'audio/mpeg', '.wav': 'audio/wav', '.ogg': 'audio/ogg',
            '.jpg': 'image/jpeg', '.jpeg': 'image/jpeg', '.png': 'image/png',
            '.gif': 'image/gif', '.webp': 'image/webp', '.svg': 'image/svg+xml',
            '.pdf': 'application/pdf',
            '.docx': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
            '.doc': 'application/msword',
            '.xlsx': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
            '.xls': 'application/vnd.ms-excel',
            '.csv': 'text/csv',
            '.json': 'application/json',
            '.txt': 'text/plain',
        }
        
        if ext in type_map:
            return type_map[ext]
            
        content_type, _ = mimetypes.guess_type(filename)
        return content_type or "application/octet-stream"

    def _needs_conversion(self, filename):
        """Check if file needs format conversion."""
        return self._get_extension(filename) in self.NEEDS_CONVERSION

    # ---------------------------------------------------
    # DECRYPT STREAM (LOCAL ENCRYPTED FILE FORMAT)
    # ---------------------------------------------------

    def _decrypt_stream(self, file_path):
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
                if len(encrypted) < 16:
                    break
                tag = encrypted[-16:]
                ciphertext = encrypted[:-16]
                
                try:
                    cipher = Cipher(
                        algorithms.AES(key),
                        modes.GCM(iv, tag),
                        backend=default_backend()
                    )
                    decryptor = cipher.decryptor()
                    decrypted = decryptor.update(ciphertext) + decryptor.finalize()
                    yield decrypted
                except Exception as e:
                    logger.error(f"Decryption chunk failed for {file_path}: {e}")
                    break

    def _get_decrypted_bytes(self, file_path, cache_key=None):
        """Decrypt full file, optionally from cache."""
        if cache_key:
            cached = cache.get(cache_key)
            if cached:
                return cached
        
        try:
            decrypted = bytearray()
            for chunk in self._decrypt_stream(file_path):
                decrypted.extend(chunk)
            file_bytes = bytes(decrypted)
            
            if cache_key:
                cache.set(cache_key, file_bytes, timeout=self.CACHE_TIMEOUT)
            return file_bytes
        except Exception as e:
            logger.error(f"Full decryption failed for {file_path}: {e}")
            return None

    # ---------------------------------------------------
    # FORMAT CONVERSION METHODS
    # ---------------------------------------------------

    def _convert_heic_to_jpeg(self, file_bytes, quality=85):
        """Convert HEIC/HEIF to JPEG bytes."""
        try:
            from pillow_heif import register_heif_opener
            from PIL import Image
            import io
            
            register_heif_opener()
            image = Image.open(io.BytesIO(file_bytes))
            
            # Convert to RGB if necessary
            if image.mode in ('RGBA', 'P'):
                image = image.convert('RGB')
            
            output = io.BytesIO()
            image.save(output, format='JPEG', quality=quality, optimize=True)
            return output.getvalue()
        except Exception as e:
            logger.error(f"HEIC conversion failed: {e}")
            return None

    def _convert_raw_to_jpeg(self, file_bytes, quality=85, max_size=(4000, 4000)):
        """Convert RAW camera files (CR2, NEF, ARW) to JPEG."""
        try:
            from PIL import Image
            import io
            import rawpy
            
            # Use rawpy for RAW processing
            with rawpy.imread(io.BytesIO(file_bytes)) as raw:
                rgb = raw.postprocess(
                    use_camera_wb=True,
                    half_size=False,
                    no_auto_bright=False,
                    output_bps=8
                )
                image = Image.fromarray(rgb)
                
                # Resize if too large
                if max_size:
                    image.thumbnail(max_size, Image.Resampling.LANCZOS)
                
                output = io.BytesIO()
                image.save(output, format='JPEG', quality=quality, optimize=True)
                return output.getvalue()
        except Exception as e:
            logger.error(f"RAW conversion failed: {e}")
            # Fallback to PIL if rawpy fails
            try:
                from PIL import Image
                import io
                image = Image.open(io.BytesIO(file_bytes))
                if image.mode != 'RGB':
                    image = image.convert('RGB')
                output = io.BytesIO()
                image.save(output, format='JPEG', quality=quality)
                return output.getvalue()
            except Exception as e2:
                logger.error(f"RAW fallback conversion failed: {e2}")
                return None

    def _convert_tiff_to_jpeg(self, file_bytes, quality=85, max_size=(4000, 4000)):
        """Convert TIFF to JPEG."""
        try:
            from PIL import Image
            import io
            
            image = Image.open(io.BytesIO(file_bytes))
            
            # Handle multipage TIFF
            if hasattr(image, 'n_frames') and image.n_frames > 1:
                image.seek(0)
            
            if image.mode in ('RGBA', 'P', 'CMYK'):
                image = image.convert('RGB')
            
            if max_size:
                image.thumbnail(max_size, Image.Resampling.LANCZOS)
            
            output = io.BytesIO()
            image.save(output, format='JPEG', quality=quality, optimize=True)
            return output.getvalue()
        except Exception as e:
            logger.error(f"TIFF conversion failed: {e}")
            return None


    def _convert_video_to_mp4(self, file_bytes, source_ext):
        """Convert video formats to browser-compatible MP4 (H.264/AAC)."""
        try:
            import subprocess
            import tempfile
            import os
            
            with tempfile.TemporaryDirectory() as tmpdir:
                input_ext = source_ext.lstrip('.')
                input_path = os.path.join(tmpdir, f'input.{input_ext}')
                output_path = os.path.join(tmpdir, 'output.mp4')
                
                with open(input_path, 'wb') as f:
                    f.write(file_bytes)
                
                # FFmpeg conversion settings optimized for web playback
                cmd = [
                    'ffmpeg', '-y', '-i', input_path,
                    '-c:v', 'libx264', '-preset', 'fast', '-crf', '23',
                    '-c:a', 'aac', '-b:a', '128k',
                    '-movflags', '+faststart',  # Web optimization
                    '-pix_fmt', 'yuv420p',       # Browser compatibility
                    output_path
                ]
                
                result = subprocess.run(
                    cmd, 
                    capture_output=True, 
                    text=True,
                    timeout=300  # 5 minute timeout for large files
                )
                
                if result.returncode != 0:
                    logger.error(f"FFmpeg error: {result.stderr}")
                    return None
                
                with open(output_path, 'rb') as f:
                    return f.read()
                    
        except subprocess.TimeoutExpired:
            logger.error(f"Video conversion timeout for {source_ext}")
            return None
        except FileNotFoundError:
            logger.error("FFmpeg not found. Please install FFmpeg.")
            return None
        except Exception as e:
            logger.error(f"Video conversion failed: {e}")
            return None

    # ---------------------------------------------------
    # CONVERSION ROUTER
    # ---------------------------------------------------
    
    def _convert_file(self, file_bytes, filename, media_id):
        """Route to appropriate converter based on extension."""
        ext = self._get_extension(filename)
        cache_key = f"gallery_converted_{media_id}_{ext}"
        
        # Check cache first
        cached = cache.get(cache_key)
        if cached:
            return cached, self._get_converted_filename(filename, ext)
        
        converted = None
        new_ext = ext
        
        # Image conversions
        if ext in ('.heic', '.heif'):
            converted = self._convert_heic_to_jpeg(file_bytes)
            new_ext = '.jpg'
        elif ext in ('.raw', '.cr2', '.nef', '.arw'):
            converted = self._convert_raw_to_jpeg(file_bytes)
            new_ext = '.jpg'
        elif ext in ('.tiff', '.tif'):
            converted = self._convert_tiff_to_jpeg(file_bytes)
            new_ext = '.jpg'
        
        # Document conversions
        elif ext == '.doc':
            converted = self._convert_doc_to_docx(file_bytes, filename)
            new_ext = '.docx'
        
        # Video conversions
        elif ext in ('.mkv', '.avi', '.wmv', '.flv', '.mov', '.ts', '.m4v', '.3gp', '.mpeg', '.mpg'):
            converted = self._convert_video_to_mp4(file_bytes, ext)
            new_ext = '.mp4'
        
        if converted:
            cache.set(cache_key, converted, timeout=self.CACHE_TIMEOUT)
            return converted, self._get_converted_filename(filename, new_ext)
        
        return None, filename

    def _get_converted_filename(self, original_filename, new_ext):
        """Generate filename for converted file."""
        base = original_filename.rsplit('.', 1)[0]
        return f"{base}{new_ext}"

    # ---------------------------------------------------
    # RANGE STREAMING (UNCHANGED CORE LOGIC)
    # ---------------------------------------------------

    def _serve_pdf_with_range(self, request, file_bytes, filename):
        """Serve PDF with byte-range support."""
        file_size = len(file_bytes)
        range_header = request.headers.get("Range", "")
        start, end = 0, file_size - 1
        status_code = 200

        if range_header:
            m = re.match(r"bytes=(\d+)-(\d*)", range_header)
            if m:
                start = int(m.group(1))
                end = int(m.group(2)) if m.group(2) else file_size - 1
                end = min(end, file_size - 1)
                status_code = 206

        content = file_bytes[start:end + 1]
        
        if status_code == 206:
            response = StreamingHttpResponse(
                iter([content]),
                status=206,
                content_type="application/pdf"
            )
        else:
            response = HttpResponse(content, content_type="application/pdf", status=200)

        response["Accept-Ranges"] = "bytes"
        response["Content-Length"] = str(len(content))
        response["Content-Disposition"] = "inline"
        response["X-Content-Type-Options"] = "nosniff"
        response["Cache-Control"] = "private, max-age=3600"
        
        if status_code == 206:
            response["Content-Range"] = f"bytes {start}-{end}/{file_size}"
            
        response["Access-Control-Allow-Origin"] = "*"
        response["Access-Control-Expose-Headers"] = "Accept-Ranges, Content-Range, Content-Length"
        
        try:
            frame_ancestors = " ".join(getattr(settings, "CORS_ALLOWED_ORIGINS", []))
            if frame_ancestors:
                response["Content-Security-Policy"] = f"frame-ancestors 'self' {frame_ancestors};"
        except Exception:
            pass
            
        return response

    def _stream_file_with_range(self, request, file_bytes, content_type, filename):
        """Generic byte-range streaming for video/audio/documents."""
        file_size = len(file_bytes)
        range_header = request.headers.get("Range")
        start = 0
        end = file_size - 1
        status_code = 200

        if range_header:
            m = re.match(r"bytes=(\d+)-(\d*)", range_header)
            if m:
                start = int(m.group(1))
                end = int(m.group(2)) if m.group(2) else file_size - 1
                status_code = 206

        end = min(end, file_size - 1)

        def stream():
            try:
                pos = start
                while pos <= end:
                    chunk_end = min(pos + self.STREAMING_CHUNK_SIZE, end + 1)
                    yield file_bytes[pos:chunk_end]
                    pos = chunk_end
            except BrokenPipeError:
                pass

        response = StreamingHttpResponse(
            stream(),
            status=status_code,
            content_type=content_type
        )
        response["Accept-Ranges"] = "bytes"
        response["Content-Length"] = str(end - start + 1)
        response["Content-Disposition"] = "inline"
        response["Cache-Control"] = "private, max-age=3600"
        response["X-Content-Type-Options"] = "nosniff"
        
        if status_code == 206:
            response["Content-Range"] = f"bytes {start}-{end}/{file_size}"
            
        response["Access-Control-Allow-Origin"] = "*"
        response["Access-Control-Expose-Headers"] = "Accept-Ranges, Content-Range, Content-Length"
        response["Cross-Origin-Resource-Policy"] = "cross-origin"
        
        try:
            frame_ancestors = " ".join(getattr(settings, "CORS_ALLOWED_ORIGINS", []))
            if frame_ancestors:
                response["Content-Security-Policy"] = f"media-src *; frame-ancestors 'self' {frame_ancestors};"
        except Exception:
            pass
            
        return response

    # ---------------------------------------------------
    # UPDATED RANGE STREAM ROUTER WITH CONVERSIONS
    # ---------------------------------------------------

    def _range_stream(self, request, file_path, content_type, filename, media_id, category):
        """
        Route by category with format conversion support.
        Mirrors S3 ServeTimeCapSoulMedia pattern for local files.
        """
        ext = self._get_extension(filename)
        needs_conversion = self._needs_conversion(filename)
        
        # Handle conversions that require full decryption first
        if category in ("image", "document", "video") and needs_conversion:
            decrypt_cache_key = f"gallery_bytes_{media_id}"
            file_bytes = self._get_decrypted_bytes(file_path, decrypt_cache_key)
            
            if not file_bytes:
                raise Http404("File decryption failed")
            
            converted_bytes = None
            converted_filename = filename
            new_content_type = content_type
        
            if ext == '.doc':
                cache_key = f'gallery_docx_{media_id}'
                converted_bytes = cache.get(cache_key)
                
                if not converted_bytes:
                    user = self.get_current_user(request)
                    user_email = getattr(user, 'email', 'anonymous')
                    
                    converted_bytes = convert_doc_to_docx_bytes(
                        file_bytes, media_id, user_email
                    )
                    if converted_bytes:
                        cache.set(cache_key, converted_bytes, timeout=self.CACHE_TIMEOUT)
                
                if converted_bytes and converted_bytes != file_bytes: 
                    new_content_type = "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
                    converted_filename = filename.replace(".doc", ".docx")
                    file_bytes = converted_bytes
                    filename = converted_filename
                    content_type = new_content_type
            
            # HEIC conversion
            elif ext in ('.heic', '.heif'):
                cache_key = f'gallery_jpeg_{media_id}'
                converted_bytes = cache.get(cache_key)
                
                if not converted_bytes:
                    converted_bytes = self._convert_heic_to_jpeg(file_bytes)
                    if converted_bytes:
                        cache.set(cache_key, converted_bytes, timeout=self.CACHE_TIMEOUT)
                
                if converted_bytes:
                    content_type = "image/jpeg"
                    filename = filename.rsplit('.', 1)[0] + '.jpg'
                    file_bytes = converted_bytes
            
            # TIFF conversion
            elif ext in ('.tiff', '.tif'):
                cache_key = f'gallery_jpeg_{media_id}'
                converted_bytes = cache.get(cache_key)
                
                if not converted_bytes:
                    converted_bytes = self._convert_tiff_to_jpeg(file_bytes)
                    if converted_bytes:
                        cache.set(cache_key, converted_bytes, timeout=self.CACHE_TIMEOUT)
                
                if converted_bytes:
                    content_type = "image/jpeg"
                    filename = filename.rsplit('.', 1)[0] + '.jpg'
                    file_bytes = converted_bytes
            
            # RAW conversion
            elif ext in ('.raw', '.cr2', '.nef', '.arw'):
                cache_key = f'gallery_jpeg_{media_id}'
                converted_bytes = cache.get(cache_key)
                
                if not converted_bytes:
                    converted_bytes = self._convert_raw_to_jpeg(file_bytes)
                    if converted_bytes:
                        cache.set(cache_key, converted_bytes, timeout=self.CACHE_TIMEOUT)
                
                if converted_bytes:
                    content_type = "image/jpeg"
                    filename = filename.rsplit('.', 1)[0] + '.jpg'
                    file_bytes = converted_bytes
            
            # Video conversion
            elif ext in ('.mkv', '.avi', '.wmv', '.flv', '.mov', '.ts', '.m4v', '.3gp', '.mpeg', '.mpg'):
                cache_key = f'gallery_mp4_{media_id}'
                converted_bytes = cache.get(cache_key)
                
                if not converted_bytes:
                    converted_bytes = self._convert_video_to_mp4(file_bytes, ext)
                    if converted_bytes:
                        cache.set(cache_key, converted_bytes, timeout=self.CACHE_TIMEOUT)
                
                if converted_bytes:
                    content_type = "video/mp4"
                    filename = filename.rsplit('.', 1)[0] + '.mp4'
                    file_bytes = converted_bytes
                    # Video needs range support after conversion
                    return self._stream_file_with_range(
                        request, file_bytes, content_type, filename
                    )
            
            # After conversion, serve based on new type
            if category == "document":
                # DOCX should be served with range support like in S3 version
                if filename.endswith('.docx'):
                    return self._stream_file_with_range(
                        request, file_bytes, content_type, filename
                    )
                # If conversion failed, serve original .doc as download
                else:
                    response = HttpResponse(file_bytes, content_type="application/msword")
                    response["Content-Disposition"] = f'attachment; filename="{filename}"'
                    response["Cache-Control"] = "private, max-age=3600"
                    return response
            
            elif category == "image":
                # Converted images served as simple response
                response = HttpResponse(file_bytes, content_type=content_type)
                response["Content-Disposition"] = "inline"
                response["Cache-Control"] = "private, max-age=3600"
                return response
        
        # Standard routing (no conversion needed)
        cache_key = f"gallery_bytes_{media_id}" if media_id else None

        if category in ("video", "audio"):
            file_bytes = self._get_decrypted_bytes(file_path, cache_key)
            if not file_bytes:
                raise Http404("File decryption failed")
            return self._stream_file_with_range(request, file_bytes, content_type, filename)

        if category == "pdf":
            file_bytes = self._get_decrypted_bytes(file_path, cache_key)
            if not file_bytes:
                raise Http404("File decryption failed")
            return self._serve_pdf_with_range(request, file_bytes, filename)

        if category == "document":
            file_bytes = self._get_decrypted_bytes(file_path, cache_key)
            if not file_bytes:
                raise Http404("File decryption failed")
            # Native DOCX/XLSX/PDF - serve with range
            return self._stream_file_with_range(request, file_bytes, content_type, filename)

        if category == "image":
            # SVG special handling
            if ext == '.svg':
                file_bytes = self._get_decrypted_bytes(file_path, cache_key)
                response = HttpResponse(file_bytes, content_type='image/svg+xml')
                response["Content-Security-Policy"] = (
                    "default-src 'none'; img-src * data:; style-src 'unsafe-inline';"
                )
                response["Content-Disposition"] = "inline"
                return response
            
            # Progressive streaming for native images
            response = StreamingHttpResponse(
                self._decrypt_stream(file_path),
                content_type=content_type
            )
            response["Content-Disposition"] = "inline"
            response["Cache-Control"] = "private, max-age=3600"
            response["X-Content-Type-Options"] = "nosniff"
            return response

        # Fallback for other files
        file_bytes = self._get_decrypted_bytes(file_path, cache_key)
        if not file_bytes:
            raise Http404("File decryption failed")
        response = HttpResponse(file_bytes, content_type=content_type)
        response["Content-Disposition"] = "inline"
        response["Cache-Control"] = "private, max-age=3600"
        response["X-Content-Type-Options"] = "nosniff"
        return response
    # ---------------------------------------------------
    # MAIN GET (UNCHANGED)
    # ---------------------------------------------------

    def get(self, request, media_id):
        user = self.get_current_user(request)

        exp = request.GET.get("exp")
        sig = request.GET.get("sig")
        if not exp or not sig:
            return Response(status=status.HTTP_404_NOT_FOUND)

        try:
            if int(exp) < int(time.time()):
                return Response(status=status.HTTP_404_NOT_FOUND)
        except (ValueError, TypeError):
            return Response(status=status.HTTP_404_NOT_FOUND)

        if not self._validate_signature(str(media_id), exp, sig):
            return Response(status=status.HTTP_403_FORBIDDEN)

        try:
            media = FamilyTreeGallery.objects.select_related("family_tree").get(
                id=media_id,
                is_deleted=False
            )
        except FamilyTreeGallery.DoesNotExist:
            return Response(status=status.HTTP_404_NOT_FOUND)

        family_tree = get_shared_family_tree(user=user, family_tree_id=media.family_tree_id)
        if not family_tree:
            return Response(
                {"detail": "You do not have permission to access this gallery."},
                status=status.HTTP_403_FORBIDDEN
            )

        if not media.file:
            return Response(status=status.HTTP_404_NOT_FOUND)

        file_path = media.file.path
        if not os.path.exists(file_path):
            raise Http404("File not found on server")

        filename = media.file.name or os.path.basename(file_path)
        category = self._categorize(filename)
        content_type = self._guess_type(filename)

        return self._range_stream(
            request,
            file_path,
            content_type,
            os.path.basename(filename),
            str(media_id),
            category
        )

