import os
import time
import json
import uuid
import struct
import logging
import re, mimetypes, hmac, hashlib
from django.conf import settings
from django.core.cache import cache
from django.core.files import File
from django.http import Http404, JsonResponse, StreamingHttpResponse, HttpResponse
from django.shortcuts import get_object_or_404
from django.utils.text import get_valid_filename
from django.db.models import Q
from django.core.cache import cache
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

from rest_framework import status
from rest_framework.response import Response


from userauth.apis.views.views import SecuredView
from memory_map.models import (
    MemoryMap,
    MemoryMediaDetails,
    MemoryMapPinnedLocationInfo,
    MemoryMapBucketInfo,
    MemoryMapRecipients,
)
from memory_map.apis.serializers.media import MemoryMediaDetailsSerializer,MemoryMediaUpdateSerializer

from memory_room.utils import get_file_category
from family_tree.utils.upload_helper import ChunkedUploadSession  # reuse existing session class
from memory_map.utils.media_pagination import MemoryMapMediaPagination
from family_tree.utils.upload_helper import UniversalThumbnailService

logger = logging.getLogger(__name__)


# ----------------------------------------------------------------
# Path helpers
# ----------------------------------------------------------------

def get_local_upload_path(location_id, upload_id, filename):
    return os.path.join(
        settings.MEDIA_ROOT,
        "memory_map_uploads",       # separate folder from family tree uploads
        str(location_id),
        upload_id,
        filename
    )

def ensure_dir(path):
    os.makedirs(os.path.dirname(path), exist_ok=True)

# ----------------------------------------------------------------
# resolve_location — decides which table to query based on location_type
# frontend MUST send "pinned" or "bucket" so we know which FK to use.
# Without it, location_id=5 is ambiguous — could be pinned row 5 OR bucket row 5.
# ----------------------------------------------------------------
def resolve_location(location_type, location_id):
    location_type = location_type.strip().lower()

    if location_type == "pinned":
        return get_object_or_404(
            MemoryMapPinnedLocationInfo,
            id=location_id,
            is_deleted=False
        )
    elif location_type == "bucket":
        return get_object_or_404(
            MemoryMapBucketInfo,
            id=location_id,
            is_deleted=False
        )
    return None
    # raise Http404("Invalid location type")

# ----------------------------------------------------------------
# Permission check — owner OR "edit" recipients can upload
# VIEW-only recipients must NOT be able to upload (per feature spec)
# ----------------------------------------------------------------
def user_has_location_access(user, location_obj, permission="view"):
    memory_map = location_obj.memory_map

    if memory_map.user_id == user.id:      # Owner = full access
        return True
    print("CHECKING ACCESS:", user.email, permission)
    
    qs = MemoryMapRecipients.objects.filter(
        memory_map=memory_map,
        email=user.email,
        is_deleted=False
    ).filter(
        Q(user=user) | Q(email=user.email)
    )

    if permission == "edit":
        qs = qs.filter(permission="edit")   #permission given to edit = can upload 
    return qs.exists()


"""will use it in upload API
if not user_has_location_access(user, location_obj, "edit"):
    return Response({"detail": "Permission denied"}, status=403)"""

"""will use it in list API
if not user_has_location_access(user, location_obj, "view"):
    return Response({"detail": "Permission denied"}, status=403) """


# # def user_can_upload_to_location(user, location_obj):
#     memory_map = location_obj.memory_map          # traverse FK to get the parent map

#     if memory_map.user_id == user.id:             # owner — always allowed
#         return True

#     # edit-permission recipients can also upload
#     return MemoryMapRecipients.objects.filter(
#         memory_map=memory_map,
#         email=user.email,
#         permission="edit",
#         is_deleted=False
#     ).exists()
# def user_can_view_location(user, location_obj):
    # memory_map = location_obj.memory_map

    # # owner
    # if memory_map.user_id == user.id:
    #     return True

    # #ANY shared user (view OR edit)
    # return MemoryMapRecipients.objects.filter(
    #     memory_map=memory_map,
    #     email=user.email,
    #     is_deleted=False
    # ).exists()

#this function is used in media details API to validate that the requested media_id actually belongs to the requested location (pinned or bucket) and that the user has access to it. It prevents unauthorized access to media files by ID alone without checking the location context.
def get_media_for_location(location_obj, media_id):
    media = MemoryMediaDetails.objects.filter(
        id=media_id,
        is_deleted=False
    ).first()

    if not media:
        return None
    # Validate correct ownership
    if isinstance(location_obj, MemoryMapPinnedLocationInfo):
        if media.memory_place_id != location_obj.id:
            return None
        
    elif isinstance(location_obj, MemoryMapBucketInfo):
        if media.bucket_item_id != location_obj.id:
            return None

    else:
        return None  # safety fallback

    return media

# ===================================================================
class MemoryMapChunkedUploadView(SecuredView):

    CACHE_PREFIX    = "mm_upload"        # isolated cache namespace (not shared with family tree)
    SESSION_TIMEOUT = 3600               # 1 hour stale sessions get rejected
    MAX_CHUNK_SIZE  = 50 * 1024 * 1024   # 50 MB per chunk hard cap

    # ----------------------------------------------------------------
    # Cache helpers
    # ----------------------------------------------------------------
    def _key(self, upload_id):
        return f"{self.CACHE_PREFIX}:{str(upload_id)}"

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
            self._key(str(session.upload_id)),
            json.dumps(session.to_dict(), default=str),
            self.SESSION_TIMEOUT
        )

    def delete_session(self, upload_id):
        cache.delete(self._key(str(upload_id)))

    # ----------------------------------------------------------------
    # MAIN ENTRY 
    # URL pattern: POST /memory-map/media/<location_id>/<action>/
    # ----------------------------------------------------------------
    def post(self, request, location_id, action):
        user = self.get_current_user(request)

        location_type = request.POST.get("location_type", "pinned")  # required from frontend

        location_obj = resolve_location(location_type, location_id)
        if location_obj is None:
            return Response({"error": "Invalid location_type. Must be 'pinned' or 'bucket'."}, status=400)

        # Security gate — runs before EVERY action (init, upload, complete, abort)
        # old = if not user_can_upload_to_location(user, location_obj):
        if not user_has_location_access(user, location_obj, "edit"):
            print("USER:", user.id, user.email)
            print("LOCATION OBJ:", location_obj)
            print("LOCATION TYPE:", location_type)
            print("OWNER:", location_obj.memory_map.user_id)
            print("RECIPIENTS:", list(MemoryMapRecipients.objects.filter(memory_map=location_obj.memory_map).values()))
            return Response(
                {"detail": "You do not have permission to upload to this location."},
                status=status.HTTP_403_FORBIDDEN
            )

        if action == "init":
            return self.initialize_uploads(request, user, location_id, location_type)
        if action == "upload":
            return self.upload_chunk(request, user)
        if action == "complete":
            return self.complete_upload(request, user, location_obj, location_type)
        if action == "abort":
            return self.abort_upload(request, user)

        return JsonResponse({"error": "Invalid action"}, status=400)

    # ----------------------------------------------------------------
    # INIT — frontend sends file metadata list, backend creates sessions
    # Returns: uploadId per file (frontend uses this to identify which chunk belongs to which file), plus any validation errors
    # ----------------------------------------------------------------
    def initialize_uploads(self, request, user, location_id, location_type):
        files_data = json.loads(request.POST.get("filesData", "[]"))

        if not files_data:
            return JsonResponse({"error": "No files provided"}, status=400)

        MAX_FILE_SIZE     = 2 * 1024 * 1024 * 1024   # 2 GB hard cap per file
        initialized_files = []

        for file_data in files_data:
            file_name    = file_data.get("fileName", "")
            file_size    = int(file_data.get("fileSize", 0))
            total_chunks = int(file_data.get("totalChunks", 0))
            chunk_size   = int(file_data.get("chunkSize", 0))

            if file_size <= 0 or file_size > MAX_FILE_SIZE:
                return JsonResponse({"error": f"Invalid file size for: {file_name}"}, status=400)

            upload_id  = str(uuid.uuid4())
            clean_name = get_valid_filename(os.path.basename(file_name))  # strip path traversal chars

            local_path = get_local_upload_path(location_id, upload_id, clean_name)

            # ChunkedUploadSession holds state in cache between chunk requests
            # gallery_media_id field is reused here to store location_id
            session = ChunkedUploadSession(
                upload_id        = upload_id,
                user_id          = user.id,
                gallery_media_id = location_id,          # stores location_id in session
                file_name        = clean_name,
                file_size        = file_size,
                file_type        = get_file_category(clean_name), 
                total_chunks     = total_chunks,
                chunk_size       = chunk_size,
            )

            session.local_path     = local_path
            session.temp_file_path = f"{local_path}.part"  # chunks land in .part until complete
            session.is_small_file  = file_size < (5 * 1024 * 1024)

            ensure_dir(session.temp_file_path)
            self.save_session(session)

            initialized_files.append({
                "uploadId"    : upload_id,
                "fileName"    : file_name,
                "totalChunks" : total_chunks,
                "percentage"  : 5,              # 5% signals to frontend that init succeeded
            })

        return JsonResponse({"files": initialized_files})

    # ----------------------------------------------------------------
    # UPLOAD CHUNK — appends each encrypted chunk to the .part temp file
    # Frontend sends: uploadId, chunkIndex, chunk (binary blob), iv (hex string)
    # Response is SSE so frontend gets live progress updates per chunk
    # ----------------------------------------------------------------
    def upload_chunk(self, request, user):
        upload_id   = request.POST.get("uploadId")
        chunk_index = int(request.POST.get("chunkIndex", -1))
        chunk_file  = request.FILES.get("chunk")
        iv          = request.POST.get("iv")              # AES-GCM IV from frontend

        if not upload_id or not chunk_file:
            return JsonResponse({"error": "Missing uploadId or chunk"}, status=400)

        def stream():
            session = self.get_session(upload_id)

            if not session:
                yield self._event(upload_id, "error", 0, "Unauthorized session")
                return

            # Reject stale sessions — prevents resuming old ghost uploads
            if time.time() - session.last_activity > self.SESSION_TIMEOUT:
                self.delete_session(upload_id)
                yield self._event(upload_id, "error", 0, "Session expired")
                return

            if chunk_index < 0 or chunk_index >= session.total_chunks:
                yield self._event(upload_id, "error", 0, "Invalid chunk index")
                return

            # Duplicate chunk guard — network retries can re-send the same chunk
            if chunk_index in session.uploaded_chunks:
                # retry case → don't fail
                yield self._event(upload_id,"uploaded",getattr(session, "last_percent", 0))
                return
            # if chunk_index in session.uploaded_chunks:
                # yield self._event(upload_id, "error", 0, "Duplicate chunk")
                # return

            encrypted  = chunk_file.read()
            chunk_size = len(encrypted)
            

            if chunk_size > self.MAX_CHUNK_SIZE:
                yield self._event(upload_id, "error", 0, "Chunk too large")
                return
            
            #check chunk itegrity , last chunk can be smaller =  no check needed
            expected_size =session.chunk_size 
            if chunk_index != session.total_chunks - 1:
                if chunk_size != expected_size:
                    yield self._event(upload_id, "error", 0, "Invalid chunk size")
                    return

            # IV is mandatory — AES-GCM cannot decrypt without it
            if not iv:
                yield self._event(upload_id, "error", 0, "Missing IV")
                return

            try:
                iv_bytes = bytes.fromhex(iv)
            except ValueError:
                yield self._event(upload_id, "error", 0, "Invalid IV format")
                return

            if len(iv_bytes) != 12:    # AES-GCM IV is always 12 bytes
                yield self._event(upload_id, "error", 0, "Invalid IV length — must be 12 bytes")
                return

            # On-disk format per chunk: [IV 12B] [length 4B big-endian] [encrypted bytes]
            # This layout lets the decrypt reader re-read chunks in order
            with session.lock:
                ensure_dir(session.temp_file_path)

                with open(session.temp_file_path, "ab") as f:                 # I/O mode is append-binary —                  for concurrent chunk writes without overwriting..appending to file so that multiple chunks write sequentially without overwriting each other 
                    f.write(iv_bytes)
                    f.write(struct.pack(">I", len(encrypted)))                # 4-byte big-endian length prefix
                    f.write(encrypted)

                session.uploaded_chunks.add(chunk_index)
            # ensure_dir(session.temp_file_path)
            # with open(session.temp_file_path, "ab") as f:                     
                # f.write(iv_bytes)
                # f.write(struct.pack(">I", len(encrypted)))            # 4-byte big-endian length prefix
                # f.write(encrypted)

            # with session.lock:
                # session.uploaded_chunks.add(chunk_index)

            session.received_bytes += chunk_size                               # track total byte recieved for calculation 
            self.save_session(session)

            # Progress 0-90 percent during chunks; 90-100 percent is reserved for the complete step , will show real time progress based on total bytes received vs file size
            # old = percent = (len(session.uploaded_chunks) / session.total_chunks) * 90
            percent = int((session.received_bytes / session.file_size) * 90)
            last_percent = getattr(session, "last_percent", 0)

            if percent > last_percent:
                session.last_percent = percent
                self.save_session(session)
            # if percent > session.last_percent:                             # only send update if percent increased to reduce redundant messages on very large files with many small chunks
                # session.last_percent = percent
                # self.save_session(session) 
                # yield self._event(upload_id, "uploaded", self._percent(percent))


        return StreamingHttpResponse(
            stream(),
            content_type="text/event-stream",
            headers={"Cache-Control": "no-cache"}
        )

    # ----------------------------------------------------------------
    # COMPLETE — validates all chunks arrived, moves temp file, saves DB record
    # Frontend sends: uploadIds[] (list allows completing multiple files in one call)
    # ----------------------------------------------------------------
    def complete_upload(self, request, user, location_obj, location_type):
        upload_ids = request.POST.getlist("uploadIds[]")

        def stream():
            for upload_id in upload_ids:
                session = self.get_session(upload_id)

                if not session:
                    yield self._event(upload_id, "error", 0, "Session not found")
                    continue

                # Ensure every single chunk arrived before finalizing
                if len(session.uploaded_chunks) != session.total_chunks:
                    missing = session.total_chunks - len(session.uploaded_chunks)
                    yield self._event(upload_id, "error", 0, f"Incomplete — {missing} chunks missing")
                    continue

                final_path = session.local_path
                temp_path  = session.temp_file_path

                # Atomic rename: .part = final (no corrupt file if server dies mid-rename)
                try:
                    os.replace(temp_path, final_path)
                except Exception:
                    yield self._event(upload_id, "error", 0, "File move failed")
                    continue

                # Build MemoryMediaDetails kwargs — only set the correct FK
                media_kwargs = {
                    "user"      : user,
                    "file_type" : session.file_type,
                    "file_size" : session.file_size,
                    "title"     : session.file_name,
                }

                # Conditionally set FK based on location_type from the request
                if location_type == "pinned":
                    media_kwargs["memory_place"] = location_obj   # pinned location FK
                elif location_type == "bucket":
                    media_kwargs["bucket_item"]  = location_obj   # bucket list item FK

                media = MemoryMediaDetails.objects.create(**media_kwargs)

                # Save file into Django FileField (handles MEDIA_ROOT path resolution)
                try:
                    with open(final_path, "rb") as f:
                        media.file.save(
                            os.path.basename(final_path),
                            File(f),
                            save=True
                        )
                except Exception:
                    media.delete()                      # roll back DB record if file save fails
                    self.delete_session(upload_id)
                    yield self._event(upload_id, "error", 0, "File save failed")
                    continue
                

                #thumbnail generation for media files , keep it non-blocking and best effort..if it fails, we log but don't fail the whole upload since user got their file saved successfully
                try:
                    ext = os.path.splitext(session.file_name)[-1].lower()
                    if session.file_type in ('image', 'video', 'audio'):
                        thumb_bytes = UniversalThumbnailService.generate(
                            encrypted_file_path=media.file.path,
                            decrypt_func=lambda path: self._decrypt_stream(path),
                            extension=ext
                        )
                        if thumb_bytes:
                            from django.core.files.base import ContentFile
                            media.thumbnail.save(
                                f"thumb_{media.id}.jpg",
                                ContentFile(thumb_bytes),
                                save=True
                            )
                except Exception as e:
                    logger.error(f"Thumbnail generation failed for media {media.id}: {e}")
                    # Non-fatal — media is saved, user gets their file, just no thumbnail

                self.delete_session(upload_id)               #clean up cache session
                yield self._event(upload_id, "complete", 100)

                                
        return StreamingHttpResponse(
            stream(),
            content_type="text/event-stream",
            headers={"Cache-Control": "no-cache"}
        )

    # ----------------------------------------------------------------
    # ABORT — frontend triggered cancel; removes temp file + session
    # ----------------------------------------------------------------
    def abort_upload(self, request, user):
        upload_id = request.POST.get("uploadId")
        session   = self.get_session(upload_id)

        # Remove partial .part file from disk to free up space
        if session and session.temp_file_path and os.path.exists(session.temp_file_path):
            os.remove(session.temp_file_path)

        self.delete_session(upload_id)
        return JsonResponse({"status": "aborted"})

    # ----------------------------------------------------------------
    # SSE event formatter 
    # stage values: "uploaded" | "complete" | "error"
    # ----------------------------------------------------------------
    def _event(self, upload_id, stage, percentage, error=None):
        payload = {
            "uploadId"   : upload_id,
            "stage"      : stage,
            "percentage" : percentage,
        }
        if error:
            payload["error"] = error
        return f"data: {json.dumps(payload)}\n\n"
    

##########################################################################################################################################
class MemoryMapMediaListView(SecuredView):
    pagination_class = MemoryMapMediaPagination
 
    def get(self, request, location_id):
        user = self.get_current_user(request)

        location_type = request.GET.get("location_type", "pinned")    # required from frontend to know which FK to check and which media to list
        
        location_obj = resolve_location(location_type, location_id)
        if location_obj is None:
            return Response({"error": "Invalid location_type. Must be 'pinned' or 'bucket'."}, status=400)
        
        if not user_has_location_access(user, location_obj, "view"):
            return Response({"detail": "You do not have permission to access this gallery."}, status=403)
        
        queryset = location_obj.media_files.filter(is_deleted=False)

        file_type = request.query_params.get("file_type")
        if file_type:
            queryset = queryset.filter(file_type__iexact=file_type)

        queryset = queryset.order_by("-created_at") # ordering

        # pagination
        paginator = self.pagination_class()
        page = paginator.paginate_queryset(queryset, request)

        serializer = MemoryMediaDetailsSerializer(page, many=True)

        return paginator.get_paginated_response(serializer.data)


##########################################################################################################################################
class MemoryMapMediaEditDeleteView(SecuredView):

    # ---------------- DELETE ----------------
    def delete(self, request, location_id, media_id):
        user = self.get_current_user(request)

        location_obj, error = self._get_location(request, location_id)
        if error:
            return error
        
        if not user_has_location_access(user, location_obj, "edit"):
            return Response({"detail":"You do not have permission to delete this media."}, status=403)
        
        media = get_media_for_location(location_obj, media_id)
        if not media:
            return Response({"detail": "Media not found"}, status=404)        
        media.is_deleted = True
        media.save()

        return Response({"detail": "Media deleted successfully"},status=204)
    
    # ---------------- UPDATE ----------------
    def patch(self, request, location_id, media_id):
        user = self.get_current_user(request)

        location_obj, error = self._get_location(request, location_id)
        if error:
            return error
        
        if not user_has_location_access(user, location_obj, "edit"):
            return Response({"detail": "You do not have permission to edit this media"}, status=403)
        
        media = get_media_for_location(location_obj, media_id)
        if not media:
            return Response({"detail": "Media not found"}, status=404)
        
        serializer = MemoryMediaUpdateSerializer(
            media,
            data=request.data,
            partial=True
        )
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response({"detail": "Media updated successfully"},status=200)




    
#------------SERVE MEDIA ---------------------------------------------------------------------------------------------
class ServeMemoryMapMedia(SecuredView):

    CACHE_TIMEOUT = 60 * 60 * 24 * 7   # 7 days
    CHUNK_SIZE    = 64 * 1024           # 64 KB

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

    # ── SECURITY ──────────────────────────────────────────────────────────

    def _validate_signature(self, media_id, exp, sig):
        data = f"{media_id}:{exp}"
        expected = hmac.new(
            settings.SECRET_KEY.encode(),
            data.encode(),
            hashlib.sha256
        ).hexdigest()
        return hmac.compare_digest(expected, sig)

    def _check_permission(self, user, media):
        """
        Allow if:
          - user owns the media, OR
          - user is a recipient on the memory map (view or edit)
        """
        if media.user_id == user.id:
            return True

        user_email = getattr(user, 'email', None)
        if not user_email:
            return False

        return MemoryMapRecipients.objects.filter(
            memory_map=media.memory_map,   # see note below
            email=user_email,
            is_deleted=False
        ).exists()

    # ── HELPERS ───────────────────────────────────────────────────────────

    def _ext(self, filename):
        return ('.' + filename.lower().rsplit('.', 1)[-1]) if '.' in filename else ''

    def _categorize(self, filename):
        ext = self._ext(filename)
        if ext in self.IMAGE_EXTENSIONS:
            return 'image'
        if ext in self.VIDEO_EXTENSIONS:
            return 'video'
        if ext in self.AUDIO_EXTENSIONS:
            return 'audio'
        if ext in self.PDF_EXTENSIONS:
            return 'pdf'
        if ext in self.DOCUMENT_EXTENSIONS:
            return 'document'
        return 'other'

    def _content_type(self, filename, override_ext=None):
        ext = override_ext or self._ext(filename)
        type_map = {
            '.mp4': 'video/mp4',        '.webm': 'video/webm',
            '.mp3': 'audio/mpeg',       '.wav': 'audio/wav',
            '.ogg': 'audio/ogg',        '.m4a': 'audio/mp4',
            '.aac': 'audio/aac',        '.flac': 'audio/flac',
            '.opus': 'audio/ogg',       '.wma': 'audio/x-ms-wma',
            '.jpg': 'image/jpeg',       '.jpeg': 'image/jpeg',
            '.png': 'image/png',        '.gif': 'image/gif',
            '.webp': 'image/webp',      '.svg': 'image/svg+xml',
            '.pdf': 'application/pdf',
            '.docx': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
            '.doc':  'application/msword',
            '.xlsx': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
            '.xls':  'application/vnd.ms-excel',
            '.csv':  'text/csv',
            '.json': 'application/json',
            '.txt':  'text/plain',
        }
        if ext in type_map:
            return type_map[ext]
        ct, _ = mimetypes.guess_type(filename)
        return ct or 'application/octet-stream'

    # ── DECRYPTION — identical AES-GCM chunked format ────────────────────

    def _decrypt_stream(self, file_path):
        key = settings.ENCRYPTION_KEY
        with open(file_path, 'rb') as f:
            while True:
                iv = f.read(12)
                if not iv:
                    break
                length_bytes = f.read(4)
                if not length_bytes:
                    break
                encrypted_length = struct.unpack('>I', length_bytes)[0]
                encrypted = f.read(encrypted_length)
                if len(encrypted) < 16:
                    break
                tag, ciphertext = encrypted[-16:], encrypted[:-16]
                try:
                    cipher = Cipher(
                        algorithms.AES(key),
                        modes.GCM(iv, tag),
                        backend=default_backend()
                    )
                    dec = cipher.decryptor()
                    yield dec.update(ciphertext) + dec.finalize()
                except Exception as e:
                    logger.error(f"Decrypt chunk failed [{file_path}]: {e}")
                    break

    def _decrypt_full(self, file_path, cache_key=None):
        if cache_key:
            cached = cache.get(cache_key)
            if cached:
                return cached
        try:
            buf = bytearray()
            for chunk in self._decrypt_stream(file_path):
                buf.extend(chunk)
            data = bytes(buf)
            if cache_key:
                cache.set(cache_key, data, timeout=self.CACHE_TIMEOUT)
            return data
        except Exception as e:
            logger.error(f"Full decryption failed [{file_path}]: {e}")
            return None

    # ── FORMAT CONVERSIONS ────────────────────────────────────────────────

    def _convert_heic_to_jpeg(self, file_bytes):
        try:
            from pillow_heif import register_heif_opener
            from PIL import Image
            import io
            register_heif_opener()
            image = Image.open(io.BytesIO(file_bytes))
            if image.mode in ('RGBA', 'P'):
                image = image.convert('RGB')
            out = io.BytesIO()
            image.save(out, format='JPEG', quality=85, optimize=True)
            return out.getvalue()
        except Exception as e:
            logger.error(f"HEIC conversion failed: {e}")
            return None

    def _convert_tiff_to_jpeg(self, file_bytes):
        try:
            from PIL import Image
            import io
            image = Image.open(io.BytesIO(file_bytes))
            if hasattr(image, 'n_frames') and image.n_frames > 1:
                image.seek(0)
            if image.mode in ('RGBA', 'P', 'CMYK'):
                image = image.convert('RGB')
            image.thumbnail((4000, 4000), Image.Resampling.LANCZOS)
            out = io.BytesIO()
            image.save(out, format='JPEG', quality=85, optimize=True)
            return out.getvalue()
        except Exception as e:
            logger.error(f"TIFF conversion failed: {e}")
            return None

    def _convert_raw_to_jpeg(self, file_bytes):
        try:
            import rawpy, io
            from PIL import Image
            with rawpy.imread(io.BytesIO(file_bytes)) as raw:
                rgb = raw.postprocess(use_camera_wb=True, output_bps=8)
                image = Image.fromarray(rgb)
                image.thumbnail((4000, 4000), Image.Resampling.LANCZOS)
                out = io.BytesIO()
                image.save(out, format='JPEG', quality=85, optimize=True)
                return out.getvalue()
        except Exception as e:
            logger.error(f"RAW conversion failed: {e}")
            return None

    def _convert_video_to_mp4(self, file_bytes, source_ext):
        try:
            import subprocess, tempfile
            with tempfile.TemporaryDirectory() as tmpdir:
                input_path  = os.path.join(tmpdir, f'input{source_ext}')
                output_path = os.path.join(tmpdir, 'output.mp4')
                with open(input_path, 'wb') as f:
                    f.write(file_bytes)
                cmd = [
                    'ffmpeg', '-y', '-i', input_path,
                    '-c:v', 'libx264', '-preset', 'fast', '-crf', '23',
                    '-c:a', 'aac', '-b:a', '128k',
                    '-movflags', '+faststart',
                    '-pix_fmt', 'yuv420p',
                    output_path
                ]
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
                if result.returncode != 0:
                    logger.error(f"FFmpeg error: {result.stderr}")
                    return None
                with open(output_path, 'rb') as f:
                    return f.read()
        except subprocess.TimeoutExpired:
            logger.error(f"Video conversion timeout: {source_ext}")
            return None
        except FileNotFoundError:
            logger.error("FFmpeg not found")
            return None
        except Exception as e:
            logger.error(f"Video conversion failed: {e}")
            return None

    def _convert_doc_to_docx(self, file_bytes, media_id):
        """
        Reuse your existing convert_doc_to_docx_bytes utility.
        Import path — adjust to match your project.
        """
        try:
            from family_tree.utils import convert_doc_to_docx_bytes
            return convert_doc_to_docx_bytes(file_bytes, media_id, 'memory_map')
        except Exception as e:
            logger.error(f"DOC→DOCX conversion failed: {e}")
            return None

    # ── RESPONSE BUILDERS ─────────────────────────────────────────────────

    def _stream_with_range(self, request, file_bytes, content_type):
        """Range-aware streaming — needed for video/audio seeking."""
        size   = len(file_bytes)
        start, end, status_code = 0, size - 1, 200

        range_header = request.headers.get('Range')
        if range_header:
            m = re.match(r'bytes=(\d+)-(\d*)', range_header)
            if m:
                start = int(m.group(1))
                end   = int(m.group(2)) if m.group(2) else size - 1
                end   = min(end, size - 1)
                status_code = 206

        def stream():
            pos = start
            while pos <= end:
                yield file_bytes[pos: min(pos + self.CHUNK_SIZE, end + 1)]
                pos += self.CHUNK_SIZE

        resp = StreamingHttpResponse(stream(), status=status_code, content_type=content_type)
        resp['Accept-Ranges']     = 'bytes'
        resp['Content-Length']    = str(end - start + 1)
        resp['Content-Disposition'] = 'inline'
        resp['Cache-Control']     = 'private, max-age=3600'
        resp['X-Content-Type-Options'] = 'nosniff'
        if status_code == 206:
            resp['Content-Range'] = f'bytes {start}-{end}/{size}'
        return resp

    def _simple_response(self, file_bytes, content_type, download=False, filename='file'):
        resp = HttpResponse(file_bytes, content_type=content_type)
        disposition = f'attachment; filename="{filename}"' if download else 'inline'
        resp['Content-Disposition'] = disposition
        resp['Cache-Control']       = 'private, max-age=3600'
        resp['X-Content-Type-Options'] = 'nosniff'
        return resp

    # ── CONVERSION ROUTER ─────────────────────────────────────────────────

    def _maybe_convert(self, file_bytes, ext, media_id):
        """
        Returns (converted_bytes, new_ext) or (None, ext) if no conversion needed/failed.
        Results are cached so conversion only happens once per media item.
        """
        if ext in ('.heic', '.heif'):
            cache_key = f'mm_jpeg_{media_id}'
            cached = cache.get(cache_key)
            if cached:
                return cached, '.jpg'
            converted = self._convert_heic_to_jpeg(file_bytes)
            if converted:
                cache.set(cache_key, converted, self.CACHE_TIMEOUT)
            return (converted, '.jpg') if converted else (None, ext)

        if ext in ('.tiff', '.tif'):
            cache_key = f'mm_jpeg_{media_id}'
            cached = cache.get(cache_key)
            if cached:
                return cached, '.jpg'
            converted = self._convert_tiff_to_jpeg(file_bytes)
            if converted:
                cache.set(cache_key, converted, self.CACHE_TIMEOUT)
            return (converted, '.jpg') if converted else (None, ext)

        if ext in ('.raw', '.cr2', '.nef', '.arw'):
            cache_key = f'mm_jpeg_{media_id}'
            cached = cache.get(cache_key)
            if cached:
                return cached, '.jpg'
            converted = self._convert_raw_to_jpeg(file_bytes)
            if converted:
                cache.set(cache_key, converted, self.CACHE_TIMEOUT)
            return (converted, '.jpg') if converted else (None, ext)

        if ext in ('.mkv', '.avi', '.wmv', '.flv', '.mov', '.ts', '.m4v', '.3gp', '.mpeg', '.mpg'):
            cache_key = f'mm_mp4_{media_id}'
            cached = cache.get(cache_key)
            if cached:
                return cached, '.mp4'
            converted = self._convert_video_to_mp4(file_bytes, ext)
            if converted:
                cache.set(cache_key, converted, self.CACHE_TIMEOUT)
            return (converted, '.mp4') if converted else (None, ext)

        if ext == '.doc':
            cache_key = f'mm_docx_{media_id}'
            cached = cache.get(cache_key)
            if cached:
                return cached, '.docx'
            converted = self._convert_doc_to_docx(file_bytes, media_id)
            if converted:
                cache.set(cache_key, converted, self.CACHE_TIMEOUT)
            return (converted, '.docx') if converted else (None, ext)

        return None, ext   # no conversion needed for this ext

    # ── SERVE LOGIC ───────────────────────────────────────────────────────

    def _serve(self, request, file_path, filename, media_id, category):
        ext       = self._ext(filename)
        cache_key = f'mm_bytes_{media_id}'

        # Files that need conversion — decrypt first, then convert
        if ext in self.NEEDS_CONVERSION:
            file_bytes = self._decrypt_full(file_path, cache_key)
            if not file_bytes:
                raise Http404('Decryption failed')

            converted, new_ext = self._maybe_convert(file_bytes, ext, media_id)

            if converted:
                ct = self._content_type(filename, override_ext=new_ext)
                if new_ext == '.mp4':
                    return self._stream_with_range(request, converted, ct)
                if new_ext == '.docx':
                    return self._stream_with_range(request, converted, ct)
                if new_ext == '.jpg':
                    return self._simple_response(converted, ct)
            else:
                # Conversion failed — serve original as download so user isn't stuck
                ct = self._content_type(filename)
                return self._simple_response(file_bytes, ct, download=True, filename=filename)

        # ── No conversion needed below ────────────────────────────────────

        if category in ('video', 'audio'):
            file_bytes = self._decrypt_full(file_path, cache_key)
            if not file_bytes:
                raise Http404('Decryption failed')
            return self._stream_with_range(request, file_bytes, self._content_type(filename))

        if category == 'pdf':
            file_bytes = self._decrypt_full(file_path, cache_key)
            if not file_bytes:
                raise Http404('Decryption failed')
            # Reuse range streaming — PDF viewers need it too
            return self._stream_with_range(request, file_bytes, 'application/pdf')

        if category == 'document':
            file_bytes = self._decrypt_full(file_path, cache_key)
            if not file_bytes:
                raise Http404('Decryption failed')
            return self._stream_with_range(request, file_bytes, self._content_type(filename))

        if category == 'image':
            if ext == '.svg':
                file_bytes = self._decrypt_full(file_path, cache_key)
                resp = HttpResponse(file_bytes, content_type='image/svg+xml')
                resp['Content-Security-Policy'] = (
                    "default-src 'none'; img-src * data:; style-src 'unsafe-inline';"
                )
                resp['Content-Disposition'] = 'inline'
                return resp
            # Progressive stream — no need to buffer full image in memory
            resp = StreamingHttpResponse(
                self._decrypt_stream(file_path),
                content_type=self._content_type(filename)
            )
            resp['Content-Disposition'] = 'inline'
            resp['Cache-Control'] = 'private, max-age=3600'
            return resp

        # Fallback
        file_bytes = self._decrypt_full(file_path, cache_key)
        if not file_bytes:
            raise Http404('Decryption failed')
        return self._simple_response(file_bytes, self._content_type(filename))

    # ── MAIN ENTRY ────────────────────────────────────────────────────────

    def get(self, request, media_id):
        # 1. Signed URL validation
        exp = request.GET.get('exp')
        sig = request.GET.get('sig')
        if not exp or not sig:
            return Response(status=status.HTTP_404_NOT_FOUND)
        try:
            if int(exp) < int(time.time()):
                return Response(status=status.HTTP_404_NOT_FOUND)
        except (ValueError, TypeError):
            return Response(status=status.HTTP_404_NOT_FOUND)
        if not self._validate_signature(str(media_id), exp, sig):
            return Response(status=status.HTTP_403_FORBIDDEN)

        # 2. Fetch record
        # try:
        #     media = MemoryMediaDetails.objects.select_related('user').get(
        #         id=media_id, is_deleted=False
        #     )
        try:
            media = MemoryMediaDetails.objects.select_related(
                'user',
                'memory_place__memory_map',
                'bucket_item__memory_map',
            ).get(id=media_id, is_deleted=False)


    
        except MemoryMediaDetails.DoesNotExist:
            return Response(status=status.HTTP_404_NOT_FOUND)

        # 3. Permission — owner OR map recipient
        user = self.get_current_user(request)
        if not self._check_permission(user, media):
            return Response(status=status.HTTP_403_FORBIDDEN)

        # 4. File on disk
        if not media.file:
            return Response(status=status.HTTP_404_NOT_FOUND)
        file_path = media.file.path
        if not os.path.exists(file_path):
            raise Http404('File not found on server')

        filename = os.path.basename(media.file.name or file_path)
        category = self._categorize(filename)

        return self._serve(
            request, 
            file_path, 
            filename, 
            str(media_id),
            category
        )

#---------------------------------DOWNLOAD MEDIA----------------------------------------
class MemoryMapMediaDownloadAPIView(SecuredView):
    CHUNK_SIZE = 1024 * 1024  # 1MB

    # ------------------------------------------------------------
    # Decrypt stream 
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
                    raise Http404("Corrupted file")

                for i in range(0, len(decrypted), self.CHUNK_SIZE):
                    yield decrypted[i:i+self.CHUNK_SIZE]

    # ------------------------------------------------------------
    # GET
    # ------------------------------------------------------------
    def get(self, request, media_id):
        user = self.get_current_user(request)

        if not user:
            return Response(status=401)

        # 1. Get media
        try:
            media = MemoryMediaDetails.objects.select_related(
                "memory_place__memory_map",
                "bucket_item__memory_map"
            ).get(id=media_id, is_deleted=False)

        except MemoryMediaDetails.DoesNotExist:
            raise Http404("Media not found")

        # 2. Permission
        memory_map = media.memory_map

        if not (
            memory_map.user_id == user.id or
            MemoryMapRecipients.objects.filter(
                memory_map=memory_map,
                email=user.email,
                is_deleted=False
            ).exists()
        ):
            return Response({"detail": "Permission denied"}, status=403)

        # 3. File check
        if not media.file:
            raise Http404("File not available")

        file_path = media.file.path
        if not os.path.exists(file_path):
            raise Http404("File missing")

        # 4. Filename (use title)
        disk_name = os.path.basename(file_path)
        ext = os.path.splitext(disk_name)[1]

        filename = media.title or disk_name
        if not filename.lower().endswith(ext.lower()):
            filename = f"{filename}{ext}"

        # 5. Content type
        content_type, _ = mimetypes.guess_type(filename)
        content_type = content_type or "application/octet-stream"

        # 6. Response
        response = StreamingHttpResponse(
            self._stream_decrypted_chunks(file_path),
            content_type=content_type
        )

        response["Content-Disposition"] = f'attachment; filename="{filename}"'
        response["Cache-Control"] = "no-store"
        response["X-Content-Type-Options"] = "nosniff"

        return response

        


                             


        




        
        










        

        

        

        

        

        



        



