import boto3, io, re
import logging
import json
import time
import mimetypes
from rest_framework import serializers
from memory_room.signals import update_user_storage, update_users_storage
from botocore.exceptions import ClientError
from django.conf import settings
from django.http import StreamingHttpResponse, Http404, JsonResponse
from django.shortcuts import get_object_or_404

from rest_framework import generics, permissions, status
from rest_framework.response import Response
from rest_framework.parsers import MultiPartParser
from rest_framework.exceptions import ValidationError
from rest_framework.pagination import PageNumberPagination
from memory_room.tasks import copy_s3_object_preserve_meta_kms


import hmac
import hashlib
import base64
import time
from django.conf import settings
from django.http import HttpResponse, HttpResponseForbidden
from django.views import View

from django.http import StreamingHttpResponse, HttpResponse, FileResponse
from django.utils.http import http_date
from rest_framework.response import Response
from rest_framework import status
import time, logging
from wsgiref.util import FileWrapper
from io import BytesIO

from channels.layers import get_channel_layer
from asgiref.sync import async_to_sync
import threading
import queue
import time

import tempfile
from moviepy.editor import VideoFileClip
from memory_room.media_helper import decrypt_s3_file_chunked,decrypt_s3_file_chunked_range,ChunkedDecryptor,S3MediaDecryptor
from django.core.cache import cache
from concurrent.futures import ThreadPoolExecutor, as_completed
from memory_room.helpers import generate_unique_memory_room_name,upload_file_to_s3_kms_chunked

from userauth.models import Assets
from userauth.apis.views.views import SecuredView, NewSecuredView

from memory_room.models import (
    MemoryRoom,
    MemoryRoomTemplateDefault,
    MemoryRoomMediaFile,
    FILE_TYPES,
    CustomMemoryRoomTemplate
)
from memory_room.apis.serializers.memory_room import (
    AssetSerializer,
    MemoryRoomCreationSerializer,
    MemoryRoomTemplateDefaultSerializer,
    MemoryRoomUpdationSerializer,
    MemoryRoomMediaFileSerializer,
    MemoryRoomMediaFileCreationSerializer,
    MemoryRoomMediaFileReadOnlySerializer,
    MemoryRoomMediaFileDescriptionUpdateSerializer
)
from memory_room.apis.serializers.serailizers import MemoryRoomSerializer
from memory_room.crypto_utils import  verify_signature,get_file_bytes
from memory_room.utils import determine_download_chunk_size,convert_doc_to_docx_bytes
from memory_room.tasks import update_memory_room_occupied_storage

logger = logging.getLogger(__name__)
from memory_room.s3_helpers import s3_helper

from memory_room.crypto_utils import generate_signed_path,save_and_upload_decrypted_file,decrypt_and_get_image,encrypt_and_upload_file,get_decrypt_file_bytes,get_media_file_bytes_with_content_type,generate_room_media_s3_key
from memory_room.utils import convert_heic_to_jpeg_bytes,convert_mkv_to_mp4_bytes, convert_file_size, convert_video_to_mp4_bytes, convert_audio_to_mp3_bytes, convert_mpeg_to_mp4_bytes

from memory_room.utils import upload_file_to_s3_bucket, get_file_category, generate_unique_slug, convert_doc_to_docx_bytes,convert_heic_to_jpeg_bytes,convert_mkv_to_mp4_bytes, convert_video_to_mp4_bytes, convert_mov_bytes_to_mp4_bytes,convert_mpeg_bytes_to_mp4_bytes_strict,convert_mpg_bytes_to_mp4_bytes_strict,convert_ts_bytes_to_mp4_bytes_strict,convert_mov_bytes_to_mp4_bytes_strict,convert_3gp_bytes_to_mp4_bytes_strict,convert_m4v_bytes_to_mp4_bytes_strict,convert_tiff_bytes_to_jpg_bytes

MEDIA_FILES_BUCKET = 'yurayi-media'

import os
import time
import json
import uuid
import base64
import logging
from io import BytesIO
from concurrent.futures import ThreadPoolExecutor
import threading

import boto3
from botocore.config import Config

from django.conf import settings
from django.http import JsonResponse
from django.shortcuts import get_object_or_404
from django.core.cache import cache

from rest_framework.views import APIView

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend

from memory_room.models import TimeCapSoul, TimeCapSoulMediaFile
from memory_room.crypto_utils import clean_filename, generate_capsoul_media_s3_key,generate_room_media_s3_key
from memory_room.upload_helper import extract_thumbnail_from_segment
from memory_room.media_helper import ChunkedDecryptor
from timecapsoul.utils import MediaThumbnailExtractor
from memory_room.utils import (
    get_file_category
)
from memory_room.signals import update_users_storage
from userauth.models import User


import hashlib

def media_cache_key(prefix: str, s3_key: str) -> str:
    digest = hashlib.sha256(s3_key.encode("utf-8")).hexdigest()
    return f"{prefix}:{digest}"


s3 = boto3.client("s3", region_name='ap-south-1',
    aws_access_key_id=settings.AWS_ACCESS_KEY_ID,
    aws_secret_access_key=settings.AWS_SECRET_ACCESS_KEY,
)


def display_cache_message(msg:str):
    try:
        print(f'\n ---- {msg}   ----')
    except Exception as e:
        pass
    

class MemoryRoomCoverView(SecuredView):
    """
    API endpoint to list all assets of type 'Memory Room Cover'.
    Only authenticated users can access this.
    """
    def get(self, request):
        logger.info("MemoryRoomCoverView.get called")
        """
        Returns all memory room cover assets ordered by creation date.
        """
        cache_key = 'memory_room_covers'
        data  = cache.get(cache_key)
        if not data:
            assets = Assets.objects.filter(asset_types='Memory Room Cover', is_deleted = False).order_by('-created_at')
            data = AssetSerializer(assets, many=True).data
            cache.set(cache_key, data, timeout=60 * 60)  # 1 hour cache

        return Response(data)

class UserMemoryRoomListView(SecuredView):
    """
    API endpoint to list all non-deleted memory rooms of the current user.
    """
    def get(self,request):
        logger.info("UserMemoryRoomListView.get called")
        """
        Returns all memory rooms for the current user that are not deleted.
        """
        user  = self.get_current_user(request)
        cached_key = f'{user.email}__rooms_list'
        cached_data =  cache.get(cached_key)
        if cached_data:
            display_cache_message(f'room list shared via cached')
            return Response(cached_data)
        rooms = MemoryRoom.objects.filter(user=user, is_deleted=False).order_by('-updated_at')
        serializer_data = MemoryRoomSerializer(rooms, many=True).data
        cache.set(cached_key, serializer_data, 60*60*24)
        return Response(serializer_data)

class MemoryRoomTemplateDefaultViewSet(SecuredView):
    """
    API endpoint to list all default memory room templates.
    """
    def get(self, request):
        logger.info("MemoryRoomTemplateDefaultViewSet.get called")
        """
        Returns all non-deleted default memory room templates ordered by creation.
        """
        cache_key = 'memory_room_default_temlates'
        data  = cache.get(cache_key)
        if not data:
            rooms = MemoryRoomTemplateDefault.objects.filter(is_deleted=False).order_by('-created_at')
            data = MemoryRoomTemplateDefaultSerializer(rooms, many=True).data
            # store in cache
            cache.set(cache_key, data, timeout=60*60) # 24 hour  cached  
            
        return Response(data)

class CreateMemoryRoomView(SecuredView):
    """
    API view to create, update, or delete a memory room.
    Inherits authentication logic from `SecuredView`.
    """

    def post(self, request, format=None):
        logger.info("CreateMemoryRoomView.post called")
        """
        Create a new memory room.
        """
        user = self.get_current_user(request)
        serializer = MemoryRoomCreationSerializer(data=request.data, context={'user': user})
        serializer.is_valid(raise_exception=True)
        memory_room = serializer.validated_data.get('memory_room')
        serialized_data = MemoryRoomSerializer(memory_room).data if memory_room else {}
        response = {
            'message': 'Memory created successfully',
            'memory_room': serialized_data
        }
        cache.delete(f'{user.email}__rooms_list')
        display_cache_message('Room cache deleted while new room creation')
        return Response(response)

    def delete(self, request, memory_room_id, format=None):
        logger.info("CreateMemoryRoomView.delete called")
        """
        Delete an existing memory room.
        """
        user = self.get_current_user(request)
        memory_room = get_object_or_404(MemoryRoom, id=memory_room_id, user=user)
        room_name = memory_room.room_template.name
        memory_room.is_deleted = True
        memory_room.save()
        is_updated = update_users_storage(
            capsoul=memory_room
        )
        media_file = memory_room.memory_media_files.filter(is_deleted = False)
        media_file.update(is_deleted = True)
        cache.delete(f'{user.email}__rooms_list')
        display_cache_message('Room list cache deleted while room deletion')
        return Response(
            {'message': f'Memory deleted successfully named as : {room_name}'},
            status=status.HTTP_204_NO_CONTENT
        )

    def patch(self, request, memory_room_id):
        logger.info("CreateMemoryRoomView.patch called")
        """
        Partially update fields of a memory room.
        """
        user = self.get_current_user(request)
        memory_room = get_object_or_404(MemoryRoom, id=memory_room_id, user=user)
        serializer = MemoryRoomUpdationSerializer(instance=memory_room, data=request.data, partial=True)

        if serializer.is_valid():
            updated_room = serializer.save()
            cache.delete(f'{user.email}__rooms_list')
            display_cache_message('Room cache deleted while room updation ')
            return Response(MemoryRoomSerializer(updated_room).data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class SetMemoryRoomCoverImageAPIView(SecuredView):
    def post(self, request, memory_room_id, media_file_id):
        user = self.get_current_user(request)
        logger.info(f"SetMemoryRoomCoverImageAPIView.post called by {user.email} room: {memory_room_id} media-id: {media_file_id}")
        user = self.get_current_user(request)
        # memory_room = get_object_or_404(MemoryRoom, id=memory_room_id, user=user)
        media_file = get_object_or_404(MemoryRoomMediaFile, id=media_file_id, user = user)
        memory_room= media_file.memory_room
        
        if memory_room.room_template.default_template is None:
            # media_file = get_object_or_404(MemoryRoomMediaFile, id=media_file_id, user = user, memory_room = memory_room)
            if media_file.file_type == 'image' and media_file.is_cover_image == False:
                logger.info(f"SetMemoryRoomCoverImageAPIView.post cover setting started by {user.email} room: {memory_room_id} media-id: {media_file_id}")
                
                # now images as cover image here
                from userauth.models import Assets
                media_s3_key =  str(media_file.s3_key)
                # file_name = media_s3_key.split('/')[-1]
                # file_bytes, content_type = get_media_file_bytes_with_content_type(media_file, user)
                # if not file_bytes or not content_type:
                #     return Response(status=status.HTTP_500_INTERNAL_SERVER_ERROR)
                # s3_key, url = save_and_upload_decrypted_file(filename=file_name, decrypted_bytes=file_bytes, bucket='time-capsoul-files', content_type=content_type)
                assets_obj = Assets.objects.create(s3_key=media_s3_key)
                room_template = memory_room.room_template
                room_template.cover_image = assets_obj
                room_template.save()
                memory_room.save()
                media_file.is_cover_image = True
                media_file.save()
                other_media = MemoryRoomMediaFile.objects.filter(memory_room = memory_room, is_deleted=False, user = user).exclude(id = media_file.id)
                other_media.update(is_cover_image = False)
                logger.info(f'Memory Room cover set successfully by {user.email} room: {memory_room_id} media id: {media_file_id} ')
                cache.delete(f'{user.email}__rooms_list')
                cache.delete(f'{user.email}_room_{memory_room.id}_media_list')
                display_cache_message('Room cache deleted setting new cover image')
            else:
                logger.info(f'Memory Room cover already set by {user.email} room: {memory_room_id} media id: {media_file_id} ')
                
        serializer = MemoryRoomSerializer(memory_room)
        return Response(serializer.data)


class MemoryRoomMediaFileListCreateAPI(SecuredView):
    """
    API view to manage (list, add, move, delete) media files within a memory room.
    """
    parser_classes = [MultiPartParser]

    def get_memory_room(self, user, memory_room_id):
        """
        Utility method to get a memory room owned by the user.
        """
        return get_object_or_404(MemoryRoom, id=memory_room_id, user=user)

    def get(self, request, memory_room_id):
        logger.info("MemoryRoomMediaFileListCreateAPI.get called")
        """
        List all media files of a memory room.
        """
        user = self.get_current_user(request)
        cache_key = f'{user.email}_room_{memory_room_id}_media_list'
        cached_data  = cache.get(cache_key)
        if cached_data:
            display_cache_message('media serve from cache')
            return Response(cached_data)
        
        memory_room = self.get_memory_room(user, memory_room_id)
        media_files = MemoryRoomMediaFile.objects.filter(memory_room=memory_room, user=user, is_deleted=False).order_by('-updated_at')
        serializer_data =  MemoryRoomMediaFileSerializer(media_files, many=True).data
        cache.set(cache_key, serializer_data, 60*60*24)
        return Response(serializer_data)
        
   
    def post(self, request, memory_room_id):
        """
        Upload multiple media files to a memory room with streaming progress updates.
        Each file has its own IV for decryption. Uses multi-threading for parallel uploads.
        """
        user = self.get_current_user(request)
        memory_room = self.get_memory_room(user, memory_room_id)

        files = request.FILES.getlist('file')
        created_objects = []
        results = []

        if len(files) == 0: 
            raise serializers.ValidationError({'file': "Media files is required"})

        # Parse IVs from frontend
        try:
            ivs_json = request.POST.get('ivs', '[]')
            ivs = json.loads(ivs_json)
        except json.JSONDecodeError:
            raise serializers.ValidationError({'ivs': "Invalid IVs format"})

        # Ensure we have an IV for each file
        if len(ivs) != len(files):
            raise serializers.ValidationError({'ivs': f"Number of IVs ({len(ivs)}) must match number of files ({len(files)})"})

        # Dynamic worker calculation based on file count and sizes
        total_files = len(files)
        total_size = sum(f.size for f in files)
        
        if total_files <= 2:
            max_workers = 1
        elif total_files <= 5:
            max_workers = 2
        elif total_size > 500 * 1024 * 1024:  # > 500MB total
            max_workers = min(total_files, 4)
        else:
            max_workers = min(total_files, 6)

        # Thread-safe progress tracking
        progress_lock = threading.Lock()
        progress_event = threading.Event()

        file_progress = {i: {'progress': 0, 'message': 'Queued', 'status': 'pending'} for i in range(total_files)}
        
        def update_file_progress(file_index, progress, message, status='processing'):
            with progress_lock:
                file_progress[file_index] = {
                    'progress': progress,
                    'message': message,
                    'status': status
                }
                progress_event.set()

                # print(f'\n File {file_progress}')

        def calculate_overall_progress():
            with progress_lock:
                if not file_progress:
                    return 0
                total_progress = sum(fp['progress'] for fp in file_progress.values())
                return int(total_progress / len(file_progress))

        def file_upload_stream():
            def process_single_file(file_index, uploaded_file, file_iv):
                """Process a single file upload with progress tracking"""
                try:
                    def progress_callback(progress, message):
                        if progress == -1:  # Error case
                            update_file_progress(file_index, 0, message, 'failed')
                        else:
                            update_file_progress(file_index, progress, message, 'processing')
                    
                    uploaded_file.seek(0)
                    
                    serializer = MemoryRoomMediaFileCreationSerializer(
                        data={'file': uploaded_file, 'iv': file_iv},
                        context={
                            'user': user, 
                            'memory_room': memory_room,
                            'progress_callback': progress_callback
                        }
                    )

                    if serializer.is_valid():
                        media_file = serializer.save()
                       
                        update_file_progress(file_index, 96, 'Upload completed successfully', 'success')
                        
                        is_updated = update_users_storage(
                            operation_type='addition',
                            media_updation='memory_room',
                            media_file=media_file
                        )
                        cache.delete(f'{user.email}_room_{memory_room_id}_media_list')
                        display_cache_message('media cached list cleared at new file upload')

                        update_file_progress(file_index, 98, 'Upload completed successfully', 'success')
                        
                        return {
                            'index': file_index,
                            'result': {
                                "file": uploaded_file.name,
                                "status": "success",
                                "progress": 99,
                                "data": MemoryRoomMediaFileSerializer(media_file).data
                            },
                            'media_file': media_file
                        }
                    else:
                        update_file_progress(file_index, 0, f"Validation failed: {serializer.errors}", 'failed')
                        return {
                            'index': file_index,
                            'result': {
                                "file": uploaded_file.name,
                                "status": "failed",
                                "progress": 0,
                                "errors": serializer.errors
                            },
                            'media_file': None
                        }

                except Exception as e:
                    error_msg = str(e)
                    update_file_progress(file_index, 0, f"Upload failed: {error_msg}", 'failed')
                    return {
                        'index': file_index,
                        'result': {
                            "file": uploaded_file.name,
                            "status": "failed",
                            "progress": 0,
                            "error": error_msg
                        },
                        'media_file': None
                    }

            with ThreadPoolExecutor(max_workers=max_workers) as executor:
                future_to_index = {
                    executor.submit(process_single_file, index, files[index], ivs[index]): index
                    for index in range(total_files)
                }
                
                started_files = set()
                last_sent_progress = {i: -1 for i in range(total_files)}  # track last sent progress
                
                while len(results) < total_files:
                    progress_event.wait(timeout=1.0)   # wakes immediately when set OR after 1s
                    progress_event.clear()

                    with progress_lock:
                        for file_index, progress_data in file_progress.items():
                            file_name = files[file_index].name

                            # Send start message once
                            if file_index not in started_files and progress_data['status'] != 'pending':
                                yield f"data: Starting upload of {file_name}\n\n"
                                started_files.add(file_index)

                            # Only send progress if changed
                            if (
                                progress_data['status'] == 'processing' and 
                                progress_data['progress'] != last_sent_progress[file_index]
                            ):
                                yield f"data: {file_name} -> {progress_data['progress']}\n\n"
                                last_sent_progress[file_index] = progress_data['progress']
                    
                    # Handle completed tasks
                    completed_futures = []
                    for future in future_to_index:
                        if future.done():
                            completed_futures.append(future)
                    
                    for future in completed_futures:
                        try:
                            result_data = future.result()
                            if result_data['media_file']:
                                created_objects.append(result_data['media_file'])
                            results.append(result_data['result'])
                            
                            file_name = result_data['result']['file']
                            if result_data['result']['status'] == 'success':
                                yield f"data: {file_name} -> 100\n\n"
                                yield f"data: {file_name} upload completed successfully\n\n"
                            else:
                                error_msg = result_data['result'].get('error') or result_data['result'].get('errors', 'Upload failed')
                                yield f"data: {file_name} upload failed: {json.dumps(error_msg) if isinstance(error_msg, dict) else error_msg}\n\n"
                            
                            del future_to_index[future]
                        
                        except Exception as e:
                            logger.exception("Task completion error")
                            del future_to_index[future]
                    
                    # time.sleep(0.1)
                    time.sleep(0.1)
                    
            
            yield f"data: FINAL_RESULTS::{json.dumps(results)}\n\n"

        # return StreamingHttpResponse(
        #     file_upload_stream(),
        #     content_type='text/event-stream',
        #     status=status.HTTP_200_OK
        # )
        
        response = StreamingHttpResponse(
            file_upload_stream(),
            content_type='text/event-stream',
        )
        response['Cache-Control'] = 'no-cache'
        response['X-Accel-Buffering'] = 'no'  # disables buffering in nginx
        # response['Connection'] = 'keep-alive'
        return response


    def patch(self, request, memory_room_id, media_file_id):
        """
        Move a media file to another memory room.
        """
        user = self.get_current_user(request)
        new_room = self.get_memory_room(user, memory_room_id)
        media_file = get_object_or_404(MemoryRoomMediaFile, id=media_file_id, user=user)

        media_file.memory_room = new_room
        media_file.save()
        cache.delete(f'{user.email}_room_{memory_room_id}_media_list') # 
        cache.delete(f'{user.email}_room_{media_file.memory_room.id}_media_list')
        display_cache_message('media cached list cleared at file move to another ')
        return Response({'message': "Media files moved successfully"}, status=status.HTTP_200_OK)
    
    def delete(self, request, memory_room_id, media_file_id):
        """
        Delete a media file from a memory room.
        """
        user = self.get_current_user(request)
        memory_room = self.get_memory_room(user, memory_room_id)
        media_file = get_object_or_404(
            MemoryRoomMediaFile,
            id=media_file_id,
            user=user,
            memory_room=memory_room
        )
        media_file.is_deleted = True
        media_file.save()
        is_updated = update_users_storage(
            operation_type='remove',
            media_updation='memory_room',
            media_file=media_file
        )
        cache.delete(f'{user.email}_room_{media_file.memory_room.id}_media_list')
        display_cache_message('media cached list cleared at file deleted ')
        return Response({'message': 'Media file deleted successfully'}, status=status.HTTP_204_NO_CONTENT)

from memory_room.upload_helper import (
    ChunkedUploadSession,truncate_filename, s3, kms, AWS_KMS_KEY_ID
    )

executor = ThreadPoolExecutor(max_workers=10)

from memory_room.jpg_images_handler import (
    is_image_corrupted,try_fix_corrupted_jpg, opencv_repair_jpg, force_repair_jpeg, reencode_jpg
)
from pathlib import Path

import math


class ChunkedMediaUploadView(SecuredView):
    CACHE_PREFIX = "chunked_upload"
    SESSION_TIMEOUT = 3600
    MAX_CHUNK_SIZE = 50 * 1024 * 1024
    SMALL_FILE_THRESHOLD = 5 * 1024 * 1024  # 5 MB

    def _key(self, upload_id):
        return f"{self.CACHE_PREFIX}:{upload_id}"

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

    def _percent(self, value):
        """
        Always return percentage as integer (digits only)
        """
        try:
            return int(min(max(round(float(value)), 0), 100))
        except Exception as e:
            return 0


    def post(self, request, memory_room_id, action):
        memory_room = get_object_or_404(MemoryRoom, id=memory_room_id)
        user = self.get_current_user(request)

        if action == "init":
            return self.initialize_uploads(request, user, memory_room)
        if action == "upload":
            return self.upload_chunk(request, user)
        if action == "complete":
            # Use streaming for completion
            return self.complete_upload_streaming(request, user)
        if action == "abort":
            return self.abort_upload(request, user)

        return JsonResponse({"error": "Invalid action"}, status=400)

    def initialize_uploads(self, request, user, memory_room):
        """Initialize multiple file uploads at once"""
        try:
            files_data = json.loads(request.POST.get("filesData", "[]"))
            
            if not files_data:
                return JsonResponse({"error": "No files provided"}, status=400)
            
            initialized_files = []
            
            for file_data in files_data:
                file_name = file_data["fileName"]
                file_size = int(file_data["fileSize"])
                total_chunks = int(file_data["totalChunks"])
                chunk_size = int(file_data["chunkSize"])
                
                clean_name = clean_filename(truncate_filename(file_name))
                file_type = get_file_category(clean_name)
                
                if file_type == "invalid":
                    raise ValidationError({
                        "file_type": f"Unsupported file type: {file_name}"
                    })
                    continue
                
                upload_id = str(uuid.uuid4())
                file_ext = os.path.splitext(clean_name)[1].lower()

                s3_key = generate_room_media_s3_key(
                    clean_name, 
                    user.s3_storage_id, 
                    memory_room.id, 
                    upload_id=upload_id
                )

                session = ChunkedUploadSession(
                    upload_id,
                    user.id,
                    memory_room.id,
                    file_name,
                    file_size,
                    file_type,
                    total_chunks,
                    chunk_size,
                    s3_key,
                )

                # Generate encryption key
                key = kms.generate_data_key(KeyId=AWS_KMS_KEY_ID, KeySpec="AES_256")
                session.data_key_plain = key["Plaintext"]
                session.data_key_encrypted = key["CiphertextBlob"]
                session.aesgcm = AESGCM(session.data_key_plain)
                
                # Check if file is JPG/JPEG or small file
                session.is_jpg = file_ext in ('.jpg', '.jpeg')
                session.file_ext = file_ext
                session.is_small_file = file_size < self.SMALL_FILE_THRESHOLD
                
                # Only JPG files need temporary storage for corruption checking
                if session.is_jpg:
                    session.temp_chunks_key = f"temp_chunks:{upload_id}"
                    cache.set(session.temp_chunks_key, json.dumps([]), self.SESSION_TIMEOUT)

                # Start multipart upload
                mp = s3.create_multipart_upload(
                    Bucket=MEDIA_FILES_BUCKET,
                    Key=s3_key,
                    Metadata={
                        "edk": base64.b64encode(session.data_key_encrypted).decode(),
                        'chunk_size': str(chunk_size),
                        'file_size': str(file_size),
                        'totalChunks': str(total_chunks),
                    },
                )
                session.s3_upload_id = mp["UploadId"]

                self.save_session(session)

                initialized_files.append({
                    "percentage": 5,              
                    "uploadId": upload_id,
                    "fileName": file_name,
                    "s3Key": s3_key,
                    "totalChunks": total_chunks,
                    "isJpg": session.is_jpg,
                    "isSmallFile": session.is_small_file,
                    "needsProcessing": session.is_jpg  # Only JPG needs special processing
                })

            return JsonResponse({
                "files": initialized_files,
                "message": f"{len(initialized_files)} file(s) initialized successfully"
            })

        except Exception as e:
            logger.exception(f"Init uploads failed: {e}")
            return JsonResponse({"error": str(e)}, status=500)
    
    def upload_chunk(self, request, user):
        upload_id = request.POST.get("uploadId")
        chunk_index = int(request.POST.get("chunkIndex", -1))
        chunk_file = request.FILES.get("chunk")
        iv = request.POST.get("iv")

        if not upload_id or not chunk_file:
            return JsonResponse({"error": "Invalid chunk data"}, status=400)

        lock_key = f"lock:chunk:{upload_id}:{chunk_index}"
        if not cache.add(lock_key, 1, timeout=15):
            return JsonResponse({"status": "retry"}, status=409)

        def stream():
            try:
                session = self.get_session(upload_id)
                if not session:
                    yield f"data: {json.dumps({'uploadId': upload_id, 'error': 'Session expired'})}\n\n"
                    return

                # ---------- DUPLICATE GUARD ----------
                with session.lock:
                    if chunk_index in session.uploaded_chunks:
                        uploaded = len(session.uploaded_chunks)
                        max_percent = (
                            50 if session.is_jpg
                            else 90 if session.file_type in ["video", "audio"]
                            else 100
                        )
                        percent = (uploaded / session.total_chunks) * max_percent

                        yield f"data: {json.dumps({
                            'uploadId': upload_id,
                            'status': 'duplicate',
                            'uploadedChunks': uploaded,
                            'percentage': self._percent(percent)
                        })}\n\n"
                        return

                decrypted = self._decrypt_chunk(chunk_file, iv)

                # ---------- JPG TEMP CACHE ----------
                if session.is_jpg:
                    chunks = json.loads(cache.get(session.temp_chunks_key, "[]"))
                    chunks.append({
                        "index": chunk_index,
                        "data": base64.b64encode(decrypted).decode()
                    })
                    cache.set(session.temp_chunks_key, json.dumps(chunks), self.SESSION_TIMEOUT)

                    with session.lock:
                        session.uploaded_chunks.add(chunk_index)

                    self.save_session(session)

                    percent = (len(session.uploaded_chunks) / session.total_chunks) * 50

                    yield f"data: {json.dumps({
                        'uploadId': upload_id,
                        'status': 'uploaded',
                        'stage': 'receiving',
                        'percentage': self._percent(percent)
                    })}\n\n"
                    return

                # ---------- S3 UPLOAD ----------
                encrypted = self._encrypt_for_s3(decrypted, session.aesgcm)
                part_no = chunk_index + 1

                resp = s3.upload_part(
                    Bucket=MEDIA_FILES_BUCKET,
                    Key=session.s3_key,
                    UploadId=session.s3_upload_id,
                    PartNumber=part_no,
                    Body=encrypted,
                )

                with session.lock:
                    session.s3_parts[str(part_no)] = resp["ETag"]
                    session.uploaded_chunks.add(chunk_index)

                self.save_session(session)

                uploaded = len(session.uploaded_chunks)
                max_percent = 90 if session.file_type in ["video", "audio"] else 100
                percent = (uploaded / session.total_chunks) * max_percent

                yield f"data: {json.dumps({
                    'uploadId': upload_id,
                    'status': 'uploaded',
                    'uploadedChunks': uploaded,
                    'percentage': self._percent(percent)
                })}\n\n"

            except Exception as e:
                logger.exception(e)
                yield f"data: {json.dumps({
                    'uploadId': upload_id,
                    'error': str(e),
                    'percentage': 0
                })}\n\n"

            finally:
                cache.delete(lock_key)

        return StreamingHttpResponse(
            stream(),
            content_type="text/event-stream",
            headers={
                "Cache-Control": "no-cache",
                "X-Accel-Buffering": "no"
            }
        )


    def complete_upload_streaming(self, request, user):
        upload_ids = request.POST.getlist("uploadIds[]")
        if not upload_ids:
            return JsonResponse({"error": "No uploads provided"}, status=400)

        def stream():
            completed, failed = [], []

            for upload_id in upload_ids:
                yield f"data: {json.dumps({'uploadId': upload_id, 'stage': 'starting', 'percentage': 90})}\n\n"

                try:
                    for event in self._complete_single_upload_streaming(upload_id, user):
                        yield f"data: {json.dumps(event)}\n\n"

                    session = self.get_session(upload_id)
                    if session and session.completion_result:
                        completed.append(session.completion_result)
                    else:
                        failed.append(upload_id)

                except Exception as e:
                    logger.exception(e)
                    failed.append(upload_id)
                    yield f"data: {json.dumps({'uploadId': upload_id, 'error': str(e)})}\n\n"

            yield f"data: {json.dumps({
                'type': 'summary',
                'completed': completed,
                'failed': failed
            })}\n\n"

        return StreamingHttpResponse(
            stream(),
            content_type="text/event-stream",
            headers={
                "Cache-Control": "no-cache",
                "X-Accel-Buffering": "no"
            }
        )

    def _complete_single_upload_streaming(self, upload_id, user):
        """
        Completes a single upload with strict streaming guarantees.
        NEVER returns early without yielding progress.
        SAFE for multi-file concurrent uploads.
        """

        session = self.get_session(upload_id)

        if not session:
            yield {
                "uploadId": upload_id,
                "stage": "error",
                "error": "Session expired",
                "percentage": 0
            }
            return

        # ---------- VALIDATION ----------
        if len(session.uploaded_chunks) != session.total_chunks:
            yield {
                "uploadId": upload_id,
                "stage": "error",
                "error": f"Incomplete upload {len(session.uploaded_chunks)}/{session.total_chunks}",
                "percentage": 0
            }
            return

        try:
            # ---------- JPG FLOW ----------
            if session.is_jpg:
                yield {"uploadId": upload_id, "stage": "jpg_processing", "percentage": 50}

                for event in self._process_jpg_file_streaming(session, user, upload_id):
                    yield event

            # ---------- SMALL FILE FLOW ----------
            elif session.is_small_file:
                if len(session.s3_parts) != session.total_chunks:
                    yield {
                        "uploadId": upload_id,
                        "stage": "error",
                        "error": "Missing S3 parts",
                        "percentage": 85
                    }
                    return

                if session.file_type in ["video", "audio"]:
                    yield {"uploadId": upload_id, "stage": "completing_s3", "percentage": 87}

                parts = [
                    {"PartNumber": int(p), "ETag": et}
                    for p, et in session.s3_parts.items()
                ]
                parts.sort(key=lambda x: x["PartNumber"])

                s3.complete_multipart_upload(
                    Bucket=MEDIA_FILES_BUCKET,
                    Key=session.s3_key,
                    UploadId=session.s3_upload_id,
                    MultipartUpload={"Parts": parts},
                )

                yield {
                    "uploadId": upload_id,
                    "stage": "s3_complete",
                    "percentage": 90 if session.file_type in ["video", "audio"] else 100
                }

            # ---------- LARGE FILE FLOW ----------
            else:
                if len(session.s3_parts) != session.total_chunks:
                    yield {
                        "uploadId": upload_id,
                        "stage": "error",
                        "error": "Missing S3 parts",
                        "percentage": 85
                    }
                    return

                yield {
                    "uploadId": upload_id,
                    "stage": "completing_s3",
                    "percentage": 87 if session.file_type in ["video", "audio"] else 95
                }

                parts = [
                    {"PartNumber": int(p), "ETag": et}
                    for p, et in session.s3_parts.items()
                ]
                parts.sort(key=lambda x: x["PartNumber"])

                s3.complete_multipart_upload(
                    Bucket=MEDIA_FILES_BUCKET,
                    Key=session.s3_key,
                    UploadId=session.s3_upload_id,
                    MultipartUpload={"Parts": parts},
                )

                yield {
                    "uploadId": upload_id,
                    "stage": "s3_complete",
                    "percentage": 90 if session.file_type in ["video", "audio"] else 98
                }

            yield {
                "uploadId": upload_id,
                "stage": "creating_record",
                "percentage": 92 if session.file_type in ["video", "audio"] else 98
            }

            memory_room = MemoryRoom.objects.get(id=session.time_capsoul_id)

            from memory_room.utils import get_readable_file_size_from_bytes
            file_size = get_readable_file_size_from_bytes(session.file_size)

            media = MemoryRoomMediaFile.objects.create(
                user=user,
                memory_room=memory_room,
                file_type=session.file_type,
                file_size=file_size,
                title=session.file_name,
                s3_key=session.s3_key,
            )
            cache.delete(f'{user.email}__rooms_list')
            cache.delete(f'{user.email}_room_{memory_room.id}_media_list')

            if session.is_jpg and session.temp_chunks_key:
                cache.delete(session.temp_chunks_key)

            # ---------- THUMBNAIL ----------
            if session.file_type in ["video", "audio"]:
                yield {"uploadId": upload_id, "stage": "thumbnail_start", "percentage": 95}

                for thumb_event in self._extract_thumbnail_with_progress(
                    media.id,
                    session.s3_key,
                    session.file_type,
                    session.file_ext,
                    user.id,
                    upload_id,
                ):
                    yield thumb_event

            update_users_storage("addition", "memory_room", media)

            # ---------- FINALIZE ----------
            session.completion_result = {
                "status": "success",
                "uploadId": upload_id,
                "id": media.id,
                "fileName": session.file_name,
            }

            self.save_session(session)

            yield {"uploadId": upload_id, "stage": "complete", "percentage": 100}

            # Cleanup async
            threading.Timer(5, lambda: self.delete_session(upload_id)).start()

        except Exception as e:
            logger.exception(f"Completion failed {upload_id}: {e}")

            session.completion_result = {
                "status": "error",
                "uploadId": upload_id,
                "error": str(e),
            }
            self.save_session(session)

            yield {
                "uploadId": upload_id,
                "stage": "error",
                "error": str(e),
                "percentage": 0
            }

    def _process_small_file_streaming(self, session, user, upload_id):
        """This method is no longer needed - small files upload directly"""
        # Small files are uploaded immediately during chunk upload
        # No processing needed in complete phase
        pass

    def _process_jpg_file_streaming(self, session, user, upload_id):
        """Process JPG file with streaming progress"""
        try:
            logger.info(f"[JPG] Processing {session.file_name}...")
            
            yield {"uploadId": upload_id, "stage": "reconstructing", "percentage": 51}
            
            # Retrieve all decrypted chunks
            chunks_data = json.loads(cache.get(session.temp_chunks_key, '[]'))
            
            if not chunks_data:
                yield {"uploadId": upload_id, "error": "No JPG chunks found", "percentage": 50}
                return
            
            # Sort chunks by index
            chunks_data.sort(key=lambda x: x['index'])
            
            yield {"uploadId": upload_id, "stage": "assembling", "percentage": 53}
            
            # Reconstruct full file bytes
            original_bytes = b''.join([
                base64.b64decode(chunk['data']) 
                for chunk in chunks_data
            ])
            
            logger.info(f"[JPG] Reconstructed {len(original_bytes)} bytes for {session.file_name}")
            
            yield {"uploadId": upload_id, "stage": "checking", "percentage": 56}
            
            # Check and fix JPG corruption
            final_bytes = None
            for progress in self._check_and_fix_jpg_streaming(original_bytes, session.file_name, upload_id):
                # Extract final_bytes before yielding (don't send bytes over JSON)
                if 'final_bytes' in progress:
                    final_bytes = progress.pop('final_bytes')
                yield progress
            
            if not final_bytes:
                yield {"uploadId": upload_id, "error": "JPG processing failed", "percentage": 60}
                return
            
            yield {"uploadId": upload_id, "stage": "preparing_upload", "percentage": 72}
            
            # Upload processed JPG
            for upload_progress in self._upload_processed_file_streaming(final_bytes, session, upload_id):
                yield upload_progress
            
            logger.info(f"[JPG] Successfully processed and uploaded {session.file_name}")
            
        except Exception as e:
            logger.exception(f"JPG processing failed: {e}")
            yield {"uploadId": upload_id, "error": f"JPG processing failed: {str(e)}", "percentage": 50}

    def _check_and_fix_jpg_streaming(self, original_bytes, file_name, upload_id):
        """Check JPG corruption and fix if needed with streaming progress"""
        logger.info(f"[JPG] Checking corruption for {file_name}...")
        
        yield {"uploadId": upload_id, "stage": "validating", "percentage": 58}
        
        if not is_image_corrupted(original_bytes):
            logger.info(f"[JPG] File is valid, no repair needed")
            # Don't include bytes in the yielded data - store separately
            final_result = {"uploadId": upload_id, "stage": "valid", "percentage": 70}
            final_result['final_bytes'] = original_bytes
            yield final_result
            return
        
        logger.warning(f"[JPG] Corruption detected, attempting repair...")
        yield {"uploadId": upload_id, "stage": "repairing_pillow", "percentage": 61}
        
        # Try Pillow repair
        repaired = try_fix_corrupted_jpg(original_bytes)
        if repaired:
            logger.info(f"[JPG] Repaired with Pillow")
            final_result = {"uploadId": upload_id, "stage": "repaired_pillow", "percentage": 70}
            final_result['final_bytes'] = repaired
            yield final_result
            return
        
        # Try OpenCV repair
        logger.info(f"[JPG] Pillow failed, trying OpenCV...")
        yield {"uploadId": upload_id, "stage": "repairing_opencv", "percentage": 64}
        cv_fixed = opencv_repair_jpg(original_bytes)
        if cv_fixed:
            logger.info(f"[JPG] Repaired with OpenCV")
            final_result = {"uploadId": upload_id, "stage": "repaired_opencv", "percentage": 70}
            final_result['final_bytes'] = cv_fixed
            yield final_result
            return
        
        # Try extreme header rebuild
        logger.info(f"[JPG] OpenCV failed, trying extreme repair...")
        yield {"uploadId": upload_id, "stage": "repairing_extreme", "percentage": 67}
        extreme_fix = force_repair_jpeg(original_bytes)
        if extreme_fix:
            logger.info(f"[JPG] Repaired with extreme method")
            final_result = {"uploadId": upload_id, "stage": "repaired_extreme", "percentage": 70}
            final_result['final_bytes'] = extreme_fix
            yield final_result
            return
        
        # Last resort: re-encode
        logger.warning(f"[JPG] All repairs failed, attempting re-encode...")
        yield {"uploadId": upload_id, "stage": "reencoding", "percentage": 69}
        try:
            final_bytes = reencode_jpg(original_bytes)
            logger.info(f"[JPG] Successfully re-encoded")
            final_result = {"uploadId": upload_id, "stage": "reencoded", "percentage": 70}
            final_result['final_bytes'] = final_bytes
            yield final_result
        except Exception as e:
            logger.error(f"[JPG] Re-encoding failed: {e}")
            yield {"uploadId": upload_id, "error": f"Image unrecoverable: {str(e)}", "percentage": 60}
    
    def _upload_processed_file_streaming(self, file_bytes, session, upload_id):
        """
        Upload processed JPG safely.
        - Uses put_object for <5MB
        - Uses multipart ONLY if >=5MB
        """
        total_size = len(file_bytes)
        MIN_PART_SIZE = 5 * 1024 * 1024  # 5MB

        # ---------- SMALL FILE → SINGLE PUT ----------
        if total_size < MIN_PART_SIZE:
            yield {"uploadId": upload_id, "stage": "encrypting", "percentage": 74}

            encrypted = self._encrypt_for_s3(file_bytes, session.aesgcm)

            yield {"uploadId": upload_id, "stage": "uploading_single", "percentage": 82}

            s3.put_object(
                Bucket=MEDIA_FILES_BUCKET,
                Key=session.s3_key,
                Body=encrypted,
                Metadata={
                    "edk": base64.b64encode(session.data_key_encrypted).decode(),
                    "file_size": str(session.file_size),
                },
            )

            yield {"uploadId": upload_id, "stage": "upload_complete", "percentage": 90}
            return  # ❗ VERY IMPORTANT (no multipart complete)

        # ---------- MULTIPART (>=5MB) ----------
        yield {"uploadId": upload_id, "stage": "encrypting_chunks", "percentage": 74}

        chunk_size = max(session.chunk_size, MIN_PART_SIZE)
        total_parts = math.ceil(total_size / chunk_size)

        part_number = 1
        for offset in range(0, total_size, chunk_size):
            chunk = file_bytes[offset:offset + chunk_size]

            encrypted = self._encrypt_for_s3(chunk, session.aesgcm)

            resp = s3.upload_part(
                Bucket=MEDIA_FILES_BUCKET,
                Key=session.s3_key,
                UploadId=session.s3_upload_id,
                PartNumber=part_number,
                Body=encrypted,
            )

            session.s3_parts[str(part_number)] = resp["ETag"]

            progress = 75 + (part_number / total_parts) * 13
            yield {
                "uploadId": upload_id,
                "stage": "uploading_s3",
                "percentage": round(progress, 2),
            }

            part_number += 1

        yield {"uploadId": upload_id, "stage": "completing_s3", "percentage": 90}

        parts = [
            {"PartNumber": int(p), "ETag": et}
            for p, et in session.s3_parts.items()
        ]
        parts.sort(key=lambda x: x["PartNumber"])

        s3.complete_multipart_upload(
            Bucket=MEDIA_FILES_BUCKET,
            Key=session.s3_key,
            UploadId=session.s3_upload_id,
            MultipartUpload={"Parts": parts},
        )

        yield {"uploadId": upload_id, "stage": "upload_complete", "percentage": 93}

    def _extract_thumbnail_with_progress(self, media_id, s3_key, file_type, file_ext, user_id, upload_id):
        """Extract thumbnail with streaming progress (95% → 100%)"""
        try:
            from memory_room.crypto_utils import get_media_file_bytes_with_content_type
            
            yield {"uploadId": upload_id, "stage": "downloading_for_thumbnail", "percentage": 95}
            
            media = MemoryRoomMediaFile.objects.get(id=media_id)

            decryptor = S3MediaDecryptor(s3_key)
            file_bytes = decryptor.get_full_decrypted_bytes()
            
            yield {"uploadId": upload_id, "stage": "decrypting_for_thumbnail", "percentage": 96}
            
            cache_key = media_cache_key('media_bytes_', s3_key)
            if file_bytes:
                cache.set(cache_key, file_bytes, timeout=60*60*24)

            thumbnail_data = None
            
            # yield {"uploadId": upload_id, "stage": "processing_thumbnail", "percentage": 97}
            
            if file_type == 'video':
                thumbnail_data = extract_thumbnail_from_segment(file_bytes, file_ext, "full_file")
            else:
                extractor = MediaThumbnailExtractor(file='', file_ext=file_ext)
                thumbnail_data = extractor.extract_audio_thumbnail_from_bytes(
                    extension=file_ext,
                    decrypted_bytes=file_bytes
                )
                
                if not thumbnail_data:
                    from memory_room.upload_helper import extract_audio_thumbnail_from_bytes
                    thumbnail_data = extract_audio_thumbnail_from_bytes(
                        extension=file_ext,
                        audio_bytes=file_bytes,
                    )

            yield {"uploadId": upload_id, "stage": "saving_thumbnail", "percentage": 98}

            if thumbnail_data:
                from django.core.files.base import ContentFile
                from userauth.models import Assets
                
                image_file = ContentFile(
                    thumbnail_data, 
                    name=f"thumbnail_{media.title.split('.')[0]}.jpg"
                )
                asset = Assets.objects.create(image=image_file, asset_types='TimeCapsoul/Thubmnail/Audio')
                media.thumbnail_url = asset.s3_url
                media.thumbnail_key = asset.s3_key
                media.save()
                
                yield {"uploadId": upload_id, "stage": "thumbnail_complete", "percentage": 99}
                logger.info(f'Thumbnail updated for media: {media.id}')
            else:
                yield {"uploadId": upload_id, "stage": "thumbnail_skipped", "percentage": 99}
                logger.warning(f'No thumbnail extracted for media: {media.id}')

        except Exception as e:
            logger.error(f'Thumbnail extraction failed for media {media_id}: {e}')
            yield {"uploadId": upload_id, "stage": "thumbnail_failed", "percentage": 99}

    def _extract_thumbnail_async(self, media_id, s3_key, file_type, file_ext, user_id):
        """Legacy async thumbnail extraction - kept for backward compatibility"""
        try:
            from memory_room.crypto_utils import get_media_file_bytes_with_content_type
            media = MemoryRoomMediaFile.objects.get(id=media_id)

            decryptor = S3MediaDecryptor(s3_key)
            file_bytes = decryptor.get_full_decrypted_bytes()
            
            cache_key = media_cache_key('media_bytes_', s3_key)
            if file_bytes:
                cache.set(cache_key, file_bytes, timeout=60*60*24)

            thumbnail_data = None
            
            if file_type == 'video':
                thumbnail_data = extract_thumbnail_from_segment(file_bytes, file_ext, "full_file")
            else:
                extractor = MediaThumbnailExtractor(file='', file_ext=file_ext)
                thumbnail_data = extractor.extract_audio_thumbnail_from_bytes(
                    extension=file_ext,
                    decrypted_bytes=file_bytes
                )
                
                if not thumbnail_data:
                    from memory_room.upload_helper import extract_audio_thumbnail_from_bytes
                    thumbnail_data = extract_audio_thumbnail_from_bytes(
                        extension=file_ext,
                        audio_bytes=file_bytes,
                    )

            if thumbnail_data:
                from django.core.files.base import ContentFile
                from userauth.models import Assets
                
                image_file = ContentFile(
                    thumbnail_data, 
                    name=f"thumbnail_{media.title.split('.')[0]}.jpg"
                )
                asset = Assets.objects.create(image=image_file, asset_types='TimeCapsoul/Thubmnail/Audio')
                media.thumbnail_url = asset.s3_url
                media.thumbnail_key = asset.s3_key
                media.save()
                print(f'\n Thumbnail updated for media: {media.id}')

        except Exception as e:
            logger.error(f'Async thumbnail extraction failed for media {media_id}: {e}')

    def abort_upload(self, request, user):
        """Abort single or multiple uploads"""
        upload_ids = request.POST.getlist("uploadIds[]") or [request.POST.get("uploadId")]
        
        aborted_count = 0
        failed_aborts = []
        
        for upload_id in upload_ids:
            if not upload_id:
                continue
                
            session = self.get_session(upload_id)
            if session:
                try:
                    # Abort S3 multipart upload
                    s3.abort_multipart_upload(
                        Bucket=MEDIA_FILES_BUCKET,
                        Key=session.s3_key,
                        UploadId=session.s3_upload_id,
                    )
                    logger.info(f"Aborted S3 multipart upload for {upload_id}")
                except Exception as e:
                    logger.error(f"Failed to abort S3 upload {upload_id}: {e}")
                    failed_aborts.append({
                        "uploadId": upload_id,
                        "error": str(e),
                        "fileName": session.file_name
                    })

                # Clean up temp chunks (only for JPG files)
                if session.is_jpg and session.temp_chunks_key:
                    try:
                        cache.delete(session.temp_chunks_key)
                        logger.info(f"Deleted temp chunks for JPG {upload_id}")
                    except Exception as e:
                        logger.error(f"Failed to delete temp chunks for {upload_id}: {e}")

                # Clean up session
                self.delete_session(upload_id)
                aborted_count += 1
                logger.info(f"Aborted upload {upload_id} ({session.file_name})")
            else:
                logger.warning(f"Session not found for upload_id {upload_id}")

        response_data = {
            "status": "aborted",
            "count": aborted_count,
            "message": f"{aborted_count} upload(s) aborted successfully"
        }
        
        if failed_aborts:
            response_data["failed"] = failed_aborts
            response_data["message"] += f", {len(failed_aborts)} failed to abort cleanly"

        return JsonResponse(response_data)

    def _decrypt_chunk(self, chunk_file, iv_str):
        """Decrypt chunk using AES-256-GCM"""
        try:
            if all(c in "0123456789abcdefABCDEF" for c in iv_str.strip()):
                iv = bytes.fromhex(iv_str)
            else:
                iv = base64.b64decode(iv_str)
        except Exception as e:
            raise ValueError(f"Invalid IV format: {e}")

        key_bytes = settings.ENCRYPTION_KEY
        if isinstance(key_bytes, str):
            key_bytes = base64.b64decode(key_bytes)

        encrypted_data = chunk_file.read()

        if len(encrypted_data) < 16:
            raise ValueError("Encrypted chunk too short")

        ciphertext = encrypted_data[:-16]
        auth_tag = encrypted_data[-16:]

        cipher = Cipher(
            algorithms.AES(key_bytes),
            modes.GCM(iv, auth_tag),
            backend=default_backend()
        )
        decryptor = cipher.decryptor()
        decrypted = decryptor.update(ciphertext) + decryptor.finalize()

        return decrypted

    def _encrypt_for_s3(self, data, aesgcm):
        """Encrypt data for S3 storage using KMS key"""
        if aesgcm is None:
            raise RuntimeError("AESGCM is not initialized")

        nonce = os.urandom(12)
        ciphertext = aesgcm.encrypt(nonce, data, None)
        return nonce + ciphertext

class UpdateMediaFileDescriptionView(SecuredView):
    def patch(self, request, memory_room_id, media_file_id):
        try:
            user = self.get_current_user(request)
            memory_room= get_object_or_404(MemoryRoom, id=memory_room_id,user=user)
            media_file = get_object_or_404(MemoryRoomMediaFile, id=media_file_id,memory_room=memory_room)
        except MemoryRoomMediaFile.DoesNotExist:
            return Response({'detail': 'Media  file not found.'}, status=status.HTTP_404_NOT_FOUND)

        serializer = MemoryRoomMediaFileDescriptionUpdateSerializer(media_file, data=request.data, partial=True)
        if serializer.is_valid():
            updated_data = serializer.save()
            cache.delete(f'{user.email}_room_{memory_room_id}_media_list')
            display_cache_message('media cached list cleared media description updation')

            return Response({'message': 'Description updated successfully.', 'data': MemoryRoomMediaFileReadOnlySerializer(updated_data).data})
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

# class MediaFileDownloadView(SecuredView):
#     def get(self, request, memory_room_id, media_file_id):
#         """
#         Securely stream a media file from S3 using optimized chunk size based on file size.
#         """
#         user = self.get_current_user(request)
#         memory_room = get_object_or_404(MemoryRoom, id=memory_room_id, user=user)
#         media_file = get_object_or_404(
#             MemoryRoomMediaFile,
#             id=media_file_id,
#             user=user,
#             memory_room=memory_room
#         )

#         # file_name = media_file.title
#         file_name  = f'{media_file.title.split(".", 1)[0].replace(" ", "_")}.{media_file.s3_key.split(".")[-1]}'
        
#         file_bytes, content_type = get_media_file_bytes_with_content_type(media_file, user)
#         if not file_bytes or not content_type:
#             return Response(status=status.HTTP_500_INTERNAL_SERVER_ERROR)

#         try:
#             file_size = len(file_bytes)
#             chunk_size = determine_download_chunk_size(file_size)
#             file_stream = io.BytesIO(file_bytes)

#             mime_type = (
#                 content_type
#                 or mimetypes.guess_type(file_name)[0]
#                 or 'application/octet-stream'
#             )

#             def file_iterator():
#                 while True:
#                     chunk = file_stream.read(chunk_size)
#                     if not chunk:
#                         break
#                     yield chunk

#             response = StreamingHttpResponse(
#                 streaming_content=file_iterator(),
#                 content_type=mime_type
#             )
#             response['Content-Disposition'] = f'attachment; filename="{file_name}"'
#             response['Content-Length'] = str(file_size)
#             response['Accept-Ranges'] = 'bytes'
#             response['Cache-Control'] = 'no-cache, no-store, must-revalidate'
#             response['Access-Control-Expose-Headers'] = 'Content-Length, Content-Disposition'

#             return response

#         except Exception as e:
#             return Response(status=status.HTTP_404_NOT_FOUND)


class MediaFileDownloadView(SecuredView):
    """
    Securely stream media file downloads from S3 without loading full file into memory.
    """
    
    DOWNLOAD_CHUNK_SIZE = 256 * 1024  # 256KB chunks for downloads

    def _stream_full_bytes(self, full_plaintext):
        total = len(full_plaintext)
        offset = 0

        while offset < total:
            yield full_plaintext[offset:offset + self.DOWNLOAD_CHUNK_SIZE]
            offset += self.DOWNLOAD_CHUNK_SIZE
            time.sleep(0.02)  # optional
    
    def _stream_decrypted_chunks_new(self, s3_key: str):
        """
        Stream using new S3MediaDecryptor with chunk metadata.
        Yields 256KB chunks for download streaming.
        """
        decryptor = S3MediaDecryptor(s3_key)
        
        # Stream decrypted chunks
        for chunk in decryptor.stream_decrypted_chunks(output_chunk_size=self.DOWNLOAD_CHUNK_SIZE):
            yield chunk

    def _stream_chunked_bytes(self, s3_key):
        with ChunkedDecryptor(s3_key) as decryptor:
            for decrypted_chunk in decryptor.decrypt_chunks():
                if not decrypted_chunk:
                    continue

                offset = 0
                size = len(decrypted_chunk)

                while offset < size:
                    yield decrypted_chunk[offset:offset + self.DOWNLOAD_CHUNK_SIZE]
                    offset += self.DOWNLOAD_CHUNK_SIZE

    def _stream_chunked_decrypt_download(self, s3_key, media_file=None, user=None):
        """Generator that streams decrypted chunks for download."""
        # with ChunkedDecryptor(s3_key) as decryptor:
        #     for decrypted_chunk in decryptor.decrypt_chunks():
        #         chunk_offset = 0
        #         while chunk_offset < len(decrypted_chunk):
        #             yield decrypted_chunk[chunk_offset:chunk_offset + self.DOWNLOAD_CHUNK_SIZE]
        #             chunk_offset += self.DOWNLOAD_CHUNK_SIZE
        
        with ChunkedDecryptor(s3_key) as decryptor:
        
            # If no chunk-size present in metadata => full decryption mode
            if not decryptor.metadata.get("chunk-size"):
                # cache_key = f"media_bytes_{s3_key}"
                cache_key = media_cache_key('media_bytes_', s3_key)

                cached_data = cache.get(cache_key)
                if cached_data:
                    full_plaintext = cached_data
                else:
                    full_plaintext, content = get_file_bytes(s3_key)

                    if not full_plaintext and media_file and user:
                        full_plaintext, content_type = get_media_file_bytes_with_content_type(media_file, user)

                    if full_plaintext:
                        cache.set(cache_key, full_plaintext, timeout=self.CACHE_TIMEOUT)




                # Yield in streamable pieces
                offset = 0
                while offset < len(full_plaintext):
                    yield full_plaintext[offset:offset + self.DOWNLOAD_CHUNK_SIZE]
                    offset += self.DOWNLOAD_CHUNK_SIZE

            else:
                # Chunked mode (large files)
                for decrypted_chunk in decryptor.decrypt_chunks():
                    if not decrypted_chunk:
                        continue
                    
                    offset = 0
                    while offset < len(decrypted_chunk):
                        yield decrypted_chunk[offset:offset + self.DOWNLOAD_CHUNK_SIZE]
                        offset += self.DOWNLOAD_CHUNK_SIZE
    
    def _get_file_size_from_metadata(self, s3_key):
        """Calculate decrypted file size from S3 metadata."""
        try:
            obj = s3.head_object(Bucket=MEDIA_FILES_BUCKET, Key=s3_key)
            encrypted_size = obj['ContentLength']
            chunk_size = int(obj['Metadata'].get('chunk-size', 10 * 1024 * 1024))
            
            num_chunks = (encrypted_size + chunk_size + 27) // (chunk_size + 28)
            overhead = num_chunks * 28
            decrypted_size = encrypted_size - overhead
            
            return decrypted_size
        except Exception as e:
            logger.error(f"Failed to calculate file size for {s3_key}: {e}")
            return None
    
    def _guess_content_type(self, filename):
        """Guess content type from filename extension."""
        import mimetypes
        content_type, _ = mimetypes.guess_type(filename)
        
        lower_filename = filename.lower()
        
        # Quick lookup for common types
        type_map = {
            # Video
            '.mp4': 'video/mp4', '.m4v': 'video/mp4', '.webm': 'video/webm',
            '.mov': 'video/quicktime', '.mkv': 'video/x-matroska', '.avi': 'video/x-msvideo',
            '.mpeg': 'video/mpeg', '.mpg': 'video/mpeg', '.3gp': 'video/3gpp',
            # Audio
            '.mp3': 'audio/mpeg', '.m4a': 'audio/mp4', '.aac': 'audio/aac',
            '.wav': 'audio/wav', '.flac': 'audio/flac', '.ogg': 'audio/ogg',
            # Image
            '.jpg': 'image/jpeg', '.jpeg': 'image/jpeg', '.png': 'image/png',
            '.gif': 'image/gif', '.webp': 'image/webp', '.svg': 'image/svg+xml',
            # Documents
            '.pdf': 'application/pdf',
            '.docx': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
            '.xlsx': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
            '.csv': 'text/csv',
            '.json': 'application/json',
            '.txt': 'text/plain',
            '.zip': 'application/zip',
        }
        
        for ext, mime in type_map.items():
            if lower_filename.endswith(ext):
                return mime
        
        return content_type or 'application/octet-stream'
    
    def get(self, request, memory_room_id, media_file_id):
        """
        Securely stream a media file from S3 - returns original file without conversions.
        """
        user = self.get_current_user(request)
        memory_room = get_object_or_404(MemoryRoom, id=memory_room_id, user=user)
        media_file = get_object_or_404(
            MemoryRoomMediaFile,
            id=media_file_id,
            user=user,
            memory_room=memory_room
        )

        try:
            s3_key = media_file.s3_key
            # filename = s3_key.split("/")[-1]
            
            # Clean up the download filename
            file_name = f'{media_file.title.split(".", 1)[0].replace(" ", "_")}.{s3_key.split(".")[-1]}'
            content_type = self._guess_content_type(file_name)

            decryptor = S3MediaDecryptor(s3_key)
            file_info = decryptor.get_file_info()
            has_chunk_metadata = (
                    file_info.get('chunk_size') and 
                    file_info.get('total_chunks')
                )
            if has_chunk_metadata:
                    # Use new chunked streaming
                    logger.info(f"Using new chunked decryption for {file_name}")
                    file_size = file_info.get('decrypted_size')
                    
                    response = StreamingHttpResponse(
                        streaming_content=self._stream_decrypted_chunks_new(s3_key),
                        content_type=content_type,
                    )
            else:
                with ChunkedDecryptor(s3_key) as decryptor:

                    if not decryptor.metadata.get("chunk-size"):

                        full_plaintext, _ = get_file_bytes(s3_key)

                        if not full_plaintext:
                            full_plaintext, _ = get_media_file_bytes_with_content_type(
                                media_file, user
                            )

                        if not full_plaintext:
                            return Response(status=status.HTTP_500_INTERNAL_SERVER_ERROR)

                        file_size = len(full_plaintext)

                        response = StreamingHttpResponse(
                            streaming_content=self._stream_full_bytes(full_plaintext),
                            content_type=content_type,
                        )

                    # ================= CHUNKED MODE =================
                    else:
                        file_size = self._get_file_size_from_metadata(s3_key)
                        if not file_size:
                            return Response(status=status.HTTP_500_INTERNAL_SERVER_ERROR)

                        response = StreamingHttpResponse(
                            streaming_content=self._stream_chunked_bytes(s3_key),  
                            content_type=content_type,
                        )

            # ================= HEADERS =================
            response["Content-Disposition"] = f'attachment; filename="{file_name}"'
            response["Content-Length"] = str(file_size)
            response["Cache-Control"] = "no-cache, no-store, must-revalidate"
            response["Access-Control-Expose-Headers"] = "Content-Length, Content-Disposition"
            response["X-Content-Type-Options"] = "nosniff"

            logger.info(f"Streaming download for {file_name}")
            return response
            
        except Exception as e:
            logger.error(f"Download failed for media {media_file_id}: {e}")
            return Response(status=status.HTTP_404_NOT_FOUND)


class MemoryRoomMediaFileFilterView(SecuredView):

    def get(self, request):
        user = self.get_current_user(request)
        query_params = request.query_params

        memory_room_id = query_params.get('memory_room_id')
        if not memory_room_id:
            raise ValidationError({'memory_room_id': 'Memory room id is required.'})

        file_type = query_params.get('file_type')
        if file_type and file_type not in dict(FILE_TYPES).keys():
            raise ValidationError({
                'file_type': f"'{file_type}' is not a valid file type. Allowed: {', '.join(dict(FILE_TYPES).keys())}"
            })

        # filter conditions
        media_filters = {
            key: value for key, value in {
                'memory_room__id': memory_room_id,
                'file_type': file_type,
                'description__icontains': query_params.get('description'),
                # 'title__icontains': query_params.get('description'),
                'user': user,
                'created_at__date': query_params.get('date'),
                'is_deleted': False
            }.items() if value is not None
        }

        queryset = MemoryRoomMediaFile.objects.filter(**media_filters)

        # Sorting logic 
        sort_by = query_params.get('sort_by')       # "alphabetical" or "upload_date"
        sort_order = query_params.get('sort_order') # "asc" or "desc"

        if sort_by == 'alphabetical':
            if sort_order == 'asc':
                queryset = queryset.order_by('title')
            elif sort_order == 'desc':
                queryset = queryset.order_by('-title')
        else:  # Default to sorting by upload_date
            if sort_order == 'asc':
                queryset = queryset.order_by('created_at')
            else:
                queryset = queryset.order_by('-created_at')

        # Pagination
        paginator = PageNumberPagination()
        paginator.page_size = 8
        paginated_queryset = paginator.paginate_queryset(queryset, request)

        serializer = MemoryRoomMediaFileReadOnlySerializer(paginated_queryset, many=True)
        return paginator.get_paginated_response({'media_files': serializer.data})




class GetMedia(SecuredView):
    """
    Securely stream a media file from S3 (decrypted).
    User must own the MemoryRoom and MediaFile.
    """

    def get(self, request, memory_room_id, media_file_id):
        user = self.get_current_user(request)

        # Verify ownership
        memory_room = get_object_or_404(MemoryRoom, id=memory_room_id, user=user)
        media_file = get_object_or_404(
            MemoryRoomMediaFile,
            id=media_file_id,
            user=user,
            memory_room=memory_room
        )

        # Get decrypted bytes
        file_bytes = decrypt_and_get_image(media_file.s3_key)
        content_type = getattr(media_file, "content_type", "application/octet-stream")

        response = HttpResponse(file_bytes, content_type=content_type)
        response["Content-Disposition"] = f'inline; filename="{media_file.s3_key}"'
        return response


# class ServeMedia(SecuredView):
#     """
#     Simplified streaming media server with unified response handling.
#     """
    
#     CACHE_TIMEOUT = 60 * 60 * 24*7  # 7 days 
#     STREAMING_CHUNK_SIZE = 64 * 1024  # 64KB chunks
    
#     # File category extensions (same as before)
#     IMAGE_EXTENSIONS = {'.jpg', '.jpeg', '.png', '.gif', '.bmp', '.tiff', '.webp', 
#                         '.heic', '.heif', '.svg', '.ico', '.raw', '.psd'}
#     VIDEO_EXTENSIONS = {'.mp4', '.avi', '.mov', '.wmv', '.flv', '.mkv', '.webm', 
#                         '.3gp', '.mpg', '.ts', '.m4v','.mpeg'}
#     AUDIO_EXTENSIONS = {'.mp3', '.wav', '.aac', '.flac', '.ogg', '.wma', '.alac', 
#                         '.aiff', '.m4a', '.opus', '.amr'}
#     OTHER_EXTENSIONS = {'.txt', '.doc', '.docx', '.pdf', '.rtf', '.odt', '.md', '.tex',
#                         '.csv', '.xls', '.xlsx', '.ods', '.tsv', '.json', '.xml', '.yaml', '.yml',
#                         '.zip', '.rar', '.7z', '.tar', '.gz', '.bz2', '.xz', '.iso',
#                         '.exe', '.msi', '.apk', '.bat', '.sh', '.app',
#                         '.html', '.htm', '.css', '.js', '.ts', '.py', '.java', '.c', '.cpp', '.cs',
#                         '.php', '.rb', '.go', '.swift', '.rs', '.kt', '.sql', '.ini', '.env', '.toml'}
    
#     def _get_file_extension(self, filename):
#         """Extract file extension from filename."""
#         return '.' + filename.lower().rsplit('.', 1)[-1] if '.' in filename else ''
    
#     def _categorize_file(self, filename):
#         """Determine file category based on extension."""
#         ext = self._get_file_extension(filename)
#         if ext in self.IMAGE_EXTENSIONS:
#             return 'image'
#         elif ext in self.VIDEO_EXTENSIONS:
#             return 'video'
#         elif ext in self.AUDIO_EXTENSIONS:
#             return 'audio'
#         elif ext in self.OTHER_EXTENSIONS:
#             return 'other'
#         return 'unknown'
    
#     def _is_pdf_file(self, filename):
#         """Check if file is a PDF."""
#         return filename.lower().endswith('.pdf')
    
#     def _is_csv_file(self, filename):
#         """Check if file is a CSV."""
#         return filename.lower().endswith('.csv')
    
#     def _is_json_file(self, filename):
#         """Check if file is a JSON."""
#         return filename.lower().endswith('.json')
    
#     def _guess_content_type(self, filename):
#         """Guess content type from filename extension."""
#         import mimetypes
#         content_type, _ = mimetypes.guess_type(filename)
        
#         ext = self._get_file_extension(filename)
        
#         # Quick lookup for common types
#         type_map = {
#             # Video
#             '.mp4': 'video/mp4', '.m4v': 'video/mp4', '.webm': 'video/webm',
#             '.mov': 'video/quicktime', '.mkv': 'video/mp4', '.avi': 'video/mp4',
#             '.mpeg': 'video/mpeg', '.mpg': 'video/mpeg', '.3gp': 'video/3gpp',
#             # Audio
#             '.mp3': 'audio/mpeg', '.m4a': 'audio/mp4', '.aac': 'audio/mp4',
#             '.wav': 'audio/wav', '.flac': 'audio/flac', '.ogg': 'audio/ogg',
#             # Image
#             '.jpg': 'image/jpeg', '.jpeg': 'image/jpeg', '.png': 'image/png',
#             '.gif': 'image/gif', '.webp': 'image/webp', '.svg': 'image/svg+xml',
#             # Documents
#             '.pdf': 'application/pdf',
#             '.docx': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
#             '.xlsx': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
#             '.csv': 'text/csv',
#             '.json': 'application/json',
#         }
        
#         return type_map.get(ext, content_type or 'application/octet-stream')
    
#     def _create_response(self, content, content_type, filename, streaming=False, 
#                         range_support=False, start=0, end=None, total_size=None):
#         """
#         Unified response creator for all file types.
        
#         Args:
#             content: File bytes or generator for streaming
#             content_type: MIME type
#             filename: Original filename
#             streaming: Whether to use StreamingHttpResponse
#             range_support: Whether to add Range headers
#             start: Start byte for range requests
#             end: End byte for range requests
#             total_size: Total file size for range requests
#         """
#         # Create appropriate response type
#         if streaming:
#             response = StreamingHttpResponse(content, content_type=content_type)
#             if range_support and start > 0:
#                 response.status_code = 206
#         else:
#             response = HttpResponse(content, content_type=content_type)
        
#         # Set content length
#         if streaming and total_size:
#             length = (end - start) if end else total_size
#             response["Content-Length"] = str(length)
#         elif not streaming:
#             response["Content-Length"] = str(len(content))
        
#         # Range headers
#         if range_support:
#             response["Accept-Ranges"] = "bytes"
#             if start > 0 and end and total_size:
#                 response["Content-Range"] = f"bytes {start}-{end-1}/{total_size}"
        
#         # Security headers
#         response["Content-Disposition"] = "inline"
#         response["X-Content-Type-Options"] = "nosniff"
#         response["Cache-Control"] = "private, max-age=3600"
        
#         # Special CSP for SVG
#         if content_type == "image/svg+xml":
#             response["Content-Security-Policy"] = "default-src 'none'; style-src 'unsafe-inline'; img-src data:;"
#         else:
#             frame_ancestors = " ".join(settings.CORS_ALLOWED_ORIGINS)
#             csp = f"frame-ancestors 'self' {frame_ancestors};"
#             if range_support:
#                 csp = f"media-src *; {csp}"
#             response["Content-Security-Policy"] = csp
        
#         # CORS headers
#         response["Cross-Origin-Resource-Policy"] = "cross-origin"
#         response["Access-Control-Allow-Origin"] = "*"
#         if range_support:
#             response["Access-Control-Expose-Headers"] = "Accept-Ranges, Content-Range, Content-Length"
        
#         return response
    
#     def _serve_pdf_with_range(self, request, file_bytes, filename):
#         """
#         Serve PDF with proper Range support for browser preview.
#         PDFs need range support for progressive loading in browser viewers.
#         """
#         file_size = len(file_bytes)
#         range_header = request.headers.get("Range", "")
        
#         # Parse range
#         start, end = 0, file_size - 1
#         if range_header:
#             import re
#             m = re.match(r"bytes=(\d+)-(\d*)", range_header)
#             if m:
#                 start = int(m.group(1))
#                 if m.group(2):
#                     end = int(m.group(2))
#                 end = min(end, file_size - 1)
        
#         is_partial = range_header != ""
        
#         # Use streaming response for range requests, regular for full file
#         if is_partial:
#             from wsgiref.util import FileWrapper
#             from io import BytesIO
#             response = StreamingHttpResponse(
#                 FileWrapper(BytesIO(file_bytes[start:end + 1]), 8192),
#                 content_type="application/pdf",
#                 status=206
#             )
#         else:
#             response = HttpResponse(
#                 file_bytes,
#                 content_type="application/pdf",
#                 status=200
#             )
        
#         # PDF-specific headers
#         response["Accept-Ranges"] = "bytes"
#         response["Content-Length"] = str(end - start + 1)
#         response["Content-Disposition"] = "inline"
#         response["X-Content-Type-Options"] = "nosniff"
#         response["Cache-Control"] = "private, max-age=3600"
        
#         if is_partial:
#             response["Content-Range"] = f"bytes {start}-{end}/{file_size}"
        
#         # CORS for PDF.js and other viewers
#         response["Access-Control-Allow-Origin"] = "*"
#         response["Access-Control-Expose-Headers"] = "Accept-Ranges, Content-Range, Content-Length"
#         response["Cross-Origin-Resource-Policy"] = "cross-origin"
        
#         # Allow embedding in iframes from allowed origins
#         frame_ancestors = " ".join(settings.CORS_ALLOWED_ORIGINS)
#         response["Content-Security-Policy"] = f"frame-ancestors 'self' {frame_ancestors};"
        
#         return response
    
#     def _serve_csv_with_range(self, request, file_bytes, filename):
#         """
#         Serve CSV with Range support for large file preview.
#         Allows browsers/editors to load CSV progressively.
#         """
#         file_size = len(file_bytes)
#         range_header = request.headers.get("Range", "")
        
#         # Parse range
#         start, end = 0, file_size - 1
#         if range_header:
#             import re
#             m = re.match(r"bytes=(\d+)-(\d*)", range_header)
#             if m:
#                 start = int(m.group(1))
#                 if m.group(2):
#                     end = int(m.group(2))
#                 end = min(end, file_size - 1)
        
#         is_partial = range_header != ""
        
#         # Use streaming response for range requests
#         if is_partial:
#             from wsgiref.util import FileWrapper
#             from io import BytesIO
#             response = StreamingHttpResponse(
#                 FileWrapper(BytesIO(file_bytes[start:end + 1]), 8192),
#                 content_type="text/csv",
#                 status=206
#             )
#         else:
#             response = HttpResponse(
#                 file_bytes,
#                 content_type="text/csv",
#                 status=200
#             )
        
#         # CSV-specific headers
#         response["Accept-Ranges"] = "bytes"
#         response["Content-Length"] = str(end - start + 1)
#         response["Content-Disposition"] = "inline"
#         response["X-Content-Type-Options"] = "nosniff"
#         response["Cache-Control"] = "private, max-age=3600"
        
#         if is_partial:
#             response["Content-Range"] = f"bytes {start}-{end}/{file_size}"
        
#         # CORS for CSV viewers
#         response["Access-Control-Allow-Origin"] = "*"
#         response["Access-Control-Expose-Headers"] = "Accept-Ranges, Content-Range, Content-Length"
#         response["Cross-Origin-Resource-Policy"] = "cross-origin"
        
#         # Allow embedding
#         frame_ancestors = " ".join(settings.CORS_ALLOWED_ORIGINS)
#         response["Content-Security-Policy"] = f"default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'self' {frame_ancestors};"
        
#         return response
    
#     def _serve_json_with_range(self, request, file_bytes, filename):
#         """
#         Serve JSON with Range support for large file preview.
#         Allows progressive loading of large JSON files.
#         """
#         file_size = len(file_bytes)
#         range_header = request.headers.get("Range", "")
        
#         # Parse range
#         start, end = 0, file_size - 1
#         if range_header:
#             import re
#             m = re.match(r"bytes=(\d+)-(\d*)", range_header)
#             if m:
#                 start = int(m.group(1))
#                 if m.group(2):
#                     end = int(m.group(2))
#                 end = min(end, file_size - 1)
        
#         is_partial = range_header != ""
        
#         # Use streaming response for range requests
#         if is_partial:
#             from wsgiref.util import FileWrapper
#             from io import BytesIO
#             response = StreamingHttpResponse(
#                 FileWrapper(BytesIO(file_bytes[start:end + 1]), 8192),
#                 content_type="application/json",
#                 status=206
#             )
#         else:
#             response = HttpResponse(
#                 file_bytes,
#                 content_type="application/json",
#                 status=200
#             )
        
#         # JSON-specific headers
#         response["Accept-Ranges"] = "bytes"
#         response["Content-Length"] = str(end - start + 1)
#         response["Content-Disposition"] = "inline"
#         response["X-Content-Type-Options"] = "nosniff"
#         response["Cache-Control"] = "private, max-age=3600"
        
#         if is_partial:
#             response["Content-Range"] = f"bytes {start}-{end}/{file_size}"
        
#         # CORS for JSON viewers
#         response["Access-Control-Allow-Origin"] = "*"
#         response["Access-Control-Expose-Headers"] = "Accept-Ranges, Content-Range, Content-Length"
#         response["Cross-Origin-Resource-Policy"] = "cross-origin"
        
#         # Allow embedding with strict CSP for JSON
#         frame_ancestors = " ".join(settings.CORS_ALLOWED_ORIGINS)
#         response["Content-Security-Policy"] = f"default-src 'none'; style-src 'unsafe-inline'; script-src 'none'; frame-ancestors 'self' {frame_ancestors};"
        
#         return response
    
#     def _stream_chunked_decrypt(self, s3_key, start_byte=0, end_byte=None):
#         """Generator that streams decrypted chunks."""
#         # with ChunkedDecryptor(s3_key) as decryptor:
#         #     for decrypted_chunk in decryptor.decrypt_chunks(start_byte, end_byte):
#         #         chunk_offset = 0
#         #         while chunk_offset < len(decrypted_chunk):
#         #             yield decrypted_chunk[chunk_offset:chunk_offset + self.STREAMING_CHUNK_SIZE]
#         #             chunk_offset += self.STREAMING_CHUNK_SIZE
        
#         with ChunkedDecryptor(s3_key) as decryptor:
        
#             # If no chunk-size present in metadata => full decryption mode
#             if not decryptor.metadata.get("chunk-size"):
#                 full_plaintext, content = get_file_bytes(s3_key)


#                 # Yield in streamable pieces
#                 offset = 0
#                 while offset < len(full_plaintext):
#                     yield full_plaintext[offset:offset + self.STREAMING_CHUNK_SIZE]
#                     offset += self.STREAMING_CHUNK_SIZE

#             else:
#                 # Chunked mode (large files)
#                 for decrypted_chunk in decryptor.decrypt_chunks():
#                     if not decrypted_chunk:
#                         continue
                    
#                     offset = 0
#                     while offset < len(decrypted_chunk):
#                         yield decrypted_chunk[offset:offset + self.STREAMING_CHUNK_SIZE]
#                         offset += self.STREAMING_CHUNK_SIZE
    
#     def _get_file_size_from_metadata(self, s3_key):
#         """Calculate decrypted file size from S3 metadata."""
#         cache_key = f"media_size_{s3_key}"
#         cached_size = cache.get(cache_key)
#         if cached_size:
#             return cached_size
        
#         try:
#             obj = s3.head_object(Bucket=MEDIA_FILES_BUCKET, Key=s3_key)
#             encrypted_size = obj['ContentLength']
#             chunk_size = int(obj['Metadata'].get('chunk-size', 10 * 1024 * 1024))
            
#             num_chunks = (encrypted_size + chunk_size + 27) // (chunk_size + 28)
#             overhead = num_chunks * 28
#             decrypted_size = encrypted_size - overhead
            
#             cache.set(cache_key, decrypted_size, timeout=self.CACHE_TIMEOUT)
#             return decrypted_size
#         except Exception as e:
#             logger.error(f"Failed to calculate file size for {s3_key}: {e}")
#             return None
    
#     def get(self, request, s3_key, media_file_id):
#         """Main entry point - simplified routing and response."""
#         user = self.get_current_user(request)
#         if not user:
#             return Response(status=status.HTTP_401_UNAUTHORIZED)

#         try:
#             # Validate signature
#             exp = request.GET.get("exp")
#             sig = request.GET.get("sig")
#             if not exp or not sig or int(exp) < int(time.time()):
#                 return Response(status=status.HTTP_404_NOT_FOUND)

#             media_file = MemoryRoomMediaFile.objects.only('id', 's3_key', 'user_id').get(
#                 id=media_file_id, user=user
#             )

#             if not verify_signature(media_file.s3_key, exp, sig):
#                 return Response(status=status.HTTP_404_NOT_FOUND)

#             s3_key = media_file.s3_key
#             filename = s3_key.split("/")[-1]
#             extension = self._get_file_extension(filename)
#             category = self._categorize_file(filename)
#             content_type = self._guess_content_type(filename)
            
#             # Check for special cases
#             is_pdf = self._is_pdf_file(filename)
#             is_csv = self._is_csv_file(filename)
#             is_json = self._is_json_file(filename)
#             needs_conversion = extension in {'.mkv', '.avi', '.wmv', '.mpeg', '.mpg', '.flv'}
#             is_special = extension in {'.svg', '.heic', '.heif', '.doc'} or needs_conversion
            
#             # Route 1: Streaming with range support (video/audio that don't need conversion)
#             if (category in ['video', 'audio']) and not needs_conversion and not is_special:
#                 file_size = self._get_file_size_from_metadata(s3_key)
#                 if not file_size:
#                     return Response(status=status.HTTP_500_INTERNAL_SERVER_ERROR)
                
#                 # Parse range header
#                 start, end = 0, file_size
#                 range_header = request.headers.get("Range", "")
#                 if range_header:
#                     import re
#                     m = re.match(r"bytes=(\d+)-(\d*)", range_header)
#                     if m:
#                         start = int(m.group(1))
#                         end = int(m.group(2)) + 1 if m.group(2) else file_size
#                         end = min(end, file_size)
                
#                 logger.info(f"Streaming {category}: {filename}")
#                 return self._create_response(
#                     self._stream_chunked_decrypt(s3_key, start, end),
#                     content_type, filename,
#                     streaming=True, range_support=True,
#                     start=start, end=end, total_size=file_size
#                 )
            
#             # Route 2: Progressive streaming (images, no special handling)
#             elif category == 'image' and not is_special:
#                 file_size = self._get_file_size_from_metadata(s3_key)
#                 if not file_size:
#                     return Response(status=status.HTTP_500_INTERNAL_SERVER_ERROR)
                
#                 logger.info(f"Progressive image: {filename}")
#                 return self._create_response(
#                     self._stream_chunked_decrypt(s3_key),
#                     content_type, filename,
#                     streaming=True, range_support=False
#                 )
            
#             # Route 3: Full file with conversions (everything else)
#             else:
#                 logger.info(f"Full decrypt for {category}: {filename}")
                
#                 # Get or decrypt full file
#                 bytes_cache_key = f"media_bytes_{s3_key}"
#                 cached_data = cache.get(bytes_cache_key)
                
#                 if cached_data:
#                     file_bytes, _ = cached_data
#                 else:
#                     file_bytes, _ = decrypt_s3_file_chunked(s3_key)
#                     if not file_bytes:
#                         return Response(status=status.HTTP_500_INTERNAL_SERVER_ERROR)
#                     cache.set(bytes_cache_key, (file_bytes, content_type), timeout=self.CACHE_TIMEOUT)
                
#                 # Check if PDF, CSV, or JSON after decryption
#                 if is_pdf:
#                     logger.info(f"Serving PDF with range support: {filename}")
#                     return self._serve_pdf_with_range(request, file_bytes, filename)
#                 elif is_csv:
#                     logger.info(f"Serving CSV with range support: {filename}")
#                     return self._serve_csv_with_range(request, file_bytes, filename)
#                 elif is_json:
#                     logger.info(f"Serving JSON with range support: {filename}")
#                     return self._serve_json_with_range(request, file_bytes, filename)
                
#                 # Handle conversions
#                 if extension == '.doc':
#                     cache_key = f'{media_file.id}_docx_preview'
#                     file_bytes = cache.get(cache_key) or convert_doc_to_docx_bytes(file_bytes, media_file.id, user.email)
#                     cache.set(cache_key, file_bytes, timeout=self.CACHE_TIMEOUT)
#                     content_type = "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
#                     filename = filename.replace(".doc", ".docx")
                
#                 elif extension in {'.heic', '.heif'}:
#                     cache_key = f'{bytes_cache_key}_jpeg'
#                     file_bytes = cache.get(cache_key) or convert_heic_to_jpeg_bytes(file_bytes)[0]
#                     cache.set(cache_key, file_bytes, timeout=self.CACHE_TIMEOUT)
#                     content_type = "image/jpeg"
#                     filename = filename.rsplit('.', 1)[0] + '.jpg'
                
#                 elif needs_conversion:
#                     cache_key = f'{bytes_cache_key}_mp4'
#                     mp4_bytes = cache.get(cache_key)
                    
#                     if not mp4_bytes:
#                         try:
#                             logger.info(f"Converting {extension} to MP4 for {filename}")
#                             if extension in {'.mpeg', '.mpg'}:
#                                 mp4_bytes, _ = self.convert_mpeg_to_mp4_bytes(file_bytes)
#                             else:
#                                 mp4_bytes, _ = self.convert_video_to_mp4_bytes(extension, file_bytes)
#                             cache.set(cache_key, mp4_bytes, timeout=self.CACHE_TIMEOUT)
#                         except Exception as e:
#                             logger.error(f"Conversion failed for {filename}: {e}")
#                             return Response(status=status.HTTP_500_INTERNAL_SERVER_ERROR)
                    
#                     file_bytes = mp4_bytes
#                     content_type = "video/mp4"
#                     filename = filename.rsplit('.', 1)[0] + '.mp4'
                    
#                     # Now stream the converted MP4 with range support
#                     logger.info(f"Streaming converted MP4: {filename}")
                    
#                     # Store converted file temporarily for range streaming
#                     converted_s3_key = f"temp_converted_{media_file.id}"
#                     temp_cache_key = f"media_bytes_{converted_s3_key}"
#                     cache.set(temp_cache_key, (file_bytes, content_type), timeout=self.CACHE_TIMEOUT)
                    
#                     # Return streaming response with range support
#                     file_size = len(file_bytes)
                    
#                     # Parse range header
#                     start, end = 0, file_size
#                     range_header = request.headers.get("Range", "")
#                     if range_header:
#                         import re
#                         m = re.match(r"bytes=(\d+)-(\d*)", range_header)
#                         if m:
#                             start = int(m.group(1))
#                             end = int(m.group(2)) + 1 if m.group(2) else file_size
#                             end = min(end, file_size)
                    
#                     # Create generator for range
#                     def generate_range():
#                         chunk_size = self.STREAMING_CHUNK_SIZE
#                         pos = start
#                         while pos < end:
#                             chunk_end = min(pos + chunk_size, end)
#                             yield file_bytes[pos:chunk_end]
#                             pos = chunk_end
                    
#                     return self._create_response(
#                         generate_range(),
#                         content_type, filename,
#                         streaming=True, range_support=True,
#                         start=start, end=end, total_size=file_size
#                     )
#                 # For non-converted files, return simple response
#                 return self._create_response(file_bytes, content_type, filename)

#         except MemoryRoomMediaFile.DoesNotExist:
#             return Response(status=status.HTTP_404_NOT_FOUND)
#         except Exception as e:
#             logger.warning(f'Exception serving media {s3_key} for {user.email}: {e}')
#             return Response(status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    
#     # Keep conversion methods as-is
#     def convert_mpeg_to_mp4_bytes(self, file_bytes):
#         """Convert MPEG/MPG to MP4 bytes using MoviePy."""
#         logger.info("Converting MPEG/MPG to MP4...")
#         with tempfile.NamedTemporaryFile(suffix=".mpeg") as temp_in, \
#              tempfile.NamedTemporaryFile(suffix=".mp4") as temp_out:
#             temp_in.write(file_bytes)
#             temp_in.flush()
#             try:
#                 clip = VideoFileClip(temp_in.name)
#                 clip.write_videofile(temp_out.name, codec="libx264", audio_codec="aac", verbose=False, logger=None)
#                 clip.close()
#             except Exception as e:
#                 logger.error(f"MoviePy conversion failed: {e}")
#                 raise
#             temp_out.seek(0)
#             mp4_bytes = temp_out.read()
#         logger.info(f"Conversion successful ({len(mp4_bytes)} bytes)")
#         return mp4_bytes, "converted.mp4"

#     def convert_video_to_mp4_bytes(self, source_format, file_bytes):
#         """Generic video converter for MKV, AVI, WMV, etc."""
#         logger.info(f"Converting {source_format} to MP4...")
#         with tempfile.NamedTemporaryFile(suffix=source_format) as temp_in, \
#              tempfile.NamedTemporaryFile(suffix=".mp4") as temp_out:
#             temp_in.write(file_bytes)
#             temp_in.flush()
#             try:
#                 clip = VideoFileClip(temp_in.name)
#                 clip.write_videofile(temp_out.name, codec="libx264", audio_codec="aac", verbose=False, logger=None)
#                 clip.close()
#             except Exception as e:
#                 logger.error(f"Video conversion failed for {source_format}: {e}")
#                 raise
#             temp_out.seek(0)
#             mp4_bytes = temp_out.read()
#         logger.info(f"Conversion complete ({len(mp4_bytes)} bytes)")
#         return mp4_bytes, "converted.mp4"



class ServeMedia(SecuredView):
    """
    Securely serve decrypted media from S3 via Django.
    Streaming responses for all files with lazy loading for audio/video.
    """
    
    CACHE_TIMEOUT = 60 * 60 * 24*7  # 24 hours
    STREAMING_CHUNK_SIZE = 64 * 1024  # 64KB chunks
    
    # File category extensions
    IMAGE_EXTENSIONS = {'.jpg', '.jpeg', '.png', '.gif', '.bmp', '.tiff', '.webp', 
                        '.heic', '.heif', '.svg', '.ico', '.raw', '.psd'}
    VIDEO_EXTENSIONS = {'.mp4', '.avi', '.mov', '.wmv', '.flv', '.mkv', '.webm', 
                        '.3gp', '.mpg', '.ts', '.m4v', '.mpeg'}
    AUDIO_EXTENSIONS = {'.mp3', '.wav', '.aac', '.flac', '.ogg', '.wma', '.alac', 
                        '.aiff', '.m4a', '.opus', '.amr'}
    
    def _get_file_extension(self, filename):
        """Extract file extension from filename."""
        return '.' + filename.lower().rsplit('.', 1)[-1] if '.' in filename else ''
    
    def _categorize_file(self, filename):
        """Determine file category based on extension."""
        ext = self._get_file_extension(filename)
        if ext in self.IMAGE_EXTENSIONS:
            return 'image'
        elif ext in self.VIDEO_EXTENSIONS:
            return 'video'
        elif ext in self.AUDIO_EXTENSIONS:
            return 'audio'
        return 'other'
    
    def _guess_content_type(self, filename):
        """Guess content type from filename extension for better browser compatibility."""
        import mimetypes
        content_type, _ = mimetypes.guess_type(filename)
        
        ext = self._get_file_extension(filename)
        
        # Quick lookup for common types
        type_map = {
            # Video
            '.mp4': 'video/mp4', '.m4v': 'video/mp4', '.webm': 'video/webm',
            '.mov': 'video/quicktime', '.mkv': 'video/mp4', '.avi': 'video/mp4',
            '.mpeg': 'video/mpeg', '.mpg': 'video/mpeg', '.3gp': 'video/3gpp',
            '.flv': 'video/mp4', '.wmv': 'video/mp4',
            # Audio
            '.mp3': 'audio/mpeg', '.m4a': 'audio/mp4', '.aac': 'audio/mp4',
            '.wav': 'audio/wav', '.flac': 'audio/flac', '.ogg': 'audio/ogg',
            '.opus': 'audio/ogg', '.wma': 'audio/x-ms-wma',
            # Image
            '.jpg': 'image/jpeg', '.jpeg': 'image/jpeg', '.png': 'image/png',
            '.gif': 'image/gif', '.webp': 'image/webp', '.svg': 'image/svg+xml',
            # Documents
            '.pdf': 'application/pdf',
            '.docx': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
            '.xlsx': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
            '.csv': 'text/csv',
            '.json': 'application/json',
        }
        
        return type_map.get(ext, content_type or 'application/octet-stream')
    
    def _is_pdf_file(self, filename):
        """Check if file is a PDF."""
        return filename.lower().endswith('.pdf')
    
    def _is_csv_file(self, filename):
        """Check if file is a CSV."""
        return filename.lower().endswith('.csv')
    
    def _is_json_file(self, filename):
        """Check if file is a JSON."""
        return filename.lower().endswith('.json')

    def _serve_pdf_with_range(self, request, file_bytes, filename):
        """
        Serve PDF with proper Range support for browser preview.
        PDFs need range support for progressive loading in browser viewers.
        """
        file_size = len(file_bytes)
        range_header = request.headers.get("Range", "")
        
        # Parse range
        start, end = 0, file_size - 1
        if range_header:
            import re
            m = re.match(r"bytes=(\d+)-(\d*)", range_header)
            if m:
                start = int(m.group(1))
                if m.group(2):
                    end = int(m.group(2))
                end = min(end, file_size - 1)
        
        is_partial = range_header != ""
        
        # Use streaming response for range requests, regular for full file
        if is_partial:
            from wsgiref.util import FileWrapper
            from io import BytesIO
            response = StreamingHttpResponse(
                FileWrapper(BytesIO(file_bytes[start:end + 1]), 8192),
                content_type="application/pdf",
                status=206
            )
        else:
            response = HttpResponse(
                file_bytes,
                content_type="application/pdf",
                status=200
            )
        
        # PDF-specific headers
        response["Accept-Ranges"] = "bytes"
        response["Content-Length"] = str(end - start + 1)
        response["Content-Disposition"] = "inline"
        response["X-Content-Type-Options"] = "nosniff"
        response["Cache-Control"] = "private, max-age=3600"
        
        if is_partial:
            response["Content-Range"] = f"bytes {start}-{end}/{file_size}"
        
        # CORS for PDF.js and other viewers
        response["Access-Control-Allow-Origin"] = "*"
        response["Access-Control-Expose-Headers"] = "Accept-Ranges, Content-Range, Content-Length"
        response["Cross-Origin-Resource-Policy"] = "cross-origin"
        
        # Allow embedding in iframes from allowed origins
        frame_ancestors = " ".join(settings.CORS_ALLOWED_ORIGINS)
        response["Content-Security-Policy"] = f"frame-ancestors 'self' {frame_ancestors};"
        
        return response
    
    def _serve_csv_with_range(self, request, file_bytes, filename):
        """
        Serve CSV with Range support for large file preview.
        Allows browsers/editors to load CSV progressively.
        """
        file_size = len(file_bytes)
        range_header = request.headers.get("Range", "")
        
        # Parse range
        start, end = 0, file_size - 1
        if range_header:
            import re
            m = re.match(r"bytes=(\d+)-(\d*)", range_header)
            if m:
                start = int(m.group(1))
                if m.group(2):
                    end = int(m.group(2))
                end = min(end, file_size - 1)
        
        is_partial = range_header != ""
        
        # Use streaming response for range requests
        if is_partial:
            from wsgiref.util import FileWrapper
            from io import BytesIO
            response = StreamingHttpResponse(
                FileWrapper(BytesIO(file_bytes[start:end + 1]), 8192),
                content_type="text/csv",
                status=206
            )
        else:
            response = HttpResponse(
                file_bytes,
                content_type="text/csv",
                status=200
            )
        
        # CSV-specific headers
        response["Accept-Ranges"] = "bytes"
        response["Content-Length"] = str(end - start + 1)
        response["Content-Disposition"] = "inline"
        response["X-Content-Type-Options"] = "nosniff"
        response["Cache-Control"] = "private, max-age=3600"
        
        if is_partial:
            response["Content-Range"] = f"bytes {start}-{end}/{file_size}"
        
        # CORS for CSV viewers
        response["Access-Control-Allow-Origin"] = "*"
        response["Access-Control-Expose-Headers"] = "Accept-Ranges, Content-Range, Content-Length"
        response["Cross-Origin-Resource-Policy"] = "cross-origin"
        
        # Allow embedding
        frame_ancestors = " ".join(settings.CORS_ALLOWED_ORIGINS)
        response["Content-Security-Policy"] = f"default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'self' {frame_ancestors};"
        
        return response
    
    def _serve_json_with_range(self, request, file_bytes, filename):
        """
        Serve JSON with Range support for large file preview.
        Allows progressive loading of large JSON files.
        """
        file_size = len(file_bytes)
        range_header = request.headers.get("Range", "")
        
        # Parse range
        start, end = 0, file_size - 1
        if range_header:
            import re
            m = re.match(r"bytes=(\d+)-(\d*)", range_header)
            if m:
                start = int(m.group(1))
                if m.group(2):
                    end = int(m.group(2))
                end = min(end, file_size - 1)
        
        is_partial = range_header != ""
        
        # Use streaming response for range requests
        if is_partial:
            from wsgiref.util import FileWrapper
            from io import BytesIO
            response = StreamingHttpResponse(
                FileWrapper(BytesIO(file_bytes[start:end + 1]), 8192),
                content_type="application/json",
                status=206
            )
        else:
            response = HttpResponse(
                file_bytes,
                content_type="application/json",
                status=200
            )
        
        # JSON-specific headers
        response["Accept-Ranges"] = "bytes"
        response["Content-Length"] = str(end - start + 1)
        response["Content-Disposition"] = "inline"
        response["X-Content-Type-Options"] = "nosniff"
        response["Cache-Control"] = "private, max-age=3600"
        
        if is_partial:
            response["Content-Range"] = f"bytes {start}-{end}/{file_size}"
        
        # CORS for JSON viewers
        response["Access-Control-Allow-Origin"] = "*"
        response["Access-Control-Expose-Headers"] = "Accept-Ranges, Content-Range, Content-Length"
        response["Cross-Origin-Resource-Policy"] = "cross-origin"
        
        # Allow embedding with strict CSP for JSON
        frame_ancestors = " ".join(settings.CORS_ALLOWED_ORIGINS)
        response["Content-Security-Policy"] = f"default-src 'none'; style-src 'unsafe-inline'; script-src 'none'; frame-ancestors 'self' {frame_ancestors};"
        
        return response

    # def _create_response(self, content, content_type, filename, streaming=False, 
    #                     range_support=False, start=0, end=None, total_size=None):
    #     """
    #     Unified response creator for all file types.
        
    #     Args:
    #         content: File bytes or generator for streaming
    #         content_type: MIME type
    #         filename: Original filename
    #         streaming: Whether to use StreamingHttpResponse
    #         range_support: Whether to add Range headers
    #         start: Start byte for range requests
    #         end: End byte for range requests
    #         total_size: Total file size for range requests
    #     """
    #     # Create appropriate response type
    #     if streaming:
    #         response = StreamingHttpResponse(content, content_type=content_type)
    #         if range_support and start > 0:
    #             response.status_code = 206
    #     else:
    #         response = HttpResponse(content, content_type=content_type)
        
    #     # Set content length
    #     if streaming and total_size:
    #         length = (end - start) if end else total_size
    #         response["Content-Length"] = str(length)
    #     elif not streaming:
    #         if content:
    #             response["Content-Length"] = str(len(content))
        
    #     # Range headers
    #     if range_support:
    #         response["Accept-Ranges"] = "bytes"
    #         if start > 0 and end and total_size:
    #             response["Content-Range"] = f"bytes {start}-{end-1}/{total_size}"
        
    #     # Security headers
    #     response["Content-Disposition"] = "inline"
    #     response["X-Content-Type-Options"] = "nosniff"
    #     response["Cache-Control"] = "private, max-age=3600"
        
    #     # Special CSP for SVG
    #     if content_type == "image/svg+xml":
    #         response["Content-Security-Policy"] = "default-src 'none'; style-src 'unsafe-inline'; img-src data:;"
    #     else:
    #         frame_ancestors = " ".join(settings.CORS_ALLOWED_ORIGINS)
    #         csp = f"frame-ancestors 'self' {frame_ancestors};"
    #         if range_support:
    #             csp = f"media-src *; {csp}"
    #         response["Content-Security-Policy"] = csp
        
    #     # CORS headers
    #     response["Cross-Origin-Resource-Policy"] = "cross-origin"
    #     response["Access-Control-Allow-Origin"] = "*"
    #     if range_support:
    #         response["Access-Control-Expose-Headers"] = "Accept-Ranges, Content-Range, Content-Length"
        
    #     return response
    
    # def _stream_chunked_decrypt(self, s3_key, start_byte=0, end_byte=None, media_file=None ,user=None):
    #     """Generator that streams decrypted chunks."""
    #     with ChunkedDecryptor(s3_key) as decryptor:
        
    #         # If no chunk-size present in metadata => full decryption mode
    #         if not decryptor.metadata.get("chunk-size"):
    #             # full_plaintext = decryptor.decrypt_full()
    #             full_plaintext, content = get_file_bytes(s3_key)

    #             if not full_plaintext and media_file and user:
    #                 full_plaintext, content_type = get_media_file_bytes_with_content_type(media_file, user)


    #             # Yield in streamable pieces
    #             offset = 0
    #             while offset < len(full_plaintext):
    #                 yield full_plaintext[offset:offset + self.STREAMING_CHUNK_SIZE]
    #                 offset += self.STREAMING_CHUNK_SIZE

    #         else:
    #             # Chunked mode (large files)
    #             for decrypted_chunk in decryptor.decrypt_chunks(start_byte, end_byte):
    #                 if not decrypted_chunk:
    #                     continue
                    
    #                 offset = 0
    #                 while offset < len(decrypted_chunk):
    #                     yield decrypted_chunk[offset:offset + self.STREAMING_CHUNK_SIZE]
    #                     offset += self.STREAMING_CHUNK_SIZE
    

    def _create_response(
        self,
        content,
        content_type,
        filename,
        streaming=False,
        range_support=False,
        start=0,
        end=None,
        total_size=None
    ):
        if streaming:
            response = StreamingHttpResponse(content, content_type=content_type)
        else:
            response = HttpResponse(content, content_type=content_type)

        # ---------- RANGE HEADERS ----------
        if range_support and total_size is not None and (start > 0 or end is not None):
            response.status_code = 206
            response["Accept-Ranges"] = "bytes"

            actual_end = (end - 1) if end is not None else (total_size - 1)
            content_length = actual_end - start + 1

            response["Content-Length"] = str(content_length)
            response["Content-Range"] = f"bytes {start}-{actual_end}/{total_size}"
        else:
            response.status_code = 200
            if not streaming and content:
                response["Content-Length"] = str(len(content))

        # ---------- COMMON HEADERS ----------
        response["Content-Disposition"] = "inline"
        response["X-Content-Type-Options"] = "nosniff"
        response["Cache-Control"] = "private, max-age=3600"

        # ---------- CSP ----------
        if content_type == "image/svg+xml":
            response["Content-Security-Policy"] = (
                "default-src 'none'; style-src 'unsafe-inline'; img-src data:;"
            )
        else:
            frame_ancestors = " ".join(settings.CORS_ALLOWED_ORIGINS)
            csp = f"frame-ancestors 'self' {frame_ancestors};"
            if range_support:
                csp = f"media-src *; {csp}"
            response["Content-Security-Policy"] = csp

        # ---------- CORS ----------
        response["Cross-Origin-Resource-Policy"] = "cross-origin"
        response["Access-Control-Allow-Origin"] = "*"
        if range_support:
            response["Access-Control-Expose-Headers"] = (
                "Accept-Ranges, Content-Range, Content-Length"
            )

        return response

    def _stream_chunked_decrypt(self, s3_key, start_byte=0, end_byte=None, media_file=None, user=None):
        """Generator that streams decrypted chunks with proper Range support."""
        with ChunkedDecryptor(s3_key) as decryptor:

            # ---------- FULL DECRYPT MODE ----------
            if not decryptor.metadata.get("chunk-size"):
                # cache_key = f"media_bytes_{s3_key}"
                cache_key = media_cache_key('media_bytes_', s3_key)
                full_plaintext = cache.get(cache_key)

                if not full_plaintext:
                    full_plaintext, _ = get_file_bytes(s3_key)
                    if not full_plaintext and media_file and user:
                        full_plaintext, _ = get_media_file_bytes_with_content_type(media_file, user)
                    if full_plaintext:
                        cache.set(cache_key, full_plaintext, timeout=self.CACHE_TIMEOUT)

                if not full_plaintext:
                    return

                # ✅ RANGE-AWARE STREAMING 
                offset = start_byte
                limit = end_byte if end_byte is not None else len(full_plaintext)

                while offset < limit:
                    chunk_end = min(offset + self.STREAMING_CHUNK_SIZE, limit)
                    yield full_plaintext[offset:chunk_end]
                    offset = chunk_end

            # ---------- CHUNKED DECRYPT MODE ----------
            else:
                for decrypted_chunk in decryptor.decrypt_chunks(start_byte, end_byte):
                    if not decrypted_chunk:
                        continue

                    offset = 0
                    while offset < len(decrypted_chunk):
                        chunk_end = min(offset + self.STREAMING_CHUNK_SIZE, len(decrypted_chunk))
                        yield decrypted_chunk[offset:chunk_end]
                        offset = chunk_end

    
    # def _stream_file_with_range(self, request, file_bytes, content_type, filename):
    #     file_size = len(file_bytes)
    #     range_header = request.headers.get("Range", "").strip()

    #     if range_header:
    #         import re
    #         match = re.match(r"bytes=(\d+)-(\d*)", range_header)
    #     else:
    #         match = None

    #     if match:
    #         start = int(match.group(1))
    #         end = match.group(2)
    #         end = int(end) if end else file_size - 1
    #         length = end - start + 1

    #         resp = StreamingHttpResponse(
    #             FileWrapper(BytesIO(file_bytes[start:end+1])),
    #             status=206,
    #             content_type=content_type
    #         )
    #         resp["Content-Range"] = f"bytes {start}-{end}/{file_size}"
    #         resp["Content-Length"] = str(length)

    #     else:
    #         resp = StreamingHttpResponse(
    #             FileWrapper(BytesIO(file_bytes)),
    #             content_type=content_type
    #         )
    #         resp["Content-Length"] = str(file_size)

    #     resp["Accept-Ranges"] = "bytes"
    #     resp["Content-Disposition"] = f'inline; filename="{filename}"'
    #     frame_ancestors = " ".join(settings.CORS_ALLOWED_ORIGINS)
    #     resp["Content-Security-Policy"] = f"frame-ancestors 'self' {frame_ancestors};"
    #     return resp
    
    def _stream_file_with_range(self, request, file_bytes, content_type, filename):
        file_size = len(file_bytes)
        range_header = request.headers.get("Range")

        if range_header:
            import re
            m = re.match(r"bytes=(\d+)-(\d*)", range_header)
            start = int(m.group(1))
            end = int(m.group(2)) if m.group(2) else file_size - 1
        else:
            # ✅ FORCE RANGE ON FIRST REQUEST
            start = 0
            end = file_size - 1

        end = min(end, file_size - 1)

        def stream():
            pos = start
            while pos <= end:
                chunk_end = min(pos + self.STREAMING_CHUNK_SIZE, end + 1)
                yield file_bytes[pos:chunk_end]
                pos = chunk_end

        response = StreamingHttpResponse(
            stream(),
            status=206,                     # ✅ ALWAYS 206
            content_type=content_type
        )

        response["Accept-Ranges"] = "bytes"
        response["Content-Range"] = f"bytes {start}-{end}/{file_size}"
        response["Content-Length"] = str(end - start + 1)
        response["Content-Disposition"] = "inline"
        response["Cache-Control"] = "no-store"
        response["X-Content-Type-Options"] = "nosniff"

        response["Access-Control-Allow-Origin"] = "*"
        response["Access-Control-Expose-Headers"] = (
            "Accept-Ranges, Content-Range, Content-Length"
        )

        return response

    def _get_file_size_from_metadata(self, s3_key):
        """Calculate decrypted file size from S3 metadata."""
        cache_key = f"media_size_{s3_key}"
        cached_size = cache.get(cache_key)
        if cached_size:
            return cached_size
        
        try:
            obj = s3.head_object(Bucket=MEDIA_FILES_BUCKET, Key=s3_key)
            encrypted_size = obj['ContentLength']
            metadata =  obj['Metadata']
            chunk_size = metadata.get('chunk-size')
            if not chunk_size:
                meta_cache_key = f'meta_cache_key_{s3_key}'
                cache.set(meta_cache_key, metadata, 60*60*24)
                
            
            chunk_size = int(obj['Metadata'].get('chunk-size', 10 * 1024 * 1024))
            
            num_chunks = (encrypted_size + chunk_size + 27) // (chunk_size + 28)
            overhead = num_chunks * 28
            decrypted_size = encrypted_size - overhead
            
            cache.set(cache_key, decrypted_size, timeout=self.CACHE_TIMEOUT)
            return decrypted_size
        except Exception as e:
            logger.error(f"Failed to calculate file size for {s3_key}: {e}")
            return None

    def get(self, request, s3_key, media_file_id=None):
        exp = request.GET.get("exp")
        sig = request.GET.get("sig")
        
        
        if not exp or not sig:
            return Response(status=status.HTTP_404_NOT_FOUND)

        if int(exp) < int(time.time()):
            return Response(status=status.HTTP_404_NOT_FOUND)

        user = self.get_current_user(request)
        if user is None:
            return Response(status=status.HTTP_401_UNAUTHORIZED)

        media_file = MemoryRoomMediaFile.objects.only('id', 's3_key', 'user_id').get( id=media_file_id, user=user )

        s3_key = media_file.s3_key
        filename = s3_key.split("/")[-1]
        extension = self._get_file_extension(filename)
        # category = self._categorize_file(filename)
        category = media_file.file_type
        content_type = self._guess_content_type(filename)
        
        # Check for special cases
        is_pdf = self._is_pdf_file(filename)
        is_csv = self._is_csv_file(filename)
        is_json = self._is_json_file(filename)
        needs_conversion = extension in {'.mkv', '.avi', '.wmv', '.mpeg', '.mpg', '.flv', '.mov', '.ts', '.m4v', '.3gp'}
        is_special = extension in {'.svg', '.heic', '.heif', '.doc','.tiff', '.raw'} or needs_conversion
        
        # Route 1: Streaming with range support (video/audio that don't need conversion)
        if (category in ['video', 'audio']) and not needs_conversion and not is_special:
            # file_size = self._get_file_size_from_metadata(s3_key)
            # if not file_size:
            #     return Response(status=status.HTTP_500_INTERNAL_SERVER_ERROR)
            
            # # Parse range header
            # start, end = 0, file_size
            # range_header = request.headers.get("Range", "")
            # if range_header:
            #     import re
            #     m = re.match(r"bytes=(\d+)-(\d*)", range_header)
            #     if m:
            #         start = int(m.group(1))
            #         end = int(m.group(2)) + 1 if m.group(2) else file_size
            #         end = min(end, file_size)
            
            # logger.info(f"Streaming {category}: {filename}")
            # return self._create_response(
            #     self._stream_chunked_decrypt(s3_key, start, end, media_file, user),
            #     content_type, filename,
            #     streaming=True, range_support=True,
            #     start=start, end=end, total_size=file_size
            # )

            logger.info(f"Serving {category} via byte-range: {filename}")

            # cache_key = f"media_bytes_{s3_key}"
            cache_key = media_cache_key('media_bytes_', s3_key)
            file_bytes = cache.get(cache_key)

            if not file_bytes:
                file_bytes, _ = decrypt_s3_file_chunked(s3_key)
                if not file_bytes:
                    file_bytes, _ = get_media_file_bytes_with_content_type(media_file, user)
                if not file_bytes:
                    return Response(status=500)

                cache.set(cache_key, file_bytes, timeout=self.CACHE_TIMEOUT)

            return self._stream_file_with_range(
                request,
                file_bytes,
                content_type,
                filename
            )
        
        # Route 2: Progressive streaming (images, no special handling)
        elif category == 'image' and not is_special:
            file_size = self._get_file_size_from_metadata(s3_key)
            if not file_size:
                return Response(status=status.HTTP_500_INTERNAL_SERVER_ERROR)
            
            logger.info(f"Progressive image: {filename}")
            return self._create_response(
                self._stream_chunked_decrypt(s3_key=s3_key, media_file=media_file, user=user),
                content_type, filename,
                streaming=True, range_support=False
            )
        
        # Route 3: Full file with conversions (everything else)
        else:
            logger.info(f"Full decrypt for {category}: {filename}")
            
            # Get or decrypt full file
            # bytes_cache_key = f"media_bytes_{s3_key}"
            bytes_cache_key = media_cache_key('media_bytes_', s3_key)

            cached_data = cache.get(bytes_cache_key)
            
            if cached_data:
                file_bytes, _ = cached_data
            else:
                file_bytes, _ = decrypt_s3_file_chunked(s3_key)
                if not file_bytes:
                    file_bytes, _ = get_media_file_bytes_with_content_type(media_file, user)
                    if not file_bytes:
                        return Response(status=status.HTTP_500_INTERNAL_SERVER_ERROR)
                cache.set(bytes_cache_key, (file_bytes, content_type), timeout=self.CACHE_TIMEOUT)
            
            # Check if PDF, CSV, or JSON after decryption
            if is_pdf:
                logger.info(f"Serving PDF with range support: {filename}")
                return self._serve_pdf_with_range(request, file_bytes, filename)
            elif is_csv:
                logger.info(f"Serving CSV with range support: {filename}")
                return self._serve_csv_with_range(request, file_bytes, filename)
            elif is_json:
                logger.info(f"Serving JSON with range support: {filename}")
                return self._serve_json_with_range(request, file_bytes, filename)
            
            # Handle conversions
            if extension == '.doc':
                cache_key = f'{media_file.id}_docx_preview'
                file_bytes = cache.get(cache_key) or convert_doc_to_docx_bytes(file_bytes, media_file.id, user.email)
                cache.set(cache_key, file_bytes, timeout=self.CACHE_TIMEOUT)
                content_type = "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
                filename = filename.replace(".doc", ".docx")
            
            elif extension in {'.heic', '.heif'}:
                cache_key = f'{bytes_cache_key}_jpeg'
                file_bytes = cache.get(cache_key) or convert_heic_to_jpeg_bytes(file_bytes)[0]
                cache.set(cache_key, file_bytes, timeout=self.CACHE_TIMEOUT)
                content_type = "image/jpeg"
                filename = filename.rsplit('.', 1)[0] + '.jpg'
            
            elif extension  == '.tiff':
                cache_key = f'{bytes_cache_key}_jpeg'
                file_bytes = cache.get(cache_key) or convert_tiff_bytes_to_jpg_bytes(
                                                        file_bytes,
                                                        quality=85,
                                                        max_size=(4000, 4000)  # optional
                                                    )

                cache.set(cache_key, file_bytes, timeout=self.CACHE_TIMEOUT)
                content_type = "image/jpeg"
                filename = filename.rsplit('.', 1)[0] + '.jpg'
            
            
            elif needs_conversion:

                cache_key = f'{bytes_cache_key}_mp4'
                mp4_bytes = cache.get(cache_key)

                if not mp4_bytes:
                    try:
                        logger.info(f"Converting {extension} to MP4 for {filename}")
                        if extension == '.mpeg':
                            mp4_bytes = convert_mpeg_bytes_to_mp4_bytes_strict(file_bytes)
                        elif extension == '.mpg':
                            mp4_bytes = convert_mpg_bytes_to_mp4_bytes_strict(file_bytes)
                        elif extension == '.ts':
                            mp4_bytes = convert_ts_bytes_to_mp4_bytes_strict(file_bytes)
                        elif extension == '.mov':
                            mp4_bytes = convert_mov_bytes_to_mp4_bytes_strict(file_bytes)
                        elif extension == '.3gp':
                            mp4_bytes = convert_3gp_bytes_to_mp4_bytes_strict(file_bytes)
                        
                        elif extension == '.m4v':
                            mp4_bytes = convert_m4v_bytes_to_mp4_bytes_strict(file_bytes)

                        else:
                            try:
                                mp4_bytes, _ = convert_video_to_mp4_bytes(
                                    source_format=extension,
                                    file_bytes=file_bytes
                                )
                            except Exception as e:
                                mp4_bytes = convert_mov_bytes_to_mp4_bytes(file_bytes)
                            except Exception as e:
                                logger.error(f"Conversion failed for {filename}: {e}")
                                return Response(status=status.HTTP_500_INTERNAL_SERVER_ERROR)
                    
                        if mp4_bytes:
                            logger.info(f"Convereted {extension} to MP4 for {filename}")
                            cache.set(cache_key, mp4_bytes, timeout=self.CACHE_TIMEOUT)

                    except Exception as e:
                        logger.error(f"Conversion failed for {filename}: {e}")
                        return Response(status=status.HTTP_500_INTERNAL_SERVER_ERROR)
                
                file_bytes = mp4_bytes
                content_type = "video/mp4"
                filename = filename.rsplit('.', 1)[0] + '.mp4'
                
                # Now stream the converted MP4 with range support
                logger.info(f"Streaming converted MP4: {filename}")
                file_size = len(file_bytes)
                
                # Parse range header
                start, end = 0, file_size
                range_header = request.headers.get("Range", "")
                if range_header:
                    import re
                    m = re.match(r"bytes=(\d+)-(\d*)", range_header)
                    if m:
                        start = int(m.group(1))
                        end = int(m.group(2)) + 1 if m.group(2) else file_size
                        end = min(end, file_size)
                
                # Create generator for range
                def generate_range():
                    chunk_size = self.STREAMING_CHUNK_SIZE
                    pos = start
                    while pos < end:
                        chunk_end = min(pos + chunk_size, end)
                        yield file_bytes[pos:chunk_end]
                        pos = chunk_end
                
                return self._create_response(
                    generate_range(),
                    content_type, filename,
                    streaming=True, range_support=True,
                    start=start, end=end, total_size=file_size
                )
            
            # For non-converted files, return simple response
            return self._create_response(file_bytes, content_type, filename)

class RefreshMediaURL(SecuredView):
    """
    Refresh expired signed URLs for media.
    """

    def get(self, request):
        user = self.get_current_user(request)
        s3_key = request.GET.get("s3_key")

        if not s3_key:
            return JsonResponse({"error": "Missing s3_key"}, status=400)

        # Always prepend user's storage ID
        s3_storage_id = user.s3_storage_id
        full_key = f"{s3_storage_id}/{s3_key}"

        # Generate new signed path (short-lived)
        new_url = generate_signed_path(full_key, expiry_seconds=60)

        return JsonResponse({"url": new_url})

def create_duplicate_room(room:MemoryRoom):
    from django.utils import timezone
    new_room = None
    user = room.user
    logger.info(f'Room duplication creation started for user: {room.user.email} room-id: {room.id}')
    try:
        # duplicate_capsoul = MemoryRoom.objects.filter(room_duplicate = room, is_deleted = False)
        # capsoul_duplication_number = f' ({1 + duplicate_capsoul.count()})'
        
        unique_room_name = generate_unique_memory_room_name(room.user, room.room_template.name)
        # create duplicate room here
        created_at = timezone.localtime(timezone.now())
        old_room_template = room.room_template
        new_custom_template  =  CustomMemoryRoomTemplate.objects.create(
            name= unique_room_name,
            slug = old_room_template.slug,
            summary = old_room_template.summary,
            cover_image = old_room_template.cover_image,
            default_template = old_room_template.default_template,
            created_at = created_at
        )
        new_custom_template.save()
        
        new_room = MemoryRoom.objects.create(
            user = room.user,
            room_template = new_custom_template,
            room_duplicate = room,
            occupied_storage=room.occupied_storage,
            created_at = created_at
        )
        
    except Exception as e:
        logger.error(f'Exception while create duplicate room for {room.user.email} room id: {room.id}')
    else:
        try:
            # now create duplicate media files here
            media_files = MemoryRoomMediaFile.objects.filter(
                user=room.user,
                memory_room=room,
                is_deleted=False
            )  # reverse by primary key (latest first)
            old_files_count = media_files.count()
            duplicate_media_count  = 0
            
            for media in media_files:
                try:
                        new_media = MemoryRoomMediaFile.objects.create(
                            user = media.user,
                            memory_room = new_room,
                            file = media.file,
                            file_type = media.file_type,
                            cover_image = media.cover_image,
                            title = media.title,
                            description = media.description,
                            is_cover_image = media.is_cover_image,
                            thumbnail_url = media.thumbnail_url,
                            thumbnail_key = media.thumbnail_key,
                            s3_url = media.s3_url,
                            s3_key = media.s3_key,
                            media_file_duplicate = media,
                            created_at = created_at,
                            media_type = 'duplicate'
                        )
                        if new_media:
                            is_updated = update_users_storage(
                                operation_type='addition',
                                media_updation='memory_room',
                                media_file=new_media
                            )
                            # bind with celery task
                            copy_s3_object_preserve_meta_kms.apply_async(
                                args=[new_media.id, 5, 2,'memory_room']
                            )
                            duplicate_media_count += 1
                except Exception as e:
                    logger.error(f'Exception while creating duplicate media for user: {user.email} old-media id: {media.id} s3_key: {media.s3_keys}')
                    pass
                    
                except Exception as e:
                    logger.error(f'Exception while creating media file duplicate for media: {media.id} and room: {room.id} user: {room.user.email}')
            print(f'Room duplication creation completed for user: {room.user.email} room-id: {room.id} old media files count: {old_files_count} duplicate file count: {duplicate_media_count}')
            logger.info(f'Room duplication creation completed for user: {room.user.email} room-id: {room.id} old media files count: {old_files_count} duplicate file count: {duplicate_media_count}')
            
        
        except Exception as e:
            logger.error(f'Exception while creating room media duplica for {room.id}')
        
        return new_room
            
      
class MemoryRoomDuplicationApiView(SecuredView):
    
    def post(self, request, memory_room_id, format=None):
        user  = self.get_current_user(request)
        logger.info(f'MemoryRoomDuplicationApiView is called by {user.email}')
        memory_room = get_object_or_404(MemoryRoom, id=memory_room_id, user = user)
        duplicate_room = create_duplicate_room(memory_room)
        serializer = MemoryRoomSerializer(duplicate_room)
        logger.info(f'Memory room duplicate created successfully for room: {memory_room.id} for user {user.email} ')
        cache.delete(f'{user.email}__rooms_list')
        display_cache_message('Room cache deleted while duplicate room creation')
        return Response(serializer.data, status=status.HTTP_201_CREATED)
        
        