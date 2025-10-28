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

from channels.layers import get_channel_layer
from asgiref.sync import async_to_sync
import threading
import queue
import time
from memory_room.media_helper import decrypt_s3_file_chunked,decrypt_s3_file_chunked_range
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
from memory_room.crypto_utils import  verify_signature
from memory_room.utils import determine_download_chunk_size,convert_doc_to_docx_bytes
from memory_room.tasks import update_memory_room_occupied_storage

logger = logging.getLogger(__name__)
from memory_room.s3_helpers import s3_helper

from memory_room.crypto_utils import generate_signed_path,save_and_upload_decrypted_file,decrypt_and_get_image,encrypt_and_upload_file,get_decrypt_file_bytes,get_media_file_bytes_with_content_type,generate_room_media_s3_key
from memory_room.utils import convert_heic_to_jpeg_bytes,convert_mkv_to_mp4_bytes, convert_file_size, convert_video_to_mp4_bytes, convert_audio_to_mp3_bytes

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
        rooms = MemoryRoom.objects.filter(user=user, is_deleted=False).order_by('-created_at')
        serializer = MemoryRoomSerializer(rooms, many=True)
        return Response(serializer.data)

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

        return Response({
            'message': 'Memory created successfully',
            'memory_room': serialized_data
        })

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
        # memory_room.delete()
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
            return Response(MemoryRoomSerializer(updated_room).data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class SetMemoryRoomCoverImageAPIView(SecuredView):
    def post(self, request, memory_room_id, media_file_id):
        user = self.get_current_user(request)
        logger.info(f"SetMemoryRoomCoverImageAPIView.post called by {user.email} room: {memory_room_id} media-id: {media_file_id}")
        user = self.get_current_user(request)
        memory_room = get_object_or_404(MemoryRoom, id=memory_room_id, user=user)
        if memory_room.room_template.default_template is None:
            media_file = get_object_or_404(MemoryRoomMediaFile, id=media_file_id, user = user, memory_room = memory_room)
            if media_file.file_type == 'image' and media_file.is_cover_image == False:
                logger.info(f"SetMemoryRoomCoverImageAPIView.post cover setting started by {user.email} room: {memory_room_id} media-id: {media_file_id}")
                
                # now images as cover image here
                from userauth.models import Assets
                media_s3_key =  str(media_file.s3_key)
                file_name = media_s3_key.split('/')[-1]
                file_bytes, content_type = get_media_file_bytes_with_content_type(media_file, user)
                if not file_bytes or not content_type:
                    return Response(status=status.HTTP_500_INTERNAL_SERVER_ERROR)
                s3_key, url = save_and_upload_decrypted_file(filename=file_name, decrypted_bytes=file_bytes, bucket='time-capsoul-files', content_type=content_type)
                assets_obj = Assets.objects.create(image = media_file.file, s3_url=url, s3_key=s3_key)
                
                room_template = memory_room.room_template
                room_template.cover_image = assets_obj
                room_template.save()
                memory_room.save()
                media_file.is_cover_image = True
                media_file.save()
                logger.info(f'Memory Room cover set successfully by {user.email} room: {memory_room_id} media id: {media_file_id} ')
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
        memory_room = self.get_memory_room(user, memory_room_id)
        media_files = MemoryRoomMediaFile.objects.filter(memory_room=memory_room, user=user, is_deleted=False).order_by('-created_at')
        return Response(MemoryRoomMediaFileSerializer(media_files, many=True).data)
        
   
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
        from rest_framework import serializers

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
        file_progress = {i: {'progress': 0, 'message': 'Queued', 'status': 'pending'} for i in range(total_files)}
        
        def update_file_progress(file_index, progress, message, status='processing'):
            with progress_lock:
                file_progress[file_index] = {
                    'progress': progress,
                    'message': message,
                    'status': status
                }

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
                        # update_memory_room_occupied_storage.apply_async(
                        #     args=[media_file.id, 'addition'],
                        # )
                        # update_user_storage(
                        #     user=user,
                        #     media_id=media_file.id,
                        #     file_size=media_file.file_size,
                        #     cache_key=f'user_storage_id_{user.id}',
                        #     operation_type='addition'
                        # )
                        is_updated = update_users_storage(
                            operation_type='addition',
                            media_updation='memory_room',
                            media_file=media_file
                        )
                        update_file_progress(file_index, 100, 'Upload completed successfully', 'success')
                        
                        return {
                            'index': file_index,
                            'result': {
                                "file": uploaded_file.name,
                                "status": "success",
                                "progress": 100,
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
                    
                    time.sleep(0.1)
            
            yield f"data: FINAL_RESULTS::{json.dumps(results)}\n\n"

        return StreamingHttpResponse(
            file_upload_stream(),
            content_type='text/event-stream',
            status=status.HTTP_200_OK
        )


    def patch(self, request, memory_room_id, media_file_id):
        """
        Move a media file to another memory room.
        """
        user = self.get_current_user(request)
        new_room = self.get_memory_room(user, memory_room_id)
        media_file = get_object_or_404(MemoryRoomMediaFile, id=media_file_id, user=user)

        media_file.memory_room = new_room
        media_file.save()
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
        # update_memory_room_occupied_storage.apply_async( 
        #     args=[media_file.id, 'remove'],
        # )
        # update_user_storage(
        #     user=user,
        #     media_id=media_file.id,
        #     file_size=media_file.file_size,
        #     cache_key=f'user_storage_id_{user.id}',
        #     operation_type='remove'
        # )
        return Response({'message': 'Media file deleted successfully'}, status=status.HTTP_204_NO_CONTENT)

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

            return Response({'message': 'Description updated successfully.', 'data': MemoryRoomMediaFileReadOnlySerializer(updated_data).data})
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class MediaFileDownloadView(SecuredView):
    def get(self, request, memory_room_id, media_file_id):
        """
        Securely stream a media file from S3 using optimized chunk size based on file size.
        """
        user = self.get_current_user(request)
        memory_room = get_object_or_404(MemoryRoom, id=memory_room_id, user=user)
        media_file = get_object_or_404(
            MemoryRoomMediaFile,
            id=media_file_id,
            user=user,
            memory_room=memory_room
        )

        # file_name = media_file.title
        file_name  = f'{media_file.title.split(".", 1)[0].replace(" ", "_")}.{media_file.s3_key.split(".")[-1]}'
        
        file_bytes, content_type = get_media_file_bytes_with_content_type(media_file, user)
        if not file_bytes or not content_type:
            return Response(status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        try:
            file_size = len(file_bytes)
            chunk_size = determine_download_chunk_size(file_size)
            file_stream = io.BytesIO(file_bytes)

            mime_type = (
                content_type
                or mimetypes.guess_type(file_name)[0]
                or 'application/octet-stream'
            )

            def file_iterator():
                while True:
                    chunk = file_stream.read(chunk_size)
                    if not chunk:
                        break
                    yield chunk

            response = StreamingHttpResponse(
                streaming_content=file_iterator(),
                content_type=mime_type
            )
            response['Content-Disposition'] = f'attachment; filename="{file_name}"'
            response['Content-Length'] = str(file_size)
            response['Accept-Ranges'] = 'bytes'
            response['Cache-Control'] = 'no-cache, no-store, must-revalidate'
            response['Access-Control-Expose-Headers'] = 'Content-Length, Content-Disposition'

            return response

        except Exception as e:
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

MEDIA_FILES_BUCKET = settings.MEDIA_FILES_BUCKET
from django.http import StreamingHttpResponse, HttpResponse


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


import boto3
import hmac
import hashlib
import base64
import time
import boto3
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

# working
# class ServeMedia(SecuredView):
#     """
#     Securely serve decrypted media from S3 via Django.
#     Supports Range requests for video/audio playback.
#     Optimized for speed with caching.
#     """
    
#     CACHE_TIMEOUT = 60 * 60 * 2  # 2 hours
    
#     def _serve_svg_safely(self, file_bytes, filename):
#         """
#         Serve SVG files with proper security headers to prevent XSS.
#         """
#         response = HttpResponse(file_bytes, content_type="image/svg+xml")
#         response["Content-Length"] = str(len(file_bytes))
#         response["Content-Disposition"] = f'inline; filename="{filename}"'
#         response["Cache-Control"] = "private, max-age=3600"
#         # Strict CSP for SVG to prevent script execution
#         response["Content-Security-Policy"] = "default-src 'none'; style-src 'unsafe-inline'; img-src data:;"
#         response["X-Content-Type-Options"] = "nosniff"
#         return response
    
#     def _is_video_file(self, filename):
#         """Check if file is a video by extension."""
#         return filename.lower().endswith(('.mp4', '.mkv', '.webm', '.mov', '.avi', '.flv', '.wmv', '.m4v'))
    
#     def _is_audio_file(self, filename):
#         """Check if file is audio by extension."""
#         return filename.lower().endswith(('.mp3', '.m4a', '.aac', '.wav', '.flac', '.ogg', '.wma', '.opus'))
  
#     def _stream_file_with_range(self, request, file_bytes, content_type, filename):
#         """
#         Stream decrypted media file with proper Range support (seekable, inline playback).
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

#         length = end - start + 1
#         is_partial = range_header != ""

#         # ✅ Use correct status based on Range
#         status_code = 206 if is_partial else 200

#         # ✅ Send correct content type based on file extension (most reliable)
#         lower_filename = filename.lower()
#         if lower_filename.endswith((".mp4", ".m4v")):
#             content_type = "video/mp4"
#         elif lower_filename.endswith((".webm",)):
#             content_type = "video/webm"
#         elif lower_filename.endswith((".mov",)):
#             content_type = "video/quicktime"
#         elif lower_filename.endswith((".mkv", ".avi", ".flv", ".wmv")):
#             content_type = "video/mp4"  # Browser-friendly fallback
#         elif lower_filename.endswith((".mp3",)):
#             content_type = "audio/mpeg"
#         elif lower_filename.endswith((".m4a", ".aac")):
#             content_type = "audio/mp4"
#         elif lower_filename.endswith((".wav",)):
#             content_type = "audio/wav"
#         elif lower_filename.endswith((".flac",)):
#             content_type = "audio/flac"
#         elif lower_filename.endswith((".ogg", ".opus")):
#             content_type = "audio/ogg"
#         elif lower_filename.endswith((".wma",)):
#             content_type = "audio/x-ms-wma"

#         # ✅ Prepare response
#         resp = StreamingHttpResponse(
#             FileWrapper(BytesIO(file_bytes[start:end + 1]), 8192),
#             status=status_code,
#             content_type=content_type,
#         )

#         # ✅ Critical headers for inline playback (NOT download)
#         resp["Accept-Ranges"] = "bytes"
#         resp["Content-Length"] = str(length)
        
#         # 🔥 FIX: Use 'inline' WITHOUT filename to prevent download prompts
#         resp["Content-Disposition"] = "inline"
        
#         # 🔥 FIX: Prevent MIME type sniffing that can break playback
#         resp["X-Content-Type-Options"] = "nosniff"

#         if is_partial:
#             resp["Content-Range"] = f"bytes {start}-{end}/{file_size}"

#         # ✅ CORS + security
#         resp["Cross-Origin-Resource-Policy"] = "cross-origin"
#         resp["Access-Control-Allow-Origin"] = "*"
#         resp["Access-Control-Expose-Headers"] = "Accept-Ranges, Content-Range, Content-Length"

#         # 🔥 FIX: Allow caching for better streaming performance (scrubbing, seeking)
#         resp["Cache-Control"] = "private, max-age=3600"
        
#         frame_ancestors = " ".join(settings.CORS_ALLOWED_ORIGINS)
#         resp["Content-Security-Policy"] = f"media-src *; frame-ancestors 'self' {frame_ancestors};"

#         return resp
    
    
#     def get(self, request, s3_key, media_file_id):
#         user = self.get_current_user(request)
#         if user is None:
#             return Response(status=status.HTTP_401_UNAUTHORIZED)

#         try:
#             exp = request.GET.get("exp")
#             sig = request.GET.get("sig")
#             if not exp or not sig or int(exp) < int(time.time()):
#                 return Response(status=status.HTTP_404_NOT_FOUND)

#             # Optimize: Only fetch needed fields from DB
#             media_file = MemoryRoomMediaFile.objects.only('id', 's3_key', 'user_id').get(
#                 id=media_file_id, user=user
#             )

#             if not verify_signature(media_file.s3_key, exp, sig):
#                 return Response(status=status.HTTP_404_NOT_FOUND)

#             s3_key = media_file.s3_key
#             filename = s3_key.split("/")[-1]
#             file_ext = s3_key.lower()
            
#             # Check if it's an image first - fast path for images (excluding svg)
#             is_image = file_ext.endswith(('.jpg', '.jpeg', '.png', '.gif', '.bmp', '.webp'))
#             is_svg = file_ext.endswith('.svg')
            
#             # 🔥 Check if it's video/audio by extension
#             is_video = self._is_video_file(filename)
#             is_audio = self._is_audio_file(filename)
            
#             # Cache decrypted file bytes to avoid repeated decryption
#             bytes_cache_key = f"media_bytes_{s3_key}"
            
#             # For images, try cache first before any processing
#             if is_image or is_svg:
#                 cached_data = cache.get(bytes_cache_key)
#                 if cached_data:
#                     file_bytes, content_type = cached_data
#                     # SVG gets special secure handling
#                     if is_svg:
#                         return self._serve_svg_safely(file_bytes, filename)
#                     # Direct response for cached images - fastest path
#                     response = HttpResponse(file_bytes, content_type=content_type)
#                     response["Content-Length"] = str(len(file_bytes))
#                     response["Content-Disposition"] = f'inline; filename="{filename}"'
#                     response["Cache-Control"] = "private, max-age=3600"
#                     response["X-Content-Type-Options"] = "nosniff"
#                     frame_ancestors = " ".join(settings.CORS_ALLOWED_ORIGINS)
#                     response["Content-Security-Policy"] = f"frame-ancestors 'self' {frame_ancestors};"
#                     return response
            
#             # Get file bytes - check cache first
#             cached_data = cache.get(bytes_cache_key)
#             if cached_data:
#                 file_bytes, content_type = cached_data
#             else:
#                 # Decrypt or fetch from S3
#                 file_bytes, content_type = decrypt_s3_file_chunked(media_file.s3_key)
#                 if not file_bytes or not content_type:
#                     return Response(status=status.HTTP_500_INTERNAL_SERVER_ERROR)
#                 # Cache the decrypted bytes for future requests
#                 cache.set(bytes_cache_key, (file_bytes, content_type), timeout=self.CACHE_TIMEOUT)
            
#             # Fast path for SVG with security
#             if is_svg:
#                 return self._serve_svg_safely(file_bytes, filename)
            
#             # Fast path for regular images - use HttpResponse instead of StreamingHttpResponse
#             if is_image:
#                 response = HttpResponse(file_bytes, content_type=content_type)
#                 response["Content-Length"] = str(len(file_bytes))
#                 response["Content-Disposition"] = f'inline; filename="{filename}"'
#                 response["Cache-Control"] = "private, max-age=3600"
#                 response["X-Content-Type-Options"] = "nosniff"
#                 frame_ancestors = " ".join(settings.CORS_ALLOWED_ORIGINS)
#                 response["Content-Security-Policy"] = f"frame-ancestors 'self' {frame_ancestors};"
#                 return response

#             # Handle .doc (convert to docx)
#             if file_ext.endswith(".doc"):
#                 docx_bytes_cache_key = f'{media_file.id}_docx_preview'
#                 docx_bytes = cache.get(docx_bytes_cache_key)
#                 if not docx_bytes:
#                     docx_bytes = convert_doc_to_docx_bytes(file_bytes, media_file_id=media_file.id, email=user.email)
#                     cache.set(docx_bytes_cache_key, docx_bytes, timeout=self.CACHE_TIMEOUT)

#                 response = HttpResponse(
#                     docx_bytes,
#                     content_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document"
#                 )
#                 response["Content-Length"] = str(len(docx_bytes))
#                 response["X-Content-Type-Options"] = "nosniff"
#                 frame_ancestors = " ".join(settings.CORS_ALLOWED_ORIGINS)
#                 response["Content-Security-Policy"] = f"frame-ancestors 'self' {frame_ancestors};"
#                 response["Content-Disposition"] = f'inline; filename="{filename.replace(".doc", ".docx")}"'
#                 return response

#             # Handle HEIC/HEIF to JPEG
#             if file_ext.endswith((".heic", ".heif")):
#                 jpeg_cache_key = f'{bytes_cache_key}_jpeg'
#                 jpeg_file_bytes = cache.get(jpeg_cache_key)
#                 if not jpeg_file_bytes:
#                     jpeg_file_bytes, content_type = convert_heic_to_jpeg_bytes(file_bytes)
#                     cache.set(jpeg_cache_key, jpeg_file_bytes, timeout=self.CACHE_TIMEOUT)

#                 # Fast HttpResponse for converted images
#                 response = HttpResponse(jpeg_file_bytes, content_type="image/jpeg")
#                 response["Content-Length"] = str(len(jpeg_file_bytes))
#                 response["Content-Disposition"] = f'inline; filename="{filename.replace(".heic", ".jpg").replace(".heif", ".jpg")}"'
#                 response["Cache-Control"] = "private, max-age=3600"
#                 response["X-Content-Type-Options"] = "nosniff"
#                 frame_ancestors = " ".join(settings.CORS_ALLOWED_ORIGINS)
#                 response["Content-Security-Policy"] = f"frame-ancestors 'self' {frame_ancestors};"
#                 return response

#             # Handle MKV → MP4
#             if file_ext.endswith(".mkv"):
#                 mp4_cache_key = f'{bytes_cache_key}_mp4'
#                 mp4_bytes = cache.get(mp4_cache_key)
#                 if not mp4_bytes:
#                     mp4_bytes, content_type = convert_mkv_to_mp4_bytes(file_bytes)
#                     cache.set(mp4_cache_key, mp4_bytes, timeout=self.CACHE_TIMEOUT)
#                 filename = filename.replace(".mkv", ".mp4")
#                 return self._stream_file_with_range(request, mp4_bytes, "video/mp4", filename)

#             # 🔥 FIX: Stream audio/video by FILE EXTENSION (not content_type string check)
#             if is_video or is_audio:
#                 return self._stream_file_with_range(request, file_bytes, content_type, filename)

#             # Default file (normal response)
#             response = HttpResponse(file_bytes, content_type=content_type)
#             response["Content-Length"] = str(len(file_bytes))
#             response["X-Content-Type-Options"] = "nosniff"
#             frame_ancestors = " ".join(settings.CORS_ALLOWED_ORIGINS)
#             response["Content-Security-Policy"] = f"frame-ancestors 'self' {frame_ancestors};"
#             response["Content-Disposition"] = f'inline; filename="{filename.replace(".enc", "")}"'
#             return response

#         except MemoryRoomMediaFile.DoesNotExist:
#             return Response(status=status.HTTP_404_NOT_FOUND)
#         except Exception as e:
#             logger.warning(f'Exception while serving media file {s3_key} for user {user.email}: {e}')
#             return Response(status=status.HTTP_500_INTERNAL_SERVER_ERROR)

# better one working 
class ServeMedia(SecuredView):
    """
    Securely serve decrypted media from S3 via Django.
    Supports Range requests for video/audio playback.
    Optimized for speed with full response caching.
    """
    
    CACHE_TIMEOUT = 60 * 60 * 2  # 2 hours
    
    def _guess_content_type(self, filename):
        """Guess content type from filename extension."""
        import mimetypes
        content_type, _ = mimetypes.guess_type(filename)
        
        # Override for better browser compatibility
        lower_filename = filename.lower()
        if lower_filename.endswith(('.mp4', '.m4v')):
            return 'video/mp4'
        elif lower_filename.endswith('.webm'):
            return 'video/webm'
        elif lower_filename.endswith('.mov'):
            return 'video/quicktime'
        elif lower_filename.endswith(('.mkv', '.avi', '.flv', '.wmv')):
            return 'video/mp4'
        elif lower_filename.endswith('.mp3'):
            return 'audio/mpeg'
        elif lower_filename.endswith(('.m4a', '.aac')):
            return 'audio/mp4'
        elif lower_filename.endswith('.wav'):
            return 'audio/wav'
        elif lower_filename.endswith('.flac'):
            return 'audio/flac'
        elif lower_filename.endswith(('.ogg', '.opus')):
            return 'audio/ogg'
        elif lower_filename.endswith('.wma'):
            return 'audio/x-ms-wma'
        elif lower_filename.endswith('.svg'):
            return 'image/svg+xml'
        elif lower_filename.endswith('.pdf'):
            return 'application/pdf'
        elif lower_filename.endswith(('.doc', '.docx')):
            return 'application/vnd.openxmlformats-officedocument.wordprocessingml.document'
        
        return content_type or 'application/octet-stream'
    
    def _serve_svg_safely(self, file_bytes, filename):
        """Serve SVG files with proper security headers to prevent XSS."""
        response = HttpResponse(file_bytes, content_type="image/svg+xml")
        response["Content-Length"] = str(len(file_bytes))
        response["Content-Disposition"] = "inline"
        response["Cache-Control"] = "private, max-age=3600"
        response["Content-Security-Policy"] = "default-src 'none'; style-src 'unsafe-inline'; img-src data:;"
        response["X-Content-Type-Options"] = "nosniff"
        return response
    
    def _is_video_file(self, filename):
        """Check if file is a video by extension."""
        return filename.lower().endswith(('.mp4', '.mkv', '.webm', '.mov', '.avi', '.flv', '.wmv', '.m4v'))
    
    def _is_audio_file(self, filename):
        """Check if file is audio by extension."""
        return filename.lower().endswith(('.mp3', '.m4a', '.aac', '.wav', '.flac', '.ogg', '.wma', '.opus'))
  
    def _stream_file_with_range(self, request, file_bytes, content_type, filename):
        """Stream decrypted media file with proper Range support (seekable, inline playback)."""
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

        length = end - start + 1
        is_partial = range_header != ""
        status_code = 206 if is_partial else 200

        # Use guessed content type
        content_type = self._guess_content_type(filename)

        # Use HttpResponse for non-partial, StreamingHttpResponse only for Range requests
        if is_partial:
            resp = StreamingHttpResponse(
                FileWrapper(BytesIO(file_bytes[start:end + 1]), 8192),
                status=status_code,
                content_type=content_type,
            )
        else:
            # For direct access without Range, use HttpResponse (cacheable and inline)
            resp = HttpResponse(
                file_bytes,
                status=status_code,
                content_type=content_type,
            )

        # Critical headers for inline playback
        resp["Accept-Ranges"] = "bytes"
        resp["Content-Length"] = str(length)
        resp["Content-Disposition"] = "inline"
        resp["X-Content-Type-Options"] = "nosniff"

        if is_partial:
            resp["Content-Range"] = f"bytes {start}-{end}/{file_size}"

        # CORS + security
        resp["Cross-Origin-Resource-Policy"] = "cross-origin"
        resp["Access-Control-Allow-Origin"] = "*"
        resp["Access-Control-Expose-Headers"] = "Accept-Ranges, Content-Range, Content-Length"
        resp["Cache-Control"] = "private, max-age=3600"
        
        frame_ancestors = " ".join(settings.CORS_ALLOWED_ORIGINS)
        resp["Content-Security-Policy"] = f"media-src *; frame-ancestors 'self' {frame_ancestors};"

        return resp
    
    def _create_inline_response(self, file_bytes, content_type, filename):
        """Create a standard inline response for non-streaming files."""
        response = HttpResponse(file_bytes, content_type=content_type)
        response["Content-Length"] = str(len(file_bytes))
        response["Content-Disposition"] = "inline"
        response["Cache-Control"] = "private, max-age=3600"
        response["X-Content-Type-Options"] = "nosniff"
        frame_ancestors = " ".join(settings.CORS_ALLOWED_ORIGINS)
        response["Content-Security-Policy"] = f"frame-ancestors 'self' {frame_ancestors};"
        return response
    
    def get(self, request, s3_key, media_file_id):
        user = self.get_current_user(request)
        if user is None:
            return Response(status=status.HTTP_401_UNAUTHORIZED)

        try:
            exp = request.GET.get("exp")
            sig = request.GET.get("sig")
            if not exp or not sig or int(exp) < int(time.time()):
                return Response(status=status.HTTP_404_NOT_FOUND)

            # Optimize: Only fetch needed fields from DB
            media_file = MemoryRoomMediaFile.objects.only('id', 's3_key', 'user_id').get(
                id=media_file_id, user=user
            )

            if not verify_signature(media_file.s3_key, exp, sig):
                return Response(status=status.HTTP_404_NOT_FOUND)

            s3_key = media_file.s3_key
            filename = s3_key.split("/")[-1]
            file_ext = s3_key.lower()
            extension = s3_key.lower().split('/')[-1].split('.')[-1]
            
            
            # Check file type
            is_image = file_ext.endswith(('.jpg', '.jpeg', '.png', '.gif', '.bmp', '.webp'))
            is_svg = file_ext.endswith('.svg')
            is_video = self._is_video_file(filename)
            is_audio = self._is_audio_file(filename)
            is_doc = file_ext.endswith('.doc')
            is_heic = file_ext.endswith(('.heic', '.heif'))
            is_mkv = file_ext.endswith('.mkv')
            is_avi = file_ext.endswith('.avi')
            is_wmv = file_ext.endswith('.wmv')
            is_mpeg = file_ext.endswith('.mpeg')
            is_avi = file_ext.endswith('.avi')
            

            
            
            # Get file bytes from cache or decrypt
            bytes_cache_key = f"media_bytes_{s3_key}"
            cached_data = cache.get(bytes_cache_key)
            
            if cached_data:
                file_bytes, original_content_type = cached_data
            else:
                # Decrypt or fetch from S3
                file_bytes, original_content_type = decrypt_s3_file_chunked(media_file.s3_key)
                if not file_bytes or not original_content_type:
                    return Response(status=status.HTTP_500_INTERNAL_SERVER_ERROR)
                # Cache the decrypted bytes
                cache.set(bytes_cache_key, (file_bytes, original_content_type), timeout=self.CACHE_TIMEOUT)
            
            # Guess better content type from filename (more reliable than S3 metadata)
            content_type = self._guess_content_type(filename)
            
            # Handle special conversions
            if is_doc:
                docx_bytes_cache_key = f'{media_file.id}_docx_preview'
                docx_bytes = cache.get(docx_bytes_cache_key)
                if not docx_bytes:
                    docx_bytes = convert_doc_to_docx_bytes(file_bytes, media_file_id=media_file.id, email=user.email)
                    cache.set(docx_bytes_cache_key, docx_bytes, timeout=self.CACHE_TIMEOUT)
                
                file_bytes = docx_bytes
                content_type = "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
                filename = filename.replace(".doc", ".docx")
            
            elif is_heic:
                jpeg_cache_key = f'{bytes_cache_key}_jpeg'
                jpeg_file_bytes = cache.get(jpeg_cache_key)
                if not jpeg_file_bytes:
                    jpeg_file_bytes, _ = convert_heic_to_jpeg_bytes(file_bytes)
                    cache.set(jpeg_cache_key, jpeg_file_bytes, timeout=self.CACHE_TIMEOUT)
                
                file_bytes = jpeg_file_bytes
                content_type = "image/jpeg"
                filename = filename.replace(".heic", ".jpg").replace(".heif", ".jpg")
            
            elif is_mkv or is_wmv or is_avi or is_mpeg:
                mp4_cache_key = f'{bytes_cache_key}_mp4'
                mp4_bytes = cache.get(mp4_cache_key)
                if not mp4_bytes:
                    try:
                        if is_mpeg :
                            
                            mp4_bytes, _ = convert_audio_to_mp3_bytes(
                                source_format = f'.{extension}',
                                file_bytes = file_bytes
                            )
                        else:
                            mp4_bytes, _ = convert_video_to_mp4_bytes(
                            source_format = f'.{extension}',
                            file_bytes = file_bytes
                            )
                        cache.set(mp4_cache_key, mp4_bytes, timeout=self.CACHE_TIMEOUT)
                    except Exception as e:
                        logger.error(f"MKV conversion failed: {e} for {user.email} media-id: {media_file.id}")
                        return Response(status=status.HTTP_500_INTERNAL_SERVER_ERROR)
                file_bytes = mp4_bytes
                content_type = "video/mp4"
                if is_mkv:
                    filename = filename.replace(".mkv", ".mp4")
                elif is_wmv:
                    filename = filename.replace(".wmv", ".mp4")
                else:
                    filename = filename.replace(".avi", ".mp4")
            
            
            # Return appropriate response based on file type
            if is_svg:
                return self._serve_svg_safely(file_bytes, filename)
            elif is_video or is_audio:
                # This handles both direct access and Range requests properly
                return self._stream_file_with_range(request, file_bytes, content_type, filename)
            else:
                # All other files (PDFs, images, documents, etc.)
                return self._create_inline_response(file_bytes, content_type, filename)

        except MemoryRoomMediaFile.DoesNotExist:
            return Response(status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            logger.warning(f'Exception while serving media file {s3_key} for user {user.email}: {e}')
            return Response(status=status.HTTP_500_INTERNAL_SERVER_ERROR)



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
                    # file_bytes, content_type = get_media_file_bytes_with_content_type(media, user)
                    # if not file_bytes or not content_type:
                        # raise Exception('File decryption failed')
                    # else:
                        file_name  = f'{media.title.split(".", 1)[0].replace(" ", "_")}.{media.s3_key.split(".")[-1]}' # get file name 
                        file_name = re.sub(r'[^A-Za-z0-9_]', '', file_name) # remove special characters from file name
                        s3_key = generate_room_media_s3_key(file_name, user.s3_storage_id, room.id)
                        
                        # upload_file_to_s3_kms_chunked(
                        #     key=s3_key,
                        #     plaintext_bytes=file_bytes,
                        #     content_type=content_type,
                        #     progress_callback=None
                        # )
                        
                        res = s3_helper.copy_s3_object_preserve_meta_kms(
                            source_key=media.s3_key,
                            destination_key=s3_key
                        )
                                        
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
                            created_at = created_at
                        )
                        if new_media:
                            is_updated = update_users_storage(
                                operation_type='addition',
                                media_updation='memory_room',
                                media_file=new_media
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
        return Response(serializer.data, status=status.HTTP_201_CREATED)
        
        