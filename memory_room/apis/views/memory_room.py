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
from memory_room.media_helper import decrypt_s3_file_chunked,decrypt_s3_file_chunked_range,ChunkedDecryptor
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


MEDIA_FILES_BUCKET = 'yurayi-media'

s3 = boto3.client("s3", region_name='ap-south-1',
    aws_access_key_id=settings.AWS_ACCESS_KEY_ID,
    aws_secret_access_key=settings.AWS_SECRET_ACCESS_KEY,
)


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
        media_file = memory_room.memory_media_files.filter(is_deleted = False)
        media_file.update(is_deleted = True)
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
        file_progress = {i: {'progress': 1, 'message': 'Queued', 'status': 'pending'} for i in range(total_files)}
        
        def update_file_progress(file_index, progress, message, status='processing'):
            with progress_lock:
                file_progress[file_index] = {
                    'progress': progress,
                    'message': message,
                    'status': status
                }
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
    
    def _stream_chunked_decrypt_download(self, s3_key):
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
                full_plaintext, content = get_file_bytes(s3_key)


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
            filename = s3_key.split("/")[-1]
            
            # Clean up the download filename
            file_name = f'{media_file.title.split(".", 1)[0].replace(" ", "_")}.{s3_key.split(".")[-1]}'
            
            # Get file size without downloading
            file_size = self._get_file_size_from_metadata(s3_key)
            if not file_size:
                logger.error(f"Failed to get file size for {s3_key}")
                return Response(status=status.HTTP_500_INTERNAL_SERVER_ERROR)
            
            # Determine content type
            content_type = self._guess_content_type(filename)
            
            # Stream directly without any conversions
            logger.info(f"Streaming download for {filename}")
            response = StreamingHttpResponse(
                streaming_content=self._stream_chunked_decrypt_download(s3_key),
                content_type=content_type
            )
            
            # Set download headers
            response['Content-Disposition'] = f'attachment; filename="{file_name}"'
            response['Content-Length'] = str(file_size)
            response['Accept-Ranges'] = 'bytes'
            response['Cache-Control'] = 'no-cache, no-store, must-revalidate'
            response['Access-Control-Expose-Headers'] = 'Content-Length, Content-Disposition'
            response['X-Content-Type-Options'] = 'nosniff'

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


class ServeMedia(SecuredView):
    """
    Simplified streaming media server with unified response handling.
    """
    
    CACHE_TIMEOUT = 60 * 60 * 24*7  # 7 days 
    STREAMING_CHUNK_SIZE = 64 * 1024  # 64KB chunks
    
    # File category extensions (same as before)
    IMAGE_EXTENSIONS = {'.jpg', '.jpeg', '.png', '.gif', '.bmp', '.tiff', '.webp', 
                        '.heic', '.heif', '.svg', '.ico', '.raw', '.psd'}
    VIDEO_EXTENSIONS = {'.mp4', '.avi', '.mov', '.wmv', '.flv', '.mkv', '.webm', 
                        '.3gp', '.mpg', '.ts', '.m4v','.mpeg'}
    AUDIO_EXTENSIONS = {'.mp3', '.wav', '.aac', '.flac', '.ogg', '.wma', '.alac', 
                        '.aiff', '.m4a', '.opus', '.amr'}
    OTHER_EXTENSIONS = {'.txt', '.doc', '.docx', '.pdf', '.rtf', '.odt', '.md', '.tex',
                        '.csv', '.xls', '.xlsx', '.ods', '.tsv', '.json', '.xml', '.yaml', '.yml',
                        '.zip', '.rar', '.7z', '.tar', '.gz', '.bz2', '.xz', '.iso',
                        '.exe', '.msi', '.apk', '.bat', '.sh', '.app',
                        '.html', '.htm', '.css', '.js', '.ts', '.py', '.java', '.c', '.cpp', '.cs',
                        '.php', '.rb', '.go', '.swift', '.rs', '.kt', '.sql', '.ini', '.env', '.toml'}
    
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
        elif ext in self.OTHER_EXTENSIONS:
            return 'other'
        return 'unknown'
    
    def _is_pdf_file(self, filename):
        """Check if file is a PDF."""
        return filename.lower().endswith('.pdf')
    
    def _is_csv_file(self, filename):
        """Check if file is a CSV."""
        return filename.lower().endswith('.csv')
    
    def _is_json_file(self, filename):
        """Check if file is a JSON."""
        return filename.lower().endswith('.json')
    
    def _guess_content_type(self, filename):
        """Guess content type from filename extension."""
        import mimetypes
        content_type, _ = mimetypes.guess_type(filename)
        
        ext = self._get_file_extension(filename)
        
        # Quick lookup for common types
        type_map = {
            # Video
            '.mp4': 'video/mp4', '.m4v': 'video/mp4', '.webm': 'video/webm',
            '.mov': 'video/quicktime', '.mkv': 'video/mp4', '.avi': 'video/mp4',
            '.mpeg': 'video/mpeg', '.mpg': 'video/mpeg', '.3gp': 'video/3gpp',
            # Audio
            '.mp3': 'audio/mpeg', '.m4a': 'audio/mp4', '.aac': 'audio/mp4',
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
        }
        
        return type_map.get(ext, content_type or 'application/octet-stream')
    
    def _create_response(self, content, content_type, filename, streaming=False, 
                        range_support=False, start=0, end=None, total_size=None):
        """
        Unified response creator for all file types.
        
        Args:
            content: File bytes or generator for streaming
            content_type: MIME type
            filename: Original filename
            streaming: Whether to use StreamingHttpResponse
            range_support: Whether to add Range headers
            start: Start byte for range requests
            end: End byte for range requests
            total_size: Total file size for range requests
        """
        # Create appropriate response type
        if streaming:
            response = StreamingHttpResponse(content, content_type=content_type)
            if range_support and start > 0:
                response.status_code = 206
        else:
            response = HttpResponse(content, content_type=content_type)
        
        # Set content length
        if streaming and total_size:
            length = (end - start) if end else total_size
            response["Content-Length"] = str(length)
        elif not streaming:
            response["Content-Length"] = str(len(content))
        
        # Range headers
        if range_support:
            response["Accept-Ranges"] = "bytes"
            if start > 0 and end and total_size:
                response["Content-Range"] = f"bytes {start}-{end-1}/{total_size}"
        
        # Security headers
        response["Content-Disposition"] = "inline"
        response["X-Content-Type-Options"] = "nosniff"
        response["Cache-Control"] = "private, max-age=3600"
        
        # Special CSP for SVG
        if content_type == "image/svg+xml":
            response["Content-Security-Policy"] = "default-src 'none'; style-src 'unsafe-inline'; img-src data:;"
        else:
            frame_ancestors = " ".join(settings.CORS_ALLOWED_ORIGINS)
            csp = f"frame-ancestors 'self' {frame_ancestors};"
            if range_support:
                csp = f"media-src *; {csp}"
            response["Content-Security-Policy"] = csp
        
        # CORS headers
        response["Cross-Origin-Resource-Policy"] = "cross-origin"
        response["Access-Control-Allow-Origin"] = "*"
        if range_support:
            response["Access-Control-Expose-Headers"] = "Accept-Ranges, Content-Range, Content-Length"
        
        return response
    
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
    
    def _stream_chunked_decrypt(self, s3_key, start_byte=0, end_byte=None):
        """Generator that streams decrypted chunks."""
        # with ChunkedDecryptor(s3_key) as decryptor:
        #     for decrypted_chunk in decryptor.decrypt_chunks(start_byte, end_byte):
        #         chunk_offset = 0
        #         while chunk_offset < len(decrypted_chunk):
        #             yield decrypted_chunk[chunk_offset:chunk_offset + self.STREAMING_CHUNK_SIZE]
        #             chunk_offset += self.STREAMING_CHUNK_SIZE
        
        with ChunkedDecryptor(s3_key) as decryptor:
        
            # If no chunk-size present in metadata => full decryption mode
            if not decryptor.metadata.get("chunk-size"):
                full_plaintext, content = get_file_bytes(s3_key)


                # Yield in streamable pieces
                offset = 0
                while offset < len(full_plaintext):
                    yield full_plaintext[offset:offset + self.STREAMING_CHUNK_SIZE]
                    offset += self.STREAMING_CHUNK_SIZE

            else:
                # Chunked mode (large files)
                for decrypted_chunk in decryptor.decrypt_chunks():
                    if not decrypted_chunk:
                        continue
                    
                    offset = 0
                    while offset < len(decrypted_chunk):
                        yield decrypted_chunk[offset:offset + self.STREAMING_CHUNK_SIZE]
                        offset += self.STREAMING_CHUNK_SIZE
    
    def _get_file_size_from_metadata(self, s3_key):
        """Calculate decrypted file size from S3 metadata."""
        cache_key = f"media_size_{s3_key}"
        cached_size = cache.get(cache_key)
        if cached_size:
            return cached_size
        
        try:
            obj = s3.head_object(Bucket=MEDIA_FILES_BUCKET, Key=s3_key)
            encrypted_size = obj['ContentLength']
            chunk_size = int(obj['Metadata'].get('chunk-size', 10 * 1024 * 1024))
            
            num_chunks = (encrypted_size + chunk_size + 27) // (chunk_size + 28)
            overhead = num_chunks * 28
            decrypted_size = encrypted_size - overhead
            
            cache.set(cache_key, decrypted_size, timeout=self.CACHE_TIMEOUT)
            return decrypted_size
        except Exception as e:
            logger.error(f"Failed to calculate file size for {s3_key}: {e}")
            return None
    
    def get(self, request, s3_key, media_file_id):
        """Main entry point - simplified routing and response."""
        user = self.get_current_user(request)
        if not user:
            return Response(status=status.HTTP_401_UNAUTHORIZED)

        try:
            # Validate signature
            exp = request.GET.get("exp")
            sig = request.GET.get("sig")
            if not exp or not sig or int(exp) < int(time.time()):
                return Response(status=status.HTTP_404_NOT_FOUND)

            media_file = MemoryRoomMediaFile.objects.only('id', 's3_key', 'user_id').get(
                id=media_file_id, user=user
            )

            if not verify_signature(media_file.s3_key, exp, sig):
                return Response(status=status.HTTP_404_NOT_FOUND)

            s3_key = media_file.s3_key
            filename = s3_key.split("/")[-1]
            extension = self._get_file_extension(filename)
            category = self._categorize_file(filename)
            content_type = self._guess_content_type(filename)
            
            # Check for special cases
            is_pdf = self._is_pdf_file(filename)
            is_csv = self._is_csv_file(filename)
            is_json = self._is_json_file(filename)
            needs_conversion = extension in {'.mkv', '.avi', '.wmv', '.mpeg', '.mpg', '.flv'}
            is_special = extension in {'.svg', '.heic', '.heif', '.doc'} or needs_conversion
            
            # Route 1: Streaming with range support (video/audio that don't need conversion)
            if (category in ['video', 'audio']) and not needs_conversion and not is_special:
                file_size = self._get_file_size_from_metadata(s3_key)
                if not file_size:
                    return Response(status=status.HTTP_500_INTERNAL_SERVER_ERROR)
                
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
                
                logger.info(f"Streaming {category}: {filename}")
                return self._create_response(
                    self._stream_chunked_decrypt(s3_key, start, end),
                    content_type, filename,
                    streaming=True, range_support=True,
                    start=start, end=end, total_size=file_size
                )
            
            # Route 2: Progressive streaming (images, no special handling)
            elif category == 'image' and not is_special:
                file_size = self._get_file_size_from_metadata(s3_key)
                if not file_size:
                    return Response(status=status.HTTP_500_INTERNAL_SERVER_ERROR)
                
                logger.info(f"Progressive image: {filename}")
                return self._create_response(
                    self._stream_chunked_decrypt(s3_key),
                    content_type, filename,
                    streaming=True, range_support=False
                )
            
            # Route 3: Full file with conversions (everything else)
            else:
                logger.info(f"Full decrypt for {category}: {filename}")
                
                # Get or decrypt full file
                bytes_cache_key = f"media_bytes_{s3_key}"
                cached_data = cache.get(bytes_cache_key)
                
                if cached_data:
                    file_bytes, _ = cached_data
                else:
                    file_bytes, _ = decrypt_s3_file_chunked(s3_key)
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
                
                elif needs_conversion:
                    cache_key = f'{bytes_cache_key}_mp4'
                    mp4_bytes = cache.get(cache_key)
                    
                    if not mp4_bytes:
                        try:
                            logger.info(f"Converting {extension} to MP4 for {filename}")
                            if extension in {'.mpeg', '.mpg'}:
                                mp4_bytes, _ = self.convert_mpeg_to_mp4_bytes(file_bytes)
                            else:
                                mp4_bytes, _ = self.convert_video_to_mp4_bytes(extension, file_bytes)
                            cache.set(cache_key, mp4_bytes, timeout=self.CACHE_TIMEOUT)
                        except Exception as e:
                            logger.error(f"Conversion failed for {filename}: {e}")
                            return Response(status=status.HTTP_500_INTERNAL_SERVER_ERROR)
                    
                    file_bytes = mp4_bytes
                    content_type = "video/mp4"
                    filename = filename.rsplit('.', 1)[0] + '.mp4'
                    
                    # Now stream the converted MP4 with range support
                    logger.info(f"Streaming converted MP4: {filename}")
                    
                    # Store converted file temporarily for range streaming
                    converted_s3_key = f"temp_converted_{media_file.id}"
                    temp_cache_key = f"media_bytes_{converted_s3_key}"
                    cache.set(temp_cache_key, (file_bytes, content_type), timeout=self.CACHE_TIMEOUT)
                    
                    # Return streaming response with range support
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

        except MemoryRoomMediaFile.DoesNotExist:
            return Response(status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            logger.warning(f'Exception serving media {s3_key} for {user.email}: {e}')
            return Response(status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    
    # Keep conversion methods as-is
    def convert_mpeg_to_mp4_bytes(self, file_bytes):
        """Convert MPEG/MPG to MP4 bytes using MoviePy."""
        logger.info("Converting MPEG/MPG to MP4...")
        with tempfile.NamedTemporaryFile(suffix=".mpeg") as temp_in, \
             tempfile.NamedTemporaryFile(suffix=".mp4") as temp_out:
            temp_in.write(file_bytes)
            temp_in.flush()
            try:
                clip = VideoFileClip(temp_in.name)
                clip.write_videofile(temp_out.name, codec="libx264", audio_codec="aac", verbose=False, logger=None)
                clip.close()
            except Exception as e:
                logger.error(f"MoviePy conversion failed: {e}")
                raise
            temp_out.seek(0)
            mp4_bytes = temp_out.read()
        logger.info(f"Conversion successful ({len(mp4_bytes)} bytes)")
        return mp4_bytes, "converted.mp4"

    def convert_video_to_mp4_bytes(self, source_format, file_bytes):
        """Generic video converter for MKV, AVI, WMV, etc."""
        logger.info(f"Converting {source_format} to MP4...")
        with tempfile.NamedTemporaryFile(suffix=source_format) as temp_in, \
             tempfile.NamedTemporaryFile(suffix=".mp4") as temp_out:
            temp_in.write(file_bytes)
            temp_in.flush()
            try:
                clip = VideoFileClip(temp_in.name)
                clip.write_videofile(temp_out.name, codec="libx264", audio_codec="aac", verbose=False, logger=None)
                clip.close()
            except Exception as e:
                logger.error(f"Video conversion failed for {source_format}: {e}")
                raise
            temp_out.seek(0)
            mp4_bytes = temp_out.read()
        logger.info(f"Conversion complete ({len(mp4_bytes)} bytes)")
        return mp4_bytes, "converted.mp4"

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
        return Response(serializer.data, status=status.HTTP_201_CREATED)
        
        