import boto3, io
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
from django.core.cache import cache
from concurrent.futures import ThreadPoolExecutor, as_completed

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

from memory_room.crypto_utils import generate_signed_path,save_and_upload_decrypted_file,decrypt_and_get_image,encrypt_and_upload_file,get_decrypt_file_bytes,get_media_file_bytes_with_content_type
from memory_room.utils import convert_heic_to_jpeg_bytes,convert_mkv_to_mp4_bytes, convert_file_size

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

SECRET = settings.SECRET_KEY.encode()


class ServeMedia(SecuredView):
    """
    Securely serve decrypted media from S3 via Django.
    """

    def get(self, request, s3_key, media_file_id):
        user  = self.get_current_user(request)
        if user is None:
            return Response(status=status.HTTP_401_UNAUTHORIZED)
        try:
            exp = request.GET.get("exp")
            sig = request.GET.get("sig")
            
            if not exp or not sig:
                return Response(status=status.HTTP_404_NOT_FOUND)

            if int(exp) < int(time.time()):
                return Response(status=status.HTTP_404_NOT_FOUND)
            
            media_file =  get_object_or_404(MemoryRoomMediaFile, id = media_file_id, user = user)
            
            #  signature-verification
            if not verify_signature(media_file.s3_key, exp, sig):
                return Response(status=status.HTTP_404_NOT_FOUND)
            
            bytes_cache_key = str(media_file.s3_key)
            file_bytes, content_type = get_media_file_bytes_with_content_type(media_file, user)
            if not file_bytes or not content_type:
                return Response(status=status.HTTP_500_INTERNAL_SERVER_ERROR)
                        
            if file_bytes and content_type:
                if media_file.s3_key.lower().endswith(".doc"): # .doc to .docx conversion here
                    try:
                        docx_bytes_cache_key = f'{media_file.id}_docx_preview'
                        docx_bytes = cache.get(docx_bytes_cache_key)
                        
                        if not docx_bytes:
                            docx_bytes = convert_doc_to_docx_bytes(file_bytes, media_file_id=media_file.id, email=user.email)
                            cache.set(docx_bytes_cache_key, docx_bytes, timeout=60*60*2)  
                            
                        response = HttpResponse(
                            docx_bytes,
                            content_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document"
                        )
                        frame_ancestors = " ".join(settings.CORS_ALLOWED_ORIGINS)
                        response["Content-Security-Policy"] = f"frame-ancestors 'self' {frame_ancestors};"
                        response["Content-Disposition"] = f'inline; filename="{media_file.s3_key.split("/")[-1].replace(".doc", ".docx")}"'
                        return response
                    except Exception as e:
                        logger.error(f'Exception while generating docx for doc files as {e}')
                        return Response(status=status.HTTP_500_INTERNAL_SERVER_ERROR)
                else:
                    if media_file.s3_key.lower().endswith(".heic")  or media_file.s3_key.lower().endswith(".heif"):
                        jpeg_cache_key = f'{bytes_cache_key}_jpeg'
                        jpeg_file_bytes = cache.get(jpeg_cache_key)
                        if not jpeg_file_bytes:
                            jpeg_file_bytes, content_type = convert_heic_to_jpeg_bytes(file_bytes)
                            cache.set(jpeg_cache_key, jpeg_file_bytes, timeout=60*60*2)
                            
                        response = HttpResponse(jpeg_file_bytes, content_type="image/jpeg")
                        response["Content-Disposition"] = (
                            f'inline; filename="{media_file.s3_key.split("/")[-1].replace(".heic", ".jpg")}"'
                        )
                        return response
                    elif media_file.s3_key.lower().endswith(".mkv"):
                        cache_key = f'{bytes_cache_key}_mp4'
                        mp4_bytes = cache.get(cache_key)
                        if not mp4_bytes:
                            try:
                                mp4_bytes, content_type = convert_mkv_to_mp4_bytes(file_bytes)
                                content_type = "video/mp4"
                                cache.set(cache_key, mp4_bytes, timeout=60*60*2)
                            except Exception as e:
                                logger.error(f"MKV conversion failed: {e} for {user.email} media-id: {media_file.id}")
                                return Response(status=status.HTTP_500_INTERNAL_SERVER_ERROR)

                        download_name = media_file.s3_key.split("/")[-1]
                        download_name = download_name.replace(".mkv", ".mp4")
                        response = HttpResponse(mp4_bytes, content_type=content_type)
                        frame_ancestors = " ".join(settings.CORS_ALLOWED_ORIGINS)
                        response["Content-Security-Policy"] = f"frame-ancestors 'self' {frame_ancestors};"
                        response["Content-Disposition"] = f'inline; filename="{download_name}"'
                        return response
                    else:
                        response = HttpResponse(file_bytes, content_type=content_type)
                        frame_ancestors = " ".join(settings.CORS_ALLOWED_ORIGINS) # 
                        response["Content-Security-Policy"] = f"frame-ancestors 'self' {frame_ancestors};"
                        response["Content-Disposition"] = f'inline; filename="{s3_key.split("/")[-1].replace(".enc", "")}"'
                        return response
        except Exception as e:
            logger.warning(f'Exception while serving media file as s3-key: {s3_key} user: {user.email}')
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
    logger.info(f'Room duplication creation started for user: {room.user.email} room-id: {room.id}')
    try:
        duplicate_capsoul = MemoryRoom.objects.filter(room_duplicate = room, is_deleted = False)
        capsoul_duplication_number = f' ({1 + duplicate_capsoul.count()})'
        # create duplicate room here
        created_at = timezone.localtime(timezone.now())
        old_room_template = room.room_template
        new_custom_template  =  CustomMemoryRoomTemplate.objects.create(
            name= old_room_template.name + capsoul_duplication_number,
            slug = old_room_template,
            summary = old_room_template.summary,
            cover_image = old_room_template.cover_image,
            default_template = old_room_template.default_template,
            created_at = created_at
        )
        
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
            # media_files = MemoryRoomMediaFile.objects.filter(user = room.user, memory_room = room, is_deleted =False)
            media_files = MemoryRoomMediaFile.objects.filter(
                user=room.user,
                memory_room=room,
                is_deleted=False
            )  # reverse by primary key (latest first)
            
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
                        created_at = created_at
                    )
                except Exception as e:
                    logger.error(f'Exception while creating media file duplicate for media: {media.id} and room: {room.id} user: {room.user.email}')
            
            logger.info(f'Room duplication creation completed for user: {room.user.email} room-id: {room.id}')
            
        
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
        
        