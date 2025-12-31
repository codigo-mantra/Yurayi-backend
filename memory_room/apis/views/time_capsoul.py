import boto3,mimetypes
import logging
from rest_framework.parsers import MultiPartParser
from django.shortcuts import get_object_or_404
from rest_framework import generics, permissions, status
from rest_framework.response import Response
from botocore.exceptions import ClientError
from django.conf import settings
from django.http import StreamingHttpResponse, Http404,HttpResponse, JsonResponse, HttpResponseNotFound
from memory_room.utils import determine_download_chunk_size
from memory_room.utils import parse_storage_size, to_mb, to_gb, convert_file_size,auto_format_size
from memory_room.views import parse_storage_size as parse_into_mbs
from memory_room.signals import update_user_storage, update_users_storage
from memory_room.tasks import update_time_capsoul_occupied_storage
from timecapsoul.utils import MediaThumbnailExtractor
from memory_room.notification_service import NotificationService
from memory_room.media_helper import decrypt_s3_file_chunked,ChunkedDecryptor

import time
from io import BytesIO
from django.http import StreamingHttpResponse
from PIL import Image
from wsgiref.util import FileWrapper
from django.utils import timezone


from memory_room.helpers import (
    upload_file_to_s3_kms,
    create_duplicate_time_capsoul,
    create_parent_media_files_replica_upload_to_s3_bucket, generate_unique_capsoul_name,
    create_time_capsoul,create_time_capsoul_media_file, get_recipient_capsoul_ids
    )

logger = logging.getLogger(__name__)
from rest_framework.pagination import PageNumberPagination
from rest_framework.exceptions import ValidationError
from rest_framework import serializers
import json,io
import hmac
from django.core.cache import cache
import hashlib
import base64
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed

import time
from django.http import HttpResponseForbidden, HttpResponseRedirect,Http404
from memory_room.utils import upload_file_to_s3_bucket, get_file_category, generate_unique_slug, convert_doc_to_docx_bytes,convert_heic_to_jpeg_bytes,convert_mkv_to_mp4_bytes, convert_video_to_mp4_bytes, convert_mov_bytes_to_mp4_bytes,convert_mpeg_bytes_to_mp4_bytes_strict,convert_mpg_bytes_to_mp4_bytes_strict,convert_ts_bytes_to_mp4_bytes_strict,convert_mov_bytes_to_mp4_bytes_strict,convert_3gp_bytes_to_mp4_bytes_strict,convert_m4v_bytes_to_mp4_bytes_strict,convert_tiff_bytes_to_jpg_bytes,convert_raw_bytes_to_jpg_bytes


from userauth.models import Assets
from userauth.apis.views.views import SecuredView,NewSecuredView,APIView


from memory_room.apis.serializers.memory_room import (
    AssetSerializer,
)

from memory_room.models import (
    TimeCapSoulTemplateDefault, TimeCapSoul, TimeCapSoulDetail, TimeCapSoulMediaFile,RecipientsDetail,TimeCapSoulRecipient,
    TimeCapSoulRecipient,FILE_TYPES, CustomTimeCapSoulTemplate, MemoryRoom, MemoryRoomMediaFile, Notification
    )

from memory_room.apis.serializers.time_capsoul import (
    TimeCapSoulTemplateDefaultReadOnlySerializer, TimeCapSoulCreationSerializer,TimeCapSoulMediaFileReadOnlySerializer,
    TimeCapSoulSerializer, TimeCapSoulUpdationSerializer,TimeCapSoulMediaFileSerializer,TimeCapSoulMediaFilesReadOnlySerailizer, TimeCapsoulMediaFileUpdationSerializer,
    TimeCapsoulUnlockSerializer, TimeCapsoulUnlockSerializer,RecipientsDetailSerializer,TimeCapSoulMediaFileReadOnlySerializer, TimeCapSoulRecipientSerializer
)
from memory_room.apis.serializers.notification import TimeCapSoulRecipientUpdateSerializer
from memory_room.crypto_utils import get_file_bytes, encrypt_and_upload_file, decrypt_and_get_image, save_and_upload_decrypted_file, decrypt_and_replicat_files, generate_signature, verify_signature,get_media_file_bytes_with_content_type,encrypt_and_upload_file_chunked,generate_capsoul_media_s3_key,clean_filename

import hashlib

def media_cache_key(prefix: str, s3_key: str) -> str:
    digest = hashlib.sha256(s3_key.encode("utf-8")).hexdigest()
    return f"{prefix}:{digest}"

MEDIA_FILES_BUCKET = 'yurayi-media'

s3 = boto3.client("s3", region_name='ap-south-1',
    aws_access_key_id=settings.AWS_ACCESS_KEY_ID,
    aws_secret_access_key=settings.AWS_SECRET_ACCESS_KEY,
)

class TimeCapSoulCoverView(SecuredView):
    """
    API endpoint to list all assets of type 'Time CapSoul Cover'.
    Only authenticated users can access this.
    """
    def get(self,request):
        logger.info("TimeCapSoulCoverView.get called")
        """
        Returns all Time CapSoul Cover assets ordered by creation date.
        """
        cache_key = 'time_capsoul_covers'
        data  = cache.get(cache_key)
        if not data:
            assets = Assets.objects.filter(asset_types='Time CapSoul Cover', is_deleted = False).order_by('-created_at')
            data = AssetSerializer(assets, many=True).data
            cache.set(cache_key, data, timeout=60*60) # 10 minutes cached 
        logger.info(f"TimeCapSoulCoverView.get data: served from cache")
            
        return Response(data)

class TimeCapSoulDefaultTemplateAPI(SecuredView):
    def get(self, request, format=None):
        logger.info("TimeCapSoulDefaultTemplateAPI.get called")
        cache_key = 'time_capsoul_templates'
        data  = cache.get(cache_key)
        if not data:
            default_templates = TimeCapSoulTemplateDefault.objects.filter(is_deleted = False)
            data = TimeCapSoulTemplateDefaultReadOnlySerializer(default_templates, many=True).data
            cache.set(cache_key, data, timeout=60*60) 
        logger.info("TimeCapSoulDefaultTemplateAPI. data served ")
        return Response(data)

class CreateTimeCapSoulView(SecuredView):
    """
    API view to create, update, or delete a time-capsoul.
    Inherits authentication logic from `SecuredView`.
    """
    def get_time_capsoul(self, user, time_capsoul_id):
        """
        Utility method to get a time capsoul owned by the user.
        """
        return get_object_or_404(TimeCapSoul, id=time_capsoul_id, user=user, is_deleted = False)

    def post(self, request, format=None):
        logger.info("CreateTimeCapSoulView.post called")
        """
        Create a new time-capsoul.
        """
        user = self.get_current_user(request)
        serializer = TimeCapSoulCreationSerializer(data=request.data, context={'user': user})
        serializer.is_valid(raise_exception=True)
        timecapsoul = serializer.validated_data.get('time_capsoul')
        serialized_data = TimeCapSoulSerializer(timecapsoul, context={'user': user}).data if timecapsoul else {}
        cache.delete(f'{user.email}_capsouls')
        print(f'\n ----- Cached cleared for Capsoul at: post request ---- ')

        return Response({
            'message': 'Time CapSoul created successfully',
            'time_capsoul': serialized_data
        }, status=status.HTTP_201_CREATED)
    
    def get(self, request, format=None):
        logger.info("CreateTimeCapSoulView.get list called")
        """Time CapSoul list"""
        user = self.get_current_user(request)
        cache_key = f'{user.email}_capsouls'
        cached_data = cache.get(cache_key)
        if cached_data:
            print(f'Cached reponse ---- capsoul list ---- ')
            return Response(cached_data)
        
        time_capsouls = TimeCapSoul.objects.filter(user=user, is_deleted = False).order_by('-updated_at') # owner capsoul
        try: 
            # tagged capsoul
            tagged_time_capsouls = TimeCapSoul.objects.filter(
                recipient_detail__email=user.email,
                recipient_detail__is_capsoul_deleted=False
            ).exclude(user = user).order_by('-updated_at')
            
            tagged_time_capsouls_replica = TimeCapSoul.objects.filter(
                user=user,
                capsoul_replica_refrence__in=tagged_time_capsouls,
                is_deleted = False
            ).order_by('-updated_at')
            if tagged_time_capsouls and tagged_time_capsouls_replica:
                tagged_time_capsouls = tagged_time_capsouls.union(tagged_time_capsouls_replica)
            
            
        except TimeCapSoulRecipient.DoesNotExist:
            tagged_time_capsouls = None

        # Get all replicas in one query (instead of loop)
        time_capsoul_replicas = TimeCapSoul.objects.filter(
            user=user,
            capsoul_replica_refrence__in=time_capsouls,
            is_deleted = False
        ).order_by('-updated_at')
        if tagged_time_capsouls:
            time_capsouls = time_capsouls.union(tagged_time_capsouls)
        

        serializer_data = TimeCapSoulSerializer(time_capsouls, many=True, context={'user': user}).data
        replica_serializer = TimeCapSoulSerializer(time_capsouls, many=True, context={'user': user}).data
        
        # combined_queryset = (time_capsouls | time_capsoul_replicas).order_by('-updated_at')
        # serializer_data = TimeCapSoulSerializer(combined_queryset, many=True, context={'user': user}).data
        response = {
            'time_capsoul': serializer_data,
            'replica_capsoul': replica_serializer
        }
        cache.set(cache_key, response, 60*60*24)
        return Response(response)
        
class TimeCapSoulUpdationView(SecuredView):
    def patch(self, request, time_capsoul_id):
        logger.info("TimeCapSoulUpdationView.patch called")
        
        user = self.get_current_user(request)
        time_capsoul = get_object_or_404(TimeCapSoul, id=time_capsoul_id)
        serializer = TimeCapSoulUpdationSerializer(instance = time_capsoul, data=request.data, partial = True, context={'is_owner': True if time_capsoul.user == user else False, 'current_user': user})
        if serializer.is_valid():
            update_time_capsoul = serializer.save()
            cache.delete(f'{user.email}_capsouls')
            print(f'\n ----- Cached cleared for Capsoul at: path request ---- ')
            
            return Response(TimeCapSoulSerializer(update_time_capsoul, context={'user': user}).data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    def delete(self, request, time_capsoul_id):
        user = self.get_current_user(request)
        logger.info(f"TimeCapSoulUpdationView.delete called by user {user.email} for time_capsoul_id {time_capsoul_id}")

        from django.utils import timezone

        time_capsoul = get_object_or_404(TimeCapSoul, id=time_capsoul_id)
        if time_capsoul.user != user:
            recipient = TimeCapSoulRecipient.objects.filter(time_capsoul = time_capsoul, email = user.email).first()
            if not recipient:
                logger.info(f"Recipient not found for tagged capsoul")
                return Response({"media_files": []}, status=status.HTTP_404_NOT_FOUND)
            
            # if time_capsoul.unlock_date and timezone.now() < time_capsoul.unlock_date:
            current_date = timezone.now()
            is_unlocked = (
                bool(time_capsoul.unlock_date) and current_date >= time_capsoul.unlock_date
            )
            # if (time_capsoul.unlock_date and current_date) and (current_date>= time_capsoul.unlock_date):
            if not is_unlocked:
                logger.info("Recipient not found for tagged capsoul")
                return Response({"media_files": []}, status=status.HTTP_404_NOT_FOUND)
            recipient.is_capsoul_deleted = True 
            recipient.save()
            cache.delete(f'{user.email}_capsouls')
            print(f'\n ----- Cached cleared for Capsoul at: delete request ---- ')
            return Response({'message': f'Time Capsoul deleted successfully for {user.email}'})
        else:
            if  time_capsoul.is_deleted == False:
                is_updated = update_users_storage(
                    capsoul=time_capsoul
                )
                time_capsoul.is_deleted = True
                time_capsoul.save()
                cache.delete(f'{user.email}_capsouls')
                media_files = time_capsoul.timecapsoul_media_files.filter(is_deleted = False)
                media_files.update(is_deleted  = True)
                cache.delete(f'{user.email}_capsouls')
                print(f'\n ----- Cached cleared for Capsoul at: delete request ---- ')
            return Response({'message': "Time capsoul deleted successfully"})

class TimeCapSoulMediaFilesView(SecuredView):
    """
    API view to manage (list, add, move, delete) media files within a time-capsoul room.
    """
    parser_classes = [MultiPartParser]

    def get_time_capsoul(self, user, time_capsoul_id):
        """
        Utility method to get a time-capsoul owned by the user.
        """
        return get_object_or_404(TimeCapSoul, id=time_capsoul_id, user=user)
    
    def get__tagged_time_capsoul(self, time_capsoul_id):
        """
        Utility method to get a time-capsoul owned by the user.
        """
        return get_object_or_404(TimeCapSoul, id=time_capsoul_id)

    def get(self, request, time_capsoul_id):
        logger.info("TimeCapSoulMediaFilesView.get called")
        """
        List all media files of a time-capsoul.
        """
        from django.utils import timezone
        user = self.get_current_user(request)
        cache_key = f'{user.email}_capsoul_{time_capsoul_id}'
        cached_data = cache.get(cache_key)
        if cached_data:
            print(f'\n media list served from cache for capsuul: {time_capsoul_id}')
            return Response(cached_data)
        
        # if user is Owner of the time-capsoul 
        try:
            time_capsoul = get_object_or_404(TimeCapSoul, id=time_capsoul_id)
        except Exception as e:
            logger.error(f"Error fetching time_capsoul: {e} for user {user.email} for time_capsoul_id {time_capsoul_id}")
            return Response(status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        else:
            if time_capsoul.user == user:
                if time_capsoul.is_deleted == True:
                    return Response(status=status.HTTP_404_NOT_FOUND)

                media_files = TimeCapSoulMediaFile.objects.filter(time_capsoul=time_capsoul,user=user, is_deleted =False).order_by('-updated_at')
            else:
                recipient = TimeCapSoulRecipient.objects.filter(time_capsoul = time_capsoul, email = user.email, is_capsoul_deleted = False).first()
                if not recipient:
                    logger.info(f'User is not owner and recipient not found for tagged capsoul {time_capsoul.id} and user {user.email}')
                    return Response(status=status.HTTP_404_NOT_FOUND)
                
                # if time_capsoul.unlock_date and timezone.now() < time_capsoul.unlock_date:
                current_date = timezone.now()
                is_unlocked = (
                    bool(time_capsoul.unlock_date) and current_date >= time_capsoul.unlock_date
                )
                if not is_unlocked:
                    logger.info(f'User is not owner and capsoul is locked for tagged capsoul {time_capsoul.id} and user {user.email}')
                    return Response(status=status.HTTP_404_NOT_FOUND)

                # parent_files_id = (
                #     [int(i.strip()) for i in recipient.parent_media_refrences.split(',') if i.strip().isdigit()]
                #     if recipient.parent_media_refrences else []
                # )
                parent_files_id = get_recipient_capsoul_ids(recipient)
                media_files = TimeCapSoulMediaFile.objects.filter(
                    time_capsoul=time_capsoul,
                    id__in = parent_files_id,
                ).order_by('-updated_at')
                
        serializer = TimeCapSoulMediaFileReadOnlySerializer(media_files, many=True)
        capsoul_data = TimeCapSoulSerializer(time_capsoul, context={'user': user}).data
        response = {
            'time_capsoul': capsoul_data,
            'media_files': serializer.data
        }
        cache.set(cache_key, response, 60*60*24)
        return Response(response)

    
    def post(self, request, time_capsoul_id):
        """
        Upload multiple media files to a TimeCapSoul with streaming progress updates.
        Each file has its own IV for decryption. Uses multi-threading for parallel uploads.
        """
        user = self.get_current_user(request) #
        time_capsoul = get_object_or_404(TimeCapSoul, id=time_capsoul_id)
        replica_instance = None
        files = request.FILES.getlist('file')
        created_objects = []
        upload_errors = []
        
        results = []

        if len(files) == 0: 
            raise serializers.ValidationError({'file': "Media files are required"})

        # Parse IVs from frontend
        try:
            ivs_json = request.POST.get('ivs', '[]')
            ivs = json.loads(ivs_json)
        except json.JSONDecodeError:
            raise serializers.ValidationError({'ivs': "Invalid IVs format"})

        # Ensure we have an IV for each file
        if len(ivs) != len(files):
            raise serializers.ValidationError({
                'ivs': f"Number of IVs ({len(ivs)}) must match number of files ({len(files)})"
            })
        
        if time_capsoul.status == "sealed":
            from django.utils import timezone

            unlock_date = time_capsoul.unlock_date
            current_datetime = timezone.now()  
            
            if unlock_date and current_datetime > unlock_date:
                time_capsoul.status = 'unlocked'
                time_capsoul.save()
        
        if time_capsoul.status == 'unlocked':
            try:
                replica_instance = create_time_capsoul(
                    old_time_capsoul = time_capsoul, # create time-capsoul replica
                    current_user = user,
                    option_type = 'replica_creation',
                )
                cache.delete(f'{user.email}_capsouls')
                print(f'\n ----- Cached cleared for Capsoul at replica creation ---- ')
    
                if user.id == time_capsoul.user.id: # if user is owner of the capsoul
                    parent_media_files = TimeCapSoulMediaFile.objects.filter(time_capsoul = time_capsoul, is_deleted = False).order_by('-updated_at')
                else:
                    recipient = TimeCapSoulRecipient.objects.filter(time_capsoul = time_capsoul, email = user.email).first()
                    if not recipient:
                        logger.info(f"Recipient not found for tagged capsoul for {time_capsoul.id} and user {user.email}")
                        return Response(status=status.HTTP_404_NOT_FOUND)
                    else:
                        # parent_files_id = (
                        #     [int(i.strip()) for i in recipient.parent_media_refrences.split(',') if i.strip().isdigit()]
                        #     if recipient.parent_media_refrences else []
                        # )
                        parent_files_id =  get_recipient_capsoul_ids(recipient)
                        parent_media_files = TimeCapSoulMediaFile.objects.filter(
                            time_capsoul=time_capsoul,
                            id__in = parent_files_id,
                        ).order_by('-updated_at')
                new_media_count = 0
                old_media_count = parent_media_files.count() 
                for parent_file in parent_media_files:
                    try:
                        is_media_created = create_time_capsoul_media_file(
                            old_media=parent_file,
                            new_capsoul=replica_instance,
                            current_user = user,
                            option_type = 'replica_creation',
                        )
                    except Exception as e:
                        logger.exception(F'Exception while creating time-capsoul media-file replica for media-file id {parent_file.id} and user {user.email}')
                        pass
                    else:
                        if is_media_created:
                            new_media_count += 1
                print(f"Old media count: {old_media_count}, New media count: {new_media_count}")
            except Exception as e:
                logger.error(f'Exception while creating time-capsoul replica user {user.email} capsoul-id: {time_capsoul_id} errors: {e}')
                

        if replica_instance is not None:
            time_capsoul = replica_instance
            
        # Dynamic worker calculation
        total_files = len(files)
        total_size = sum(f.size for f in files)

        # if total_files <= 2:
        #     max_workers = 1
        # elif total_files <= 5:
        #     max_workers = 2
        # elif total_size > 500 * 1024 * 1024:  # > 500MB
        #     max_workers = min(total_files, 4)
        # else:
        #     max_workers = min(total_files, 6)
        
        total_files = len(files)
        total_size = sum(f.size for f in files)
        avg_file_size = total_size / total_files if total_files > 0 else 0

        # Memory-aware worker allocation
        if total_files == 1:
            max_workers = 1
        elif total_size > 2 * 1024 * 1024 * 1024:  # > 2GB total
            max_workers = 2  # Conservative for large uploads
        elif avg_file_size > 100 * 1024 * 1024:  # Avg > 100MB per file
            max_workers = min(total_files, 3)
        elif total_files <= 3:
            max_workers = 2
        else:
            max_workers = min(total_files, 4)  # HARD CAP at 4
        
        logger.info(f"Starting upload: {total_files} files, {total_size / (1024*1024):.2f}MB total, {max_workers} workers")
        

        # Thread-safe progress tracking
        progress_lock = threading.Lock()
        file_progress = {
            i: {'progress': 0, 'message': 'Queued', 'status': 'pending'}
            for i in range(total_files)
        }
        progress_event = threading.Event()


        def update_file_progress(file_index, progress, message, status='processing'):
            with progress_lock:
                file_progress[file_index] = {
                    'progress': progress,
                    'message': message,
                    'status': status
                }
                progress_event.set()

                # print(f"\n File {file_progress}")

        # def file_upload_stream():
        #     def process_single_file(file_index, uploaded_file, file_iv, time_capsoul):
        #         """Process a single file upload with progress tracking"""
        #         try:
        #             def progress_callback(progress, message):
        #                 if progress == -1:  # Error
        #                     update_file_progress(file_index, 0, message, 'failed')
        #                 else:
        #                     update_file_progress(file_index, progress, message, 'processing')

        #             uploaded_file.seek(0)

        #             serializer = TimeCapSoulMediaFileSerializer(
        #                 data={'file': uploaded_file, 'iv': file_iv},
        #                 context={
        #                     'user': user,
        #                     'time_capsoul': time_capsoul,
        #                     'progress_callback': progress_callback
        #                 }
        #             )

        #             if serializer.is_valid():
        #                 media_file = serializer.save()
        #                 time_capsoul = media_file.time_capsoul
        #                 if time_capsoul.status == 'sealed':
        #                     capsoul_recipients = TimeCapSoulRecipient.objects.filter(time_capsoul = time_capsoul)
        #                     if capsoul_recipients.count() >0:
        #                         try:
        #                             existing_media_ids = eval(capsoul_recipients[0].parent_media_refrences)
        #                             if  existing_media_ids and  type(existing_media_ids) is list:
        #                                 existing_media_ids.append(media_file.id)
        #                                 capsoul_recipients.update(parent_media_refrences = existing_media_ids)
        #                         except Exception as e:
        #                             logger.error(f'Error while updating parent media references list: {e} for user {user.email} and capsoul id {time_capsoul.id}')
                                

                                
        #                         # updated_media_ids = existing_media_ids +  f',{media_file.id}'
        #                         # capsoul_recipients.update(parent_media_refrences = updated_media_ids)
        #                 update_file_progress(file_index, 93, 'Upload completed successfully', 'success')
                            
                        
        #                 is_updated = update_users_storage(
        #                     operation_type='addition',
        #                     media_updation='capsoul',
        #                     media_file=media_file
        #                 )
        #                 update_file_progress(file_index, 98, 'Upload completed successfully', 'success')

        #                 return {
        #                     'index': file_index,
        #                     'result': {
        #                         "file": uploaded_file.name,
        #                         "status": "success",
        #                         "progress": 99,
        #                         "data": TimeCapSoulMediaFileReadOnlySerializer(media_file).data
        #                     },
        #                     'media_file': media_file
        #                 }
        #             else:
        #                 update_file_progress(file_index, 0, f"Validation failed: {serializer.errors}", 'failed')
        #                 return {
        #                     'index': file_index,
        #                     'result': {
        #                         "file": uploaded_file.name,
        #                         "status": "failed",
        #                         "progress": 0,
        #                         "errors": serializer.errors
        #                     },
        #                     'media_file': None
        #                 }

        #         except Exception as e:
        #             error_msg = str(e)
        #             update_file_progress(file_index, 0, f"Upload failed: {error_msg}", 'failed')
        #             return {
        #                 'index': file_index,
        #                 'result': {
        #                     "file": uploaded_file.name,
        #                     "status": "failed",
        #                     "progress": 0,
        #                     "error": error_msg
        #                 },
        #                 'media_file': None
        #             }

        #     with ThreadPoolExecutor(max_workers=max_workers) as executor:
        #         future_to_index = {
        #             executor.submit(process_single_file, i, files[i], ivs[i], time_capsoul): i
        #             for i in range(total_files)
        #         }

        #         started_files = set()
        #         last_sent_progress = {i: -1 for i in range(total_files)}

        #         while len(results) < total_files:
        #             with progress_lock:
        #                 for file_index, progress_data in file_progress.items():
        #                     file_name = files[file_index].name

        #                     # Start message
        #                     if file_index not in started_files and progress_data['status'] != 'pending':
        #                         yield f"data: Starting upload of {file_name}\n\n"
        #                         started_files.add(file_index)

        #                     # Only send updated progress
        #                     if (
        #                         progress_data['status'] == 'processing'
        #                         and progress_data['progress'] != last_sent_progress[file_index]
        #                     ):
        #                         yield f"data: {file_name} -> {progress_data['progress']}\n\n"
        #                         last_sent_progress[file_index] = progress_data['progress']

        #             # Handle completed uploads
        #             completed_futures = []
        #             for future in future_to_index:
        #                 if future.done():
        #                     completed_futures.append(future)

        #             for future in completed_futures:
        #                 try:
        #                     result_data = future.result()
        #                     if result_data['media_file']:
        #                         created_objects.append(result_data['media_file'])
        #                     results.append(result_data['result'])

        #                     file_name = result_data['result']['file']
        #                     if result_data['result']['status'] == 'success':
        #                         yield f"data: {file_name} -> 100\n\n"
        #                         yield f"data: {file_name} upload completed successfully\n\n"
        #                     else:
        #                         error_msg = result_data['result'].get('error') or result_data['result'].get('errors', 'Upload failed')
        #                         yield f"data: {file_name} upload failed: {json.dumps(error_msg)}\n\n"

        #                     del future_to_index[future]

        #                 except Exception as e:
        #                     logger.exception("Task completion error")
        #                     del future_to_index[future]


        #     yield f"data: FINAL_RESULTS::{json.dumps(results)}\n\n"
        
            
        def file_upload_stream():
            nonlocal created_objects, results, upload_errors
            
            def process_single_file(file_index, uploaded_file, file_iv, time_capsoul):
                """Process a single file upload with progress tracking"""
                try:
                    def progress_callback(progress, message):
                        """Enhanced progress callback with proper ranges"""
                        if progress == 0 and "failed" in message.lower():
                            update_file_progress(file_index, 0, message, 'failed')
                        elif 15 <= progress <= 85:
                            # Map internal 15-85 to display 5-90
                            display_progress = int(5 + ((progress - 15) / 70) * 85)
                            update_file_progress(file_index, display_progress, None, 'processing')
                        elif progress > 85:
                            update_file_progress(file_index, progress, message, 'processing')
                        else:
                            update_file_progress(file_index, progress, message, 'processing')

                    # Reset file pointer
                    uploaded_file.seek(0)

                    # Validate and upload
                    serializer = TimeCapSoulMediaFileSerializer(
                        data={'file': uploaded_file, 'iv': file_iv},
                        context={
                            'user': user,
                            'time_capsoul': time_capsoul,
                            'progress_callback': progress_callback
                        }
                    )

                    if serializer.is_valid():
                        media_file = serializer.save()
                        
                        # Update recipient references for sealed capsouls
                        if media_file.time_capsoul.status == 'sealed':
                            capsoul_recipients = TimeCapSoulRecipient.objects.filter(
                                time_capsoul=media_file.time_capsoul
                            )
                            
                            if capsoul_recipients.exists():
                                try:
                                    recipient = capsoul_recipients.first()
                                    existing_media_ids = eval(recipient.parent_media_refrences) if recipient.parent_media_refrences else []
                                    
                                    if isinstance(existing_media_ids, list):
                                        existing_media_ids.append(media_file.id)
                                        capsoul_recipients.update(parent_media_refrences=str(existing_media_ids))
                                    
                                    
                                        
                                except Exception as e:
                                    logger.error(f'Error updating parent media refs: {e} for user {user.email}, capsoul {time_capsoul.id}')

                        update_file_progress(file_index, 93, 'Updating storage...', 'processing')

                        # Update user storage
                        try:
                            is_updated = update_users_storage(
                                operation_type='addition',
                                media_updation='capsoul',
                                media_file=media_file
                            )
                            cache.delete(f'{user.email}_capsoul_{media_file.time_capsoul.id}')
                            print(f'\n Cache cleared at when file uploaded')
                            if not is_updated:
                                logger.warning(f"Storage update returned False for media {media_file.id}")
                        except Exception as e:
                            logger.error(f"Storage update failed for media {media_file.id}: {e}")
                            # Don't fail the upload, just log

                        update_file_progress(file_index, 96, 'Upload completed', 'success')

                        return {
                            'index': file_index,
                            'result': {
                                "file": uploaded_file.name,
                                "status": "success",
                                "progress": 98,
                                "data": TimeCapSoulMediaFileReadOnlySerializer(media_file).data
                            },
                            'media_file': media_file
                        }
                    else:
                        error_msg = f"Validation failed: {serializer.errors}"
                        # update_file_progress(file_index, 0, error_msg, 'failed')
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
                    logger.exception(f"Upload failed for file {uploaded_file.name}: {e}")
                    # update_file_progress(file_index, 0, f"Upload failed: {error_msg}", 'failed')
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

            # Execute parallel uploads with ThreadPoolExecutor
            try:
                with ThreadPoolExecutor(max_workers=max_workers) as executor:
                    future_to_index = {
                        executor.submit(process_single_file, i, files[i], ivs[i], time_capsoul): i
                        for i in range(total_files)
                    }

                    started_files = set()
                    last_sent_progress = {i: -1 for i in range(total_files)}
                    completed_count = 0

                    # Monitor progress and stream updates
                    while completed_count < total_files:
                        progress_event.wait(timeout=1.0)   # wakes immediately when set OR after 1s
                        progress_event.clear()


                        # Send progress updates
                        with progress_lock:
                            for file_index, progress_data in file_progress.items():
                                file_name = files[file_index].name

                                # Start message
                                if file_index not in started_files and progress_data['status'] != 'pending':
                                    yield f"data: Starting upload of {file_name}\n\n"
                                    started_files.add(file_index)

                                # Progress updates (only on change)
                                if (progress_data['status'] == 'processing' and 
                                    progress_data['progress'] != last_sent_progress[file_index]):
                                    yield f"data: {file_name} -> {progress_data['progress']}\n\n"
                                    last_sent_progress[file_index] = progress_data['progress']

                        # Check for completed futures
                        completed_futures = [f for f in future_to_index if f.done()]

                        for future in completed_futures:
                            try:
                                result_data = future.result(timeout=1)
                                
                                if result_data['media_file']:
                                    created_objects.append(result_data['media_file'])
                                else:
                                    upload_errors.append(result_data['result'])
                                    
                                results.append(result_data['result'])

                                file_name = result_data['result']['file']
                                if result_data['result']['status'] == 'success':
                                    yield f"data: {file_name} -> 100\n\n"
                                    yield f"data: {file_name} upload completed successfully\n\n"
                                else:
                                    error_msg = result_data['result'].get('error') or result_data['result'].get('errors', 'Upload failed')
                                    yield f"data: {file_name} upload failed: {json.dumps(error_msg)}\n\n"

                                del future_to_index[future]
                                completed_count += 1

                            except Exception as e:
                                logger.exception(f"Task completion error: {e}")
                                del future_to_index[future]
                                completed_count += 1

                        # Small delay to prevent CPU spinning
                        if completed_count < total_files:
                            time.sleep(0.1)

                # Check if any uploads failed
                if upload_errors:
                    logger.warning(f"{len(upload_errors)} of {total_files} uploads failed")
                    
                # Send final results
                yield f"data: FINAL_RESULTS::{json.dumps(results)}\n\n"

            except Exception as e:
                logger.exception(f"Critical error in upload stream: {e}")
                yield f"data: ERROR: Upload process failed: {str(e)}\n\n"
                # Optionally cleanup on catastrophic failure
                # cleanup_on_failure()

            
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


class SetTimeCapSoulCover(SecuredView):
    "Set as time-capsoul cover"
   
    def patch(self, request,  media_file_id, capsoul_id):
        """Move media file from one TimeCapsoul to another"""
        user = self.get_current_user(request)
        time_capsoul = get_object_or_404(TimeCapSoul, id=capsoul_id)
        media_file = get_object_or_404(TimeCapSoulMediaFile, id=media_file_id)
        capsoul_template = time_capsoul.capsoul_template

        title = request.data.get('title', capsoul_template.name)
        summary = request.data.get('summary', capsoul_template.summary)
        set_as_cover = request.data.get('set_as_cover', None)
        cover_image = capsoul_template.cover_image
        print(f'\n Set As Cover media:{media_file_id} cap: {capsoul_id}')

        
        if time_capsoul.status == 'unlocked':
            # If status == unlocked create replica
            try:
                replica_instance = TimeCapSoul.objects.get(capsoul_replica_refrence = time_capsoul)
            except TimeCapSoul.DoesNotExist as e:
                # create custom template for replica
                template = CustomTimeCapSoulTemplate.objects.create(
                    name = title,
                    summary = summary,
                    cover_image = cover_image,
                    default_template = time_capsoul.capsoul_template.default_template,
                    slug = time_capsoul.capsoul_template.slug,
                    
                )
                template.slug = generate_unique_slug(replica_instance)
                replica_instance = TimeCapSoul.objects.create(
                                                            user = user,
                                                            capsoul_template=template,
                                                            status = 'created',
                                                            capsoul_replica_refrence = time_capsoul
                                                            )
            if bool(set_as_cover) == True:
                if media_file.file_type == 'image':
                    media_s3_key =  str(media_file.s3_key)
                    file_name = media_s3_key.split('/')[-1]
                    file_bytes,content_type = decrypt_and_get_image(media_s3_key)
                    s3_key, url = save_and_upload_decrypted_file(filename=file_name, decrypted_bytes=file_bytes, bucket='time-capsoul-files', content_type=content_type)
                    assets_obj = Assets.objects.create(image = media_file.file, s3_url=url, s3_key=s3_key)
                    template.cover_image = assets_obj
            
            # now create get or create media-file replica here
            try:
                media_file_replica = TimeCapSoulMediaFile.objects.get(time_capsoul=replica_instance, media_refrence_replica = media_file)
            except TimeCapSoulMediaFile.DoesNotExist:
                media_file_replica = TimeCapSoulMediaFile.objects.create(
                    user = user,
                    time_capsoul = replica_instance,
                    media_refrence_replica = media_file,
                    s3_key = media_file.s3_key,
                    file_size  = media_file.file_size,
                    file_type = media_file.file_type
                )
            except Exception as e:
                logger.exception('Exception while creating time-capsoul replica')
                pass 
        else:
            if user != time_capsoul.user:
                return Response(status=status.HTTP_400_BAD_REQUEST)
            
            if time_capsoul.capsoul_template.default_template is None and set_as_cover == True and media_file.is_cover_image == False:
                custom_template = time_capsoul.capsoul_template
                
                if title:
                    capsoul_template.name = title
                    
                if summary:
                    capsoul_template.summary = summary
                
                if bool(set_as_cover) == True:
                    if media_file.file_type == 'image':
                        file_bytes, content_type = get_media_file_bytes_with_content_type(media_file, user)
                        if not file_bytes or not content_type:
                            return Response(status=status.HTTP_500_INTERNAL_SERVER_ERROR)
                        s3_key, url = save_and_upload_decrypted_file(filename='', decrypted_bytes=file_bytes, bucket='time-capsoul-files', content_type=content_type)
                        assets_obj = Assets.objects.create(image = media_file.file, s3_url=url, s3_key=s3_key)
                        # custom_template = time_capsoul.capsoul_template
                        custom_template.cover_image = assets_obj
                        media_file.is_cover_image = True
                        media_file.save()
                        other_media = TimeCapSoulMediaFile.objects.filter(time_capsoul = time_capsoul, is_deleted=False, user = user).exclude(id = media_file_id)
                        other_media.update(is_cover_image = False)
                custom_template.save()
                
            else:
                return Response({'message': "Time can not be updated its default template or image already set as cover image"})


class MoveTimeCapSoulMediaFile(SecuredView):
    def post(self, request, old_cap_soul_id, media_file_id, new_capsoul_id):
        """Move media file from one TimeCapsoul to another"""
        user = self.get_current_user(request)

        old_time_capsoul = get_object_or_404(TimeCapSoul, id=old_cap_soul_id, user=user, is_deleted = False)
        new_time_capsoul = get_object_or_404(TimeCapSoul, id=new_capsoul_id, user=user, is_deleted = False)
        
        if old_time_capsoul.status == 'created' and new_time_capsoul.status == 'created':
            media_file = get_object_or_404(TimeCapSoulMediaFile, id=media_file_id, user=user, time_capsoul=old_time_capsoul)
            # Remove from old TimeCapsoul's related set
            # old_time_capsoul.details.media_files.remove(media_file)
            # Add to new TimeCapsoul's related set
            # new_time_capsoul.details.media_files.add(media_file)

            # Update the FK on media file
            media_file.time_capsoul = new_time_capsoul
            media_file.save()
            
            cache.delete(f'{user.email}_capsoul_{old_cap_soul_id}')
            cache.delete(f'{user.email}_capsoul_{new_capsoul_id}')
            print(f'\n Cached cleared at move ')
            

            return Response({'message': 'Media file moved successfully'}, status=200)
            
            
        # Prevent move if either source or destination is locked
        return Response({'message': 'Sorry, media file cannot be moved because either the source or destination TimeCapsoul is locked.'}, status=400)



class TimeCapSoulMediaFileUpdationView(SecuredView):

    def get_time_capsoul(self, user, time_capsoul_id):
        """
        Utility method to get a time-capsoul owned by the user.
        """
        return get_object_or_404(TimeCapSoul, id=time_capsoul_id, user=user, is_deleted = False)
    

    def delete(self, request, time_capsoul_id, media_file_id):
        """Delete time-capsoul media file"""
        from django.utils import timezone
        user = self.get_current_user(request)
        media_file = get_object_or_404(TimeCapSoulMediaFile, id=media_file_id)
        if user == media_file.user:
            if media_file.is_deleted == False:
                media_file.is_deleted = True
                media_file.save()
                
                time_capsoul = media_file.time_capsoul
                if time_capsoul.status == 'sealed':
                    capsoul_recipients = TimeCapSoulRecipient.objects.filter(time_capsoul = time_capsoul)
                    if capsoul_recipients.count() >0:
                        try:
                            existing_media_ids = eval(capsoul_recipients[0].parent_media_refrences)
                            if  existing_media_ids and  type(existing_media_ids) is list:
                                existing_media_ids.remove(media_file.id)
                                capsoul_recipients.update(parent_media_refrences = existing_media_ids)
                        except Exception as e:
                            logger.error(f'Error while updating parent media references list: {e} for user {user.email} and capsoul id {time_capsoul.id}')
        
                update_users_storage(
                    operation_type='remove',
                    media_updation='capsoul',
                    media_file=media_file
                )
                cache.delete(f'{user.email}_capsoul_{time_capsoul_id}')
                print(f'\n Media cached cleare at delete for cap: {time_capsoul_id}')
            return Response({'message': 'Time Capsoul media deleted successfully'})
        else:
            # check is tagged recipient checking here
            recipient = TimeCapSoulRecipient.objects.filter(time_capsoul = media_file.time_capsoul, email = user.email,is_deleted = False).first()
            if not recipient:
                logger.info("Recipient not found for tagged capsoul")
                return Response({"media_files": []}, status=status.HTTP_404_NOT_FOUND)
            
            # if time_capsoul.unlock_date and timezone.now() < time_capsoul.unlock_date:
            current_date = timezone.now()
            is_unlocked = (
                bool(media_file.time_capsoul.unlock_date) and current_date >= media_file.time_capsoul.unlock_date
            )
            # if (time_capsoul.unlock_date and current_date) and (current_date>= time_capsoul.unlock_date):
            if not is_unlocked:
                logger.info("Recipient not found for tagged capsoul")
                return Response({"media_files": []}, status=status.HTTP_404_NOT_FOUND)

            
            parent_files_id = get_recipient_capsoul_ids(recipient)
            if media_file_id not in parent_files_id:
                return Response(status=status.HTTP_400_BAD_REQUEST)
            
            # remove current media-id from parent media 
            try:
                parent_files_id.remove(media_file_id)
            except Exception as e:
                logger.error(f'Erorr while removing media id from parent list: {e} for user {user.email} and media_file_id {media_file_id}')
            else:
            #   recipient.parent_media_refrences  = ','.join(map(str, parent_files_id)) if parent_files_id else None
                recipient.parent_media_refrences  = parent_files_id if parent_files_id else []
                recipient.save()
                cache.delete(f'{user.email}_capsoul_{time_capsoul_id}')
                print(f'\n Media cached cleare at delete for cap: {time_capsoul_id}')
            return Response(status=status.HTTP_204_NO_CONTENT)
    
    def patch(self, request, time_capsoul_id, media_file_id):
        """Set As Cover """
        user = self.get_current_user(request)
        media_file = get_object_or_404(TimeCapSoulMediaFile, id=media_file_id)
        serializer = TimeCapsoulMediaFileUpdationSerializer(instance = media_file, data=request.data, partial = True, context={'is_owner': True if media_file.user == user else False, 'current_user': user})
        serializer.is_valid(raise_exception=True)
        update_media_file = serializer.save()
        cache.delete(f'{user.email}_capsoul_{media_file.time_capsoul.id}')
        cache.delete(f'{user.email}_capsouls')
        return Response(TimeCapSoulMediaFileReadOnlySerializer(update_media_file).data)



from memory_room.upload_helper import (
    ChunkedUploadSession,truncate_filename, s3, kms, AWS_KMS_KEY_ID
    )

executor = ThreadPoolExecutor(max_workers=10)

from memory_room.jpg_images_handler import (
    is_image_corrupted,try_fix_corrupted_jpg, opencv_repair_jpg, force_repair_jpeg, reencode_jpg
)


import uuid
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend

# class ChunkedMediaFileUploadView(APIView):
#     CACHE_PREFIX = "chunked_upload"
#     SESSION_TIMEOUT = 3600
#     MAX_CHUNK_SIZE = 50 * 1024 * 1024


#     def save_session(self, session):
#         session.last_activity = time.time()
#         cache.set(
#             self._key(session.upload_id), 
#             json.dumps(session.to_dict()), 
#             self.SESSION_TIMEOUT
#         )

    
#     def _key(self, upload_id):
#         return f"{self.CACHE_PREFIX}:{upload_id}"



#     def post(self, request, time_capsoul_id,action):
#         """
#         Handle chunked uploads with progress tracking.
#         Supports init, upload, complete, and abort actions.
#         """
#         # action = request.POST.get('action')
#         # user = self.get_current_user(request)
#         time_capsoul = get_object_or_404(TimeCapSoul, id=time_capsoul_id)
#         user = time_capsoul.user
        
#         # Handle replica creation for unlocked capsouls
#         replica_instance = self._handle_replica_creation(user, time_capsoul)
#         if replica_instance:
#             time_capsoul = replica_instance
        
#         # Route to appropriate handler based on action
#         if action == "init":
#             return self.initialize_uploads(request, user, time_capsoul)
#         elif action == "upload":
#             return self.upload_chunk(request, user)
#         elif action == "complete":
#             return self.complete_upload(request, user)
#         elif action == "abort":
#             return self.abort_upload(request, user)
#         else:
#             return JsonResponse({"error": "Invalid action"}, status=400)

#     def _handle_replica_creation(self, user, time_capsoul):
#         """Handle replica creation for unlocked capsouls"""
#         replica_instance = None
        
#         if time_capsoul.status == "sealed":
#             from django.utils import timezone
#             unlock_date = time_capsoul.unlock_date
#             current_datetime = timezone.now()
            
#             if unlock_date and current_datetime > unlock_date:
#                 time_capsoul.status = 'unlocked'
#                 time_capsoul.save()
        
#         if time_capsoul.status == 'unlocked':
#             try:
#                 replica_instance = create_time_capsoul(
#                     old_time_capsoul=time_capsoul,
#                     current_user=user,
#                     option_type='replica_creation',
#                 )
#                 cache.delete(f'{user.email}_capsouls')
#                 logger.info(f'Cached cleared for Capsoul at replica creation')
                
#                 # Copy parent media files
#                 if user.id == time_capsoul.user.id:
#                     parent_media_files = TimeCapSoulMediaFile.objects.filter(
#                         time_capsoul=time_capsoul, 
#                         is_deleted=False
#                     ).order_by('-updated_at')
#                 else:
#                     recipient = TimeCapSoulRecipient.objects.filter(
#                         time_capsoul=time_capsoul, 
#                         email=user.email
#                     ).first()
                    
#                     if not recipient:
#                         logger.info(f"Recipient not found for tagged capsoul {time_capsoul.id} and user {user.email}")
#                         return None
                    
#                     parent_files_id = get_recipient_capsoul_ids(recipient)
#                     parent_media_files = TimeCapSoulMediaFile.objects.filter(
#                         time_capsoul=time_capsoul,
#                         id__in=parent_files_id,
#                     ).order_by('-updated_at')
                
#                 new_media_count = 0
#                 old_media_count = parent_media_files.count()
                
#                 for parent_file in parent_media_files:
#                     try:
#                         is_media_created = create_time_capsoul_media_file(
#                             old_media=parent_file,
#                             new_capsoul=replica_instance,
#                             current_user=user,
#                             option_type='replica_creation',
#                         )
#                         if is_media_created:
#                             new_media_count += 1
#                     except Exception as e:
#                         logger.exception(f'Exception while creating media-file replica for media-file id {parent_file.id}')
#                         pass
                
#                 logger.info(f"Replica created: Old media count: {old_media_count}, New media count: {new_media_count}")
                
#             except Exception as e:
#                 logger.error(f'Exception while creating time-capsoul replica user {user.email} capsoul-id: {replica_instance.id} errors: {e}')
        
#         return replica_instance

#     def _extract_thumbnail_async(self, media_id, s3_key, file_type, file_ext, user_id):
#         """Async thumbnail extraction to reduce response time"""
#         try:
#             from memory_room.upload_helper import extract_thumbnail_from_segment
#             from memory_room.upload_helper import extract_audio_thumbnail_from_bytes

#             media = TimeCapSoulMediaFile.objects.get(id=media_id)

#             decryptor = S3MediaDecryptor(s3_key)
#             file_bytes = decryptor.get_full_decrypted_bytes()
#             cache_key = media_cache_key('media_bytes_', s3_key)
#             if file_bytes:
#                 cache.set(cache_key, file_bytes, timeout=60*60*24)

#             thumbnail_data = None
            
#             if file_type == 'video':
#                 thumbnail_data = extract_thumbnail_from_segment(file_bytes, file_ext, "full_file")
#             else:
#                 extractor = MediaThumbnailExtractor(file='', file_ext=file_ext)
#                 thumbnail_data = extractor.extract_audio_thumbnail_from_bytes(
#                     extension=file_ext,
#                     decrypted_bytes=file_bytes
#                 )
                
#                 if not thumbnail_data:
#                     thumbnail_data = extract_audio_thumbnail_from_bytes(
#                         extension=file_ext,
#                         audio_bytes=file_bytes,
#                     )

#             if thumbnail_data:
#                 from django.core.files.base import ContentFile
#                 from userauth.models import Assets
                
#                 image_file = ContentFile(
#                     thumbnail_data, 
#                     name=f"thumbnail_{media.title.split('.')[0]}.jpg"
#                 )
#                 if image_file:
#                     asset = Assets.objects.create(image=image_file, asset_types='TimeCapsoul/Thumbnail/Audio')
#                     media.thumbnail = asset
#                     media.save()
#                     logger.info(f'Thumbnail updated for media: {media.id}')
#                     print(f'Thumbnail updated for media: {media.id}')

#         except Exception as e:
#             logger.error(f'Async thumbnail extraction failed for media {media_id}: {e}')

    
#     def _key(self, upload_id):
#         return f"{self.CACHE_PREFIX}:{upload_id}"

#     def get_session(self, upload_id):
#         data = cache.get(self._key(upload_id))
#         return ChunkedUploadSession.from_dict(json.loads(data)) if data else None

#     def save_session(self, session):
#         session.last_activity = time.time()
#         cache.set(
#             self._key(session.upload_id), 
#             json.dumps(session.to_dict()), 
#             self.SESSION_TIMEOUT
#         )

#     def delete_session(self, upload_id):
#         cache.delete(self._key(upload_id))

#     def post(self, request, time_capsoul_id, action):
#         time_capsoul = get_object_or_404(TimeCapSoul, id=time_capsoul_id)
#         user = time_capsoul.user


#         if action == "init":
#             return self.initialize_uploads(request, user, time_capsoul)
#         if action == "upload":
#             return self.upload_chunk(request, user)
#         if action == "complete":
#             return self.complete_upload(request, user)
#         if action == "abort":
#             return self.abort_upload(request, user)

#         return JsonResponse({"error": "Invalid action"}, status=400)

#     def initialize_uploads(self, request, user, time_capsoul):
#         """Initialize multiple file uploads at once"""
#         try:
#             files_data = json.loads(request.POST.get("filesData", "[]"))
            
#             if not files_data:
#                 return JsonResponse({"error": "No files provided"}, status=400)
            
#             initialized_files = []
            
#             for file_data in files_data:
#                 file_name = file_data["fileName"]
#                 file_size = int(file_data["fileSize"])
#                 total_chunks = int(file_data["totalChunks"])
#                 chunk_size = int(file_data["chunkSize"])
                
#                 clean_name = clean_filename(truncate_filename(file_name))
#                 file_type = get_file_category(clean_name)
                
#                 if file_type == "invalid":
#                     raise ValidationError({
#                         "file_type": f"Unsupported file type: {file_name}"
#                     })
                
#                 upload_id = str(uuid.uuid4())
#                 file_ext = os.path.splitext(clean_name)[1].lower()

#                 s3_key = generate_capsoul_media_s3_key(
#                     clean_name, 
#                     user.s3_storage_id, 
#                     time_capsoul.id, 
#                     upload_id=upload_id
#                 )

#                 session = ChunkedUploadSession(
#                     upload_id,
#                     user.id,
#                     time_capsoul.id,
#                     file_name,
#                     file_size,
#                     file_type,
#                     total_chunks,
#                     chunk_size,
#                     s3_key,
#                 )

#                 # Generate encryption key
#                 key = kms.generate_data_key(KeyId=AWS_KMS_KEY_ID, KeySpec="AES_256")
#                 session.data_key_plain = key["Plaintext"]
#                 session.data_key_encrypted = key["CiphertextBlob"]
#                 session.aesgcm = AESGCM(session.data_key_plain)
                
#                 # Check if file is JPG/JPEG
#                 session.is_jpg = file_ext in ('.jpg', '.jpeg')
#                 session.file_ext = file_ext
                
#                 if session.is_jpg:
#                     # Create temporary storage for decrypted JPG chunks
#                     session.jpg_chunks_key = f"jpg_chunks:{upload_id}"
#                     cache.set(session.jpg_chunks_key, json.dumps([]), self.SESSION_TIMEOUT)

#                 # Start multipart upload
#                 mp = s3.create_multipart_upload(
#                     Bucket=MEDIA_FILES_BUCKET,
#                     Key=s3_key,
#                     Metadata={
#                         "edk": base64.b64encode(session.data_key_encrypted).decode(),
#                         'chunk_size': str(chunk_size),
#                         'file_size': str(file_size),
#                         'totalChunks': str(total_chunks),
#                     },
#                 )
#                 session.s3_upload_id = mp["UploadId"]

#                 self.save_session(session)

#                 initialized_files.append({
#                     "uploadId": upload_id,
#                     "fileName": file_name,
#                     "s3Key": s3_key,
#                     "totalChunks": total_chunks,
#                     "isJpg": session.is_jpg
#                 })

#             return JsonResponse({
#                 "files": initialized_files,
#                 "message": f"{len(initialized_files)} file(s) initialized successfully"
#             })

#         except Exception as e:
#             logger.exception(f"Init uploads failed: {e}")
#             return JsonResponse({"error": str(e)}, status=500)

#     def upload_chunk(self, request, user):
#         """Upload chunk - handles JPG differently by storing decrypted chunks"""
#         upload_id = request.POST.get("uploadId")
#         chunk_index = int(request.POST.get("chunkIndex", -1))
#         chunk_file = request.FILES.get("chunk")
#         iv = request.POST.get("iv")

#         lock_key = f"lock:{upload_id}:{chunk_index}"
#         if not cache.add(lock_key, "1", 10):
#             return JsonResponse({"error": "Chunk upload in progress"}, status=429)

#         try:
#             session = self.get_session(upload_id)
#             if not session:
#                 return JsonResponse({"error": "Session expired"}, status=404)

#             # Check for duplicate
#             with session.lock:
#                 if chunk_index in session.uploaded_chunks:
#                     uploaded_chunks = len(session.uploaded_chunks)
#                     # For JPG files, chunk upload is only 50% of total progress
#                     if session.is_jpg:
#                         percentage = (uploaded_chunks / session.total_chunks) * 50
#                     else:
#                         percentage = (uploaded_chunks / session.total_chunks) * 100
                    
#                     return JsonResponse({
#                         "status": "duplicate",
#                         "uploadId": upload_id,
#                         "uploadedChunks": uploaded_chunks,
#                         "totalChunks": session.total_chunks,
#                         "percentage": round(percentage, 2)
#                     })

#             # Decrypt chunk
#             decrypted = self._decrypt_chunk(chunk_file, iv)
            
#             if session.is_jpg:
#                 # For JPG files, store decrypted chunks temporarily
#                 jpg_chunks_data = json.loads(cache.get(session.jpg_chunks_key, '[]'))
                
#                 # Store chunk with index for proper reconstruction
#                 jpg_chunks_data.append({
#                     'index': chunk_index,
#                     'data': base64.b64encode(decrypted).decode('utf-8')
#                 })
                
#                 cache.set(session.jpg_chunks_key, json.dumps(jpg_chunks_data), self.SESSION_TIMEOUT)
                
#                 # Update session
#                 with session.lock:
#                     session.uploaded_chunks.add(chunk_index)
                
#                 self.save_session(session)
                
#                 uploaded_chunks = len(session.uploaded_chunks)
#                 # For JPG: Chunk reception is 50% of progress
#                 percentage = (uploaded_chunks / session.total_chunks) * 50
                
#                 return JsonResponse({
#                     "status": "uploaded",
#                     "uploadId": upload_id,
#                     "uploadedChunks": uploaded_chunks,
#                     "totalChunks": session.total_chunks,
#                     "percentage": round(percentage, 2),
#                     "isJpg": True,
#                     "stage": "receiving"
#                 })
#             else:
#                 # For non-JPG files, encrypt and upload to S3 immediately
#                 encrypted = self._encrypt_for_s3(decrypted, session.aesgcm)

#                 part_no = chunk_index + 1
#                 resp = s3.upload_part(
#                     Bucket=MEDIA_FILES_BUCKET,
#                     Key=session.s3_key,
#                     UploadId=session.s3_upload_id,
#                     PartNumber=part_no,
#                     Body=encrypted,
#                 )

#                 with session.lock:
#                     session.s3_parts[str(part_no)] = resp["ETag"]
#                     session.uploaded_chunks.add(chunk_index)
                
#                 self.save_session(session)

#                 uploaded_chunks = len(session.uploaded_chunks)
#                 percentage = (uploaded_chunks / session.total_chunks) * 100

#                 return JsonResponse({
#                     "status": "uploaded",
#                     "uploadId": upload_id,
#                     "uploadedChunks": uploaded_chunks,
#                     "totalChunks": session.total_chunks,
#                     "percentage": round(percentage, 2)
#                 })

#         except Exception as e:
#             logger.exception(f"Error uploading chunk {chunk_index}: {e}")
#             return JsonResponse({"error": str(e)}, status=500)
#         finally:
#             cache.delete(lock_key)

#     def complete_upload(self, request, user):
#         """Complete a single file upload or multiple files"""
#         upload_ids = request.POST.getlist("uploadIds[]") or [request.POST.get("uploadId")]
        
#         if not upload_ids or not upload_ids[0]:
#             return JsonResponse({"error": "No upload IDs provided"}, status=400)

#         completed_files = []
#         failed_files = []

#         for upload_id in upload_ids:
#             try:
#                 result = self._complete_single_upload(upload_id, user)
#                 if result["status"] == "success":
#                     completed_files.append(result)
#                 else:
#                     failed_files.append({"uploadId": upload_id, "error": result.get("error")})
#             except Exception as e:
#                 logger.exception(f"Complete upload failed for {upload_id}: {e}")
#                 failed_files.append({"uploadId": upload_id, "error": str(e)})

#         response_data = {
#             "completedFiles": completed_files,
#             "failedFiles": failed_files,
#             "totalCompleted": len(completed_files),
#             "totalFailed": len(failed_files)
#         }

#         if failed_files:
#             response_data["message"] = f"{len(completed_files)} file(s) completed, {len(failed_files)} failed"
#             return JsonResponse(response_data, status=207)
        
#         response_data["message"] = f"All {len(completed_files)} file(s) completed successfully"
#         return JsonResponse(response_data)

#     def _complete_single_upload(self, upload_id, user):
#         """Complete a single file upload"""
#         session = self.get_session(upload_id)

#         if not session:
#             return {"status": "error", "error": "Session missing", "uploadId": upload_id}

#         if len(session.uploaded_chunks) != session.total_chunks:
#             return {
#                 "status": "error",
#                 "error": f"Incomplete upload: {len(session.uploaded_chunks)}/{session.total_chunks} chunks",
#                 "uploadId": upload_id
#             }

#         try:
#             if session.is_jpg:
#                 # Process JPG file: check corruption, fix if needed, then upload
#                 # This represents the remaining 50% of progress
#                 result = self._process_jpg_file(session, user, upload_id)
#                 if result["status"] == "error":
#                     return result
#             else:
#                 # Complete multipart upload for non-JPG files
#                 if len(session.s3_parts) != session.total_chunks:
#                     return {
#                         "status": "error",
#                         "error": f"Incomplete S3 upload: {len(session.s3_parts)}/{session.total_chunks} parts",
#                         "uploadId": upload_id
#                     }
                
#                 parts = [
#                     {"PartNumber": int(p), "ETag": et}
#                     for p, et in session.s3_parts.items()
#                 ]
#                 parts.sort(key=lambda x: x["PartNumber"])

#                 s3.complete_multipart_upload(
#                     Bucket=MEDIA_FILES_BUCKET,
#                     Key=session.s3_key,
#                     UploadId=session.s3_upload_id,
#                     MultipartUpload={"Parts": parts},
#                 )

#             # Create database record
#             time_capsoul = TimeCapSoul.objects.get(id=session.time_capsoul_id)
            
#             from memory_room.utils import get_readable_file_size_from_bytes
#             file_size = get_readable_file_size_from_bytes(session.file_size)

#             media = TimeCapSoulMediaFile.objects.create(
#                 user=user,
#                 time_capsoul=time_capsoul,
#                 thumbnail=None,
#                 title=session.file_name,
#                 file_size=file_size,
#                 s3_key=session.s3_key,
#                 file_type=session.file_type
#             )

#             # Clear cache
#             cache_key = f'{user.email}_capsoul_{time_capsoul.id}'
#             cache.delete(cache_key)
            
#             if session.is_jpg:
#                 cache.delete(session.jpg_chunks_key)

#             # Async thumbnail extraction for video/audio
#             if session.file_type in ['video', 'audio']:
#                 self._extract_thumbnail_async(
#                     media.id,
#                     session.s3_key,
#                     session.file_type,
#                     session.file_ext,
#                     user.id
#                 )

#             update_users_storage("addition", "capsoul", media)
#             self.delete_session(upload_id)

#             return {
#                 "status": "success",
#                 "uploadId": upload_id,
#                 "id": media.id,
#                 "fileName": session.file_name
#             }

#         except Exception as e:
#             logger.exception(f"Error completing upload {upload_id}: {e}")
#             return {
#                 "status": "error",
#                 "error": str(e),
#                 "uploadId": upload_id
#             }

#     def _update_jpg_progress(self, upload_id, percentage, stage):
#         """Helper to update JPG processing progress in cache"""
#         progress_key = f"jpg_progress:{upload_id}"
#         cache.set(progress_key, {
#             "percentage": percentage,
#             "stage": stage,
#             "timestamp": time.time()
#         }, 300)  # 5 minutes TTL

#     def _process_jpg_file(self, session, user, upload_id):
#         """Process JPG file: check corruption, fix if needed, then upload"""
#         try:
#             logger.info(f"[JPG] Processing {session.file_name}...")
            
#             # Progress: 50% (chunks received) → 55% (reconstructing)
#             self._update_jpg_progress(upload_id, 52, "reconstructing")
            
#             # Retrieve all decrypted chunks
#             jpg_chunks_data = json.loads(cache.get(session.jpg_chunks_key, '[]'))
            
#             if not jpg_chunks_data:
#                 return {"status": "error", "error": "No JPG chunks found"}
            
#             # Sort chunks by index
#             jpg_chunks_data.sort(key=lambda x: x['index'])
            
#             # Reconstruct full file bytes
#             original_bytes = b''.join([
#                 base64.b64decode(chunk['data']) 
#                 for chunk in jpg_chunks_data
#             ])
            
#             logger.info(f"[JPG] Reconstructed {len(original_bytes)} bytes for {session.file_name}")
            
#             # Progress: 55% → 65% (checking/fixing)
#             self._update_jpg_progress(upload_id, 65, "checking")
            
#             # Check and fix JPG corruption
#             final_bytes = self._check_and_fix_jpg(original_bytes, session.file_name, upload_id)
            
#             # Progress: 65% → 100% (uploading to S3)
#             self._update_jpg_progress(upload_id, 75, "uploading")
            
#             # Now encrypt and upload the final bytes in chunks
#             self._upload_processed_jpg(final_bytes, session, upload_id)
            
#             # Progress: 100%
#             self._update_jpg_progress(upload_id, 100, "complete")
            
#             logger.info(f"[JPG] Successfully processed and uploaded {session.file_name}")
#             return {"status": "success"}
            
#         except Exception as e:
#             logger.exception(f"JPG processing failed: {e}")
#             return {"status": "error", "error": f"JPG processing failed: {str(e)}"}

#     def _check_and_fix_jpg(self, original_bytes, file_name, upload_id):
#         """Check JPG corruption and fix if needed"""
#         logger.info(f"[JPG] Checking corruption for {file_name}...")
        
#         if not is_image_corrupted(original_bytes):
#             logger.info(f"[JPG] File is valid, no repair needed")
#             self._update_jpg_progress(upload_id, 70, "valid")
#             return original_bytes
        
#         logger.warning(f"[JPG] Corruption detected, attempting repair...")
#         self._update_jpg_progress(upload_id, 67, "repairing_pillow")
        
#         # Try Pillow repair
#         repaired = try_fix_corrupted_jpg(original_bytes)
#         if repaired:
#             logger.info(f"[JPG] Repaired with Pillow")
#             self._update_jpg_progress(upload_id, 70, "repaired_pillow")
#             return repaired
        
#         # Try OpenCV repair
#         logger.info(f"[JPG] Pillow failed, trying OpenCV...")
#         self._update_jpg_progress(upload_id, 68, "repairing_opencv")
#         cv_fixed = opencv_repair_jpg(original_bytes)
#         if cv_fixed:
#             logger.info(f"[JPG] Repaired with OpenCV")
#             self._update_jpg_progress(upload_id, 70, "repaired_opencv")
#             return cv_fixed
        
#         # Try extreme header rebuild
#         logger.info(f"[JPG] OpenCV failed, trying extreme repair...")
#         self._update_jpg_progress(upload_id, 69, "repairing_extreme")
#         extreme_fix = force_repair_jpeg(original_bytes)
#         if extreme_fix:
#             logger.info(f"[JPG] Repaired with extreme method")
#             self._update_jpg_progress(upload_id, 70, "repaired_extreme")
#             return extreme_fix
        
#         # Last resort: re-encode
#         logger.warning(f"[JPG] All repairs failed, attempting re-encode...")
#         self._update_jpg_progress(upload_id, 69, "reencoding")
#         try:
#             final_bytes = reencode_jpg(original_bytes)
#             logger.info(f"[JPG] Successfully re-encoded")
#             self._update_jpg_progress(upload_id, 70, "reencoded")
#             return final_bytes
#         except Exception as e:
#             logger.error(f"[JPG] Re-encoding failed: {e}")
#             raise Exception(f"Image totally unrecoverable: {str(e)}")

#     def _upload_processed_jpg(self, file_bytes, session, upload_id):
#         """Upload processed JPG file to S3 in encrypted chunks"""
#         logger.info(f"[JPG] Uploading {len(file_bytes)} bytes to S3...")
        
#         # Split into chunks and upload
#         chunk_size = session.chunk_size
#         total_bytes = len(file_bytes)
#         total_parts = (total_bytes + chunk_size - 1) // chunk_size
#         part_number = 1
        
#         for i in range(0, total_bytes, chunk_size):
#             chunk_data = file_bytes[i:i + chunk_size]
            
#             # Encrypt chunk for S3
#             encrypted = self._encrypt_for_s3(chunk_data, session.aesgcm)
            
#             # Upload part
#             resp = s3.upload_part(
#                 Bucket=MEDIA_FILES_BUCKET,
#                 Key=session.s3_key,
#                 UploadId=session.s3_upload_id,
#                 PartNumber=part_number,
#                 Body=encrypted,
#             )
            
#             session.s3_parts[str(part_number)] = resp["ETag"]
            
#             # Update progress: 75% → 95% during upload
#             upload_progress = 75 + (part_number / total_parts) * 20
#             self._update_jpg_progress(upload_id, upload_progress, "uploading_s3")
            
#             part_number += 1
        
#         # Progress: 95% → 100% (completing)
#         self._update_jpg_progress(upload_id, 95, "completing")
        
#         # Complete multipart upload
#         parts = [
#             {"PartNumber": int(p), "ETag": et}
#             for p, et in session.s3_parts.items()
#         ]
#         parts.sort(key=lambda x: x["PartNumber"])
        
#         s3.complete_multipart_upload(
#             Bucket=MEDIA_FILES_BUCKET,
#             Key=session.s3_key,
#             UploadId=session.s3_upload_id,
#             MultipartUpload={"Parts": parts},
#         )
        
#         logger.info(f"[JPG] Upload completed with {len(parts)} parts")

#     def abort_upload(self, request, user):
#         """Abort single or multiple uploads"""
#         upload_ids = request.POST.getlist("uploadIds[]") or [request.POST.get("uploadId")]
        
#         aborted_count = 0
#         for upload_id in upload_ids:
#             if not upload_id:
#                 continue
                
#             session = self.get_session(upload_id)
#             if session:
#                 try:
#                     s3.abort_multipart_upload(
#                         Bucket=MEDIA_FILES_BUCKET,
#                         Key=session.s3_key,
#                         UploadId=session.s3_upload_id,
#                     )
#                 except Exception as e:
#                     logger.error(f"Failed to abort S3 upload {upload_id}: {e}")

#                 # Clean up JPG chunks if applicable
#                 if session.is_jpg:
#                     cache.delete(session.jpg_chunks_key)
#                     cache.delete(f"jpg_progress:{upload_id}")

#                 self.delete_session(upload_id)
#                 aborted_count += 1

#         return JsonResponse({
#             "status": "aborted",
#             "count": aborted_count
#         })

#     def _decrypt_chunk(self, chunk_file, iv_str):
#         """Decrypt chunk using AES-256-GCM"""
#         try:
#             if all(c in "0123456789abcdefABCDEF" for c in iv_str.strip()):
#                 iv = bytes.fromhex(iv_str)
#             else:
#                 iv = base64.b64decode(iv_str)
#         except Exception as e:
#             raise ValueError(f"Invalid IV format: {e}")

#         key_bytes = settings.ENCRYPTION_KEY
#         if isinstance(key_bytes, str):
#             key_bytes = base64.b64decode(key_bytes)

#         encrypted_data = chunk_file.read()

#         if len(encrypted_data) < 16:
#             raise ValueError("Encrypted chunk too short")

#         ciphertext = encrypted_data[:-16]
#         auth_tag = encrypted_data[-16:]

#         cipher = Cipher(
#             algorithms.AES(key_bytes),
#             modes.GCM(iv, auth_tag),
#             backend=default_backend()
#         )
#         decryptor = cipher.decryptor()
#         decrypted = decryptor.update(ciphertext) + decryptor.finalize()

#         return decrypted

#     def _encrypt_for_s3(self, data, aesgcm):
#         if aesgcm is None:
#             raise RuntimeError("AESGCM is not initialized")

#         nonce = os.urandom(12)
#         ciphertext = aesgcm.encrypt(nonce, data, None)
#         return nonce + ciphertext

from memory_room.upload_helper import extract_thumbnail_from_segment


class ChunkedMediaFileUploadView(SecuredView):
    
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
    
    def create_time_capsoul_replica(self, request, time_capsoul):
        """Create a replica of the time capsoul if it's unlocked"""
        replica_instance = time_capsoul
        # user = time_capsoul.user
        user = self.get_current_user(request)
        if time_capsoul.status == 'unlocked':
            try:
                replica_instance = create_time_capsoul(
                    old_time_capsoul = time_capsoul, # create time-capsoul replica
                    current_user = user,
                    option_type = 'replica_creation',
                )
                cache.delete(f'{user.email}_capsouls')
                print(f'\n ----- Cached cleared for Capsoul at replica creation ---- ')
    
                if user.id == time_capsoul.user.id: # if user is owner of the capsoul
                    parent_media_files = TimeCapSoulMediaFile.objects.filter(time_capsoul = time_capsoul, is_deleted = False).order_by('-updated_at')
                else:
                    recipient = TimeCapSoulRecipient.objects.filter(time_capsoul = time_capsoul, email = user.email).first()
                    if not recipient:
                        logger.info(f"Recipient not found for tagged capsoul for {time_capsoul.id} and user {user.email}")
                        return Response(status=status.HTTP_404_NOT_FOUND)
                    else:
                        # parent_files_id = (
                        #     [int(i.strip()) for i in recipient.parent_media_refrences.split(',') if i.strip().isdigit()]
                        #     if recipient.parent_media_refrences else []
                        # )
                        parent_files_id =  get_recipient_capsoul_ids(recipient)
                        parent_media_files = TimeCapSoulMediaFile.objects.filter(
                            time_capsoul=time_capsoul,
                            id__in = parent_files_id,
                        ).order_by('-updated_at')
                new_media_count = 0
                old_media_count = parent_media_files.count() 
                for parent_file in parent_media_files:
                    try:
                        is_media_created = create_time_capsoul_media_file(
                            old_media=parent_file,
                            new_capsoul=replica_instance,
                            current_user = user,
                            option_type = 'replica_creation',
                        )
                    except Exception as e:
                        logger.exception(F'Exception while creating time-capsoul media-file replica for media-file id {parent_file.id} and user {user.email}')
                        pass
                    else:
                        if is_media_created:
                            new_media_count += 1
                print(f"Old media count: {old_media_count}, New media count: {new_media_count}")
            except Exception as e:
                logger.error(f'Exception while creating time-capsoul replica user {user.email} capsoul-id: {time_capsoul.id} errors: {e}')
        return replica_instance
    
    def post(self, request, time_capsoul_id, action):
        time_capsoul = get_object_or_404(TimeCapSoul, id=time_capsoul_id)
        replica_instance = self.create_time_capsoul_replica(request, time_capsoul)
        user = self.get_current_user(request)
        if action == "init":
            return self.initialize_uploads(request, user, time_capsoul)
        if action == "upload":
            return self.upload_chunk(request, user)
        if action == "complete":
            # Use streaming for completion
            return self.complete_upload_streaming(request, user)
        if action == "abort":
            return self.abort_upload(request, user)

        return JsonResponse({"error": "Invalid action"}, status=400)

    def initialize_uploads(self, request, user, time_capsoul):
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

                s3_key = generate_capsoul_media_s3_key(
                    clean_name, 
                    user.s3_storage_id, 
                    time_capsoul.id, 
                    upload_id=upload_id
                )

                session = ChunkedUploadSession(
                    upload_id,
                    user.id,
                    time_capsoul.id,
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
                            'percentage': round(percent, 2)
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
                        'percentage': round(percent, 2)
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
                    'percentage': round(percent, 2)
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

            # ---------- CREATE DB RECORD ----------
            yield {
                "uploadId": upload_id,
                "stage": "creating_record",
                "percentage": 92 if session.file_type in ["video", "audio"] else 98
            }

            time_capsoul = TimeCapSoul.objects.get(id=session.time_capsoul_id)
            
            from memory_room.utils import get_readable_file_size_from_bytes
            file_size = get_readable_file_size_from_bytes(session.file_size)

            media = TimeCapSoulMediaFile.objects.create(
                user=user,
                time_capsoul=time_capsoul,
                thumbnail=None,
                title=session.file_name,
                file_size=file_size,
                s3_key=session.s3_key,
                file_type=session.file_type
            )
            if media.time_capsoul.status == 'sealed':
                capsoul_recipients = TimeCapSoulRecipient.objects.filter(
                    time_capsoul=media.time_capsoul
                )
                
                if capsoul_recipients.exists():
                    try:
                        recipient = capsoul_recipients.first()
                        existing_media_ids = eval(recipient.parent_media_refrences) if recipient.parent_media_refrences else []
                        
                        if isinstance(existing_media_ids, list):
                            existing_media_ids.append(media.id)
                            capsoul_recipients.update(parent_media_refrences=str(existing_media_ids))
                    except Exception as e:
                        logger.error(f'Error updating parent media refs: {e} for user {user.email}, capsoul {time_capsoul.id}')

            # clear cache 
            cache.delete(f'{user.email}_capsoul_{media.time_capsoul.id}')
            cache.delete(f'{user.email}_capsouls')



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

            update_users_storage("addition", "capsoul", media)

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

    # def _upload_processed_file_streaming(self, file_bytes, session, upload_id):
    #     """Upload processed file to S3 with streaming progress"""
    #     logger.info(f"[UPLOAD] Uploading {len(file_bytes)} bytes to S3...")
        
    #     yield {"uploadId": upload_id, "stage": "encrypting_chunks", "percentage": 74}
        
    #     # Split into chunks and upload
    #     chunk_size = session.chunk_size
    #     total_bytes = len(file_bytes)
    #     total_parts = (total_bytes + chunk_size - 1) // chunk_size
    #     part_number = 1
        
    #     for i in range(0, total_bytes, chunk_size):
    #         chunk_data = file_bytes[i:i + chunk_size]
            
    #         # Encrypt chunk for S3
    #         encrypted = self._encrypt_for_s3(chunk_data, session.aesgcm)
            
    #         # Upload part
    #         resp = s3.upload_part(
    #             Bucket=MEDIA_FILES_BUCKET,
    #             Key=session.s3_key,
    #             UploadId=session.s3_upload_id,
    #             PartNumber=part_number,
    #             Body=encrypted,
    #         )
            
    #         session.s3_parts[str(part_number)] = resp["ETag"]
            
    #         # Stream progress: 75% → 88% during upload
    #         upload_progress = 75 + (part_number / total_parts) * 13
    #         yield {"uploadId": upload_id, "stage": "uploading_s3", "percentage": round(upload_progress, 2)}
            
    #         part_number += 1
        
    #     yield {"uploadId": upload_id, "stage": "completing_s3", "percentage": 90}
        
    #     # Complete multipart upload
    #     parts = [
    #         {"PartNumber": int(p), "ETag": et}
    #         for p, et in session.s3_parts.items()
    #     ]
    #     parts.sort(key=lambda x: x["PartNumber"])
        
    #     s3.complete_multipart_upload(
    #         Bucket=MEDIA_FILES_BUCKET,
    #         Key=session.s3_key,
    #         UploadId=session.s3_upload_id,
    #         MultipartUpload={"Parts": parts},
    #     )
        
    #     logger.info(f"[UPLOAD] Upload completed with {len(parts)} parts")
    #     yield {"uploadId": upload_id, "stage": "upload_complete", "percentage": 93}
    
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
            
            yield {"uploadId": upload_id, "stage": "downloading_for_thumbnail", "percentage": 95}
            
            media = TimeCapSoulMediaFile.objects.get(id=media_id)

            decryptor = S3MediaDecryptor(s3_key)
            file_bytes = decryptor.get_full_decrypted_bytes()
            
            
            cache_key = media_cache_key('media_bytes_', s3_key)
            if file_bytes:
                cache.set(cache_key, file_bytes, timeout=60*60*24)

            thumbnail_data = None
            
            yield {"uploadId": upload_id, "stage": "processing_thumbnail", "percentage": 97}
            
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
                media.thumbnail = asset
                media.save()
                logger.info(f'Thumbnail updated for media: {media.id}')
                print(f'Thumbnail updated for media: {media.id}')
                
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




class TimeCapSoulUnlockView(SecuredView):

    def post(self, request, time_capsoul_id):
        user = self.get_current_user(request)
        try:
            time_capsoul = TimeCapSoul.objects.get(
                id=time_capsoul_id,
                user=user,
                is_deleted = False
            )
        except TimeCapSoul.DoesNotExist:
            return Response({"error": "TimeCapsoul not found."}, status=status.HTTP_404_NOT_FOUND)

        serializer = TimeCapsoulUnlockSerializer(
            instance=time_capsoul,
            data=request.data,
            partial=True  
        )

        if serializer.is_valid():
            serializer.save()
            cache_key = f'{user.email}_capsouls'
            cache.delete(cache_key)

            return Response({"message": "TimeCapsoul locked successfully."}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)



class RecipientsDetailCreateOrUpdateView(SecuredView):
    """
    Handles GET, POST, and PUT for TimeCapSoul Recipients.
    """

    def get(self, request, time_capsoul_id):
        """
        Retrieve all recipients for a given TimeCapSoul.
        """
        user = self.get_current_user(request)
        time_capsoul = get_object_or_404(TimeCapSoul, id=time_capsoul_id, user=user)
        capsoul_recipients = TimeCapSoulRecipient.objects.filter(time_capsoul=time_capsoul)
        data  = TimeCapSoulRecipientSerializer(capsoul_recipients, many=True).data
        return Response(data)
        
    def post(self, request, time_capsoul_id):
        """
        Create a new RecipientsDetail for a given TimeCapSoul.
        """
        user = self.get_current_user(request)
        time_capsoul = get_object_or_404(TimeCapSoul, id=time_capsoul_id, user=user)

        serializer = RecipientsDetailSerializer(data=request.data, context={'time_capsoul': time_capsoul})
        if serializer.is_valid():
            serializer.save()
            return Response(status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def put(self, request, time_capsoul_id):
        """
        Update the recipients of an existing RecipientsDetail for a given TimeCapSoul.
        """
        user = self.get_current_user(request)
        time_capsoul = get_object_or_404(TimeCapSoul, id=time_capsoul_id, user=user)
        recipients_detail = get_object_or_404(RecipientsDetail, time_capsoul=time_capsoul)

        serializer = RecipientsDetailSerializer(recipients_detail, data=request.data, context={'time_capsoul': time_capsoul})
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class TimeCapsoulMediaFileFilterView(SecuredView):

    def get(self, request):
        user = self.get_current_user(request)
        query_params = request.query_params

        time_capsoul_id = query_params.get('time_capsoul_id')
        if not time_capsoul_id:
            raise ValidationError({'time_capsoul_id': 'TimeCapsoul ID is required.'})

        file_type = query_params.get('file_type')
        if file_type and file_type not in dict(FILE_TYPES).keys():
            raise ValidationError({
                'file_type': f"'{file_type}' is not valid. Allowed: {', '.join(dict(FILE_TYPES).keys())}"
            })

        # Filter conditions
        media_filters = {
            key: value for key, value in {
                'time_capsoul__id': time_capsoul_id,
                'file_type': file_type,
                'description__icontains': query_params.get('description'),
                'title__icontains': query_params.get('title'),
                'user': user,
                'created_at__date': query_params.get('date'),
            }.items() if value is not None
        }

        queryset = TimeCapSoulMediaFile.objects.filter(**media_filters)

        # Sorting logic
        sort_by = query_params.get('sort_by')        # alphabetical / upload_date
        sort_order = query_params.get('sort_order')  # asc / desc

        if sort_by == 'alphabetical':
            sort_field = 'title'
        else:
            sort_field = 'created_at'

        if sort_order == 'asc':
            queryset = queryset.order_by(sort_field)
        else:
            queryset = queryset.order_by(f'-{sort_field}')

        # Pagination
        paginator = PageNumberPagination()
        paginator.page_size = 8
        paginated_queryset = paginator.paginate_queryset(queryset, request)

        serializer = TimeCapSoulMediaFileReadOnlySerializer(paginated_queryset, many=True)
        return paginator.get_paginated_response({'media_files': serializer.data})



class TimeCapsoulFilterView(SecuredView):

    def get(self, request):
        user = self.get_current_user(request)
        query_params = request.query_params

        # Filter conditions
        timecap_soul_filters = {
            key: value for key, value in {
                'user': user,
                'status': query_params.get('status'),
                'created_at__date': query_params.get('date'),
            }.items() if value is not None
        }

        queryset = TimeCapSoul.objects.filter(**timecap_soul_filters)

        # Sorting logic
        sort_by = query_params.get('sort_by')        # alphabetical / upload_date
        sort_order = query_params.get('sort_order')  # asc / desc

        if sort_by == 'alphabetical':
            sort_field = 'title'
        else:
            sort_field = 'created_at'

        if sort_order == 'asc':
            queryset = queryset.order_by(sort_field)
        else:
            queryset = queryset.order_by(f'-{sort_field}')

        # Pagination
        paginator = PageNumberPagination()
        paginator.page_size = 8
        paginated_queryset = paginator.paginate_queryset(queryset, request)

        serializer = TimeCapSoulSerializer(paginated_queryset, many=True, context={'user': user})
        return paginator.get_paginated_response({'time_capsoul': serializer.data})


SECRET = settings.SECRET_KEY.encode()

# class ServeTimeCapSoulMedia(SecuredView):
#     """
#     Securely serve decrypted media from S3 via Django.
#     """
#     def get(self, request, s3_key, media_file_id=None):
#         exp = request.GET.get("exp")
#         sig = request.GET.get("sig")
#         user = self.get_current_user(request)
#         from django.utils import timezone

#         if not exp or not sig:
#             return Response(status=status.HTTP_404_NOT_FOUND)

#         if int(exp) < int(time.time()):
#             return Response(status=status.HTTP_404_NOT_FOUND)
        
#         if user is None:
#             return Response(status=status.HTTP_401_UNAUTHORIZED)
#         try:
#             # check time-capsoul user ownership
#             media_file = TimeCapSoulMediaFile.objects.get(id=media_file_id, user=user)
#         except TimeCapSoulMediaFile.DoesNotExist:
#             # check time-capsoul tagged-list
#             try:
#                 media_file = TimeCapSoulMediaFile.objects.get(id=media_file_id)
#             except Exception as e:
#                 return Response(status=status.HTTP_404_NOT_FOUND)
#             else:
#                 #  signature-verification
#                 if not verify_signature(media_file.s3_key, exp, sig):
#                     return Response(status=status.HTTP_404_NOT_FOUND)
                
#                 time_capsoul = media_file.time_capsoul
                
#             capsoul_recipients = TimeCapSoulRecipient.objects.filter(time_capsoul=time_capsoul, email = user.email).first()
#             if not capsoul_recipients:
#                 return Response(status=status.HTTP_404_NOT_FOUND)
            
#             # if (media_file.time_capsoul.unlock_date and timezone.now()) and (timezone.now() >= time_capsoul.unlock_date):
#             #     logger.info("Recipient not found for tagged capsoul")
#             #     return Response({"media_files": []}, status=status.HTTP_404_NOT_FOUND)

#             current_date = timezone.now()
#             is_unlocked = (
#                 bool(time_capsoul.unlock_date) and current_date >= time_capsoul.unlock_date
#             )
#             # if (time_capsoul.unlock_date and current_date) and (current_date>= time_capsoul.unlock_date):
#             if not is_unlocked:
#                 logger.info("Recipient not found for tagged capsoul")
#                 return Response({"media_files": []}, status=status.HTTP_404_NOT_FOUND)



#         except Exception:
#             return Response(status=status.HTTP_404_NOT_FOUND)

#         bytes_cache_key = media_file.s3_key
#         # file_bytes = cache.get(bytes_cache_key)
        
#         # content_type_cache_key = f'{bytes_cache_key}_type'
#         # content_type = cache.get(content_type_cache_key)
        
#         # if not file_bytes or  not content_type:
#         #     try:
#         #         file_bytes, content_type = decrypt_and_get_image(str(media_file.s3_key))
#         #     except Exception as e:
#         #         file_bytes, content_type  = decrypt_and_replicat_files(str(media_file.s3_key))
#         #     except Exception as e:
#         #         return Response(status=status.HTTP_404_NOT_FOUND)
#         #     else:
#         #         # caching here
#         #         cache.set(bytes_cache_key, file_bytes, timeout=60*60)  
#         #         cache.set(content_type_cache_key, content_type, timeout=60*60)
        
#         media_type = media_file.file_type # example image, 
        
#         file_bytes, content_type = get_media_file_bytes_with_content_type(media_file, user)
#         if not file_bytes or not content_type:
#             return Response(status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
        

                
#         if media_file.s3_key.lower().endswith(".doc"):
#             try:
                
#                 docx_bytes_cache_key = f'{bytes_cache_key}_docx_preview'
#                 docx_bytes = cache.get(docx_bytes_cache_key)
                
#                 if not docx_bytes:
#                     docx_bytes = convert_doc_to_docx_bytes(file_bytes, media_file_id=media_file.id, email=user.email)
#                     cache.set(docx_bytes_cache_key, docx_bytes, timeout=60*60*2)  
                    
#                 response = HttpResponse(
#                     docx_bytes,
#                     content_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document"
#                 )
#                 frame_ancestors = " ".join(settings.CORS_ALLOWED_ORIGINS)
#                 response["Content-Security-Policy"] = f"frame-ancestors 'self' {frame_ancestors};"
#                 response["Content-Disposition"] = f'inline; filename="{media_file.s3_key.split("/")[-1].replace(".doc", ".docx")}"'
#                 return response
                
#             except Exception as e:
#                 logger.error(f'Exception while generating docx for doc files as {e}')
#                 return Response(status=status.HTTP_500_INTERNAL_SERVER_ERROR)
#         else:
#             if media_file.s3_key.lower().endswith(".heic")  or media_file.s3_key.lower().endswith(".heif"):
#                 jpeg_cache_key = f'{bytes_cache_key}_jpeg'
#                 jpeg_file_bytes = cache.get(jpeg_cache_key)
#                 if not jpeg_file_bytes:
#                     jpeg_file_bytes, content_type = convert_heic_to_jpeg_bytes(file_bytes)
#                     cache.set(jpeg_cache_key, jpeg_file_bytes, timeout=60*60*2)
#                 response = HttpResponse(jpeg_file_bytes, content_type="image/jpeg")
#                 response["Content-Disposition"] = (
#                     f'inline; filename="{media_file.s3_key.split("/")[-1].replace(".heic", ".jpg")}"'
#                 )
#                 return response
            
#             elif media_file.s3_key.lower().endswith(".mkv"):
#                 cache_key = f'{bytes_cache_key}_mp4'
#                 mp4_bytes = cache.get(cache_key)
#                 if not mp4_bytes:
#                     try:
#                         mp4_bytes, content_type = convert_mkv_to_mp4_bytes(file_bytes)
#                         content_type = "video/mp4"
#                         cache.set(cache_key, mp4_bytes, timeout=60*60*2)
#                     except Exception as e:
#                         logger.error(f"MKV conversion failed: {e} for {user.email} media-id: {media_file.id}")
#                         return Response(status=status.HTTP_500_INTERNAL_SERVER_ERROR)

#                 download_name = media_file.s3_key.split("/")[-1]
#                 download_name = download_name.replace(".mkv", ".mp4")
#                 response = HttpResponse(mp4_bytes, content_type="mp4")
#                 frame_ancestors = " ".join(settings.CORS_ALLOWED_ORIGINS)
#                 response["Content-Security-Policy"] = f"frame-ancestors 'self' {frame_ancestors};"
#                 response["Content-Disposition"] = f'inline; filename="{download_name}"'
#                 return response

#             else:
#                 # 🔹 All other files
#                 response = HttpResponse(file_bytes, content_type=content_type)
#                 frame_ancestors = " ".join(settings.CORS_ALLOWED_ORIGINS)
#                 response["Content-Security-Policy"] = f"frame-ancestors 'self' {frame_ancestors};"
#                 response["Content-Disposition"] = f'inline; filename="{media_file.s3_key.split("/")[-1]}"'
#                 return response


# previous one
# class ServeTimeCapSoulMedia(SecuredView):
#     """
#     Securely serve decrypted media from S3 via Django.
#     Streaming responses for all files with lazy loading for audio/video.
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

#     def _stream_file_with_range(self, request, file_bytes, content_type, filename):
#         """Stream bytes with HTTP range support for audio/video."""
#         file_size = len(file_bytes)
#         range_header = request.headers.get("Range", "").strip()
        
#         if range_header:
#             import re
#             range_match = re.match(r"bytes=(\d+)-(\d*)", range_header)
#             if range_match:
#                 start = int(range_match.group(1))
#                 end = int(range_match.group(2)) if range_match.group(2) else file_size - 1
#                 length = end - start + 1
                
#                 resp = StreamingHttpResponse(
#                     FileWrapper(BytesIO(file_bytes[start:end+1]), 8192),
#                     status=206,
#                     content_type=content_type
#                 )
#                 resp["Content-Range"] = f"bytes {start}-{end}/{file_size}"
#                 resp["Content-Length"] = str(length)
#             else:
#                 resp = StreamingHttpResponse(
#                     FileWrapper(BytesIO(file_bytes), 8192),
#                     content_type=content_type
#                 )
#                 resp["Content-Length"] = str(file_size)
#         else:
#             resp = StreamingHttpResponse(
#                 FileWrapper(BytesIO(file_bytes), 8192),
#                 content_type=content_type
#             )
#             resp["Content-Length"] = str(file_size)
        
#         resp["Accept-Ranges"] = "bytes"
#         resp["Content-Disposition"] = f'inline; filename="{filename}"'
#         frame_ancestors = " ".join(settings.CORS_ALLOWED_ORIGINS)
#         resp["Content-Security-Policy"] = f"frame-ancestors 'self' {frame_ancestors};"
#         return resp

#     def get(self, request, s3_key, media_file_id=None):
#         exp = request.GET.get("exp")
#         sig = request.GET.get("sig")
        
#         if not exp or not sig:
#             return Response(status=status.HTTP_404_NOT_FOUND)

#         if int(exp) < int(time.time()):
#             return Response(status=status.HTTP_404_NOT_FOUND)

#         user = self.get_current_user(request)
#         if user is None:
#             return Response(status=status.HTTP_401_UNAUTHORIZED)

#         # Optimize: Only get s3_key and file_type from DB (minimal data)
#         try:
#             media_file = TimeCapSoulMediaFile.objects.only('s3_key', 'file_type', 'user_id', 'time_capsoul_id').select_related('time_capsoul').get(
#                 id=media_file_id, user=user
#             )
#         except TimeCapSoulMediaFile.DoesNotExist:
#             try:
#                 media_file = TimeCapSoulMediaFile.objects.only('s3_key', 'file_type', 'user_id', 'time_capsoul_id').select_related('time_capsoul').get(
#                     id=media_file_id
#                 )
#             except TimeCapSoulMediaFile.DoesNotExist:
#                 return Response(status=status.HTTP_404_NOT_FOUND)
            
#             if not verify_signature(media_file.s3_key, exp, sig):
#                 return Response(status=status.HTTP_404_NOT_FOUND)
            
#             time_capsoul = media_file.time_capsoul
#             capsoul_recipients = TimeCapSoulRecipient.objects.filter(
#                 time_capsoul=time_capsoul, email=user.email
#             ).first()
            
#             if not capsoul_recipients:
#                 return Response(status=status.HTTP_404_NOT_FOUND)

#             from django.utils import timezone
#             current_date = timezone.now()
#             is_unlocked = (
#                 bool(time_capsoul.unlock_date) and current_date >= time_capsoul.unlock_date
#             )
#             if not is_unlocked:
#                 logger.info("Recipient not found for tagged capsoul")
#                 return Response({"media_files": []}, status=status.HTTP_404_NOT_FOUND)

#         s3_key = media_file.s3_key
#         filename = s3_key.split("/")[-1]
#         file_ext = s3_key.lower()
        
#         # Check if it's an image first - fast path for images
#         is_image = file_ext.endswith(('.jpg', '.jpeg', '.png', '.gif', '.bmp', '.webp', '.svg'))
#         is_svg = file_ext.endswith('.svg')
        
        
#         # Cache decrypted file bytes to avoid repeated S3 calls
#         bytes_cache_key = f"media_bytes_{s3_key}"
        
#         cached_data = cache.get(bytes_cache_key)
#         if cached_data:
#             file_bytes, content_type = cached_data
#         else:
#             file_bytes, content_type = decrypt_s3_file_chunked(s3_key)
#             if not file_bytes or not content_type:
#                 return Response(status=status.HTTP_500_INTERNAL_SERVER_ERROR)
#             # Cache the decrypted bytes for future requests
#             cache.set(bytes_cache_key, (file_bytes, content_type), timeout=self.CACHE_TIMEOUT)
        
#         # For images, try cache first before any processing
#         if is_image or is_svg:
        
#             # SVG gets special secure handling
#             if is_svg:
#                 return self._serve_svg_safely(file_bytes, filename)
#             # Direct response for cached images - fastest path
#             response = HttpResponse(file_bytes, content_type=content_type)
#             response["Content-Length"] = str(len(file_bytes))
#             response["Content-Disposition"] = f'inline; filename="{filename}"'
#             response["Cache-Control"] = "private, max-age=3600"
#             response["X-Content-Type-Options"] = "nosniff"
#             frame_ancestors = " ".join(settings.CORS_ALLOWED_ORIGINS)
#             response["Content-Security-Policy"] = f"frame-ancestors 'self' {frame_ancestors};"
#             return response
        
#         # Handle DOC to DOCX conversion with caching
#         if file_ext.endswith(".doc"):
#             docx_cache_key = f'{bytes_cache_key}_docx_preview'
#             docx_bytes = cache.get(docx_cache_key)
#             if not docx_bytes:
#                 docx_bytes = convert_doc_to_docx_bytes(file_bytes, media_file_id=media_file.id, email=user.email)
#                 cache.set(docx_cache_key, docx_bytes, timeout=self.CACHE_TIMEOUT)
#             return self._stream_file_with_range(
#                 request, docx_bytes, 
#                 "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
#                 filename.replace(".doc", ".docx")
#             )
        
#         # Handle HEIC to JPEG conversion with caching
#         elif file_ext.endswith((".heic", ".heif")):
#             jpeg_cache_key = f'{bytes_cache_key}_jpeg'
#             jpeg_file_bytes = cache.get(jpeg_cache_key)
#             if not jpeg_file_bytes:
#                 jpeg_file_bytes, content_type = convert_heic_to_jpeg_bytes(file_bytes)
#                 cache.set(jpeg_cache_key, jpeg_file_bytes, timeout=self.CACHE_TIMEOUT)
#             # Fast HttpResponse for converted images
#             resp = HttpResponse(jpeg_file_bytes, content_type="image/jpeg")
#             resp["Content-Length"] = str(len(jpeg_file_bytes))
#             resp["Content-Disposition"] = f'inline; filename="{filename.replace(".heic", ".jpg").replace(".heif", ".jpg")}"'
#             resp["Cache-Control"] = "private, max-age=3600"
#             frame_ancestors = " ".join(settings.CORS_ALLOWED_ORIGINS)
#             resp["Content-Security-Policy"] = f"frame-ancestors 'self' {frame_ancestors};"
#             return resp

#         # Handle MKV to MP4 conversion with caching
#         elif file_ext.endswith(".mkv"):
#             mp4_cache_key = f'{bytes_cache_key}_mp4'
#             mp4_bytes = cache.get(mp4_cache_key)
#             if not mp4_bytes:
#                 try:
#                     mp4_bytes, content_type = convert_mkv_to_mp4_bytes(file_bytes)
#                     cache.set(mp4_cache_key, mp4_bytes, timeout=self.CACHE_TIMEOUT)
#                 except Exception as e:
#                     logger.error(f"MKV conversion failed: {e} for {user.email} media-id: {media_file.id}")
#                     return Response(status=status.HTTP_500_INTERNAL_SERVER_ERROR)
#             return self._stream_file_with_range(
#                 request, mp4_bytes, "video/mp4",
#                 filename.replace(".mkv", ".mp4")
#             )

#         # Stream all other files (video/audio/images/documents)
#         return self._stream_file_with_range(request, file_bytes, content_type, filename)

# current one 
# class ServeTimeCapSoulMedia(SecuredView):
#     """
#     Securely serve decrypted media from S3 via Django.
#     Streaming responses for all files with lazy loading for audio/video.
#     """
    
#     CACHE_TIMEOUT = 60 * 60 * 24  # 2 hours
    
#     def _guess_content_type(self, filename):
#         """Guess content type from filename extension for better browser compatibility."""
#         import mimetypes
#         content_type, _ = mimetypes.guess_type(filename)
        
#         lower_filename = filename.lower()
#         if lower_filename.endswith(('.mp4', '.m4v')):
#             return 'video/mp4'
#         elif lower_filename.endswith('.webm'):
#             return 'video/webm'
#         elif lower_filename.endswith('.mov'):
#             return 'video/quicktime'
#         elif lower_filename.endswith(('.mkv', '.avi', '.flv', '.wmv')):
#             return 'video/mp4'
#         elif lower_filename.endswith('.mp3'):
#             return 'audio/mpeg'
#         elif lower_filename.endswith(('.m4a', '.aac')):
#             return 'audio/mp4'
#         elif lower_filename.endswith('.wav'):
#             return 'audio/wav'
#         elif lower_filename.endswith('.flac'):
#             return 'audio/flac'
#         elif lower_filename.endswith(('.ogg', '.opus')):
#             return 'audio/ogg'
#         elif lower_filename.endswith('.wma'):
#             return 'audio/x-ms-wma'
#         elif lower_filename.endswith('.svg'):
#             return 'image/svg+xml'
#         elif lower_filename.endswith('.pdf'):
#             return 'application/pdf'
#         elif lower_filename.endswith(('.doc', '.docx')):
#             return 'application/vnd.openxmlformats-officedocument.wordprocessingml.document'
        
#         return content_type or 'application/octet-stream'
    
#     def _serve_svg_safely(self, file_bytes, filename):
#         """Serve SVG files with proper security headers to prevent XSS."""
#         response = HttpResponse(file_bytes, content_type="image/svg+xml")
#         response["Content-Length"] = str(len(file_bytes))
#         response["Content-Disposition"] = "inline"
#         response["Cache-Control"] = "private, max-age=3600"
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
#         """Stream decrypted media file with proper Range support (seekable, inline playback)."""
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
#         status_code = 206 if is_partial else 200

#         # Use guessed content type
#         content_type = self._guess_content_type(filename)

#         # Use HttpResponse for non-partial, StreamingHttpResponse only for Range requests
#         if is_partial:
#             resp = StreamingHttpResponse(
#                 FileWrapper(BytesIO(file_bytes[start:end + 1]), 8192),
#                 status=status_code,
#                 content_type=content_type,
#             )
#         else:
#             # For direct access without Range, use HttpResponse (cacheable and inline)
#             resp = HttpResponse(
#                 file_bytes,
#                 status=status_code,
#                 content_type=content_type,
#             )

#         # Critical headers for inline playback
#         resp["Accept-Ranges"] = "bytes"
#         resp["Content-Length"] = str(length)
#         resp["Content-Disposition"] = "inline"
#         resp["X-Content-Type-Options"] = "nosniff"

#         if is_partial:
#             resp["Content-Range"] = f"bytes {start}-{end}/{file_size}"

#         # CORS + security
#         resp["Cross-Origin-Resource-Policy"] = "cross-origin"
#         resp["Access-Control-Allow-Origin"] = "*"
#         resp["Access-Control-Expose-Headers"] = "Accept-Ranges, Content-Range, Content-Length"
#         resp["Cache-Control"] = "private, max-age=3600"
        
#         frame_ancestors = " ".join(settings.CORS_ALLOWED_ORIGINS)
#         resp["Content-Security-Policy"] = f"media-src *; frame-ancestors 'self' {frame_ancestors};"

#         return resp
    
#     def _create_inline_response(self, file_bytes, content_type, filename):
#         """Create a standard inline response for non-streaming files."""
#         response = HttpResponse(file_bytes, content_type=content_type)
#         response["Content-Length"] = str(len(file_bytes))
#         response["Content-Disposition"] = "inline"
#         response["Cache-Control"] = "private, max-age=3600"
#         response["X-Content-Type-Options"] = "nosniff"
#         frame_ancestors = " ".join(settings.CORS_ALLOWED_ORIGINS)
#         response["Content-Security-Policy"] = f"frame-ancestors 'self' {frame_ancestors};"
#         return response

#     def get(self, request, s3_key, media_file_id=None):
#         exp = request.GET.get("exp")
#         sig = request.GET.get("sig")
        
#         if not exp or not sig:
#             return Response(status=status.HTTP_404_NOT_FOUND)

#         if int(exp) < int(time.time()):
#             return Response(status=status.HTTP_404_NOT_FOUND)

#         user = self.get_current_user(request)
#         if user is None:
#             return Response(status=status.HTTP_401_UNAUTHORIZED)

#         # Optimize: Only get s3_key and file_type from DB (minimal data)
#         try:
#             media_file = TimeCapSoulMediaFile.objects.only('s3_key', 'file_type', 'user_id', 'time_capsoul_id').select_related('time_capsoul').get(
#                 id=media_file_id, user=user
#             )
#         except TimeCapSoulMediaFile.DoesNotExist:
#             try:
#                 media_file = TimeCapSoulMediaFile.objects.only('s3_key', 'file_type', 'user_id', 'time_capsoul_id').select_related('time_capsoul').get(
#                     id=media_file_id
#                 )
#             except TimeCapSoulMediaFile.DoesNotExist:
#                 return Response(status=status.HTTP_404_NOT_FOUND)
            
#             if not verify_signature(media_file.s3_key, exp, sig):
#                 return Response(status=status.HTTP_404_NOT_FOUND)
            
#             time_capsoul = media_file.time_capsoul
#             capsoul_recipients = TimeCapSoulRecipient.objects.filter(
#                 time_capsoul=time_capsoul, email=user.email
#             ).first()
            
#             if not capsoul_recipients:
#                 return Response(status=status.HTTP_404_NOT_FOUND)

#             from django.utils import timezone
#             current_date = timezone.now()
#             is_unlocked = (
#                 bool(time_capsoul.unlock_date) and current_date >= time_capsoul.unlock_date
#             )
#             if not is_unlocked:
#                 logger.info("Recipient not found for tagged capsoul")
#                 return Response({"media_files": []}, status=status.HTTP_404_NOT_FOUND)

#         s3_key = media_file.s3_key
#         filename = s3_key.split("/")[-1]
#         file_ext = s3_key.lower()
#         extension = s3_key.lower().split('/')[-1].split('.')[-1]
        
#         # Check file types
#         is_image = file_ext.endswith(('.jpg', '.jpeg', '.png', '.gif', '.bmp', '.webp'))
#         is_svg = file_ext.endswith('.svg')
#         is_video = self._is_video_file(filename)
#         is_audio = self._is_audio_file(filename)
#         is_doc = file_ext.endswith('.doc')
#         is_heic = file_ext.endswith(('.heic', '.heif'))
#         is_mkv = file_ext.endswith('.mkv')
#         is_avi = file_ext.endswith('.avi')
#         is_wmv = file_ext.endswith('.wmv')

        

        
#         # Cache decrypted file bytes to avoid repeated S3 calls
#         bytes_cache_key = f"media_bytes_{s3_key}"
#         cached_data = cache.get(bytes_cache_key)
        
#         if cached_data:
#             file_bytes, original_content_type = cached_data
#         else:
#             file_bytes, original_content_type = decrypt_s3_file_chunked(s3_key)
#             if not file_bytes or not original_content_type:
#                 return Response(status=status.HTTP_500_INTERNAL_SERVER_ERROR)
#             # Cache the decrypted bytes for future requests
#             cache.set(bytes_cache_key, (file_bytes, original_content_type), timeout=self.CACHE_TIMEOUT)
        
#         # Guess better content type from filename
#         content_type = self._guess_content_type(filename)
        
#         # Handle special conversions
#         if is_doc:
#             docx_cache_key = f'{bytes_cache_key}_docx_preview'
#             docx_bytes = cache.get(docx_cache_key)
#             if not docx_bytes:
#                 docx_bytes = convert_doc_to_docx_bytes(file_bytes, media_file_id=media_file.id, email=user.email)
#                 cache.set(docx_cache_key, docx_bytes, timeout=self.CACHE_TIMEOUT)
            
#             file_bytes = docx_bytes
#             content_type = "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
#             filename = filename.replace(".doc", ".docx")
        
#         elif is_heic:
#             jpeg_cache_key = f'{bytes_cache_key}_jpeg'
#             jpeg_file_bytes = cache.get(jpeg_cache_key)
#             if not jpeg_file_bytes:
#                 jpeg_file_bytes, _ = convert_heic_to_jpeg_bytes(file_bytes)
#                 cache.set(jpeg_cache_key, jpeg_file_bytes, timeout=self.CACHE_TIMEOUT)
            
#             file_bytes = jpeg_file_bytes
#             content_type = "image/jpeg"
#             filename = filename.replace(".heic", ".jpg").replace(".heif", ".jpg")
        
#         elif is_mkv or is_wmv or is_avi:
#             mp4_cache_key = f'{bytes_cache_key}_mp4'
#             mp4_bytes = cache.get(mp4_cache_key)
#             if not mp4_bytes:
#                 try:
#                     # mp4_bytes, _ = convert_mkv_to_mp4_bytes(file_bytes)
#                     mp4_bytes, _ = convert_video_to_mp4_bytes(
#                         source_format = f'.{extension}',
#                         file_bytes = file_bytes
#                     )
#                     cache.set(mp4_cache_key, mp4_bytes, timeout=self.CACHE_TIMEOUT)
#                 except Exception as e:
#                     logger.error(f"MKV conversion failed: {e} for {user.email} media-id: {media_file.id}")
#                     return Response(status=status.HTTP_500_INTERNAL_SERVER_ERROR)
            
#             file_bytes = mp4_bytes
#             content_type = "video/mp4"
#             if is_mkv:
#                 filename = filename.replace(".mkv", ".mp4")
#             elif is_wmv:
#                 filename = filename.replace(".wmv", ".mp4")
#             else:
#                 filename = filename.replace(".avi", ".mp4")
                
        
#         # Return appropriate response based on file type
#         if is_svg:
#             return self._serve_svg_safely(file_bytes, filename)
#         elif is_video or is_audio:
#             # This handles both direct access and Range requests properly
#             return self._stream_file_with_range(request, file_bytes, content_type, filename)
#         else:
#             # All other files (PDFs, images, documents, etc.)
#             return self._create_inline_response(file_bytes, content_type, filename)

# better one
# class ServeTimeCapSoulMedia(SecuredView):
#     """
#     Securely serve decrypted media from S3 via Django.
#     Streaming responses for all files with lazy loading for audio/video.
#     """
    
#     CACHE_TIMEOUT = 60 * 60 * 24  # 24 hours
#     STREAMING_CHUNK_SIZE = 64 * 1024  # 64KB chunks
    
#     def _guess_content_type(self, filename):
#         """Guess content type from filename extension for better browser compatibility."""
#         import mimetypes
#         content_type, _ = mimetypes.guess_type(filename)
        
#         lower_filename = filename.lower()
        
#         # Quick lookup for common types
#         type_map = {
#             # Video
#             '.mp4': 'video/mp4', '.m4v': 'video/mp4', '.webm': 'video/webm',
#             '.mov': 'video/quicktime', '.mkv': 'video/mp4', '.avi': 'video/mp4',
#             '.flv': 'video/mp4', '.wmv': 'video/mp4',
#             # Audio
#             '.mp3': 'audio/mpeg', '.m4a': 'audio/mp4', '.aac': 'audio/mp4',
#             '.wav': 'audio/wav', '.flac': 'audio/flac', '.ogg': 'audio/ogg',
#             '.opus': 'audio/ogg', '.wma': 'audio/x-ms-wma',
#             # Image
#             '.svg': 'image/svg+xml',
#             # Documents
#             '.pdf': 'application/pdf',
#             '.doc': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
#             '.docx': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
#         }
        
#         for ext, mime in type_map.items():
#             if lower_filename.endswith(ext):
#                 return mime
        
#         return content_type or 'application/octet-stream'
    
#     def _is_video_file(self, filename):
#         """Check if file is a video by extension."""
#         return filename.lower().endswith(('.mp4', '.mkv', '.webm', '.mov', '.avi', '.flv', '.wmv', '.m4v'))
    
#     def _is_audio_file(self, filename):
#         """Check if file is audio by extension."""
#         return filename.lower().endswith(('.mp3', '.m4a', '.aac', '.wav', '.flac', '.ogg', '.wma', '.opus'))

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
#             # For range requests, wrap bytes in FileWrapper
#             if isinstance(content, bytes):
#                 from wsgiref.util import FileWrapper
#                 from io import BytesIO
#                 content = FileWrapper(BytesIO(content), 8192)
            
#             response = StreamingHttpResponse(content, content_type=content_type)
#             if range_support and start > 0:
#                 response.status_code = 206
#         else:
#             response = HttpResponse(content, content_type=content_type)
        
#         # Set content length
#         if total_size:
#             length = (end - start + 1) if end else total_size
#             response["Content-Length"] = str(length)
#         elif not streaming and isinstance(content, bytes):
#             response["Content-Length"] = str(len(content))
        
#         # Range headers
#         if range_support:
#             response["Accept-Ranges"] = "bytes"
#             if start > 0 and end and total_size:
#                 response["Content-Range"] = f"bytes {start}-{end}/{total_size}"
        
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

#     def get(self, request, s3_key, media_file_id=None):
#         exp = request.GET.get("exp")
#         sig = request.GET.get("sig")
        
#         if not exp or not sig:
#             return Response(status=status.HTTP_404_NOT_FOUND)

#         if int(exp) < int(time.time()):
#             return Response(status=status.HTTP_404_NOT_FOUND)

#         user = self.get_current_user(request)
#         if user is None:
#             return Response(status=status.HTTP_401_UNAUTHORIZED)

#         # Optimize: Only get s3_key and file_type from DB (minimal data)
#         try:
#             media_file = TimeCapSoulMediaFile.objects.only('s3_key', 'file_type', 'user_id', 'time_capsoul_id').select_related('time_capsoul').get(
#                 id=media_file_id, user=user
#             )
#         except TimeCapSoulMediaFile.DoesNotExist:
#             try:
#                 media_file = TimeCapSoulMediaFile.objects.only('s3_key', 'file_type', 'user_id', 'time_capsoul_id').select_related('time_capsoul').get(
#                     id=media_file_id
#                 )
#             except TimeCapSoulMediaFile.DoesNotExist:
#                 return Response(status=status.HTTP_404_NOT_FOUND)
            
#             if not verify_signature(media_file.s3_key, exp, sig):
#                 return Response(status=status.HTTP_404_NOT_FOUND)
            
#             time_capsoul = media_file.time_capsoul
#             capsoul_recipients = TimeCapSoulRecipient.objects.filter(
#                 time_capsoul=time_capsoul, email=user.email
#             ).first()
            
#             if not capsoul_recipients:
#                 return Response(status=status.HTTP_404_NOT_FOUND)

#             from django.utils import timezone
#             current_date = timezone.now()
#             is_unlocked = (
#                 bool(time_capsoul.unlock_date) and current_date >= time_capsoul.unlock_date
#             )
#             if not is_unlocked:
#                 logger.info("Recipient not found for tagged capsoul")
#                 return Response({"media_files": []}, status=status.HTTP_404_NOT_FOUND)

#         s3_key = media_file.s3_key
#         filename = s3_key.split("/")[-1]
#         file_ext = s3_key.lower()
#         extension = s3_key.lower().split('/')[-1].split('.')[-1]
        
#         # Check file types
#         is_image = file_ext.endswith(('.jpg', '.jpeg', '.png', '.gif', '.bmp', '.webp'))
#         is_svg = file_ext.endswith('.svg')
#         is_video = self._is_video_file(filename)
#         is_audio = self._is_audio_file(filename)
#         is_doc = file_ext.endswith('.doc')
#         is_heic = file_ext.endswith(('.heic', '.heif'))
#         needs_conversion = file_ext.endswith(('.mkv', '.avi', '.wmv'))

#         # Cache decrypted file bytes to avoid repeated S3 calls
#         bytes_cache_key = f"media_bytes_{s3_key}"
#         cached_data = cache.get(bytes_cache_key)
        
#         if cached_data:
#             file_bytes, original_content_type = cached_data
#         else:
#             file_bytes, original_content_type = decrypt_s3_file_chunked(s3_key)
#             if not file_bytes or not original_content_type:
#                 return Response(status=status.HTTP_500_INTERNAL_SERVER_ERROR)
#             # Cache the decrypted bytes for future requests
#             cache.set(bytes_cache_key, (file_bytes, original_content_type), timeout=self.CACHE_TIMEOUT)
        
#         # Guess better content type from filename
#         content_type = self._guess_content_type(filename)
        
#         # Handle special conversions
#         if is_doc:
#             docx_cache_key = f'{bytes_cache_key}_docx_preview'
#             docx_bytes = cache.get(docx_cache_key)
#             if not docx_bytes:
#                 docx_bytes = convert_doc_to_docx_bytes(file_bytes, media_file_id=media_file.id, email=user.email)
#                 cache.set(docx_cache_key, docx_bytes, timeout=self.CACHE_TIMEOUT)
            
#             file_bytes = docx_bytes
#             content_type = "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
#             filename = filename.replace(".doc", ".docx")
        
#         elif is_heic:
#             jpeg_cache_key = f'{bytes_cache_key}_jpeg'
#             jpeg_file_bytes = cache.get(jpeg_cache_key)
#             if not jpeg_file_bytes:
#                 jpeg_file_bytes, _ = convert_heic_to_jpeg_bytes(file_bytes)
#                 cache.set(jpeg_cache_key, jpeg_file_bytes, timeout=self.CACHE_TIMEOUT)
            
#             file_bytes = jpeg_file_bytes
#             content_type = "image/jpeg"
#             filename = filename.replace(".heic", ".jpg").replace(".heif", ".jpg")
        
#         elif needs_conversion:
#             mp4_cache_key = f'{bytes_cache_key}_mp4'
#             mp4_bytes = cache.get(mp4_cache_key)
            
#             if not mp4_bytes:
#                 try:
#                     logger.info(f"Converting .{extension} to MP4 for {filename}")
#                     mp4_bytes, _ = convert_video_to_mp4_bytes(
#                         source_format=f'.{extension}',
#                         file_bytes=file_bytes
#                     )
#                     cache.set(mp4_cache_key, mp4_bytes, timeout=self.CACHE_TIMEOUT)
#                 except Exception as e:
#                     logger.error(f"Video conversion failed: {e} for {user.email} media-id: {media_file.id}")
#                     return Response(status=status.HTTP_500_INTERNAL_SERVER_ERROR)
            
#             file_bytes = mp4_bytes
#             content_type = "video/mp4"
#             filename = filename.rsplit('.', 1)[0] + '.mp4'
            
#             # After conversion, stream with range support
#             logger.info(f"Streaming converted MP4: {filename}")
#             file_size = len(file_bytes)
            
#             # Parse range header
#             start, end = 0, file_size - 1
#             range_header = request.headers.get("Range", "")
#             if range_header:
#                 import re
#                 m = re.match(r"bytes=(\d+)-(\d*)", range_header)
#                 if m:
#                     start = int(m.group(1))
#                     if m.group(2):
#                         end = int(m.group(2))
#                     end = min(end, file_size - 1)
            
#             is_partial = range_header != ""
            
#             # Return streaming response with range support
#             return self._create_response(
#                 file_bytes[start:end + 1],
#                 content_type, filename,
#                 streaming=is_partial, range_support=True,
#                 start=start, end=end, total_size=file_size
#             )
        
#         # Return appropriate response based on file type
#         if is_svg:
#             return self._create_response(file_bytes, content_type, filename)
#         elif is_video or is_audio:
#             # Stream with range support for video/audio
#             file_size = len(file_bytes)
            
#             # Parse range header
#             start, end = 0, file_size - 1
#             range_header = request.headers.get("Range", "")
#             if range_header:
#                 import re
#                 m = re.match(r"bytes=(\d+)-(\d*)", range_header)
#                 if m:
#                     start = int(m.group(1))
#                     if m.group(2):
#                         end = int(m.group(2))
#                     end = min(end, file_size - 1)
            
#             is_partial = range_header != ""
            
#             return self._create_response(
#                 file_bytes[start:end + 1],
#                 content_type, filename,
#                 streaming=is_partial, range_support=True,
#                 start=start, end=end, total_size=file_size
#             )
#         else:
#             # All other files (PDFs, images, documents, etc.)
#             return self._create_response(file_bytes, content_type, filename)

# best one 
# class ServeTimeCapSoulMedia(SecuredView):
#     """
#     Securely serve decrypted media from S3 via Django.
#     Streaming responses for all files with lazy loading for audio/video.
#     """
    
#     CACHE_TIMEOUT = 60 * 60 * 24  # 24 hours
#     STREAMING_CHUNK_SIZE = 64 * 1024  # 64KB chunks
    
#     def _guess_content_type(self, filename):
#         """Guess content type from filename extension for better browser compatibility."""
#         import mimetypes
#         content_type, _ = mimetypes.guess_type(filename)
        
#         lower_filename = filename.lower()
        
#         # Quick lookup for common types
#         type_map = {
#             # Video
#             '.mp4': 'video/mp4', '.m4v': 'video/mp4', '.webm': 'video/webm',
#             '.mov': 'video/quicktime', '.mkv': 'video/mp4', '.avi': 'video/mp4',
#             '.flv': 'video/mp4', '.wmv': 'video/mp4',
#             # Audio
#             '.mp3': 'audio/mpeg', '.m4a': 'audio/mp4', '.aac': 'audio/mp4',
#             '.wav': 'audio/wav', '.flac': 'audio/flac', '.ogg': 'audio/ogg',
#             '.opus': 'audio/ogg', '.wma': 'audio/x-ms-wma',
#             # Image
#             '.svg': 'image/svg+xml',
#             # Documents
#             '.pdf': 'application/pdf',
#             '.doc': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
#             '.docx': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
#         }
        
#         for ext, mime in type_map.items():
#             if lower_filename.endswith(ext):
#                 return mime
        
#         return content_type or 'application/octet-stream'
    
#     def _is_video_file(self, filename):
#         """Check if file is a video by extension."""
#         return filename.lower().endswith(('.mp4', '.mkv', '.webm', '.mov', '.avi', '.flv', '.wmv', '.m4v'))
    
#     def _is_audio_file(self, filename):
#         """Check if file is audio by extension."""
#         return filename.lower().endswith(('.mp3', '.m4a', '.aac', '.wav', '.flac', '.ogg', '.wma', '.opus'))
    
#     def _is_pdf_file(self, filename):
#         """Check if file is a PDF."""
#         return filename.lower().endswith('.pdf')
    
#     def _is_csv_file(self, filename):
#         """Check if file is a CSV."""
#         return filename.lower().endswith('.csv')
    
#     def _is_json_file(self, filename):
#         """Check if file is a JSON."""
#         return filename.lower().endswith('.json')

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
#             # For range requests, wrap bytes in FileWrapper
#             if isinstance(content, bytes):
#                 from wsgiref.util import FileWrapper
#                 from io import BytesIO
#                 content = FileWrapper(BytesIO(content), 8192)
            
#             response = StreamingHttpResponse(content, content_type=content_type)
#             if range_support and start > 0:
#                 response.status_code = 206
#         else:
#             response = HttpResponse(content, content_type=content_type)
        
#         # Set content length
#         if total_size:
#             length = (end - start + 1) if end else total_size
#             response["Content-Length"] = str(length)
#         elif not streaming and isinstance(content, bytes):
#             response["Content-Length"] = str(len(content))
        
#         # Range headers
#         if range_support:
#             response["Accept-Ranges"] = "bytes"
#             if start > 0 and end and total_size:
#                 response["Content-Range"] = f"bytes {start}-{end}/{total_size}"
        
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

#     def get(self, request, s3_key, media_file_id=None):
#         exp = request.GET.get("exp")
#         sig = request.GET.get("sig")
        
#         if not exp or not sig:
#             return Response(status=status.HTTP_404_NOT_FOUND)

#         if int(exp) < int(time.time()):
#             return Response(status=status.HTTP_404_NOT_FOUND)

#         user = self.get_current_user(request)
#         if user is None:
#             return Response(status=status.HTTP_401_UNAUTHORIZED)

#         # Optimize: Only get s3_key and file_type from DB (minimal data)
#         try:
#             media_file = TimeCapSoulMediaFile.objects.only('s3_key', 'file_type', 'user_id', 'time_capsoul_id').select_related('time_capsoul').get(
#                 id=media_file_id, user=user
#             )
#         except TimeCapSoulMediaFile.DoesNotExist:
#             try:
#                 media_file = TimeCapSoulMediaFile.objects.only('s3_key', 'file_type', 'user_id', 'time_capsoul_id').select_related('time_capsoul').get(
#                     id=media_file_id
#                 )
#             except TimeCapSoulMediaFile.DoesNotExist:
#                 return Response(status=status.HTTP_404_NOT_FOUND)
            
#             if not verify_signature(media_file.s3_key, exp, sig):
#                 return Response(status=status.HTTP_404_NOT_FOUND)
            
#             time_capsoul = media_file.time_capsoul
#             capsoul_recipients = TimeCapSoulRecipient.objects.filter(
#                 time_capsoul=time_capsoul, email=user.email
#             ).first()
            
#             if not capsoul_recipients:
#                 return Response(status=status.HTTP_404_NOT_FOUND)

#             from django.utils import timezone
#             current_date = timezone.now()
#             is_unlocked = (
#                 bool(time_capsoul.unlock_date) and current_date >= time_capsoul.unlock_date
#             )
#             if not is_unlocked:
#                 logger.info("Recipient not found for tagged capsoul")
#                 return Response({"media_files": []}, status=status.HTTP_404_NOT_FOUND)

#         s3_key = media_file.s3_key
#         filename = s3_key.split("/")[-1]
#         file_ext = s3_key.lower()
#         extension = s3_key.lower().split('/')[-1].split('.')[-1]
        
#         # Check file types
#         is_image = file_ext.endswith(('.jpg', '.jpeg', '.png', '.gif', '.bmp', '.webp'))
#         is_svg = file_ext.endswith('.svg')
#         is_video = self._is_video_file(filename)
#         is_audio = self._is_audio_file(filename)
#         is_pdf = self._is_pdf_file(filename)
#         is_csv = self._is_csv_file(filename)
#         is_json = self._is_json_file(filename)
#         is_doc = file_ext.endswith('.doc')
#         is_heic = file_ext.endswith(('.heic', '.heif'))
#         needs_conversion = file_ext.endswith(('.mkv', '.avi', '.wmv'))

#         # Cache decrypted file bytes to avoid repeated S3 calls
#         bytes_cache_key = f"media_bytes_{s3_key}"
#         cached_data = cache.get(bytes_cache_key)
        
#         if cached_data:
#             file_bytes, original_content_type = cached_data
#         else:
#             file_bytes, original_content_type = decrypt_s3_file_chunked(s3_key)
#             if not file_bytes or not original_content_type:
#                 return Response(status=status.HTTP_500_INTERNAL_SERVER_ERROR)
#             # Cache the decrypted bytes for future requests
#             cache.set(bytes_cache_key, (file_bytes, original_content_type), timeout=self.CACHE_TIMEOUT)
        
#         # Guess better content type from filename
#         content_type = self._guess_content_type(filename)
        
#         # Handle special conversions
#         if is_doc:
#             docx_cache_key = f'{bytes_cache_key}_docx_preview'
#             docx_bytes = cache.get(docx_cache_key)
#             if not docx_bytes:
#                 docx_bytes = convert_doc_to_docx_bytes(file_bytes, media_file_id=media_file.id, email=user.email)
#                 cache.set(docx_cache_key, docx_bytes, timeout=self.CACHE_TIMEOUT)
            
#             file_bytes = docx_bytes
#             content_type = "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
#             filename = filename.replace(".doc", ".docx")
        
#         elif is_heic:
#             jpeg_cache_key = f'{bytes_cache_key}_jpeg'
#             jpeg_file_bytes = cache.get(jpeg_cache_key)
#             if not jpeg_file_bytes:
#                 jpeg_file_bytes, _ = convert_heic_to_jpeg_bytes(file_bytes)
#                 cache.set(jpeg_cache_key, jpeg_file_bytes, timeout=self.CACHE_TIMEOUT)
            
#             file_bytes = jpeg_file_bytes
#             content_type = "image/jpeg"
#             filename = filename.replace(".heic", ".jpg").replace(".heif", ".jpg")
        
#         elif needs_conversion:
#             mp4_cache_key = f'{bytes_cache_key}_mp4'
#             mp4_bytes = cache.get(mp4_cache_key)
            
#             if not mp4_bytes:
#                 try:
#                     logger.info(f"Converting .{extension} to MP4 for {filename}")
#                     mp4_bytes, _ = convert_video_to_mp4_bytes(
#                         source_format=f'.{extension}',
#                         file_bytes=file_bytes
#                     )
#                     cache.set(mp4_cache_key, mp4_bytes, timeout=self.CACHE_TIMEOUT)
#                 except Exception as e:
#                     logger.error(f"Video conversion failed: {e} for {user.email} media-id: {media_file.id}")
#                     return Response(status=status.HTTP_500_INTERNAL_SERVER_ERROR)
            
#             file_bytes = mp4_bytes
#             content_type = "video/mp4"
#             filename = filename.rsplit('.', 1)[0] + '.mp4'
            
#             # After conversion, stream with range support
#             logger.info(f"Streaming converted MP4: {filename}")
#             file_size = len(file_bytes)
            
#             # Parse range header
#             start, end = 0, file_size - 1
#             range_header = request.headers.get("Range", "")
#             if range_header:
#                 import re
#                 m = re.match(r"bytes=(\d+)-(\d*)", range_header)
#                 if m:
#                     start = int(m.group(1))
#                     if m.group(2):
#                         end = int(m.group(2))
#                     end = min(end, file_size - 1)
            
#             is_partial = range_header != ""
            
#             # Return streaming response with range support
#             return self._create_response(
#                 file_bytes[start:end + 1],
#                 content_type, filename,
#                 streaming=is_partial, range_support=True,
#                 start=start, end=end, total_size=file_size
#             )
        
#         # Return appropriate response based on file type
#         if is_pdf:
#             # PDF needs special range support for browser preview
#             logger.info(f"Serving PDF with range support: {filename}")
#             return self._serve_pdf_with_range(request, file_bytes, filename)
#         elif is_csv:
#             # CSV with range support for large file preview
#             logger.info(f"Serving CSV with range support: {filename}")
#             return self._serve_csv_with_range(request, file_bytes, filename)
#         elif is_json:
#             # JSON with range support for large file preview
#             logger.info(f"Serving JSON with range support: {filename}")
#             return self._serve_json_with_range(request, file_bytes, filename)
#         elif is_svg:
#             return self._create_response(file_bytes, content_type, filename)
#         elif is_video or is_audio:
#             # Stream with range support for video/audio
#             file_size = len(file_bytes)
            
#             # Parse range header
#             start, end = 0, file_size - 1
#             range_header = request.headers.get("Range", "")
#             if range_header:
#                 import re
#                 m = re.match(r"bytes=(\d+)-(\d*)", range_header)
#                 if m:
#                     start = int(m.group(1))
#                     if m.group(2):
#                         end = int(m.group(2))
#                     end = min(end, file_size - 1)
            
#             is_partial = range_header != ""
            
#             return self._create_response(
#                 file_bytes[start:end + 1],
#                 content_type, filename,
#                 streaming=is_partial, range_support=True,
#                 start=start, end=end, total_size=file_size
#             )
#         else:
#             # All other files (PDFs, images, documents, etc.)
#             return self._create_response(file_bytes, content_type, filename)

class ServeTimeCapSoulMedia(SecuredView):
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
    
    def _get_file_extension(self, filename,):
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
                "default-src 'none'; "
                "img-src * data:; "
                "style-src 'unsafe-inline';"
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

        # Optimize: Only get s3_key and file_type from DB (minimal data)
        try:
            media_file = TimeCapSoulMediaFile.objects.only('s3_key','title', 'file_type', 'user_id', 'time_capsoul_id').select_related('time_capsoul').get(
                id=media_file_id, user=user
            )
        except TimeCapSoulMediaFile.DoesNotExist:
            try:
                media_file = TimeCapSoulMediaFile.objects.only('s3_key', 'file_type', 'user_id', 'time_capsoul_id').select_related('time_capsoul').get(
                    id=media_file_id
                )
            except TimeCapSoulMediaFile.DoesNotExist:
                return Response(status=status.HTTP_404_NOT_FOUND)
            
            if not verify_signature(media_file.s3_key, exp, sig):
                return Response(status=status.HTTP_404_NOT_FOUND)
            
            time_capsoul = media_file.time_capsoul
            capsoul_recipients = TimeCapSoulRecipient.objects.filter(
                time_capsoul=time_capsoul, email=user.email
            ).first()
            
            if not capsoul_recipients:
                return Response(status=status.HTTP_404_NOT_FOUND)

            from django.utils import timezone
            current_date = timezone.now()
            is_unlocked = (
                bool(time_capsoul.unlock_date) and current_date >= time_capsoul.unlock_date
            )
            if not is_unlocked:
                logger.info("Recipient not found for tagged capsoul")
                return Response({"media_files": []}, status=status.HTTP_404_NOT_FOUND)

        s3_key = media_file.s3_key
        filename = s3_key.split("/")[-1]
        extension = self._get_file_extension(filename)
        if extension == '':
            extension = '.' + media_file.title.lower().split('.', 1)[-1] 
        # category = self._categorize_file(filename)
        category = media_file.file_type
        content_type = self._guess_content_type(filename)
        if extension == '.svg':
            content_type = 'image/svg+xml'
        
        # Check for special cases
        is_pdf = self._is_pdf_file(filename)
        is_csv = self._is_csv_file(filename)
        is_json = self._is_json_file(filename)
        needs_conversion = extension in {'.mkv', '.avi', '.wmv', '.mpeg', '.mpg', '.flv', '.mov', '.ts', '.m4v', '.3gp'}
        is_special = extension in {'.svg', '.heic', '.heif', '.doc', '.tiff', '.raw'} or needs_conversion
        
        # Route 1: Streaming with range support (video/audio that don't need conversion)
        # if (category in ['video', 'audio']) and not needs_conversion and not is_special:
        #     file_size = self._get_file_size_from_metadata(s3_key)
        #     if not file_size:
        #         return Response(status=status.HTTP_500_INTERNAL_SERVER_ERROR)
            
        #     # Parse range header
        #     start, end = 0, file_size
        #     range_header = request.headers.get("Range", "")
        #     if range_header:
        #         import re
        #         m = re.match(r"bytes=(\d+)-(\d*)", range_header)
        #         if m:
        #             start = int(m.group(1))
        #             end = int(m.group(2)) + 1 if m.group(2) else file_size
        #             end = min(end, file_size)
            
        #     logger.info(f"Streaming {category}: {filename}")
        #     return self._create_response(
        #         self._stream_chunked_decrypt(s3_key, start, end, media_file, user),
        #         content_type, filename,
        #         streaming=True, range_support=True,
        #         start=start, end=end, total_size=file_size
        #     )

        # Route 1: VIDEO / AUDIO — decrypt once & serve with byte-range
        if category in ['video', 'audio'] and not needs_conversion and not is_special:
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
                self._stream_chunked_decrypt(s3_key = s3_key, media_file=media_file, user=user),
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
                file_bytes = cached_data
            else:
                file_bytes, _ = decrypt_s3_file_chunked(s3_key)
                if not file_bytes:
                    file_bytes, content_type = get_media_file_bytes_with_content_type(media_file, user)

                if not file_bytes:
                    return Response(status=status.HTTP_500_INTERNAL_SERVER_ERROR)
                cache.set(bytes_cache_key, file_bytes, timeout=self.CACHE_TIMEOUT)
            
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
            
            elif extension  == '.raw':
                cache_key = f'{bytes_cache_key}_jpeg'
                file_bytes = cache.get(cache_key) or convert_raw_bytes_to_jpg_bytes(
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
    
                return self._stream_file_with_range(
                    request,
                    mp4_bytes,
                    "video/mp4",
                    filename.rsplit('.', 1)[0] + ".mp4"
                )
            
                # cache_key = f'{bytes_cache_key}_mp4'
                # mp4_bytes = cache.get(cache_key)
                
                # if not mp4_bytes:
                #     try:
                #         logger.info(f"Converting {extension} to MP4 for {filename}")
                #         mp4_bytes, _ = convert_video_to_mp4_bytes(
                #             source_format=extension,
                #             file_bytes=file_bytes
                #         )
                #         cache.set(cache_key, mp4_bytes, timeout=self.CACHE_TIMEOUT)
                #     except Exception as e:
                #         mp4_bytes = convert_mov_bytes_to_mp4_bytes(file_bytes)

                #     except Exception as e:
                #         logger.error(f"Conversion failed for {filename}: {e}")
                #         return Response(status=status.HTTP_500_INTERNAL_SERVER_ERROR)
                
                # file_bytes = mp4_bytes
                # content_type = "video/mp4"
                # filename = filename.rsplit('.', 1)[0] + '.mp4'
                
                # # Now stream the converted MP4 with range support
                # logger.info(f"Streaming converted MP4: {filename}")
                # file_size = len(file_bytes)
                
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
                
                # # Create generator for range
                # def generate_range():
                #     chunk_size = self.STREAMING_CHUNK_SIZE
                #     pos = start
                #     while pos < end:
                #         chunk_end = min(pos + chunk_size, end)
                #         yield file_bytes[pos:chunk_end]
                #         pos = chunk_end
                
                # return self._create_response(
                #     generate_range(),
                #     content_type, filename,
                #     streaming=True, range_support=True,
                #     start=start, end=end, total_size=file_size
                # )
            
            # For non-converted files, return simple response
            return self._create_response(file_bytes, content_type, filename)

            

import math
from memory_room.media_helper import decrypt_s3_file_chunked,decrypt_s3_file_chunked_range,ChunkedDecryptor,S3MediaDecryptor


class TimeCapSoulMediaFileDownloadView(SecuredView):
    """
    Securely stream time capsule media file downloads from S3 without loading full file into memory.
    """
    
    DOWNLOAD_CHUNK_SIZE = 1024 * 1024   # 256KB chunks for downloads

    def _stream_decrypted_chunks_new(self, s3_key: str):
        """
        Stream using new S3MediaDecryptor with chunk metadata.
        Yields 256KB chunks for download streaming.
        """
        decryptor = S3MediaDecryptor(s3_key)
        
        # Stream decrypted chunks
        for chunk in decryptor.stream_decrypted_chunks(output_chunk_size=self.DOWNLOAD_CHUNK_SIZE):
            yield chunk
            # Optional: Add small sleep to prevent overwhelming the client
            # time.sleep(0.02)
    
    def _stream_chunked_decrypt_download(self, s3_key,media_file=None, user=None):
        """Generator that streams decrypted chunks for download."""
        with ChunkedDecryptor(s3_key) as decryptor:
        
            # If no chunk-size present in metadata => full decryption mode
            if not decryptor.metadata.get("chunk-size"):
                # cache_key = f"media_bytes_{s3_key}"
                # full_plaintext = cache.get(cache_key)
                
                # if not full_plaintext:
                full_plaintext, content = get_file_bytes(s3_key)

                if not full_plaintext and media_file and user:
                    full_plaintext, content_type = get_media_file_bytes_with_content_type(media_file, user)
                   
                    # if full_plaintext:
                    #     cache.set(cache_key, full_plaintext, timeout=60*60*24)

                self._actual_file_size = len(full_plaintext)
                total = self._actual_file_size

                # Yield in streamable pieces
                offset = 0
                # while offset < len(full_plaintext):
                while offset < total:
                    yield full_plaintext[offset:offset + self.DOWNLOAD_CHUNK_SIZE]
                    offset += self.DOWNLOAD_CHUNK_SIZE
                    time.sleep(0.02)  # 20ms is enough


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
    
    def _stream_full_bytes(self, full_plaintext):
        total = len(full_plaintext)
        offset = 0

        while offset < total:
            yield full_plaintext[offset:offset + self.DOWNLOAD_CHUNK_SIZE]
            offset += self.DOWNLOAD_CHUNK_SIZE
            time.sleep(0.02)  # optional

    def get(self, request, timecapsoul_id, media_file_id):
        """
        Download a media file from a TimeCapSoul securely - streams original file without conversions.
        """
        user = self.get_current_user(request)
        if user is None:
            return Response(status=status.HTTP_401_UNAUTHORIZED)
        
        try:
            # Try to get media file for the user
            media_file = TimeCapSoulMediaFile.objects.only(
                's3_key', 'title', 'user_id', 'time_capsoul_id'
            ).select_related('time_capsoul').get(id=media_file_id, user=user)
        except TimeCapSoulMediaFile.DoesNotExist:
            # Check if user is a recipient
            try:
                media_file = TimeCapSoulMediaFile.objects.only(
                    's3_key', 'title', 'user_id', 'time_capsoul_id'
                ).select_related('time_capsoul').get(id=media_file_id)
            except TimeCapSoulMediaFile.DoesNotExist:
                return Response(status=status.HTTP_404_NOT_FOUND)
            
            # Verify recipient access
            time_capsoul = media_file.time_capsoul
            if time_capsoul:
                capsoul_recipients = TimeCapSoulRecipient.objects.filter(
                    time_capsoul=time_capsoul, email=user.email
                ).first()
                
                if not capsoul_recipients:
                    return Response(status=status.HTTP_404_NOT_FOUND)
            else:
                return Response(status=status.HTTP_404_NOT_FOUND)
        
        try:
            s3_key = media_file.s3_key
            
            # Clean up the download filename
            file_name = f'{media_file.title.split(".", 1)[0].replace(" ", "_")}.{s3_key.split(".")[-1]}'
            
            
            # Determine content type
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
            logger.error(f"Download failed for time capsule media {media_file_id}: {e}")
            return Response(status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class TaggedCapsoulTracker(SecuredView):
    
    def post(self, request, capsoul_id, format=None):
        
        user = self.get_current_user(request)
        capsoul_recipient = get_object_or_404(
            TimeCapSoulRecipient,
            time_capsoul__id=capsoul_id,
            email=user.email
        )
        time_caspsoul = capsoul_recipient.time_capsoul

        serializer = TimeCapSoulRecipientUpdateSerializer(
            capsoul_recipient,
            data=request.data,
            partial=True  
        )
        
        if serializer.is_valid():
            serializer.save()
            message = f"The wait is over! {user.username if user.username else user.email} has opened a moment you shared. Dive in and relive it."
            notif = NotificationService.create_notification_with_key(
                notification_key='capsoul_unlocked',
                user=time_caspsoul.user,
                time_capsoul=time_caspsoul,
                custom_message = message
            )
            cache_key_list = f'{user.email}_capsouls'
            cache_key = f'{user.email}_capsoul_{capsoul_id}'
            cache.delete(cache_key)
            cache.delete(cache_key_list)
            return Response(serializer.data, status=status.HTTP_200_OK)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class UserStorageTracker(SecuredView):

    def get(self, request, format=None):
        user = self.get_current_user(request)
        logger.info(f"UserStorageTracker called {user.email}")

        cache_key = f'user_storage_id_{user.id}'
        user_storage_data = cache.get(cache_key)

        if not user_storage_data:
            try:
                total_space_occupied_kb = 0.0
                user_storage_limit_gb = 15
                user_storage_limit_kb = convert_file_size(f'{user_storage_limit_gb} GB', target_unit='KB')[0]

                user_storage_data = {
                    'user_storage_limit': user_storage_limit_gb,  # GB
                    'free_storage': 0,
                    'current_used_storage': 0,
                    'storage_usage_percentage': 0,
                    'images': {'percentge': 0, 'amount': 0},
                    'videos': {'percentge': 0, 'amount': 0},
                    'documents': {'percentge': 0, 'amount': 0},
                    'audio': {'percentge': 0, 'amount': 0},
                }

                user_capsouls = TimeCapSoul.objects.filter(user=user, is_deleted=False, room_duplicate__isnull=True)
                memory_rooms = MemoryRoom.objects.filter(user=user, is_deleted=False, room_duplicate__isnull=True)

                logger.info(f"UserStorageTracker storage calculation started for {user.email}")

                # ---- Calculate TimeCapsouls storage ----
                for capsoul in user_capsouls:
                    media_files = capsoul.timecapsoul_media_files.filter(is_deleted=False)
                    for media in media_files:
                        try:
                            file_size_kb = convert_file_size(media.file_size, target_unit='KB')[0]
                            if file_size_kb < 0:
                                file_size_kb = 0
                        except Exception:
                            file_size_kb = 0

                        total_space_occupied_kb += file_size_kb
                        file_type = (media.file_type or '').lower()

                        if file_type == 'image':
                            user_storage_data['images']['amount'] += file_size_kb
                        elif file_type == 'video':
                            user_storage_data['videos']['amount'] += file_size_kb
                        elif file_type == 'audio':
                            user_storage_data['audio']['amount'] += file_size_kb
                        else:
                            user_storage_data['documents']['amount'] += file_size_kb

                # ---- Calculate Memory Room storage ----
                for room in memory_rooms:
                    media_files = room.memory_media_files.filter(is_deleted=False)
                    for media in media_files:
                        try:
                            file_size_kb = convert_file_size(media.file_size, target_unit='KB')[0]
                            if file_size_kb < 0:
                                file_size_kb = 0
                        except Exception:
                            file_size_kb = 0

                        total_space_occupied_kb += file_size_kb
                        file_type = (media.file_type or '').lower()

                        if file_type == 'image':
                            user_storage_data['images']['amount'] += file_size_kb
                        elif file_type == 'video':
                            user_storage_data['videos']['amount'] += file_size_kb
                        elif file_type == 'audio':
                            user_storage_data['audio']['amount'] += file_size_kb
                        else:
                            user_storage_data['documents']['amount'] += file_size_kb

                logger.info(f"UserStorageTracker storage calculation completed for {user.email}")

                # ---- Helper for safe percentage ----
                def safe_percent(part, total):
                    return round(min(max((part * 100) / total if total > 0 else 0, 0), 100), 3)

          

                # # Convert category-wise to GB
                # for category in ['images', 'videos', 'documents', 'audio']:
                #     kb_amount = user_storage_data[category]['amount']
                #     gb_amount = kb_amount / KB_IN_GB
                #     user_storage_data[category]['amount'] = round(gb_amount, 5)
                #     user_storage_data[category]['percentge'] = safe_percent(kb_amount, user_storage_limit_kb)

                for category in ['images', 'videos', 'documents', 'audio']:
                    kb_amount = user_storage_data[category]['amount']
                    formatted_value, unit = auto_format_size(kb_amount)  # auto pick best unit
                    user_storage_data[category]['amount'] = formatted_value
                    user_storage_data[category]['unit'] = unit
                    user_storage_data[category]['percentage'] = safe_percent(kb_amount, user_storage_limit_kb)
                
                # ---- Convert all KB totals to GB ----
                KB_IN_GB = 1024 * 1024
                total_space_occupied_gb = total_space_occupied_kb / KB_IN_GB
                
                current_storage_used = auto_format_size(total_space_occupied_kb)
                same_formated = convert_file_size('15 GB', current_storage_used[-1])
                free_storage_in_kb = convert_file_size(f'{(max(0, same_formated[0] - current_storage_used[0]))} {current_storage_used[-1]}', 'KB')
                auto_formated_free_storage = auto_format_size(free_storage_in_kb[0])
                
                used_gb = round(total_space_occupied_gb, 5)
                formatted_value, unit = auto_format_size(kb_amount)  # auto pick best unit
                
                free_gb = max(user_storage_limit_gb - used_gb, 0)
                usage_percent = safe_percent(total_space_occupied_kb, user_storage_limit_kb)

                user_storage_data['current_used_storage'] = current_storage_used
                user_storage_data['free_storage'] = auto_formated_free_storage
                user_storage_data['storage_usage_percentage'] = usage_percent

                cache.set(cache_key, user_storage_data, timeout=60 * 60 * 2)

            except Exception as e:
                logger.error(f'Error in UserStorageTracker for {user.email}: {e}', exc_info=True)
                return Response({'error': 'Failed to calculate user storage'}, status=500)

        logger.info(f"UserStorageTracker data served {user.email}")
        return Response(user_storage_data)

  
      
class TimeCapsoulDuplicationApiView(SecuredView):
    
    def post(self, request, time_capsoul_id, format=None):
        user  = self.get_current_user(request)
        logger.info(f'TimeCapsoulDuplicationApiView is called by {user.email} capsoul-id: {time_capsoul_id}')
        time_capsoul = get_object_or_404(TimeCapSoul, id=time_capsoul_id)
        if user != time_capsoul.user:
            is_recipient = TimeCapSoulRecipient.objects.filter(time_capsoul=time_capsoul, email = user.email).first()
            if not is_recipient:
                return Response(status=status.HTTP_404_NOT_FOUND)
            duplicate_room = create_time_capsoul(
                    old_time_capsoul = time_capsoul, # create time-capsoul duplicate here
                    current_user = user,
                    option_type = 'duplicate_time_capsoul',
            )
            parent_files_id = get_recipient_capsoul_ids(is_recipient)
            parent_media_files = TimeCapSoulMediaFile.objects.filter(
                time_capsoul=time_capsoul,
                id__in = parent_files_id,
            ).order_by('-created_at')
        else:
            duplicate_room = create_time_capsoul(
                old_time_capsoul = time_capsoul, # create time-capsoul duplicate here
                current_user = user,
                option_type = 'duplicate_time_capsoul',
            )
            parent_media_files = TimeCapSoulMediaFile.objects.filter(
                time_capsoul=time_capsoul,
                user = user,
                is_deleted = False,
            ).order_by('-created_at')
        new_media_count = 0
        old_media_count = parent_media_files.count()   
        for parent_file in parent_media_files:
            try:
                is_media_created = create_time_capsoul_media_file(
                    old_media=parent_file,
                    new_capsoul=duplicate_room,
                    current_user = user,
                    option_type = 'duplicate_creation',
                )
            except Exception as e:
                logger.exception(F'Exception while creating time-capsoul duplicate-media-file for media-file id {parent_file.id}  user {user.email}')
                raise e  
            else:
                if is_media_created:
                    new_media_count += 1
        cache.delete(f'{user.email}_capsouls')
        print(f"Old media count: {old_media_count}, New media count: {new_media_count}")
        serializer = TimeCapSoulSerializer(duplicate_room, context = {'user': user})
        logger.info(f'Caposul  duplicate created successfully for user {user.email} capsoul: old {time_capsoul_id} new: {duplicate_room.id} old media count: {old_media_count} new-media-count: {new_media_count} ')
        return Response(serializer.data, status=status.HTTP_201_CREATED)


class ServeCoverTimecapsoulImages(SecuredView):
    """
    Securely serve decrypted images from S3 via Django.
    Streaming responses with lazy loading for all image types.
    """
    
    CACHE_TIMEOUT = 60 * 60 * 24 * 7  # 7 days
    STREAMING_CHUNK_SIZE = 64 * 1024  # 64KB chunks
    
    # Image file extensions
    IMAGE_EXTENSIONS = {'.jpg', '.jpeg', '.png', '.gif', '.bmp', '.tiff', '.webp', 
                        '.heic', '.heif', '.svg', '.ico', '.raw', '.psd'}
    
    def _get_file_extension(self, filename):
        """Extract file extension from filename."""
        return '.' + filename.lower().rsplit('.', 1)[-1] if '.' in filename else ''
    
    def _guess_content_type(self, filename):
        """Guess content type from filename extension for better browser compatibility."""
        import mimetypes
        content_type, _ = mimetypes.guess_type(filename)
        
        ext = self._get_file_extension(filename)
        
        # Quick lookup for common image types
        type_map = {
            '.jpg': 'image/jpeg',
            '.jpeg': 'image/jpeg',
            '.png': 'image/png',
            '.gif': 'image/gif',
            '.webp': 'image/webp',
            '.svg': 'image/svg+xml',
            '.bmp': 'image/bmp',
            '.tiff': 'image/tiff',
            '.ico': 'image/x-icon',
        }
        
        return type_map.get(ext, content_type or 'application/octet-stream')
    
    def _create_response(self, content, content_type, filename, streaming=False):
        """
        Unified response creator for image files.
        
        Args:
            content: File bytes or generator for streaming
            content_type: MIME type
            filename: Original filename
            streaming: Whether to use StreamingHttpResponse
        """
        # Create appropriate response type
        if streaming:
            response = StreamingHttpResponse(content, content_type=content_type)
        else:
            response = HttpResponse(content, content_type=content_type)
        
        # Set content length for non-streaming responses
        if not streaming and content:
            response["Content-Length"] = str(len(content))
        
        # Security headers
        response["Content-Disposition"] = "inline"
        response["X-Content-Type-Options"] = "nosniff"
        response["Cache-Control"] = "private, max-age=3600"
        
        # Special CSP for SVG
        # if content_type == "image/svg+xml":
        #     response["Content-Security-Policy"] = "default-src 'none'; style-src 'unsafe-inline'; img-src data:;"
        if content_type == "image/svg+xml":
            response["Content-Security-Policy"] = (
                "default-src 'none'; "
                "img-src * data:; "
                "style-src 'unsafe-inline';"
            )

        else:
            frame_ancestors = " ".join(settings.CORS_ALLOWED_ORIGINS)
            response["Content-Security-Policy"] = f"frame-ancestors 'self' {frame_ancestors};"
        
        # CORS headers
        response["Cross-Origin-Resource-Policy"] = "cross-origin"
        response["Access-Control-Allow-Origin"] = "*"
        
        return response
    
    def _stream_chunked_decrypt(self, s3_key):
        """Generator that streams decrypted chunks."""
        with ChunkedDecryptor(s3_key) as decryptor:
            
            
            if not decryptor.metadata.get("chunk-size"):
                cache_key = f"media_bytes_{s3_key}"
                full_plaintext = cache.get(cache_key)

                if not full_plaintext:
                    full_plaintext, _ = get_file_bytes(s3_key)
                    media_file = TimeCapSoulMediaFile.objects.filter(s3_key = s3_key).first()
                    if not full_plaintext and media_file and media_file.user:
                        full_plaintext, _ = get_media_file_bytes_with_content_type(media_file, user)
                    if full_plaintext:
                        cache.set(cache_key, full_plaintext, timeout=self.CACHE_TIMEOUT)

                if not full_plaintext:
                    return Response(status=status.HTTP_500_INTERNAL_SERVER_ERROR)
                
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
            metadata = obj['Metadata']
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

    def get(self, request, cover_image_id):
        user = self.get_current_user(request)
        if user is None:
            return Response(status=status.HTTP_401_UNAUTHORIZED)

        # Optimize: Only get s3_key and file_type from DB (minimal data)
        try:
            # media_file = TimeCapSoulMediaFile.objects.only('s3_key', 'file_type', 'user_id', 'time_capsoul_id').select_related('time_capsoul').get(
            #     id=media_file_id
            # )
            assets = Assets.objects.get(id = cover_image_id)
            
        except Assets.DoesNotExist:
            return Response(status=status.HTTP_404_NOT_FOUND)
        
        # else:
        #     if user != media_file.user:
        #         time_capsoul = media_file.time_capsoul
        #         capsoul_recipients = TimeCapSoulRecipient.objects.filter(
        #             time_capsoul=time_capsoul, email=user.email
        #         ).first()
            
        #         if not capsoul_recipients:
        #             return Response(status=status.HTTP_404_NOT_FOUND)

        #         from django.utils import timezone
        #         current_date = timezone.now()
        #         is_unlocked = (
        #             bool(time_capsoul.unlock_date) and current_date >= time_capsoul.unlock_date
        #         )
        #         if not is_unlocked:
        #             logger.info("Recipient not found for tagged capsoul")
        #             return Response(status=status.HTTP_404_NOT_FOUND)

        s3_key = assets.s3_key
        filename = s3_key.split("/")[-1]
        extension = self._get_file_extension(filename)
        content_type = self._guess_content_type(filename)
        
        # Check for special image formats that need conversion
        needs_conversion = extension in {'.heic', '.heif'}
        is_svg = extension == '.svg'
        
        # Route 1: Progressive streaming (standard images, no special handling)
        if not needs_conversion and not is_svg:
            file_size = self._get_file_size_from_metadata(s3_key)
            if not file_size:
                return Response(status=status.HTTP_500_INTERNAL_SERVER_ERROR)
            
            logger.info(f"Progressive image streaming: {filename}")
            return self._create_response(
                self._stream_chunked_decrypt(s3_key),
                content_type, filename,
                streaming=True
            )
        
        # Route 2: Full file with conversions (HEIC/HEIF, SVG)
        else:
            logger.info(f"Full decrypt for image: {filename}")
            
            # Get or decrypt full file
            bytes_cache_key = f"media_bytes_{s3_key}"
            cached_data = cache.get(bytes_cache_key)
            
            if cached_data:
                file_bytes = cached_data
            else:
                file_bytes, _ = decrypt_s3_file_chunked(s3_key)
                if not file_bytes:
                    media_file = TimeCapSoulMediaFile.objects.filter(s3_key=s3_key, user=user).first()
                    file_bytes, content_type = get_media_file_bytes_with_content_type(media_file, user)

                if not file_bytes:
                    return Response(status=status.HTTP_500_INTERNAL_SERVER_ERROR)
                cache.set(bytes_cache_key, file_bytes, timeout=self.CACHE_TIMEOUT)
            
            # Handle HEIC/HEIF conversion
            if needs_conversion:
                cache_key = f'{bytes_cache_key}_jpeg'
                file_bytes = cache.get(cache_key) or convert_heic_to_jpeg_bytes(file_bytes)[0]
                cache.set(cache_key, file_bytes, timeout=self.CACHE_TIMEOUT)
                content_type = "image/jpeg"
                filename = filename.rsplit('.', 1)[0] + '.jpg'
            
            # Return simple response
            return self._create_response(file_bytes, content_type, filename)