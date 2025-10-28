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


from memory_room.helpers import (
    upload_file_to_s3_kms,
    create_duplicate_time_capsoul,
    create_parent_media_files_replica_upload_to_s3_bucket, generate_unique_capsoul_name,
    create_time_capsoul,create_time_capsoul_media_file
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
from memory_room.utils import upload_file_to_s3_bucket, get_file_category, generate_unique_slug, convert_doc_to_docx_bytes,convert_heic_to_jpeg_bytes,convert_mkv_to_mp4_bytes, convert_video_to_mp4_bytes

from userauth.models import Assets
from userauth.apis.views.views import SecuredView,NewSecuredView


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
from memory_room.crypto_utils import encrypt_and_upload_file, decrypt_and_get_image, save_and_upload_decrypted_file, decrypt_and_replicat_files, generate_signature, verify_signature,get_media_file_bytes_with_content_type,encrypt_and_upload_file_chunked,generate_capsoul_media_s3_key,clean_filename


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

        return Response({
            'message': 'Time CapSoul created successfully',
            'time_capsoul': serialized_data
        }, status=status.HTTP_201_CREATED)
    
    def get(self, request, format=None):
        logger.info("CreateTimeCapSoulView.get list called")
        """Time CapSoul list"""
        user = self.get_current_user(request)
        
        time_capsouls = TimeCapSoul.objects.filter(user=user, is_deleted = False).order_by('-created_at') # owner capsoul
        try: 
            # tagged capsoul
            tagged_time_capsouls = TimeCapSoul.objects.filter(
                recipient_detail__email=user.email,
                recipient_detail__is_capsoul_deleted=False
            ).exclude(user = user)
            
            tagged_time_capsouls_replica = TimeCapSoul.objects.filter(
                user=user,
                capsoul_replica_refrence__in=tagged_time_capsouls,
                is_deleted = False
            )
            if tagged_time_capsouls and tagged_time_capsouls_replica:
                tagged_time_capsouls = tagged_time_capsouls.union(tagged_time_capsouls_replica)
            
            
        except TimeCapSoulRecipient.DoesNotExist:
            tagged_time_capsouls = None

        # Get all replicas in one query (instead of loop)
        time_capsoul_replicas = TimeCapSoul.objects.filter(
            user=user,
            capsoul_replica_refrence__in=time_capsouls,
            is_deleted = False
            
        )
        if tagged_time_capsouls:
            time_capsouls = time_capsouls.union(tagged_time_capsouls)
        

        serializer = TimeCapSoulSerializer(time_capsouls, many=True, context={'user': user})
        replica_serializer = TimeCapSoulSerializer(time_capsoul_replicas, many=True, context={'user': user})

        response = {
            'time_capsoul': serializer.data,
            'replica_capsoul': replica_serializer.data
        }
        return Response(response)
        
class TimeCapSoulUpdationView(SecuredView):
    def patch(self, request, time_capsoul_id):
        logger.info("TimeCapSoulUpdationView.patch called")
        user = self.get_current_user(request)
        time_capsoul = get_object_or_404(TimeCapSoul, id=time_capsoul_id)
        serializer = TimeCapSoulUpdationSerializer(instance = time_capsoul, data=request.data, partial = True, context={'is_owner': True if time_capsoul.user == user else False, 'current_user': user})
        if serializer.is_valid():
            update_time_capsoul = serializer.save()
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
            return Response({'message': f'Time Capsoul deleted successfully for {user.email}'})
        else:
            if  time_capsoul.is_deleted == False:
                is_updated = update_users_storage(
                    capsoul=time_capsoul
                )
                time_capsoul.is_deleted = True
                time_capsoul.save()
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
        
        # if user is Owner of the time-capsoul 
        try:
            time_capsoul = get_object_or_404(TimeCapSoul, id=time_capsoul_id)
        except Exception as e:
            logger.error(f"Error fetching time_capsoul: {e} for user {user.email} for time_capsoul_id {time_capsoul_id}")
            return Response({"media_files": []}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        else:
            if time_capsoul.user == user:
                if time_capsoul.is_deleted == True:
                    return Response({"media_files": []}, status=status.HTTP_404_NOT_FOUND)

                media_files = TimeCapSoulMediaFile.objects.filter(time_capsoul=time_capsoul,user=user, is_deleted =False)
            else:
                recipient = TimeCapSoulRecipient.objects.filter(time_capsoul = time_capsoul, email = user.email, is_deleted = False).first()
                if not recipient:
                    logger.info(f'User is not owner and recipient not found for tagged capsoul {time_capsoul.id} and user {user.email}')
                    return Response({"media_files": []}, status=status.HTTP_404_NOT_FOUND)
                
                # if time_capsoul.unlock_date and timezone.now() < time_capsoul.unlock_date:
                current_date = timezone.now()
                is_unlocked = (
                    bool(time_capsoul.unlock_date) and current_date >= time_capsoul.unlock_date
                )
                if not is_unlocked:
                    logger.info(f'User is not owner and capsoul is locked for tagged capsoul {time_capsoul.id} and user {user.email}')
                    return Response({"media_files": []}, status=status.HTTP_404_NOT_FOUND)

                parent_files_id = (
                    [int(i.strip()) for i in recipient.parent_media_refrences.split(',') if i.strip().isdigit()]
                    if recipient.parent_media_refrences else []
                )
                media_files = TimeCapSoulMediaFile.objects.filter(
                    time_capsoul=time_capsoul,
                    id__in = parent_files_id,
                )
                
        serializer = TimeCapSoulMediaFileReadOnlySerializer(media_files, many=True)
        return Response({"media_files": serializer.data})

    
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
        results = []
        from rest_framework import serializers

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
        
        if time_capsoul.status == 'unlocked':
            try:
                replica_instance = create_time_capsoul(
                    old_time_capsoul = time_capsoul, # create time-capsoul replica
                    current_user = user,
                    option_type = 'replica_creation',
                )
                if user.id == time_capsoul.user.id: # if user is owner of the capsoul
                    parent_media_files = TimeCapSoulMediaFile.objects.filter(time_capsoul = time_capsoul, is_deleted = False)
                else:
                    recipient = TimeCapSoulRecipient.objects.filter(time_capsoul = time_capsoul, email = user.email).first()
                    if not recipient:
                        logger.info(f"Recipient not found for tagged capsoul for {time_capsoul.id} and user {user.email}")
                        return Response(status=status.HTTP_404_NOT_FOUND)
                    else:
                        parent_files_id = (
                            [int(i.strip()) for i in recipient.parent_media_refrences.split(',') if i.strip().isdigit()]
                            if recipient.parent_media_refrences else []
                        )
                        parent_media_files = TimeCapSoulMediaFile.objects.filter(
                            time_capsoul=time_capsoul,
                            id__in = parent_files_id,
                        )
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

        if total_files <= 2:
            max_workers = 1
        elif total_files <= 5:
            max_workers = 2
        elif total_size > 500 * 1024 * 1024:  # > 500MB
            max_workers = min(total_files, 4)
        else:
            max_workers = min(total_files, 6)

        # Thread-safe progress tracking
        progress_lock = threading.Lock()
        file_progress = {
            i: {'progress': 0, 'message': 'Queued', 'status': 'pending'}
            for i in range(total_files)
        }

        def update_file_progress(file_index, progress, message, status='processing'):
            with progress_lock:
                file_progress[file_index] = {
                    'progress': progress,
                    'message': message,
                    'status': status
                }

        def file_upload_stream():
            def process_single_file(file_index, uploaded_file, file_iv, time_capsoul):
                """Process a single file upload with progress tracking"""
                try:
                    def progress_callback(progress, message):
                        if progress == -1:  # Error
                            update_file_progress(file_index, 0, message, 'failed')
                        else:
                            update_file_progress(file_index, progress, message, 'processing')

                    uploaded_file.seek(0)

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
                        time_capsoul = media_file.time_capsoul
                        if time_capsoul.status == 'sealed':
                            capsoul_recipients = TimeCapSoulRecipient.objects.filter(time_capsoul = time_capsoul)
                            if capsoul_recipients.count() >0:
                                existing_media_ids = capsoul_recipients[0].parent_media_refrences
                                updated_media_ids = existing_media_ids +  f',{media_file.id}'
                                capsoul_recipients.update(parent_media_refrences = updated_media_ids)
                            
                        
                        is_updated = update_users_storage(
                            operation_type='addition',
                            media_updation='capsoul',
                            media_file=media_file
                        )
                        update_file_progress(file_index, 100, 'Upload completed successfully', 'success')

                        return {
                            'index': file_index,
                            'result': {
                                "file": uploaded_file.name,
                                "status": "success",
                                "progress": 100,
                                "data": TimeCapSoulMediaFileReadOnlySerializer(media_file).data
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
                    executor.submit(process_single_file, i, files[i], ivs[i], time_capsoul): i
                    for i in range(total_files)
                }

                started_files = set()
                last_sent_progress = {i: -1 for i in range(total_files)}

                while len(results) < total_files:
                    with progress_lock:
                        for file_index, progress_data in file_progress.items():
                            file_name = files[file_index].name

                            # Start message
                            if file_index not in started_files and progress_data['status'] != 'pending':
                                yield f"data: Starting upload of {file_name}\n\n"
                                started_files.add(file_index)

                            # Only send updated progress
                            if (
                                progress_data['status'] == 'processing'
                                and progress_data['progress'] != last_sent_progress[file_index]
                            ):
                                yield f"data: {file_name} -> {progress_data['progress']}\n\n"
                                last_sent_progress[file_index] = progress_data['progress']

                    # Handle completed uploads
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
                                yield f"data: {file_name} upload failed: {json.dumps(error_msg)}\n\n"

                            del future_to_index[future]

                        except Exception as e:
                            logger.exception("Task completion error")
                            del future_to_index[future]


            yield f"data: FINAL_RESULTS::{json.dumps(results)}\n\n"

        return StreamingHttpResponse(
            file_upload_stream(),
            content_type='text/event-stream',
            status=status.HTTP_200_OK
        )


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
                        existing_media_ids = capsoul_recipients[0].parent_media_refrences
                        updated_media_ids = existing_media_ids.replace(f'{media_file_id}', '')
                        capsoul_recipients.update(parent_media_refrences = updated_media_ids)
                
                update_users_storage(
                    operation_type='remove',
                    media_updation='capsoul',
                    media_file=media_file
                )
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

            parent_files_id = (
                [int(i.strip()) for i in recipient.parent_media_refrences.split(',') if i.strip().isdigit()]
                if recipient.parent_media_refrences else []
            )
            if media_file_id not in parent_files_id:
                return Response(status=status.HTTP_400_BAD_REQUEST)
            
            # remove current media-id from parent media 
            try:
                parent_files_id.remove(media_file_id)
            except Exception as e:
                logger.error(f'Erorr while removing media id from parent list: {e} for user {user.email} and media_file_id {media_file_id}')
            else:
              recipient.parent_media_refrences  = ','.join(map(str, parent_files_id)) if parent_files_id else None
              recipient.save()
            return Response(status=status.HTTP_204_NO_CONTENT)
    
    def patch(self, request, time_capsoul_id, media_file_id):
        user = self.get_current_user(request)
        media_file = get_object_or_404(TimeCapSoulMediaFile, id=media_file_id)
        serializer = TimeCapsoulMediaFileUpdationSerializer(instance = media_file, data=request.data, partial = True, context={'is_owner': True if media_file.user == user else False, 'current_user': user})
        serializer.is_valid(raise_exception=True)
        update_media_file = serializer.save()
        return Response(TimeCapSoulMediaFileReadOnlySerializer(update_media_file).data)



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
    
    def _stream_chunked_decrypt(self, s3_key, start_byte=0, end_byte=None):
        """Generator that streams decrypted chunks."""
        with ChunkedDecryptor(s3_key) as decryptor:
            for decrypted_chunk in decryptor.decrypt_chunks(start_byte, end_byte):
                chunk_offset = 0
                while chunk_offset < len(decrypted_chunk):
                    yield decrypted_chunk[chunk_offset:chunk_offset + self.STREAMING_CHUNK_SIZE]
                    chunk_offset += self.STREAMING_CHUNK_SIZE
    
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
            media_file = TimeCapSoulMediaFile.objects.only('s3_key', 'file_type', 'user_id', 'time_capsoul_id').select_related('time_capsoul').get(
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
                        mp4_bytes, _ = convert_video_to_mp4_bytes(
                            source_format=extension,
                            file_bytes=file_bytes
                        )
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

# class TimeCapSoulMediaFileDownloadView(SecuredView):
#     def get(self, request, timecapsoul_id, media_file_id):
#         """
#         Download a media file from a TimeCapSoul securely.
#         """
#         user = self.get_current_user(request)
#         if user is None:
#             return Response(status=status.HTTP_401_UNAUTHORIZED)
#         try:
#             media_file =  TimeCapSoulMediaFile.objects.get(id = media_file_id, user=user)
#         except TimeCapSoulMediaFile.DoesNotExist:
#             try:
#                 media_file =  TimeCapSoulMediaFile.objects.get(id = media_file_id)
#             except Exception as e:
#                 return Response(status=status.HTTP_404_NOT_FOUND)
#             else:
#                 time_capsoul = media_file.time_capsoul
                
#                 if time_capsoul:
#                     capsoul_recipients = TimeCapSoulRecipient.objects.filter(time_capsoul=time_capsoul, email = user.email).first()
#                     if not capsoul_recipients:
#                         return Response(status=status.HTTP_404_NOT_FOUND)

#                     # recipients_data = list(capsoul_recipients.recipients.values_list("email", flat=True))
#                     # if user.email not in recipients_data:
#                     #     return Response(status=status.HTTP_404_NOT_FOUND)
                    
#         # file_name = media_file.s3_key.split('/')[-1]
#         file_name  = f'{media_file.title.split(".", 1)[0].replace(" ", "_")}.{media_file.s3_key.split(".")[-1]}'
#         # print(f'\nfile-name: {file_name}  {media_file.title.split(".", 1)[0].replace(" ", "_")}.{media_file.s3_key.split(".")[-1]}')
        
        
#         file_bytes, content_type = get_media_file_bytes_with_content_type(media_file, user)
#         if not file_bytes or not content_type:
#             return Response(status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
#         if file_bytes and content_type:
#             try:
#                 file_size = len(file_bytes)
#                 chunk_size = determine_download_chunk_size(file_size)
#                 file_stream = io.BytesIO(file_bytes)

#                 mime_type = (
#                     content_type
#                     or mimetypes.guess_type(file_name)[0]
#                     or 'application/octet-stream'
#                 )

#                 def file_iterator():
#                     while True:
#                         chunk = file_stream.read(chunk_size)
#                         if not chunk:
#                             break
#                         yield chunk

#                 response = StreamingHttpResponse(
#                     streaming_content=file_iterator(),
#                     content_type=mime_type
#                 )
#                 response['Content-Disposition'] = f'attachment; filename="{file_name}"'
#                 response['Content-Length'] = str(file_size)
#                 response['Accept-Ranges'] = 'bytes'
#                 response['Cache-Control'] = 'no-cache, no-store, must-revalidate'
#                 response['Access-Control-Expose-Headers'] = 'Content-Length, Content-Disposition'
#                 return response

#             except ClientError as e:
#                 return Response(status=status.HTTP_404_NOT_FOUND)
#         else:
#             return Response(status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class MediaFileDownloadView(SecuredView):
    """
    Securely stream media file downloads from S3 without loading full file into memory.
    """
    
    DOWNLOAD_CHUNK_SIZE = 256 * 1024  # 256KB chunks for downloads
    
    def _stream_chunked_decrypt_download(self, s3_key):
        """Generator that streams decrypted chunks for download."""
        with ChunkedDecryptor(s3_key) as decryptor:
            for decrypted_chunk in decryptor.decrypt_chunks():
                chunk_offset = 0
                while chunk_offset < len(decrypted_chunk):
                    yield decrypted_chunk[chunk_offset:chunk_offset + self.DOWNLOAD_CHUNK_SIZE]
                    chunk_offset += self.DOWNLOAD_CHUNK_SIZE
    
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


class TimeCapSoulMediaFileDownloadView(SecuredView):
    """
    Securely stream time capsule media file downloads from S3 without loading full file into memory.
    """
    
    DOWNLOAD_CHUNK_SIZE = 1024 * 1024   # 256KB chunks for downloads
    
    def _stream_chunked_decrypt_download(self, s3_key):
        """Generator that streams decrypted chunks for download."""
        with ChunkedDecryptor(s3_key) as decryptor:
            for decrypted_chunk in decryptor.decrypt_chunks():
                chunk_offset = 0
                while chunk_offset < len(decrypted_chunk):
                    yield decrypted_chunk[chunk_offset:chunk_offset + self.DOWNLOAD_CHUNK_SIZE]
                    chunk_offset += self.DOWNLOAD_CHUNK_SIZE
    
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
            
            # Get file size without downloading
            file_size = self._get_file_size_from_metadata(s3_key)
            if not file_size:
                logger.error(f"Failed to get file size for {s3_key}")
                return Response(status=status.HTTP_500_INTERNAL_SERVER_ERROR)
            
            # Determine content type
            content_type = self._guess_content_type(file_name)
            
            # Stream directly without any conversions
            logger.info(f"Streaming download for {file_name}")
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
            return Response(serializer.data, status=status.HTTP_200_OK)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

# class UserStorageTracker(SecuredView):
    
#     def get(self, request, format=None):
#         user = self.get_current_user(request)
#         logger.info(f"UserStorageTracker  called {user.email}")
#         user_tracker_cache_key= f'user_storage_id_{user.id}'
#         user_storage_data = cache.get(user_tracker_cache_key)
#         if not user_storage_data:
#             try:
#                 user_mapper = user.user_mapper.first() 
#                 total_space_occupied = 0
#                 user_storage_limit = parse_into_mbs(user_mapper.max_storage_limit)
#                 user_storage_limit = to_gb(user_storage_limit[0], user_storage_limit[-1])
                
                
#                 user_storage_data= {
#                     'user_storage_limit': user_storage_limit,
#                     'free_storage': 0,
#                     'current_used_storage': 0,
#                     'storage_usage_percentage': 0,
#                     'images': {
#                         'percentge': 0,
#                         'amount': 0
#                     },
#                     'videos': {
#                         'percentge': 0,
#                         'amount': 0
#                     },
#                     'documents': {
#                         'percentge': 0,
#                         'amount': 0
#                     },
#                     'audio': {
#                         'percentge': 0,
#                         'amount': 0
#                     },
#                 }
                
#                 user_capsouls = TimeCapSoul.objects.filter(user = user, is_deleted = False)
#                 memory_room = MemoryRoom.objects.filter(user= user, is_deleted = False)
#                 logger.info(f"UserStorageTracker  storage callculation started {user.email}")
                
                
#                 for capsoul in user_capsouls: # time-capsoul files calculations
#                     media_files = capsoul.timecapsoul_media_files.filter(is_deleted = False)
#                     for media in media_files: 
#                         file_size = parse_into_mbs(media.file_size)
#                         file_size = to_gb(file_size[0], file_size[-1])
#                         total_space_occupied += file_size
                        
#                         if media.file_type == 'image':
#                             user_storage_data['images']['amount'] += file_size
                            
#                         elif media.file_type == 'video':
#                             user_storage_data['videos']['amount'] += file_size
                        
#                         elif media.file_type == 'audio':
#                             user_storage_data['audio']['amount'] += file_size
                            
#                         else:
#                             user_storage_data['documents']['amount'] += file_size
                
#                 for capsoul in memory_room:   # memory-room file calculations
#                     media_files = capsoul.memory_media_files.filter(is_deleted=False)
#                     for media in media_files: 
#                         # file_size = parse_into_mbs(media.file_size)[0]
#                         file_size = parse_into_mbs(media.file_size)
#                         file_size = to_gb(file_size[0], file_size[-1])
                        
                        
#                         total_space_occupied += file_size
                        
#                         if media.file_type == 'image':
#                             user_storage_data['images']['amount'] += file_size
                            
#                         elif media.file_type == 'video':
#                             user_storage_data['videos']['amount'] += file_size
                        
#                         elif media.file_type == 'audio':
#                             user_storage_data['audio']['amount'] += file_size
                            
#                         else:
#                             user_storage_data['documents']['amount'] += file_size
                            
#                 logger.info(f"UserStorageTracker  storage callculation completed {user.email}")
                
#                 user_storage_data['images']['percentge'] = round((user_storage_data['images']['amount']*100)/user_storage_limit, 3)
#                 user_storage_data['videos']['percentge'] = round((user_storage_data['videos']['amount']*100)/user_storage_limit, 3)
#                 user_storage_data['documents']['percentge'] = round((user_storage_data['documents']['amount']*100)/user_storage_limit, 3)
#                 user_storage_data['audio']['percentge'] = round((user_storage_data['audio']['amount']*100)/user_storage_limit, 3)
                
#                 user_storage_data['current_used_storage'] = round(total_space_occupied, 5)
#                 user_storage_data['free_storage'] = round(user_storage_limit - total_space_occupied, 5)
#                 user_storage_data['storage_usage_percentage'] = round(( total_space_occupied * 100  )/user_storage_limit, 3)
#                 cache.set(user_tracker_cache_key, user_storage_data, timeout=60*60*2)
                
#             except Exception as e:
#                 logger.error(f'Exception occur at UserStorageTracker  while getting storage data for {user.email} error-message: \n {e}')
                
            
#         logger.info(f"UserStorageTracker  data served {user.email}")
#         return Response(user_storage_data)

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
            # duplicate_room = create_duplicate_time_capsoul(time_capsoul, current_user=user)
            duplicate_room = create_time_capsoul(
                    old_time_capsoul = time_capsoul, # create time-capsoul duplicate here
                    current_user = user,
                    option_type = 'duplicate_time_capsoul',
            )
            parent_files_id = (
                [int(i.strip()) for i in is_recipient.parent_media_refrences.split(',') if i.strip().isdigit()]
                if is_recipient.parent_media_refrences else []
            )
            parent_media_files = TimeCapSoulMediaFile.objects.filter(
                time_capsoul=time_capsoul,
                id__in = parent_files_id,
            )
            
            # serializer = TimeCapSoulSerializer(duplicate_room, context = {'user': user})
            # logger.info(f'Caposul  duplicate created successfully for capsoul: old {time_capsoul_id} new: {duplicate_room.id} for user {user.email} ')
            # return Response(serializer.data, status=status.HTTP_201_CREATED)
        else:
            # if time_capsoul.status != 'unlocked': 
            # duplicate_room = create_duplicate_time_capsoul(time_capsoul, current_user=user)
            duplicate_room = create_time_capsoul(
                old_time_capsoul = time_capsoul, # create time-capsoul duplicate here
                current_user = user,
                option_type = 'duplicate_time_capsoul',
            )
            parent_media_files = TimeCapSoulMediaFile.objects.filter(
                time_capsoul=time_capsoul,
                user = user,
                is_deleted = False,
            )
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
                pass
            else:
                if is_media_created:
                    new_media_count += 1
                    
        print(f"Old media count: {old_media_count}, New media count: {new_media_count}")
        serializer = TimeCapSoulSerializer(duplicate_room, context = {'user': user})
        logger.info(f'Caposul  duplicate created successfully for user {user.email} capsoul: old {time_capsoul_id} new: {duplicate_room.id}  ')
        return Response(serializer.data, status=status.HTTP_201_CREATED)
        


class GetMediaThumbnailPreview(SecuredView):
    
    def get(self, request, path, media_file_id=None):
        return Response()
        
        pass