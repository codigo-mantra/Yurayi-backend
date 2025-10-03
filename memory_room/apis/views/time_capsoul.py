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
from memory_room.utils import parse_storage_size, to_mb, to_gb, convert_file_size
from memory_room.views import parse_storage_size as parse_into_mbs
from memory_room.signals import update_user_storage
from memory_room.tasks import update_time_capsoul_occupied_storage


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
from memory_room.utils import upload_file_to_s3_bucket, get_file_category, generate_unique_slug, convert_doc_to_docx_bytes,convert_heic_to_jpeg_bytes,convert_mkv_to_mp4_bytes

from userauth.models import Assets
from userauth.apis.views.views import SecuredView,NewSecuredView


from memory_room.apis.serializers.memory_room import (
    AssetSerializer,
)

from memory_room.models import (
    TimeCapSoulTemplateDefault, TimeCapSoul, TimeCapSoulDetail, TimeCapSoulMediaFile,RecipientsDetail,
    TimeCapSoulRecipient,FILE_TYPES, CustomTimeCapSoulTemplate, MemoryRoom, MemoryRoomMediaFile
    )

from memory_room.apis.serializers.time_capsoul import (
    TimeCapSoulTemplateDefaultReadOnlySerializer, TimeCapSoulCreationSerializer,TimeCapSoulMediaFileReadOnlySerializer,
    TimeCapSoulSerializer, TimeCapSoulUpdationSerializer,TimeCapSoulMediaFileSerializer,TimeCapSoulMediaFilesReadOnlySerailizer, TimeCapsoulMediaFileUpdationSerializer,
    TimeCapsoulUnlockSerializer, TimeCapsoulUnlockSerializer,RecipientsDetailSerializer,TimeCapSoulMediaFileReadOnlySerializer, TimeCapSoulRecipientSerializer
)
from memory_room.apis.serializers.notification import TimeCapSoulRecipientUpdateSerializer
from memory_room.crypto_utils import encrypt_and_upload_file, decrypt_and_get_image, save_and_upload_decrypted_file, decrypt_and_replicat_files, generate_signature, verify_signature


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
            cache.set(cache_key, data, timeout=60*10) # 10 minutes cached 
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
            cache.set(cache_key, data, timeout=None) 
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
        time_capsouls = TimeCapSoul.objects.filter(user=user, is_deleted = False)
        try: # tagged capsoul
            tagged_time_capsouls = TimeCapSoul.objects.filter(
                recipient_detail__email=user.email,
                recipient_detail__is_capsoul_deleted=False
            ).exclude(user = user)
            
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
        time_capsoul = get_object_or_404(TimeCapSoul, id=time_capsoul_id, user = user, is_deleted = False)
        serializer = TimeCapSoulUpdationSerializer(instance = time_capsoul, data=request.data, partial = True)
        if serializer.is_valid():
            update_time_capsoul = serializer.save()
            return Response(TimeCapSoulSerializer(update_time_capsoul, context={'user': user}).data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    def delete(self, request, time_capsoul_id):
        logger.info("TimeCapSoulUpdationView.delete called")
        user = self.get_current_user(request)
        capsoul = get_object_or_404(TimeCapSoul, id=time_capsoul_id, user = user)
        capsoul.is_deleted = True
        capsoul.save()
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
            time_capsoul = TimeCapSoul.objects.get(id=time_capsoul_id, user=user, is_deleted = False)

        except TimeCapSoul.DoesNotExist:
            # --- Case 2: Tagged recipient ---
            time_capsoul = self.get__tagged_time_capsoul(time_capsoul_id)

            # if p.status != 'unlocked':
            #     logger.info("Tagged recipient not allowed: capsoul locked")
            #     return Response({"media_files": []}, status=status.HTTP_404_NOT_FOUND)

           
            recipient = TimeCapSoulRecipient.objects.filter(time_capsoul = time_capsoul, email = user.email).first()
            if not recipient:
                logger.info("Recipient not found for tagged capsoul")
                return Response({"media_files": []}, status=status.HTTP_404_NOT_FOUND)
            
            if time_capsoul.unlock_date and timezone.now() < time_capsoul.unlock_date:
                logger.info("Recipient not found for tagged capsoul")
                return Response({"media_files": []}, status=status.HTTP_404_NOT_FOUND)


            media_files = TimeCapSoulMediaFile.objects.filter(time_capsoul=time_capsoul, is_deleted =False)

        else:
            # If owner, also include replica parent files (excluding already linked ones)
            media_files = TimeCapSoulMediaFile.objects.filter(time_capsoul=time_capsoul, is_deleted =False)

            if time_capsoul.capsoul_replica_refrence:
                parent_files = TimeCapSoulMediaFile.objects.filter(
                    time_capsoul=time_capsoul.capsoul_replica_refrence
                )
                used_ids = media_files.values_list("media_refrence_replica_id", flat=True)
                media_files = media_files | parent_files.exclude(id__in=used_ids)

        serializer = TimeCapSoulMediaFileReadOnlySerializer(media_files.distinct(), many=True)
        return Response({"media_files": serializer.data})

    
    def post(self, request, time_capsoul_id):
        """
        Upload multiple media files to a TimeCapSoul with streaming progress updates.
        Each file has its own IV for decryption. Uses multi-threading for parallel uploads.
        """
        user = self.get_current_user(request)
        time_capsoul = get_object_or_404(TimeCapSoul, id=time_capsoul_id, user=user)
        replica_instance = None
        
        if time_capsoul.status == 'unlocked':
            # create  replica here
            try:
                replica_instance = TimeCapSoul.objects.get(capsoul_replica_refrence = time_capsoul)
            except TimeCapSoul.DoesNotExist as e:
                # create custom template for replica
                from django.utils import timezone

                created_at = timezone.localtime(timezone.now())
                template = time_capsoul.capsoul_template
                replica_template = CustomTimeCapSoulTemplate.objects.create(
                    name = template.name + '(1)',
                    summary = template.summary,
                    cover_image = template.cover_image,
                    default_template = time_capsoul.capsoul_template.default_template,
                    created_at = created_at
                )
                replica_template.slug = generate_unique_slug(replica_template)
                replica_instance = TimeCapSoul.objects.create(
                    user = user,
                    capsoul_template=replica_template,
                    status = 'created',
                    capsoul_replica_refrence = time_capsoul,
                    created_at = created_at
                )
        
        if replica_instance:
            time_capsoul = replica_instance
            

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
            def process_single_file(file_index, uploaded_file, file_iv):
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
                        update_time_capsoul_occupied_storage.apply_async( 
                            args=[media_file.id, 'addition'],
                        )
                        update_user_storage(
                            user=user,
                            media_id=media_file.id,
                            file_size=media_file.file_size,
                            cache_key=f'user_storage_id_{user.id}',
                            operation_type='addition'
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
                    executor.submit(process_single_file, i, files[i], ivs[i]): i
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

                    time.sleep(0.1)

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
        time_capsoul = get_object_or_404(TimeCapSoul, id=capsoul_id, user=user)
        media_file = get_object_or_404(TimeCapSoulMediaFile, id=media_file_id, user=user)
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
                    default_template = time_capsoul.capsoul_template.default_template
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
            if not time_capsoul.capsoul_template.default_template:
                custom_template = time_capsoul.capsoul_template
                
                if title:
                    capsoul_template.name = title
                    
                if summary:
                    capsoul_template.summary = summary
                
                if bool(set_as_cover) == True:
                    if media_file.file_type == 'image':
                        file_bytes,content_type = decrypt_and_get_image(str(media_file.s3_key))
                        s3_key, url = save_and_upload_decrypted_file(filename='', decrypted_bytes=file_bytes, bucket='time-capsoul-files', content_type=content_type)
                        assets_obj = Assets.objects.create(image = media_file.file, s3_url=url, s3_key=s3_key)
                        # custom_template = time_capsoul.capsoul_template
                        custom_template.cover_image = assets_obj
                        media_file.is_cover_image = True
                        media_file.save()
                custom_template.save()
                
            else:
                return Response({'message': "Time can not be updated its default template"})


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
        user = self.get_current_user(request)
        media_file = get_object_or_404(TimeCapSoulMediaFile, id=media_file_id, user=user)
        time_capsoul  = media_file.time_capsoul
        if time_capsoul.status != 'unlocked':
            # media_file.delete()
            media_file.is_deleted = True
            media_file.save()
            update_time_capsoul_occupied_storage.apply_async( 
                args=[media_file.id, 'remove'],
            )
            update_user_storage(
                user=user,
                media_id=media_file.id,
                file_size=media_file.file_size,
                cache_key=f'user_storage_id_{user.id}',
                operation_type='remove'
            )
            return Response({'message': 'Time Capsoul media deleted successfully'})
        return Response({'message': 'Soory Time capsoul media files cant be deleted'})

    
    def patch(self, request, time_capsoul_id, media_file_id):
        user = self.get_current_user(request)
        # time_capsoul = get_object_or_404(TimeCapSoul, id=time_capsoul_id)
        media_file = get_object_or_404(TimeCapSoulMediaFile, id=media_file_id, user=user, is_deleted = False)
        serializer = TimeCapsoulMediaFileUpdationSerializer(instance = media_file, data=request.data, partial = True)
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

class ServeTimeCapSoulMedia(SecuredView):
    """
    Securely serve decrypted media from S3 via Django.
    """
    def get(self, request, s3_key, media_file_id=None):
        exp = request.GET.get("exp")
        sig = request.GET.get("sig")
        user = self.get_current_user(request)
        if not exp or not sig:
            return Response(status=status.HTTP_404_NOT_FOUND)

        if int(exp) < int(time.time()):
            return Response(status=status.HTTP_404_NOT_FOUND)
       
        
        
        if user is None:
            return Response(status=status.HTTP_401_UNAUTHORIZED)
        try:
            # check time-capsoul user ownership
            media_file = TimeCapSoulMediaFile.objects.get(id=media_file_id, user=user)
        except TimeCapSoulMediaFile.DoesNotExist:
            # check time-capsoul tagged-list
            try:
                media_file = TimeCapSoulMediaFile.objects.get(id=media_file_id)
            except Exception as e:
                return Response(status=status.HTTP_404_NOT_FOUND)
            else:
                #  signature-verification
                if not verify_signature(media_file.s3_key, exp, sig):
                    return Response(status=status.HTTP_404_NOT_FOUND)
                
                time_capsoul = media_file.time_capsoul
                
            capsoul_recipients = TimeCapSoulRecipient.objects.filter(time_capsoul=time_capsoul, email = user.email).first()
            if not capsoul_recipients:
                return Response(status=status.HTTP_404_NOT_FOUND)

        except Exception:
            return Response(status=status.HTTP_404_NOT_FOUND)

        bytes_cache_key = media_file.s3_key
        file_bytes = cache.get(bytes_cache_key)
        
        content_type_cache_key = f'{bytes_cache_key}_type'
        content_type = cache.get(content_type_cache_key)
        
        if not file_bytes or  not content_type:
            try:
                file_bytes, content_type = decrypt_and_get_image(str(media_file.s3_key))
            except Exception as e:
                file_bytes, content_type  = decrypt_and_replicat_files(str(media_file.s3_key))
            except Exception as e:
                return Response(status=status.HTTP_404_NOT_FOUND)
            else:
                # caching here
                cache.set(bytes_cache_key, file_bytes, timeout=None)  
                cache.set(content_type_cache_key, content_type, timeout=None)

                
        if media_file.s3_key.lower().endswith(".doc"):
            try:
                
                docx_bytes_cache_key = f'{bytes_cache_key}_docx_preview'
                docx_bytes = cache.get(docx_bytes_cache_key)
                
                if not docx_bytes:
                    docx_bytes = convert_doc_to_docx_bytes(file_bytes, media_file_id=media_file.id, email=user.email)
                    cache.set(docx_bytes_cache_key, docx_bytes, timeout=None)  
                    
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
                    cache.set(jpeg_cache_key, jpeg_file_bytes, timeout=None)
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
                        cache.set(cache_key, mp4_bytes, timeout=None)
                    except Exception as e:
                        logger.error(f"MKV conversion failed: {e} for {user.email} media-id: {media_file.id}")
                        return Response(status=status.HTTP_500_INTERNAL_SERVER_ERROR)

                download_name = media_file.s3_key.split("/")[-1]
                download_name = download_name.replace(".mkv", ".mp4")
                response = HttpResponse(mp4_bytes, content_type="mp4")
                frame_ancestors = " ".join(settings.CORS_ALLOWED_ORIGINS)
                response["Content-Security-Policy"] = f"frame-ancestors 'self' {frame_ancestors};"
                response["Content-Disposition"] = f'inline; filename="{download_name}"'
                return response

            else:
                # 🔹 All other files
                response = HttpResponse(file_bytes, content_type=content_type)
                frame_ancestors = " ".join(settings.CORS_ALLOWED_ORIGINS)
                response["Content-Security-Policy"] = f"frame-ancestors 'self' {frame_ancestors};"
                response["Content-Disposition"] = f'inline; filename="{media_file.s3_key.split("/")[-1]}"'
                return response



class TimeCapSoulMediaFileDownloadView(SecuredView):
    def get(self, request, timecapsoul_id, media_file_id):
        """
        Download a media file from a TimeCapSoul securely.
        """
        user = self.get_current_user(request)
        if user is None:
            return Response(status=status.HTTP_401_UNAUTHORIZED)
        try:
            media_file =  TimeCapSoulMediaFile.objects.get(id = media_file_id, user=user)
        except TimeCapSoulMediaFile.DoesNotExist:
            try:
                media_file =  TimeCapSoulMediaFile.objects.get(id = media_file_id)
            except Exception as e:
                return Response(status=status.HTTP_404_NOT_FOUND)
            else:
                time_capsoul = media_file.time_capsoul
                
                if time_capsoul:
                    capsoul_recipients = TimeCapSoulRecipient.objects.filter(time_capsoul=time_capsoul, email = user.email).first()
                    if not capsoul_recipients:
                        return Response(status=status.HTTP_404_NOT_FOUND)

                    # recipients_data = list(capsoul_recipients.recipients.values_list("email", flat=True))
                    # if user.email not in recipients_data:
                    #     return Response(status=status.HTTP_404_NOT_FOUND)
                    
        # file_name = media_file.s3_key.split('/')[-1]
        file_name  = f'{media_file.title.split(".", 1)[0].replace(" ", "_")}.{media_file.s3_key.split(".")[-1]}'
        # print(f'\nfile-name: {file_name}  {media_file.title.split(".", 1)[0].replace(" ", "_")}.{media_file.s3_key.split(".")[-1]}')
        
        bytes_cache_key = str(media_file.s3_key)
        file_bytes = cache.get(bytes_cache_key)
        
        content_type_cache_key = f'{bytes_cache_key}_type'
        content_type = cache.get(content_type_cache_key)
        
        if not file_bytes or  not content_type:
            try:
                file_bytes, content_type = decrypt_and_get_image(str(media_file.s3_key))
            except Exception as e:
                file_bytes, content_type  = decrypt_and_replicat_files(str(media_file.s3_key))
            except Exception as e:
                logger.error(f'Exception while serving media file to user: {user.email} capsoul media-id: {media_file.id} as \n error message: {e}')
                return Response(status=status.HTTP_500_INTERNAL_SERVER_ERROR)
            else:
                # caching here
                cache.set(bytes_cache_key, file_bytes, timeout=None)  
                cache.set(content_type_cache_key, content_type, timeout=None)
        
        if file_bytes and content_type:
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

            except ClientError as e:
                return Response(status=status.HTTP_404_NOT_FOUND)
        else:
            return Response(status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class TaggedCapsoulTracker(SecuredView):
    
    def post(self, request, capsoul_id, format=None):
        
        user = self.get_current_user(request)
        capsoul_recipient = get_object_or_404(
            TimeCapSoulRecipient,
            time_capsoul__id=capsoul_id,
            email=user.email
        )

        serializer = TimeCapSoulRecipientUpdateSerializer(
            capsoul_recipient,
            data=request.data,
            partial=True  
        )
        
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_200_OK)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class UserStorageTracker(SecuredView):
    
    def get(self, request, format=None):
        user = self.get_current_user(request)
        logger.info(f"UserStorageTracker  called {user.email}")
        user_tracker_cache_key= f'user_storage_id_{user.id}'
        user_storage_data = cache.get(user_tracker_cache_key)
        if not user_storage_data:
            try:
                user_mapper = user.user_mapper.first() 
                total_space_occupied = 0
                user_storage_limit = parse_into_mbs(user_mapper.max_storage_limit)
                user_storage_limit = to_gb(user_storage_limit[0], user_storage_limit[-1])
                
                
                user_storage_data= {
                    'user_storage_limit': user_storage_limit,
                    'free_storage': 0,
                    'current_used_storage': 0,
                    'storage_usage_percentage': 0,
                    'images': {
                        'percentge': 0,
                        'amount': 0
                    },
                    'videos': {
                        'percentge': 0,
                        'amount': 0
                    },
                    'documents': {
                        'percentge': 0,
                        'amount': 0
                    },
                    'audio': {
                        'percentge': 0,
                        'amount': 0
                    },
                }
                
                user_capsouls = TimeCapSoul.objects.filter(user = user, is_deleted = False)
                memory_room = MemoryRoom.objects.filter(user= user, is_deleted = False)
                logger.info(f"UserStorageTracker  storage callculation started {user.email}")
                
                
                for capsoul in user_capsouls: # time-capsoul files calculations
                    media_files = capsoul.timecapsoul_media_files.filter(is_deleted = False)
                    for media in media_files: 
                        file_size = parse_into_mbs(media.file_size)
                        file_size = to_gb(file_size[0], file_size[-1])
                        total_space_occupied += file_size
                        
                        if media.file_type == 'image':
                            user_storage_data['images']['amount'] += file_size
                            
                        elif media.file_type == 'video':
                            user_storage_data['videos']['amount'] += file_size
                        
                        elif media.file_type == 'audio':
                            user_storage_data['audio']['amount'] += file_size
                            
                        else:
                            user_storage_data['documents']['amount'] += file_size
                
                for capsoul in memory_room:   # memory-room file calculations
                    media_files = capsoul.memory_media_files.filter(is_deleted=False)
                    for media in media_files: 
                        # file_size = parse_into_mbs(media.file_size)[0]
                        file_size = parse_into_mbs(media.file_size)
                        file_size = to_gb(file_size[0], file_size[-1])
                        
                        
                        total_space_occupied += file_size
                        
                        if media.file_type == 'image':
                            user_storage_data['images']['amount'] += file_size
                            
                        elif media.file_type == 'video':
                            user_storage_data['videos']['amount'] += file_size
                        
                        elif media.file_type == 'audio':
                            user_storage_data['audio']['amount'] += file_size
                            
                        else:
                            user_storage_data['documents']['amount'] += file_size
                            
                logger.info(f"UserStorageTracker  storage callculation completed {user.email}")
                
                user_storage_data['images']['percentge'] = round((user_storage_data['images']['amount']*100)/user_storage_limit, 3)
                user_storage_data['videos']['percentge'] = round((user_storage_data['videos']['amount']*100)/user_storage_limit, 3)
                user_storage_data['documents']['percentge'] = round((user_storage_data['documents']['amount']*100)/user_storage_limit, 3)
                user_storage_data['audio']['percentge'] = round((user_storage_data['audio']['amount']*100)/user_storage_limit, 3)
                
                user_storage_data['current_used_storage'] = round(total_space_occupied, 5)
                user_storage_data['free_storage'] = round(user_storage_limit - total_space_occupied, 5)
                user_storage_data['storage_usage_percentage'] = round(( total_space_occupied * 100  )/user_storage_limit, 3)
                cache.set(user_tracker_cache_key, user_storage_data, timeout=None)
                
            except Exception as e:
                logger.error(f'Exception occur at UserStorageTracker  while getting storage data for {user.email} error-message: \n {e}')
                
            
        logger.info(f"UserStorageTracker  data served {user.email}")
        return Response(user_storage_data)


def create_duplicate_time_capsoul(time_capsoul:TimeCapSoul):
    from django.utils import timezone
    new_capsoul = None
    logger.info(f'Timecapsoul duplication creation started for user: {time_capsoul.user.email} capsoul-id: {time_capsoul.id}')
    try:
        duplicate_capsoul = TimeCapSoul.objects.filter(room_duplicate = time_capsoul, is_deleted = False)
        capsoul_duplication_number = f' ({1 + duplicate_capsoul.count()})'
        
        # create duplicate room here
        created_at = timezone.localtime(timezone.now())
        old_capsoul_template = time_capsoul.capsoul_template
        new_custom_template  =  CustomTimeCapSoulTemplate.objects.create(
            name= old_capsoul_template.name + capsoul_duplication_number,
            slug = old_capsoul_template,
            summary = old_capsoul_template.summary,
            cover_image = old_capsoul_template.cover_image,
            default_template = old_capsoul_template.default_template,
            created_at = created_at
        )
        
        new_capsoul = TimeCapSoul.objects.create(
            user = time_capsoul.user,
            capsoul_template = new_custom_template,
            room_duplicate = time_capsoul,
            created_at = created_at
        )
        
    except Exception as e:
        logger.error(f'Exception while create duplicate capsoul for {time_capsoul.user.email} capsoul id: {time_capsoul.id}')
    else:
        try:
            # now create duplicate media files here
            # media_files = TimeCapSoulMediaFile.objects.filter(user = time_capsoul.user, time_capsoul = time_capsoul, is_deleted =False)
            media_files = TimeCapSoulMediaFile.objects.filter(
                user=time_capsoul.user,
                time_capsoul=time_capsoul,
                is_deleted=False
            )   # reverse by primary key (latest first)
            
            for media in media_files:
                try:
                    new_media = TimeCapSoulMediaFile.objects.create(
                        user = media.user,
                        time_capsoul = new_capsoul,
                        thumbnail = media.thumbnail,
                        media_refrence_replica = None,
                        media_duplicate = media,
                        file = media.file,
                        file_type = media.file_type,
                        title = media.title,
                        description = media.description,
                        file_size = media.file_size,
                        s3_url = media.s3_url,
                        s3_key = media.s3_key,
                        is_cover_image = media.is_cover_image,
                        
                        created_at = created_at
                    )
                except Exception as e:
                    logger.error(f'Exception while creating media file duplicate for media: {media.id} and capsoul: {time_capsoul.id} user: {time_capsoul.user.email}')
            
            logger.info(f'Capsoul duplication creation completed for user: {time_capsoul.user.email} room-id: {time_capsoul.id}')
        
        except Exception as e:
            logger.error(f'Exception while creating room media duplica for {time_capsoul.id}')
        
        return new_capsoul
    
    
  
      
class TimeCapsoulDuplicationApiView(SecuredView):
    
    def post(self, request, time_capsoul_id, format=None):
        user  = self.get_current_user(request)
        logger.info(f'TimeCapsoulDuplicationApiView is called by {user.email} capsoul-id: {time_capsoul_id}')
        time_capsoul = get_object_or_404(TimeCapSoul, id=time_capsoul_id, user = user)
        if time_capsoul.status == 'created': 
            duplicate_room = create_duplicate_time_capsoul(time_capsoul)
            serializer = TimeCapSoulSerializer(duplicate_room, context = {'user': user})
            logger.info(f'Caposul  duplicate created successfully for capsoul: old {time_capsoul_id} new: {duplicate_room.id} for user {user.email} ')
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response({'message': "Only timecapsoul with status crafted can create duplicates"})
        
        