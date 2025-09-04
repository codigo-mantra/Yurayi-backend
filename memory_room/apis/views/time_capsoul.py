import boto3,mimetypes
from rest_framework.parsers import MultiPartParser
from django.shortcuts import get_object_or_404
from rest_framework import generics, permissions, status
from rest_framework.response import Response
from botocore.exceptions import ClientError
from django.conf import settings
from django.http import StreamingHttpResponse, Http404,HttpResponse, JsonResponse, HttpResponseNotFound
from memory_room.utils import determine_download_chunk_size
from rest_framework.pagination import PageNumberPagination
from rest_framework.exceptions import ValidationError
from rest_framework import serializers
import json,io
import hmac
import hashlib
import base64
import time
from django.http import HttpResponseForbidden, HttpResponseRedirect,Http404
from memory_room.utils import upload_file_to_s3_bucket, get_file_category, generate_unique_slug

from userauth.models import Assets
from userauth.apis.views.views import SecuredView,NewSecuredView


from memory_room.apis.serializers.memory_room import (
    AssetSerializer,
)

from memory_room.models import (
    TimeCapSoulTemplateDefault, TimeCapSoul, TimeCapSoulDetail, TimeCapSoulMediaFile,RecipientsDetail,
    TimeCapSoulReplica, TimeCapSoulMediaFileReplica,TimeCapSoulRecipient,FILE_TYPES, CustomTimeCapSoulTemplate
    )

from memory_room.apis.serializers.time_capsoul import (
    TimeCapSoulTemplateDefaultReadOnlySerializer, TimeCapSoulCreationSerializer,TimeCapSoulMediaFileReadOnlySerializer,
    TimeCapSoulSerializer, TimeCapSoulUpdationSerializer,TimeCapSoulMediaFileSerializer,TimeCapSoulMediaFilesReadOnlySerailizer, TimeCapsoulMediaFileUpdationSerializer,
    TimeCapsoulUnlockSerializer, TimeCapsoulUnlockSerializer,RecipientsDetailSerializer,TimecapSoulReplicaMediaFileCreation,TimeCapSoulMediaFileReplicaSerializer,TimeCapSoulMediaFileReadOnlySerializer
)
from memory_room.crypto_utils import encrypt_and_upload_file, decrypt_and_get_image, save_and_upload_decrypted_file, decrypt_and_replicat_files, generate_signature, verify_signature


class TimeCapSoulCoverView(SecuredView):
    """
    API endpoint to list all assets of type 'Time CapSoul Cover'.
    Only authenticated users can access this.
    """

    def get(self):
        """
        Returns all Time CapSoul Cover assets ordered by creation date.
        """
        assets = Assets.objects.filter(asset_types='Time CapSoul Cover').order_by('-created_at')
        serializer = AssetSerializer(assets, many=True)
        return Response(serializer.data)

    


class TimeCapSoulDefaultTemplateAPI(SecuredView):

    

    def get(self, request, format=None):
        default_templates = TimeCapSoulTemplateDefault.objects.filter(is_deleted = False)
        serializer = TimeCapSoulTemplateDefaultReadOnlySerializer(default_templates, many=True)
        return Response(serializer.data)
        

class CreateTimeCapSoulView(SecuredView):
    """
    API view to create, update, or delete a time-capsoul.
    Inherits authentication logic from `SecuredView`.
    """
    def get_time_capsoul(self, user, time_capsoul_id):
        """
        Utility method to get a time capsoul owned by the user.
        """
        return get_object_or_404(TimeCapSoul, id=time_capsoul_id, user=user)


    def post(self, request, format=None):
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
        """Time CapSoul list"""
        user = self.get_current_user(request)
        time_capsouls = TimeCapSoul.objects.filter(user=user)
        try:
            tagged_time_capsouls = TimeCapSoul.objects.filter(
                recipient_details__recipients__email=user.email
            )
        except TimeCapSoulRecipient.DoesNotExist:
            tagged_time_capsouls = None
        # else:
            # time_capsouls = time_capsouls + tagged_time_capsouls

        # Get all replicas in one query (instead of loop)
        time_capsoul_replicas = TimeCapSoul.objects.filter(
            user=user,
            capsoul_replica_refrence__in=time_capsouls
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
        user = self.get_current_user(request)
        time_capsoul = get_object_or_404(TimeCapSoul, id=time_capsoul_id, user = user)
        serializer = TimeCapSoulUpdationSerializer(instance = time_capsoul, data=request.data, partial = True)
        if serializer.is_valid():
            update_time_capsoul = serializer.save()
            return Response(TimeCapSoulSerializer(update_time_capsoul, context={'user': user}).data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    def delete(self, request, time_capsoul_id):
        user = self.get_current_user(request)
        time_capsoul_detail = get_object_or_404(TimeCapSoulDetail, time_capsoul__id=time_capsoul_id, time_capsoul__user = user)

        if time_capsoul_detail.is_locked:
            return Response({'message': 'Soory Time capsoul is locked it cant be deleted'})
        else:
            time_capsoul_detail.delete()
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
        """
        List all media files of a time-capsoul.
        """
        user = self.get_current_user(request)

        # if user is Owner of the time-capsoul 
        try:
            time_capsoul = TimeCapSoul.objects.get(id=time_capsoul_id, user=user)

        except TimeCapSoul.DoesNotExist:
            # --- Case 2: Tagged recipient ---
            time_capsoul = self.get__tagged_time_capsoul(time_capsoul_id)

            if time_capsoul.status != 'unlocked':
                return Response({"media_files": []}, status=status.HTTP_404_NOT_FOUND)

            recipients = (
                RecipientsDetail.objects
                .filter(time_capsoul=time_capsoul)
                .values_list("recipients__email", flat=True)
            )

            if user.email not in recipients:
                return Response({"media_files": []}, status=status.HTTP_404_NOT_FOUND)

            media_files = TimeCapSoulMediaFile.objects.filter(time_capsoul=time_capsoul)

        else:
            # If owner, also include replica parent files (excluding already linked ones)
            media_files = TimeCapSoulMediaFile.objects.filter(time_capsoul=time_capsoul)

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
        Each file has its own IV for decryption.
        """
        user = self.get_current_user(request)
        time_capsoul = get_object_or_404(TimeCapSoul, id=time_capsoul_id, user=user)

        files = request.FILES.getlist('file')
        created_objects = []
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

        def file_upload_stream():
            for index, uploaded_file in enumerate(files):
                file_iv = ivs[index]
                yield f"data: Starting upload of {uploaded_file.name}\n\n"
                file_size = uploaded_file.size
                chunk_size = determine_download_chunk_size(file_size)  # same helper determine chunk size
                uploaded_so_far = 0
                percentage = 0

                try:
                    # Read file chunks and send progress updates
                    for chunk in uploaded_file.chunks(chunk_size):
                        uploaded_so_far += len(chunk)
                        new_percentage = int((uploaded_so_far / file_size) * 100)
                        if new_percentage > percentage:
                            percentage = new_percentage
                            yield f"data: {uploaded_file.name} -> {percentage}\n\n"

                    # Reset file pointer before saving
                    uploaded_file.seek(0)
                    serializer = TimeCapSoulMediaFileSerializer(
                        data={
                            'file': uploaded_file,
                            'iv': file_iv
                        },
                        context={'user': user, 'time_capsoul': time_capsoul}
                    )
                    if serializer.is_valid():
                        media_file = serializer.save()
                        created_objects.append(media_file)
                        results.append({
                            "file": uploaded_file.name,
                            "status": "success",
                            "progress": 100,
                            "data": TimeCapSoulMediaFileReadOnlySerializer(media_file).data
                        })
                        yield f"data: {uploaded_file.name} -> 100\n\n"
                        yield f"data: {uploaded_file.name} upload completed successfully\n\n"
                    else:
                        results.append({
                            "file": uploaded_file.name,
                            "status": "failed",
                            "progress": percentage,
                            "errors": serializer.errors
                        })
                        yield f"data: {uploaded_file.name} upload failed: {json.dumps(serializer.errors)}\n\n"

                except Exception as e:
                    results.append({
                        "file": uploaded_file.name,
                        "status": "failed",
                        "progress": percentage,
                        "error": str(e)
                    })
                    yield f"data: {uploaded_file.name} upload failed: {str(e)}\n\n"

            # Send final results
            yield f"data: FINAL_RESULTS::{json.dumps(results)}\n\n"

        return StreamingHttpResponse(
            file_upload_stream(),
            content_type='text/event-stream',
            status=status.HTTP_200_OK
        )

    
    # def post(self, request, time_capsoul_id):
    #     """
    #     Upload multiple media files to a time-capsoul room.
    #     """
    #     user = self.get_current_user(request)
    #     time_capsoul_detail = get_object_or_404(TimeCapSoulDetail, time_capsoul__id=time_capsoul_id)
    #     if not time_capsoul_detail.is_locked:
    #         files = request.FILES.getlist('file')
    #         if len(files)  == 0:
    #             return Response({'message': "Files are required to upload in time-capsoul"})
    #         else:
    #             created_objects = []

    #             for uploaded_file in files:
    #                 serializer = TimeCapSoulMediaFileSerializer(
    #                     data={**request.data, 'file': uploaded_file},
    #                     context={'user': user, 'time_capsoul': time_capsoul_detail.time_capsoul}
    #                 )
    #                 if serializer.is_valid():
    #                     media_file = serializer.save()
    #                     created_objects.append(media_file)
    #                 else:
    #                     return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    #             return Response(
    #                 TimeCapSoulMediaFileReadOnlySerializer(created_objects, many=True).data,
    #                 status=status.HTTP_201_CREATED
    #             )
    #     else:
    #         return Response({'message': 'Soory Time capsoul is locked now media files uploads not applicable'})


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
                print(f'Exception while creating time-capsoul replica as: {e}')
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

        old_time_capsoul = get_object_or_404(TimeCapSoul, id=old_cap_soul_id, user=user)
        new_time_capsoul = get_object_or_404(TimeCapSoul, id=new_capsoul_id, user=user)
        
        if old_time_capsoul.status == 'created' and new_time_capsoul.status == 'created':
            media_file = get_object_or_404(TimeCapSoulMediaFile, id=media_file_id, user=user, time_capsoul=old_time_capsoul)
            # Remove from old TimeCapsoul's related set
            old_time_capsoul.details.media_files.remove(media_file)
            # Add to new TimeCapsoul's related set
            new_time_capsoul.details.media_files.add(media_file)

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
        return get_object_or_404(TimeCapSoul, id=time_capsoul_id, user=user)
    
    


    def delete(self, request, time_capsoul_id, media_file_id):
        """Delete time-capsoul media file"""
        user = self.get_current_user(request)
        media_file = get_object_or_404(TimeCapSoulMediaFile, id=media_file_id, user=user)
        time_capsoul  = media_file.time_capsoul
        if time_capsoul.status == 'created':
            media_file.delete()
            return Response({'message': 'Time Capsoul media deleted successfully'})
        return Response({'message': 'Soory Time capsoul media files cant be deleted'})

    
    def patch(self, request, time_capsoul_id, media_file_id):
        user = self.get_current_user(request)
        # time_capsoul = get_object_or_404(TimeCapSoul, id=time_capsoul_id)
        media_file = get_object_or_404(TimeCapSoulMediaFile, id=media_file_id, user=user)
        serializer = TimeCapsoulMediaFileUpdationSerializer(instance = media_file, data=request.data, partial = True)
        serializer.is_valid(raise_exception=True)
        # update_media_file = serializer.validated_data.get('instance')
        update_media_file = serializer.save()
        return Response(TimeCapSoulMediaFileReadOnlySerializer(update_media_file).data)


class ReplicaTimeCapSoulMediaFileUpdationView(SecuredView):

    


    def delete(self, request,  replica_media_file_id):
        """Delete time-capsoul media file"""
        user = self.get_current_user(request)
        replica_media_file = get_object_or_404(TimeCapSoulMediaFileReplica, id=replica_media_file_id)



        # time_capsoul_detail = get_object_or_404(TimeCapSoulDetail, time_capsoul__id=time_capsoul_id)
        # if time_capsoul_detail.is_locked:
        #     return Response({'message': 'Soory Time capsoul is locked its media files cant be deleted'})
        # else:
        #     media_file = get_object_or_404(TimeCapSoulMediaFile, id=media_file_id, user=user, time_capsoul=time_capsoul_detail.time_capsoul)
        #     media_file.delete()
        #     return Response({'message': 'Time Capsoul media deleted successfully'})

    
    def patch(self, request, replica_media_file_id):
        user = self.get_current_user(request)
        media_file = get_object_or_404(TimeCapSoulMediaFileReplica, id=replica_media_file_id)
        # create new replica here
        title = request.data.get('title', media_file.title)
        set_as_cover = request.data.get('set_as_cover', False)
        description = request.data.get('description', media_file.description)


        if bool(set_as_cover) == True:
            if media_file.file_type == 'image':
                # updating time-capsoul replica
                media_s3_key =  str(media_file.s3_key)
                file_name = media_s3_key.split('/')[-1]
                file_bytes,content_type = decrypt_and_get_image(media_s3_key) # image get from s3
                s3_key, url = save_and_upload_decrypted_file(filename=file_name, decrypted_bytes=file_bytes, bucket='time-capsoul-files', content_type=content_type)
                assets_obj = Assets.objects.create(image = media_file.file, s3_key = s3_key, s3_url = url)
                # media_file.
        

        media_replica = TimeCapSoulMediaFileReplica.objects.create(
        user = user,
        file = media_file.file,
        file_type= media_file.file_type,
        title = title,
        file_size = media_file.file_size,
        description = description,
        s3_url = assets_obj.s3_key,
        s3_key = assets_obj.s3_url,
        is_cover_image = True,
        thumbnail = media_file.thumbnail,
        parent_media_file = media_file,
    )
    # media_replica.save()

        
        

        # user = self.get_current_user(request)
        # # time_capsoul = get_object_or_404(TimeCapSoul, id=time_capsoul_id)
        # media_file = get_object_or_404(TimeCapSoulMediaFile, id=media_file_id, user=user)
        # serializer = TimeCapsoulMediaFileUpdationSerializer(instance = media_file, data=request.data, partial = True)
        # serializer.is_valid(raise_exception=True)
        # update_media_file = serializer.save()
        # return Response(TimeCapSoulMediaFileReadOnlySerializer(update_media_file).data)



class TimeCapSoulUnlockView(SecuredView):

    def post(self, request, time_capsoul_id):
        user = self.get_current_user(request)
        try:
            time_capsoul_detail = TimeCapSoulDetail.objects.get(
                time_capsoul__id=time_capsoul_id,
                time_capsoul__user=user
            )
        except TimeCapSoulDetail.DoesNotExist:
            return Response({"error": "TimeCapsoul not found."}, status=status.HTTP_404_NOT_FOUND)

        serializer = TimeCapsoulUnlockSerializer(
            instance=time_capsoul_detail,
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

        try:
            recipients_detail = RecipientsDetail.objects.get(time_capsoul=time_capsoul)
            serializer = RecipientsDetailSerializer(recipients_detail)
            return Response(serializer.data, status=status.HTTP_200_OK)
        except RecipientsDetail.DoesNotExist:
            return Response({"message": "No recipients found for this Time Capsule."}, status=status.HTTP_404_NOT_FOUND)

    def post(self, request, time_capsoul_id):
        """
        Create a new RecipientsDetail for a given TimeCapSoul.
        """
        user = self.get_current_user(request)
        time_capsoul = get_object_or_404(TimeCapSoul, id=time_capsoul_id, user=user)

        serializer = RecipientsDetailSerializer(data=request.data, context={'time_capsoul': time_capsoul})
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
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

        queryset = TimeCapSoulMediaFileReplica.objects.filter(**media_filters)

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
                return Response(status=status.HTTP_401_UNAUTHORIZED)
            else:
                time_capsoul = media_file.time_capsoul
                
            capsoul_recipients = RecipientsDetail.objects.filter(time_capsoul=time_capsoul).first()
            if not capsoul_recipients:
                return Response(status=status.HTTP_401_UNAUTHORIZED)

            recipients_data = list(capsoul_recipients.recipients.values_list("email", flat=True))
            if user.email not in recipients_data:
                return Response(status=status.HTTP_401_UNAUTHORIZED)
        except Exception:
            return Response(status=status.HTTP_401_UNAUTHORIZED)

        

        if not exp or not sig:
            return Response(status=status.HTTP_401_UNAUTHORIZED)

        if int(exp) < int(time.time()):
            return Response(status=status.HTTP_401_UNAUTHORIZED)
       
        #  signature-verification
        if not verify_signature(media_file.s3_key, exp, sig):
            return Response(status=status.HTTP_401_UNAUTHORIZED)

        try:
            file_bytes, content_type = decrypt_and_get_image(str(media_file.s3_key))
        except Exception as e:
            file_bytes, content_type  = decrypt_and_replicat_files(str(media_file.s3_key))
        except Exception as e:
            return Response(status=status.HTTP_401_UNAUTHORIZED)

        response = HttpResponse(file_bytes, content_type=content_type)
        # response["Content-Disposition"] = f'inline; filename="{media_file.s3_key.split("/")[-1].replace(".enc", "")}"'
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
                return Response(status=status.HTTP_401_UNAUTHORIZED)
            else:
                time_capsoul = media_file.time_capsoul
                
                if time_capsoul:
                    capsoul_recipients = RecipientsDetail.objects.filter(time_capsoul=time_capsoul).first()
                    if not capsoul_recipients:
                        return Response(status=status.HTTP_401_UNAUTHORIZED)

                    recipients_data = list(capsoul_recipients.recipients.values_list("email", flat=True))
                    if user.email not in recipients_data:
                        return Response(status=status.HTTP_401_UNAUTHORIZED)
                    
        file_name = media_file.s3_key.split('/')[-1]
        try:
            file_bytes, content_type = decrypt_and_get_image(str(media_file.s3_key))
        except Exception as e:
            file_bytes, content_type  = decrypt_and_replicat_files(str(media_file.s3_key))
        except Exception as e:
            return Response(status=status.HTTP_401_UNAUTHORIZED)
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
            return Response(status=status.HTTP_401_UNAUTHORIZED)


            
            
       
                
                
            
            
            
        
        # timecapsoul = get_object_or_404(TimeCapSoul, id=timecapsoul_id, user=user)
        # media_file = get_object_or_404(
        #     TimeCapSoulMediaFile,
        #     id=media_file_id,
        #     user=user,
        #     time_capsoul=timecapsoul
        # )
        # file_name = media_file.title
        # file_bytes,content_type = decrypt_and_get_image(str(media_file.s3_key))
        
        # s3 = boto3.client(
        #     's3',
        #     aws_access_key_id=settings.AWS_ACCESS_KEY_ID,
        #     aws_secret_access_key=settings.AWS_SECRET_ACCESS_KEY,
        #     region_name=settings.AWS_S3_REGION_NAME
        # )

        # try:
            # s3_response = s3.get_object(Bucket=settings.AWS_STORAGE_BUCKET_NAME, Key=s3_key)
            # file_stream = s3_response['Body']
            # file_size = s3_response['ContentLength']
        #     file_size = len(file_bytes)
        #     chunk_size = determine_download_chunk_size(file_size)
        #     file_stream = io.BytesIO(file_bytes)

        #     mime_type = (
        #         content_type
        #         or mimetypes.guess_type(file_name)[0]
        #         or 'application/octet-stream'
        #     )

        #     def file_iterator():
        #         while True:
        #             chunk = file_stream.read(chunk_size)
        #             if not chunk:
        #                 break
        #             yield chunk

        #     response = StreamingHttpResponse(
        #         streaming_content=file_iterator(),
        #         content_type=mime_type
        #     )
        #     response['Content-Disposition'] = f'attachment; filename="{file_name}"'
        #     response['Content-Length'] = str(file_size)
        #     response['Accept-Ranges'] = 'bytes'
        #     response['Cache-Control'] = 'no-cache, no-store, must-revalidate'
        #     response['Access-Control-Expose-Headers'] = 'Content-Length, Content-Disposition'

        #     return response

        # except ClientError as e:
        #     raise Http404(f"Could not retrieve file")

