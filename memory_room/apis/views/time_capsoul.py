import boto3,mimetypes
from rest_framework.parsers import MultiPartParser
from django.shortcuts import get_object_or_404
from rest_framework import generics, permissions, status
from rest_framework.response import Response
from botocore.exceptions import ClientError
from django.conf import settings
from django.http import StreamingHttpResponse, Http404
from memory_room.utils import determine_download_chunk_size


from userauth.models import Assets
from userauth.apis.views.views import SecuredView,NewSecuredView


from memory_room.apis.serializers.memory_room import (
    AssetSerializer,
)

from memory_room.models import TimeCapSoulTemplateDefault, TimeCapSoul, TimeCapSoulDetail, TimeCapSoulMediaFile, TimeCapSoulReplica, TimeCapSoulMediaFileReplica
from memory_room.apis.serializers.time_capsoul import (
    TimeCapSoulTemplateDefaultReadOnlySerializer, TimeCapSoulCreationSerializer,TimeCapSoulMediaFileReadOnlySerializer,
    TimeCapSoulSerializer, TimeCapSoulUpdationSerializer,TimeCapSoulMediaFileSerializer,TimeCapSoulMediaFilesReadOnlySerailizer, TimeCapsoulMediaFileUpdationSerializer,
    TimeCapsoulUnlockSerializer, TimeCapsoulUnlockSerializer,
)

class TimeCapSoulCoverView(generics.ListAPIView):
    """
    API endpoint to list all assets of type 'Time CapSoul Cover'.
    Only authenticated users can access this.
    """
    permission_classes = [permissions.IsAuthenticated]
    serializer_class = AssetSerializer

    def get_queryset(self):
        """
        Returns all Time CapSoul Cover assets ordered by creation date.
        """
        return Assets.objects.filter(asset_types='Time CapSoul Cover').order_by('-created_at')


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
        serialized_data = TimeCapSoulSerializer(timecapsoul).data if timecapsoul else {}

        return Response({
            'message': 'Time CapSoul created successfully',
            'time_capsoul': serialized_data
        }, status=status.HTTP_201_CREATED)
    
    def get(self, request, format=None):
        """Time CapSoul list"""
        user = self.get_current_user(request)
        time_capsoul = TimeCapSoul.objects.filter(user = user)
        serializer = TimeCapSoulSerializer(time_capsoul, many=True)
        return Response(serializer.data)

        
class TimeCapSoulUpdationView(SecuredView):

    def patch(self, request, time_capsoul_id):
        user = self.get_current_user(request)
        time_capsoul_detail = get_object_or_404(TimeCapSoulDetail, time_capsoul__id=time_capsoul_id)
        serializer = TimeCapSoulUpdationSerializer(instance = time_capsoul_detail.time_capsoul, data=request.data, partial = True, context ={'time_capsoul_detial': time_capsoul_detail})
        if serializer.is_valid():
            update_time_capsoul = serializer.save()
            return Response(TimeCapSoulSerializer(update_time_capsoul).data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    def delete(self, request, time_capsoul_id):
        user = self.get_current_user(request)
        time_capsoul_detail = get_object_or_404(TimeCapSoulDetail, time_capsoul__id=time_capsoul_id)

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

    def get(self, request, time_capsoul_id):
        """
        List all media files of a time-capsoul.
        """
        user = self.get_current_user(request)
        time_capsoul = self.get_time_capsoul(user, time_capsoul_id)
        media_files = TimeCapSoulDetail.objects.filter(time_capsoul=time_capsoul).order_by('-created_at')
        return Response(TimeCapSoulMediaFilesReadOnlySerailizer(media_files, many=True).data)

    
    def post(self, request, time_capsoul_id):
        """
        Upload multiple media files to a time-capsoul room.
        """
        user = self.get_current_user(request)
        time_capsoul_detail = get_object_or_404(TimeCapSoulDetail, time_capsoul__id=time_capsoul_id)
        if not time_capsoul_detail.is_locked:
            files = request.FILES.getlist('file')
            if len(files)  == 0:
                return Response({'message': "Files are required to upload in time-capsoul"})
            else:
                created_objects = []

                for uploaded_file in files:
                    serializer = TimeCapSoulMediaFileSerializer(
                        data={**request.data, 'file': uploaded_file},
                        context={'user': user, 'time_capsoul': time_capsoul_detail.time_capsoul}
                    )
                    if serializer.is_valid():
                        media_file = serializer.save()
                        created_objects.append(media_file)
                    else:
                        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

                return Response(
                    TimeCapSoulMediaFileReadOnlySerializer(created_objects, many=True).data,
                    status=status.HTTP_201_CREATED
                )
        else:
            return Response({'message': 'Soory Time capsoul is locked now media files uploads not applicable'})

class MoveTimeCapSoulMediaFile(SecuredView):
    def post(self, request, old_cap_soul_id, media_file_id, new_capsoul_id):
        """Move media file from one TimeCapsoul to another"""
        user = self.get_current_user(request)

        old_time_capsoul = get_object_or_404(TimeCapSoulDetail, time_capsoul__id=old_cap_soul_id, time_capsoul__user=user)
        new_time_capsoul = get_object_or_404(TimeCapSoulDetail, time_capsoul__id=new_capsoul_id, time_capsoul__user=user)

        # Prevent move if either source or destination is locked
        if old_time_capsoul.is_locked or new_time_capsoul.is_locked:
            return Response({'message': 'Sorry, media file cannot be moved because either the source or destination TimeCapsoul is locked.'}, status=400)

        # Fetch the media file
        media_file = get_object_or_404(TimeCapSoulMediaFile, id=media_file_id, user=user, time_capsoul=old_time_capsoul.time_capsoul)

        # Remove from old TimeCapsoul's related set
        old_time_capsoul.media_files.remove(media_file)

        # Update the FK on media file
        media_file.time_capsoul = new_time_capsoul.time_capsoul
        media_file.save()

        # Add to new TimeCapsoul's related set
        new_time_capsoul.media_files.add(media_file)

        return Response({'message': 'Media file moved successfully'}, status=200)



class TimeCapSoulMediaFileUpdationView(SecuredView):

    def get_time_capsoul(self, user, time_capsoul_id):
        """
        Utility method to get a time-capsoul owned by the user.
        """
        return get_object_or_404(TimeCapSoul, id=time_capsoul_id, user=user)
    
    


    def delete(self, request, time_capsoul_id, media_file_id):
        """Delete time-capsoul media file"""
        user = self.get_current_user(request)
        time_capsoul_detail = get_object_or_404(TimeCapSoulDetail, time_capsoul__id=time_capsoul_id)
        if time_capsoul_detail.is_locked:
            return Response({'message': 'Soory Time capsoul is locked its media files cant be deleted'})
        else:
            media_file = get_object_or_404(TimeCapSoulMediaFile, id=media_file_id, user=user, time_capsoul=time_capsoul_detail.time_capsoul)
            media_file.delete()
            return Response({'message': 'Time Capsoul media deleted successfully'})

    
    def patch(self, request, time_capsoul_id, media_file_id):
        user = self.get_current_user(request)
        time_capsoul_detail = get_object_or_404(TimeCapSoulDetail, time_capsoul__id=time_capsoul_id)
        media_file = get_object_or_404(TimeCapSoulMediaFile, id=media_file_id, user=user, time_capsoul=time_capsoul_detail.time_capsoul)
        serializer = TimeCapsoulMediaFileUpdationSerializer(instance = media_file, data  = request.data, partial = True, context = {'time_capsoul_detial': time_capsoul_detail})
        serializer.is_valid(raise_exception=True)
        update_media_file = serializer.save()
        return Response(TimeCapSoulMediaFileReadOnlySerializer(update_media_file).data)


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


class TimeCapSoulMediaFileDownloadView(NewSecuredView):
    def get(self, request, timecapsoul_id, media_file_id):
        """
        Download a media file from a TimeCapSoul securely.
        """
        user = self.get_current_user(request)
        timecapsoul = get_object_or_404(TimeCapSoul, id=timecapsoul_id, user=user)
        media_file = get_object_or_404(
            TimeCapSoulMediaFile,
            id=media_file_id,
            user=user,
            time_capsoul=timecapsoul
        )

        s3_key = media_file.s3_key
        file_name = media_file.title

        s3 = boto3.client(
            's3',
            aws_access_key_id=settings.AWS_ACCESS_KEY_ID,
            aws_secret_access_key=settings.AWS_SECRET_ACCESS_KEY,
            region_name=settings.AWS_S3_REGION_NAME
        )

        try:
            s3_response = s3.get_object(Bucket=settings.AWS_STORAGE_BUCKET_NAME, Key=s3_key)
            file_stream = s3_response['Body']
            file_size = s3_response['ContentLength']
            chunk_size = determine_download_chunk_size(file_size)

            mime_type = (
                s3_response.get('ContentType')
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
            raise Http404(f"Could not retrieve file: {e}")
