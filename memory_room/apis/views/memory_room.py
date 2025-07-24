import boto3
from botocore.exceptions import ClientError
from django.conf import settings
from django.http import StreamingHttpResponse, Http404

from django.shortcuts import get_object_or_404
from rest_framework import generics, permissions, status
from rest_framework.response import Response
from rest_framework.parsers import MultiPartParser
from rest_framework.exceptions import ValidationError
from rest_framework.pagination import PageNumberPagination


from userauth.models import Assets
from userauth.apis.views.views import SecuredView

from memory_room.models import (
    MemoryRoom, MemoryRoomTemplateDefault,
    MemoryRoomMediaFile,FILE_TYPES
)
from memory_room.apis.serializers.memory_room import (
    AssetSerializer, MemoryRoomCreationSerializer,
    MemoryRoomTemplateDefaultSerializer, MemoryRoomUpdationSerializer,
    MemoryRoomMediaFileSerializer, MemoryRoomMediaFileCreationSerializer,MemoryRoomMediaFileReadOnlySerializer,MemoryRoomMediaFileDescriptionUpdateSerializer
)
from memory_room.apis.serializers.serailizers import MemoryRoomSerializer

from botocore.exceptions import ClientError
from django.http import StreamingHttpResponse, Http404

from channels.layers import get_channel_layer
from asgiref.sync import async_to_sync


from memory_room.utils import determine_download_chunk_size



class MemoryRoomCoverView(generics.ListAPIView):
    """
    API endpoint to list all assets of type 'Memory Room Cover'.
    Only authenticated users can access this.
    """
    permission_classes = [permissions.IsAuthenticated]
    serializer_class = AssetSerializer

    def get_queryset(self):
        """
        Returns all memory room cover assets ordered by creation date.
        """
        return Assets.objects.filter(asset_types='Memory Room Cover').order_by('-created_at')


class UserMemoryRoomListView(generics.ListAPIView):
    """
    API endpoint to list all non-deleted memory rooms of the current user.
    """
    permission_classes = [permissions.IsAuthenticated]
    serializer_class = MemoryRoomSerializer

    def get_queryset(self):
        """
        Returns all memory rooms for the current user that are not deleted.
        """
        return MemoryRoom.objects.filter(user=self.request.user, is_deleted=False).order_by('-created_at')


class MemoryRoomTemplateDefaultViewSet(generics.ListAPIView):
    """
    API endpoint to list all default memory room templates.
    """
    permission_classes = [permissions.IsAuthenticated]
    serializer_class = MemoryRoomTemplateDefaultSerializer

    def get_queryset(self):
        """
        Returns all non-deleted default memory room templates ordered by creation.
        """
        return MemoryRoomTemplateDefault.objects.filter(is_deleted=False).order_by('-created_at')


class CreateMemoryRoomView(SecuredView):
    """
    API view to create, update, or delete a memory room.
    Inherits authentication logic from `SecuredView`.
    """

    def post(self, request, format=None):
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
        """
        Delete an existing memory room.
        """
        user = self.get_current_user(request)
        memory_room = get_object_or_404(MemoryRoom, id=memory_room_id, user=user)
        room_name = memory_room.room_template.name
        memory_room.delete()
        return Response(
            {'message': f'Memory deleted successfully named as : {room_name}'},
            status=status.HTTP_204_NO_CONTENT
        )

    def patch(self, request, memory_room_id):
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
    def post(self, request, memory_room_id, cover_image_id):
        print(f'Requst received')

        user = self.get_current_user(request)
        memory_room = get_object_or_404(MemoryRoom, id=memory_room_id, user=user)
        cover_image = get_object_or_404(Assets, id=cover_image_id)
        room_template = memory_room.room_template
        room_template.cover_image = cover_image
        room_template.save()
        memory_room.save()
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
        """
        List all media files of a memory room.
        """
        user = self.get_current_user(request)
        memory_room = self.get_memory_room(user, memory_room_id)
        media_files = MemoryRoomMediaFile.objects.filter(memory_room=memory_room, user=user).order_by('-created_at')
        return Response(MemoryRoomMediaFileSerializer(media_files, many=True).data)

    
    def post(self, request, memory_room_id):
        """
        Upload multiple media files to a memory room.
        """
        user = self.get_current_user(request)
        memory_room = self.get_memory_room(user, memory_room_id)

        files = request.FILES.getlist('file')
        created_objects = []

        for uploaded_file in files:
            serializer = MemoryRoomMediaFileCreationSerializer(
                data={**request.data, 'file': uploaded_file},
                context={'user': user, 'memory_room': memory_room}
            )
            if serializer.is_valid():
                media_file = serializer.save()
                created_objects.append(media_file)
            else:
                return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        # Serialize all successfully created files
        return Response(
            MemoryRoomMediaFileSerializer(created_objects, many=True).data,
            status=status.HTTP_201_CREATED
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
        media_file.delete()
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
        Securely stream media file from S3 by file ID using stored s3_key.
        Also sends real-time progress updates over WebSocket.
        """
        user = self.get_current_user(request)
        memory_room = get_object_or_404(MemoryRoom, id=memory_room_id, user=user)
        media_file = get_object_or_404(
            MemoryRoomMediaFile,
            id=media_file_id,
            user=user,
            memory_room=memory_room
        )

        s3_key = media_file.s3_key
        file_id = str(media_file.id)
        channel_layer = get_channel_layer()
        group_name = f"progress_{file_id}"

        s3 = boto3.client(
            's3',
            aws_access_key_id=settings.AWS_ACCESS_KEY_ID,
            aws_secret_access_key=settings.AWS_SECRET_ACCESS_KEY,
            region_name=settings.AWS_S3_REGION_NAME
        )

        try:
            s3_response = s3.get_object(Bucket=settings.AWS_STORAGE_BUCKET_NAME, Key=s3_key)
            file_stream = s3_response['Body']
            content_type = s3_response.get('ContentType', 'application/octet-stream')
            file_size = s3_response['ContentLength']
            chunk_size = determine_download_chunk_size(file_size)

            def stream_with_progress():
                bytes_sent = 0
                while True:
                    chunk = file_stream.read(chunk_size)
                    if not chunk:
                        break
                    bytes_sent += len(chunk)
                    percent_done = int((bytes_sent / file_size) * 100)

                    # Send progress update via WebSocket
                    async_to_sync(channel_layer.group_send)(
                        group_name,
                        {
                            "type": "send_progress",
                            "content": {
                                "percent": percent_done
                            }
                        }
                    )
                    yield chunk

            response = StreamingHttpResponse(
                streaming_content=stream_with_progress(),
                content_type=content_type
            )
            response['Content-Disposition'] = f'attachment; filename="{s3_key.split("/")[-1]}"'
            return response

        except ClientError as e:
            raise Http404(f"Could not retrieve file: {e}")

class MemoryRoomMediaFileFilterView(SecuredView):

    def get(self, request):
        user = self.get_current_user(request)
        query_params = request.query_params

        memory_room_id = query_params.get('memory_room_id')
        if not memory_room_id:
            raise ValidationError({'memory_room_id': 'Memory room id is required.'})

        # Validate file_type if given
        file_type = query_params.get('file_type')
        if file_type and file_type not in dict(FILE_TYPES).keys():
            raise ValidationError({
                'file_type': f"'{file_type}' is not a valid file type. Allowed: {', '.join(dict(FILE_TYPES).keys())}"
            })

        # media filters
        media_filters = {
            key: value for key, value in {
                'memory_room__id': memory_room_id,
                'file_type': file_type,
                'description__icontains': query_params.get('description'),
                'user': user,
            }.items() if value is not None
        }

        queryset = MemoryRoomMediaFile.objects.filter(**media_filters)
        # pagination
        paginator = PageNumberPagination()
        paginator.page_size = 8
        paginated_queryset = paginator.paginate_queryset(queryset, request)

        serializer = MemoryRoomMediaFileReadOnlySerializer(paginated_queryset, many=True)
        return paginator.get_paginated_response({'media_files': serializer.data})
