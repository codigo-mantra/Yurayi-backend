import boto3, io
import json
import time
import mimetypes
from rest_framework import serializers

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

from userauth.models import Assets
from userauth.apis.views.views import SecuredView, NewSecuredView

from memory_room.models import (
    MemoryRoom,
    MemoryRoomTemplateDefault,
    MemoryRoomMediaFile,
    FILE_TYPES
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

from memory_room.utils import determine_download_chunk_size

from memory_room.crypto_utils import generate_signed_path

class MemoryRoomCoverView(SecuredView):
    """
    API endpoint to list all assets of type 'Memory Room Cover'.
    Only authenticated users can access this.
    """
    def get(self, request):
        """
        Returns all memory room cover assets ordered by creation date.
        """
        assets = Assets.objects.filter(asset_types='Memory Room Cover').order_by('-created_at')
        serializer = AssetSerializer(assets, many=True)
        return Response(serializer.data)

class UserMemoryRoomListView(SecuredView):
    """
    API endpoint to list all non-deleted memory rooms of the current user.
    """
    def get(self,request):
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
        """
        Returns all non-deleted default memory room templates ordered by creation.
        """
        rooms = MemoryRoomTemplateDefault.objects.filter(is_deleted=False).order_by('-created_at')
        serializer = MemoryRoomTemplateDefaultSerializer(rooms, many=True)
        return Response(serializer.data)

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
        # print(f'Requst received')

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
        Upload multiple media files to a memory room with streaming progress updates.
        Each file has its own IV for decryption.
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

        def file_upload_stream():
            for index, uploaded_file in enumerate(files):
                file_iv = ivs[index]
                yield f"data: Starting upload of {uploaded_file.name}\n\n"
                file_size = uploaded_file.size
                chunk_size = determine_download_chunk_size(file_size)
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

                    # Ensure file pointer is reset before serializer save
                    uploaded_file.seek(0)

                    # Pass both file and its corresponding IV to serializer
                    serializer = MemoryRoomMediaFileCreationSerializer(
                        data={
                            'file': uploaded_file,
                            'iv': file_iv
                        },
                        context={'user': user, 'memory_room': memory_room}
                    )

                    if serializer.is_valid():
                        media_file = serializer.save()
                        created_objects.append(media_file)
                        results.append({
                            "file": uploaded_file.name,
                            "status": "success",
                            "progress": 100,
                            "data": MemoryRoomMediaFileSerializer(media_file).data
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

        file_name = media_file.title
        file_bytes,content_type = decrypt_and_get_image(str(media_file.s3_key))

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
from memory_room.crypto_utils import encrypt_and_upload_file, decrypt_and_get_image
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

    def get(self, request, s3_key):
        user  = self.get_current_user(request)
        if user is None:
            return Response(status=status.HTTP_401_UNAUTHORIZED)
        
        try:
            exp = request.GET.get("exp")
            sig = request.GET.get("sig")
            s3_storage_id = user.s3_storage_id
            s3_key = f'{s3_storage_id}/{s3_key}'

            if not exp or not sig:
                return Response(status=status.HTTP_404_NOT_FOUND)

            if int(exp) < int(time.time()):
                return Response(status=status.HTTP_404_NOT_FOUND)

            expected_sig = base64.urlsafe_b64encode(
                hmac.new(SECRET, f"{s3_key}:{exp}".encode(), hashlib.sha256).digest()
            ).decode().rstrip("=")

            if not hmac.compare_digest(sig, expected_sig):
                return Response(status=status.HTTP_404_NOT_FOUND)

            # Decrypt actual file bytes
            file_bytes,content_type = decrypt_and_get_image(str(s3_key))


            #  Serve decrypt file via Django
            response = HttpResponse(file_bytes, content_type=content_type)
            response["Content-Disposition"] = f'inline; filename="{s3_key.split("/")[-1].replace(".enc", "")}"'
            return response
        except Exception as e:
            return Response(status=status.HTTP_404_NOT_FOUND)
            
            


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
