import boto3
from rest_framework.parsers import MultiPartParser
from django.shortcuts import get_object_or_404
from rest_framework import generics, permissions, status
from rest_framework.response import Response

from userauth.models import Assets
from userauth.apis.views.views import SecuredView


from memory_room.apis.serializers.memory_room import (
    AssetSerializer,
)

from memory_room.models import TimeCapSoulTemplateDefault, TimeCapSoul, TimeCapSoulDetail, TimeCapSoulMediaFile
from memory_room.apis.serializers.time_capsoul import (
    TimeCapSoulTemplateDefaultReadOnlySerializer, TimeCapSoulCreationSerializer,TimeCapSoulMediaFileReadOnlySerializer,
    TimeCapSoulSerializer, TimeCapSoulUpdationSerializer,TimeCapSoulMediaFileSerializer,TimeCapSoulMediaFilesReadOnlySerailizer
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
        })
    
    def get(self, request, format=None):
        """Time CapSoul list"""
        user = self.get_current_user(request)
        time_capsoul = TimeCapSoul.objects.filter(user = user)
        serializer = TimeCapSoulSerializer(time_capsoul, many=True)
        return Response(serializer.data)

        
class TimeCapSoulUpdationView(SecuredView):

    def patch(self, request, time_capsoul_id):
        user = self.get_current_user(request)
        timecap_soul = get_object_or_404(TimeCapSoul, id=time_capsoul_id, user=user)
        serializer = TimeCapSoulUpdationSerializer(instance = timecap_soul, data=request.data, partial = True)
        if serializer.is_valid():
            update_time_capsoul = serializer.save()
            return Response(TimeCapSoulSerializer(update_time_capsoul).data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    def delete(self, request, time_capsoul_id):
        user = self.get_current_user(request)
        timecap_soul = get_object_or_404(TimeCapSoul, id=time_capsoul_id, user=user)
        timecap_soul.delete()
        return Response({'message': "Time capsoul deleted successfully"})

class TimeCapSoulMediaFileUploader(SecuredView):

    def get(self, request, time_capsoul_id):
        user = self.get_current_user(request)
        timecap_soul = get_object_or_404(TimeCapSoul, id=time_capsoul_id, user=user)
        pass

    def post(self, request, time_capsoul_id):
        user = self.get_current_user(request)
        timecap_soul = get_object_or_404(TimeCapSoul, id=time_capsoul_id, user=user)







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
        time_capsoul = self.get_time_capsoul(user, time_capsoul_id)

        files = request.FILES.getlist('file')
        created_objects = []

        for uploaded_file in files:
            serializer = TimeCapSoulMediaFileSerializer(
                data={**request.data, 'file': uploaded_file},
                context={'user': user, 'time_capsoul': time_capsoul}
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


class TimeCapSoulMediaFileUpdationView(SecuredView):

    def get_time_capsoul(self, user, time_capsoul_id):
        """
        Utility method to get a time-capsoul owned by the user.
        """
        return get_object_or_404(TimeCapSoul, id=time_capsoul_id, user=user)

    def delete(self, request, time_capsoul_id, media_file_id):
        """Delete time-capsoul media file"""
        user = self.get_current_user(request)
        time_capsoul = self.get_time_capsoul(user, time_capsoul_id)
        media_file = get_object_or_404(TimeCapSoulMediaFile, id=media_file_id, user=user, time_capsoul=time_capsoul)
        media_file.delete()
        return Response({'message': 'Time Capsoul media deleted successfully'})

    
    def patch(self, request, time_capsoul_id, media_file_id):
        user = self.get_current_user(request)
        time_capsoul = self.get_time_capsoul(user, time_capsoul_id)
        media_file = get_object_or_404(TimeCapSoulMediaFile, id=media_file_id, user=user, time_capsoul=time_capsoul)
        return Response({'message': 'Time Capsoul media deleted successfully'})

