import boto3
import os
import mimetypes
from rest_framework import serializers
from django.conf import settings
from django.core.files.images import ImageFile 
from userauth.models import Assets
from memory_room.models import (
    MemoryRoomTemplateDefault, MemoryRoom, CustomMemoryRoomTemplate, MemoryRoomMediaFile
)
from memory_room.apis.serializers.serailizers import MemoryRoomSerializer
from memory_room.utils import upload_file_to_s3_bucket, get_file_category,get_readable_file_size_from_bytes
from memory_room.crypto_utils import encrypt_and_upload_file, decrypt_and_get_image, generate_signed_path, decrypt_frontend_file
from django.core.files.base import ContentFile


# AWS_KMS_REGION = settings.AWS_KMS_REGION
# AWS_KMS_KEY_ID = settings.AWS_KMS_KEY_ID
AWS_KMS_REGION = 'ap-south-1'
AWS_KMS_KEY_ID = '843da3bb-9a57-4d9f-a8ab-879a6109f460'
MEDIA_FILES_BUCKET = settings.MEDIA_FILES_BUCKET

from timecapsoul.utils import MediaThumbnailExtractor
import logging
logger = logging.getLogger(__name__)

class AssetSerializer(serializers.ModelSerializer):
    """
    Serializer for Asset model with S3 image URL.
    """
    image_url = serializers.SerializerMethodField()

    class Meta:
        model = Assets
        fields = ['id', 'title', 'image_url']

    def get_image_url(self, obj):
        return obj.s3_url


class MemoryRoomTemplateDefaultSerializer(serializers.ModelSerializer):
    """
    Serializer for default memory room templates.
    """
    cover_image = AssetSerializer()

    class Meta:
        model = MemoryRoomTemplateDefault
        fields = ['id', 'name', 'summary', 'slug', 'cover_image']


class CustomMemoryRoomTemplateSerializer(serializers.ModelSerializer):
    """
    Serializer for user-created custom memory room templates.
    """

    class Meta:
        model = CustomMemoryRoomTemplate
        fields = [
            'id', 'name', 'slug', 'summary',
            'cover_image', 'cover_image_url', 'default_template'
        ]


class MemoryRoomCreationSerializer(serializers.Serializer):
    """
    Serializer to handle creation of MemoryRoom.
    Can be based on a template or from scratch.
    """
    template_id = serializers.IntegerField(required=False)
    name = serializers.CharField(required=False)
    summary = serializers.CharField(required=False)
    cover_image = serializers.IntegerField(required=False)

    def validate(self, data):
        user = self.context['user']
        template_id = data.get('template_id')

        if template_id:
            data['memory_room'] = self._create_from_default_template(template_id, user)
        else:
            missing_fields = [f for f in ['name', 'summary', 'cover_image'] if not data.get(f)]
            if missing_fields:
                raise serializers.ValidationError({field: f'{str(field).capitalize()} field is required.' for field in missing_fields})

            data['memory_room'] = self._create_custom_room(data, user)

        return data

    def _create_from_default_template(self, template_id, user):
        """
        Create memory room from a default template.
        """
        default = MemoryRoomTemplateDefault.objects.filter(id=template_id).first()
        if not default:
            raise serializers.ValidationError({'template_id': 'Invalid ID'})

        custom = CustomMemoryRoomTemplate.objects.create(
            name=default.name, slug=default.slug, summary=default.summary,
            cover_image=default.cover_image, default_template=default
        )
        return MemoryRoom.objects.create(user=user, room_template=custom)

    def _create_custom_room(self, data, user):
        """
        Create a memory room from scratch using custom inputs.
        """
        try:
            image_asset = Assets.objects.get(id=data['cover_image']) 
        except (Assets.DoesNotExist, Assets.MultipleObjectsReturned):
            raise serializers.ValidationError({'cover_image': 'Cover-image id invalid'})

        custom = CustomMemoryRoomTemplate.objects.create(
            name=data['name'], summary=data['summary'],
            cover_image=image_asset, default_template=None
        )
        return MemoryRoom.objects.create(user=user, room_template=custom)


class MemoryRoomUpdationSerializer(serializers.ModelSerializer):
    """
    Serializer to handle updating an existing memory room template data.
    """
    name = serializers.CharField(required=False)
    summary = serializers.CharField(required=False)
    cover_image = serializers.IntegerField(required=False)

    class Meta:
        model = MemoryRoom
        fields = ('name', 'summary', 'cover_image')

    def validate_cover_image(self, value):
        """
        Validates that the provided cover_image exists and is of type 'Memory Room Cover'.
        """
        try:
            return Assets.objects.get(id=value, asset_types='Memory Room Cover')
        except Assets.DoesNotExist:
            raise serializers.ValidationError("Cover image with this ID does not exist.")

    def update(self, instance, validated_data):
        """
        Updates related CustomMemoryRoomTemplate fields.
        """
        template = instance.room_template
        template.name = validated_data.get('name', template.name)
        template.summary = validated_data.get('summary', template.summary)
        template.cover_image = validated_data.get('cover_image', template.cover_image)

        template.save()
        instance.save()
        return instance


# class MemoryRoomMediaFileCreationSerializer(serializers.ModelSerializer):
#     """
#     Handles creation of MemoryRoomMediaFile, including decrypting uploaded file
#     and re-uploading to S3.
#     """

#     # accept IV from frontend
#     iv = serializers.CharField(write_only=True, required=True)

#     class Meta:
#         model = MemoryRoomMediaFile
#         fields = (
#             'file_type',
#             'file',
#             'memory_room',
#             'user',
#             'thumbnail_url',
#             'cover_image',
#             'iv',   # <-- NEW
#         )
#         read_only_fields = ['thumbnail_url', 'cover_image']

#     def create(self, validated_data):
#         user = self.context['user']
#         memory_room = self.context['memory_room']
#         iv = validated_data.pop('iv')
#         file = validated_data.pop('file', None)

#         validated_data['user'] = user
#         validated_data['memory_room'] = memory_room

#         if not file:
#             raise serializers.ValidationError({"file": "No file provided."})


#         try:
#             # 🔑 Decrypt using shared AES key + IV
#             decrypted_bytes = decrypt_frontend_file(file, iv)
#         except Exception as e:
#             raise serializers.ValidationError({'decryption_error': f'File decryption failed: {str(e)}'})

#         # Infer file type from original name
#         file_type = get_file_category(file.name)
#         if file_type == 'invalid':
#             raise serializers.ValidationError({'file_type': 'File type is invalid.'})

#         validated_data['file_size'] = get_readable_file_size_from_bytes(len(decrypted_bytes))
#         s3_key = f"{user.s3_storage_id}/memory-room-files/{file.name}"
#         s3_key = s3_key.replace(" ", "_")

#         try:
#             # Upload decrypted file
#             upload_media_obj = encrypt_and_upload_file(
#                 key=s3_key,
#                 plaintext_bytes=decrypted_bytes,
#                 content_type=file.content_type,
#                 file_category=file_type
#             )
#         except Exception as e:
#             print(f'[Upload Error] {e}')
#             raise serializers.ValidationError({'upload_error': "File upload failed. Invalid file."})

#         # Assign uploaded file details
#         validated_data['file_type'] = file_type
#         validated_data['s3_key'] = s3_key
#         validated_data['title'] = file.name
#         validated_data['file'] = file  # keep reference (but it’s encrypted version)

#         # === Thumbnail / cover generation ===
#         try:
#             from userauth.models import Assets
#             if file_type == 'audio':
#                 ext = os.path.splitext(file.name)[1]
#                 extractor = MediaThumbnailExtractor(ContentFile(decrypted_bytes, name=file.name), ext)
#                 thumbnail_data = extractor.extract()
#                 if thumbnail_data:
#                     image_file = ContentFile(thumbnail_data, name=f"thumbnail_{file.name}.jpg")
#                     asset = Assets.objects.create(image=image_file, asset_types='Thumbnail/Audio')
#                     validated_data['cover_image'] = asset
#                     validated_data['thumbnail_url'] = asset.s3_url
#                     validated_data['thumbnail_key'] = asset.s3_key

#             elif file_type == 'image':
#                 image_file = ImageFile(ContentFile(decrypted_bytes, name=file.name))
#                 asset = Assets.objects.create(image=image_file, asset_types='Thumbnail/Image')
#                 validated_data['cover_image'] = asset
#                 validated_data['thumbnail_url'] = asset.s3_url
#                 validated_data['thumbnail_key'] = asset.s3_key

#         except Exception as e:
#             print(f'[Thumbnail Error] {e}')

#         instance = super().create(validated_data)
#         return instance

class MemoryRoomMediaFileCreationSerializer(serializers.ModelSerializer):
    """
    Handles creation of MemoryRoomMediaFile, including decrypting uploaded file
    and re-uploading to S3 with progress tracking.
    """

    # accept IV from frontend
    iv = serializers.CharField(write_only=True, required=True)

    class Meta:
        model = MemoryRoomMediaFile
        fields = (
            'file_type',
            'file',
            'memory_room',
            'user',
            'thumbnail_url',
            'cover_image',
            'iv',   # <-- NEW
        )
        read_only_fields = ['thumbnail_url', 'cover_image']

    def create(self, validated_data):
        user = self.context['user']
        memory_room = self.context['memory_room']
        progress_callback = self.context.get('progress_callback')
        iv = validated_data.pop('iv')
        file = validated_data.pop('file', None)

        validated_data['user'] = user
        validated_data['memory_room'] = memory_room

        if not file:
            raise serializers.ValidationError({"file": "No file provided."})

        # Track processing progress (first 50% of total progress)
        if progress_callback:
            progress_callback(5, "Starting file processing...")

        try:
            # 🔑 Decrypt using shared AES key + IV
            if progress_callback:
                progress_callback(10, "Decrypting file...")
            decrypted_bytes = decrypt_frontend_file(file, iv)
            if progress_callback:
                progress_callback(20, "File decrypted successfully")
        except Exception as e:
            if progress_callback:
                progress_callback(-1, f"Decryption failed: {str(e)}")
            raise serializers.ValidationError({'decryption_error': f'File decryption failed: {str(e)}'})

        # Infer file type from original name
        if progress_callback:
            progress_callback(25, "Validating file type...")
            
        file_type = get_file_category(file.name)
        if file_type == 'invalid':
            if progress_callback:
                progress_callback(-1, "Invalid file type")
            raise serializers.ValidationError({'file_type': 'File type is invalid.'})

        validated_data['file_size'] = get_readable_file_size_from_bytes(len(decrypted_bytes))
        s3_key = f"{user.s3_storage_id}/memory-room-files/{file.name}"
        s3_key = s3_key.replace(" ", "_")

        if progress_callback:
            progress_callback(30, "Preparing for upload...")

        try:
            # Create progress wrapper for upload (remaining 50% of total progress)
            def upload_progress_callback(upload_percentage, message):
                if progress_callback:
                    # Map upload progress (0-100) to overall progress (30-80)
                    if upload_percentage == -1:  # Error case
                        progress_callback(-1, message)
                    else:
                        overall_progress = 30 + int((upload_percentage / 100) * 50)
                        progress_callback(min(overall_progress, 80), message)

            # Upload decrypted file with progress tracking
            upload_media_obj = encrypt_and_upload_file(
                key=s3_key,
                plaintext_bytes=decrypted_bytes,
                content_type=file.content_type,
                file_category=file_type,
                progress_callback=upload_progress_callback
            )
        except Exception as e:
            print(f'[Upload Error] {e}')
            if progress_callback:
                progress_callback(-1, f"Upload failed: {str(e)}")
            raise serializers.ValidationError({'upload_error': "File upload failed. Invalid file."})

        # Assign uploaded file details
        validated_data['file_type'] = file_type
        validated_data['s3_key'] = s3_key
        validated_data['title'] = file.name
        validated_data['file'] = file  # keep reference (but it's encrypted version)

        if progress_callback:
            progress_callback(85, "Generating thumbnails...")

        # === Thumbnail / cover generation ===
        try:
            from userauth.models import Assets
            if file_type == 'audio':
                ext = os.path.splitext(file.name)[1]
                extractor = MediaThumbnailExtractor(ContentFile(decrypted_bytes, name=file.name), ext)
                thumbnail_data = extractor.extract()
                if thumbnail_data:
                    image_file = ContentFile(thumbnail_data, name=f"thumbnail_{file.name}.jpg")
                    asset = Assets.objects.create(image=image_file, asset_types='Thumbnail/Audio')
                    validated_data['cover_image'] = asset
                    validated_data['thumbnail_url'] = asset.s3_url
                    validated_data['thumbnail_key'] = asset.s3_key

            elif file_type == 'image':
                image_file = ImageFile(ContentFile(decrypted_bytes, name=file.name))
                asset = Assets.objects.create(image=image_file, asset_types='Thumbnail/Image')
                validated_data['cover_image'] = asset
                validated_data['thumbnail_url'] = asset.s3_url
                validated_data['thumbnail_key'] = asset.s3_key

        except Exception as e:
            print(f'[Thumbnail Error] {e}')

        if progress_callback:
            progress_callback(95, "Finalizing...")

        instance = super().create(validated_data)
        
        if progress_callback:
            progress_callback(100, "File processed successfully!")
            
        return instance

class MemoryRoomMediaFileSerializer(serializers.ModelSerializer):
    """
    Serializer for reading memory room media file objects.
    """
    cover_image = AssetSerializer()
    file_url = serializers.SerializerMethodField()
    memory_room = serializers.SerializerMethodField()
    file_title =  serializers.SerializerMethodField()

    class Meta:
        model = MemoryRoomMediaFile
        fields = [
            'id', 'file_size', 'file_title', 'file_type', 'memory_room', 'file_url', 'file_type',
            'cover_image', 'description', 'is_cover_image','thumbnail_url','created_at', 'updated_at'
        ]
        read_only_fields = ['id', 'user',  'file_url', 'cover_image', 'file_title']


    def get_file_url(self, obj):
        import time, base64, hmac, hashlib

        exp = int(time.time()) + 60*5  # 5 minutes expiry
        raw = f"{obj.s3_key}:{exp}"
        sig = base64.urlsafe_b64encode(
            hmac.new(settings.SECRET_KEY.encode(), raw.encode(), hashlib.sha256).digest()
        ).decode().rstrip("=")

        return f"/api/v0/memory-rooms/api/media/serve/{obj.s3_key[37:]}?exp={exp}&sig={sig}"
        
    
    def get_file_name(self,path: str):
        return path.split("/")[-1]

    
    def get_file_title(self, obj):
        return obj.title

    def get_memory_room(self, obj):
        return MemoryRoomSerializer(obj.memory_room).data

    def upload_file_to_s3_bucket(self, file):
        """
        Upload file to S3 and return URL and file category.
        """
        import io

        file_name = file.name
        file_category = get_file_category(file_name)
        s3_key = f"memory_room_files/{file_category}/{file_name}"
        content_type = mimetypes.guess_type(file_name)[0] or 'application/octet-stream'

        file.seek(0)
        buffer = io.BytesIO(file.read())

        s3 = boto3.client(
            's3',
            aws_access_key_id=settings.AWS_ACCESS_KEY_ID,
            aws_secret_access_key=settings.AWS_SECRET_ACCESS_KEY,
            region_name=settings.AWS_S3_REGION_NAME
        )

        try:
            s3.upload_fileobj(
                buffer,
                settings.AWS_STORAGE_BUCKET_NAME,
                s3_key,
                ExtraArgs={
                    'ContentType': content_type,
                    'ACL': 'public-read'
                }
            )
        except Exception as e:
            logger.error('S3 upload failed')
            raise Exception(f"S3 upload failed: {str(e)}")

        s3_url = f"https://{settings.AWS_STORAGE_BUCKET_NAME}.s3.{settings.AWS_S3_REGION_NAME}.amazonaws.com/{s3_key}"
        return (s3_url, file_category)

    def create(self, validated_data):
        """
        Create media file with S3 upload support.
        """
        user = self.context['user']
        memory_room = self.context['memory_room']
        file = validated_data.pop('file', None)

        validated_data['user'] = user
        validated_data['memory_room'] = memory_room

        if file:
            validated_data['file_size'] = file.size
            s3_url, file_type = self.upload_file_to_s3_bucket(file)
            validated_data['s3_url'] = s3_url
            validated_data['file_type'] = file_type

        return super().create(validated_data)

    def update(self, instance, validated_data):
        """
        Update media file and optionally replace file in S3.
        """
        file = validated_data.get('file')
        if file:
            validated_data['file_size'] = file.size
            s3_url, file_type = self.upload_file_to_s3_bucket(file)
            validated_data['s3_url'] = s3_url
            validated_data['file_type'] = file_type

        return super().update(instance, validated_data)


class MemoryRoomMediaFileReadOnlySerializer(serializers.ModelSerializer):
    """
    Read-only serializer for media files, used in simplified listing.
    """
    media_file_s3_url = serializers.SerializerMethodField()

    class Meta:
        model = MemoryRoomMediaFile
        fields = ('id', 'file_size', 'title', 'description','file_type', 'cover_image', 'media_file_s3_url', 'created_at', 'updated_at', )
    
    def get_media_file_s3_url(self, obj):
        return obj.s3_url
    
   

    
class MemoryRoomMediaFileDescriptionUpdateSerializer(serializers.ModelSerializer):
    description = serializers.CharField(allow_blank=True, required=True)

    class Meta:
        model = MemoryRoomMediaFile
        fields = ['description', 'title']