import boto3
import os
import mimetypes
from rest_framework import serializers
from userauth.models import Assets
from django.conf import settings
from memory_room.models import MemoryRoomTemplateDefault, MemoryRoom, CustomMemoryRoomTemplate, MemoryRoomMediaFile

MODE = settings.MODE 

class AssetSerializer(serializers.ModelSerializer):
    image_url = serializers.SerializerMethodField()

    class Meta:
        model = Assets
        fields = ['id', 'title', 'image', 'asset_types', 'image_url']

    def get_image_url(self, obj):
        request = self.context.get('request')
        if obj.image and hasattr(obj.image, 'url'):
            return request.build_absolute_uri(obj.image.url) if request else obj.image.url
        return None


class MemoryRoomTemplateDefaultSerializer(serializers.ModelSerializer):
    cover_image_url = serializers.SerializerMethodField()

    class Meta:
        model = MemoryRoomTemplateDefault
        fields = ['id', 'name', 'summary', 'slug', 'cover_image', 'cover_image_url']

    def get_cover_image_url(self, obj):
        request = self.context.get('request')
        if obj.cover_image and obj.cover_image.image:
            return request.build_absolute_uri(obj.cover_image.image.url) if request else obj.cover_image.image.url
        return None


class CustomMemoryRoomTemplateSerializer(serializers.ModelSerializer):

    class Meta:
        model = CustomMemoryRoomTemplate
        fields = [
            'id',
            'name',
            'slug',
            'summary',
            'cover_image',
            'cover_image_url',
            'default_template'
        ]

class MemoryRoomCreationSerializer(serializers.Serializer):
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
        default = MemoryRoomTemplateDefault.objects.filter(id=template_id).first()
        if not default:
            raise serializers.ValidationError({'template_id': 'Invalid ID'})

        custom = CustomMemoryRoomTemplate.objects.create(
            name=default.name, slug=default.slug, summary=default.summary,
            cover_image=default.cover_image, default_template=default
        )
        return MemoryRoom.objects.create(user=user, room_template=custom)

    def _create_custom_room(self, data, user):
        try:
            image_asset = Assets.objects.get(id=data['cover_image']) 
        except Assets.DoesNotExist:
            raise serializers.ValidationError({'cover_image': f'Cover-image id invalid '})
        except Assets.MultipleObjectsReturned:
            raise serializers.ValidationError({'cover_image': f'Cover-image id invalid '})
        else:
            custom = CustomMemoryRoomTemplate.objects.create(
                name=data['name'], summary=data['summary'],
                cover_image=image_asset, default_template=None
            )
            return MemoryRoom.objects.create(user=user, room_template=custom)


class MemoryRoomUpdationSerializer(serializers.ModelSerializer):
    name = serializers.CharField(required=False)
    summary = serializers.CharField(required=False)
    cover_image = serializers.IntegerField(required=False)

    class Meta:
        model = MemoryRoom
        fields = ('name', 'summary', 'cover_image')

    def validate_cover_image(self, value):
        try:
            cover_image = Assets.objects.get(id=value, asset_types='Memory Room Cover')
        except Assets.DoesNotExist:
            raise serializers.ValidationError("Cover image with this ID does not exist.")
        else:
            return cover_image

    def update(self, instance, validated_data):
        if 'name' in validated_data:
            instance.room_template.name = validated_data['name']
        if 'summary' in validated_data:
            instance.room_template.summary = validated_data['summary']
        if 'cover_image' in validated_data:
            instance.room_template.cover_image = validated_data['cover_image']  
        instance.save()
        return instance

       

class MemoryRoomMediaFileSerializer(serializers.ModelSerializer):
        file_url = serializers.SerializerMethodField()

        class Meta:
            model = MemoryRoomMediaFile
            fields = [
                'id', 'user', 'memory_room', 'file', 'file_url', 'file_type',
                'cover_image', 'description', 'is_cover_image', 'file_size'
            ]
            read_only_fields = ['id', 'user', 'file_size', 'file_url', 'cover_image']

        def get_file_url(self, obj):
            return obj.s3_url
    
        def upload_file_to_s3_bucket(self, file):
            import io
            import boto3
            import mimetypes

            file_content = file.read()  # reads the entire file into memory
            buffer = io.BytesIO(file_content)  # create a new readable stream

            file_name = f"memory_room_files/{file.name}"
            content_type = mimetypes.guess_type(file.name)[0] or 'application/octet-stream'

            s3 = boto3.client(
                's3',
                aws_access_key_id=settings.AWS_ACCESS_KEY_ID,
                aws_secret_access_key=settings.AWS_SECRET_ACCESS_KEY,
                region_name=settings.AWS_S3_REGION_NAME
            )
            
            s3.upload_fileobj(
                buffer,
                settings.AWS_STORAGE_BUCKET_NAME,
                file_name,
                ExtraArgs={'ContentType': content_type, 'ACL': 'public-read'}
            )

            return f"https://{settings.AWS_STORAGE_BUCKET_NAME}.s3.{settings.AWS_S3_REGION_NAME}.amazonaws.com/{file_name}"

        def create(self, validated_data):
            user = self.context['user']
            file = validated_data.get('file')

            validated_data['user'] = user
            if file:
                validated_data['file_size'] = file.size
                s3_url = self.upload_file_to_s3_bucket(file)
                validated_data['s3_url'] = s3_url
            return super().create(validated_data)

        def update(self, instance, validated_data):
            file = validated_data.get('file')

            if file:
                validated_data['file_size'] = file.size
                s3_url = self.upload_file_to_s3_bucket(file)
                validated_data['s3_url'] = s3_url

            return super().update(instance, validated_data)
