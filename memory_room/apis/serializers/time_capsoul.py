import os
from userauth.models import Assets
from django.core.files.images import ImageFile 
from timecapsoul.utils import MediaThumbnailExtractor
from memory_room.apis.serializers.memory_room import AssetSerializer
from memory_room.models import TimeCapSoulTemplateDefault,CustomTimeCapSoulTemplate,TimeCapSoul, TimeCapSoulMediaFile,TimeCapSoulDetail

from rest_framework import serializers
from memory_room.utils import upload_file_to_s3_bucket, get_file_category


class TimeCapSoulTemplateDefaultReadOnlySerializer(serializers.ModelSerializer):
    cover_image = AssetSerializer()
    class Meta:
        model = TimeCapSoulTemplateDefault
        fields = ('id', 'name', 'summary', 'cover_image')
    
    def get_cover_image_url(self, obj):
        cover_image_url = None

        if obj.cover_image:
            cover_image_url =  obj.cover_image.s3_url
        return cover_image_url


class TimeCapSoulCreationSerializer(serializers.Serializer):
    """
    Serializer to handle creation of Time CapSoul.
    Can be based on a template or from scratch.
    """
    time_capsoul_template_id = serializers.IntegerField(required=False)
    name = serializers.CharField(required=False)
    summary = serializers.CharField(required=False)
    cover_image = serializers.IntegerField(required=False)

    def validate(self, data):
        user = self.context['user']
        template_id = data.get('time_capsoul_template_id')

        if template_id:
            data['time_capsoul'] = self._create_from_default_template(template_id, user)
        else:
            missing_fields = [f for f in ['name', 'summary', 'cover_image'] if not data.get(f)]
            if missing_fields:
                raise serializers.ValidationError({field: f'{str(field).capitalize()} field is required.' for field in missing_fields})

            data['time_capsoul'] = self._create_custom_room(data, user)

        return data

    def _create_from_default_template(self, template_id, user):
        """
        Create time-capsoul from a default template.
        """
        default = TimeCapSoulTemplateDefault.objects.filter(id=template_id).first()
        if not default:
            raise serializers.ValidationError({'template_id': 'TimeCapsoul template id is invalid'})

        custom = CustomTimeCapSoulTemplate.objects.create(
            name=default.name, slug=default.slug, summary=default.summary,
            cover_image=default.cover_image, default_template=default
        )
        print(f'\nTime-capsoul Custom Template created: {custom}')
        return TimeCapSoul.objects.create(user=user, capsoul_template=custom)

    def _create_custom_room(self, data, user):
        """
        Create a time-capsoul from scratch using custom inputs.
        """
        try:
            image_asset = Assets.objects.get(id=data['cover_image']) 
        except (Assets.DoesNotExist, Assets.MultipleObjectsReturned):
            raise serializers.ValidationError({'cover_image': 'Cover-image id is invalid'})

        custom = CustomTimeCapSoulTemplate.objects.create(
            name=data['name'], summary=data['summary'],
            cover_image=image_asset, default_template=None
        )
        return TimeCapSoul.objects.create(user=user, capsoul_template=custom)

      
class CustomTimeCapSoulTemplateSerializer(serializers.ModelSerializer):
    cover_image = AssetSerializer()
    class Meta:
        model = CustomTimeCapSoulTemplate
        fields = ['id', 'name', 'slug', 'summary', 'cover_image']


class TimeCapSoulSerializer(serializers.ModelSerializer):
    status = serializers.SerializerMethodField()
    name = serializers.SerializerMethodField()
    summary = serializers.SerializerMethodField()
    cover_image = serializers.SerializerMethodField()

    class Meta:
        model = TimeCapSoul
        fields = ['id', 'status','name', 'summary', 'cover_image','created_at', 'updated_at']
    
    def get_status(self, obj):
        return obj.get_status_display()
    
    def get_name(self, obj):
        return obj.capsoul_template.name
    
    def get_summary(self, obj):
        return obj.capsoul_template.summary
    
    def get_cover_image(self, obj):
        cover_image = obj.capsoul_template.cover_image
        return AssetSerializer(cover_image).data

class TimeCapSoulUpdationSerializer(serializers.ModelSerializer):
    """
    Serializer to handle updating an existing memory room template data.
    """
    name = serializers.CharField(required=False)
    summary = serializers.CharField(required=False)
    cover_image = serializers.IntegerField(required=False)

    class Meta:
        model = TimeCapSoul
        fields = ('name', 'summary', 'cover_image')

    def validate_cover_image(self, value):
        """
        Validates that the provided cover_image exists and is of type 'Time CapSoul Cover'.
        """
        try:
            return Assets.objects.get(id=value, asset_types='Time CapSoul Cover')
        except Assets.DoesNotExist:
            raise serializers.ValidationError("Cover image with this ID does not exist.")

    def update(self, instance, validated_data):
        """
        Updates related Time CapSoul Template fields.
        """
        template = instance.capsoul_template
        template.name = validated_data.get('name', template.name)
        template.summary = validated_data.get('summary', template.summary)
        template.cover_image = validated_data.get('cover_image', template.cover_image)
        template.save()
        instance.save()
        return instance


class TimeCapSoulMediaFileSerializer(serializers.ModelSerializer):
    """
    Handles creation of TimeCapSoulMediaFile, including upload to S3.
    """

    class Meta:
        model = TimeCapSoulMediaFile
        fields = ('file',)


    def create(self, validated_data):
        user = self.context['user']
        file = validated_data.pop('file', None)
        time_capsoul = self.context['time_capsoul']

        validated_data['user'] = user
        validated_data['time_capsoul'] = time_capsoul

        if file:
            validated_data['file_size'] = file.size
            s3_url, file_type,s3_key = upload_file_to_s3_bucket(file, folder='memory_media_files')
            validated_data['s3_url'] = s3_url
            validated_data['file_type'] = file_type
            validated_data['s3_key'] = s3_key
            validated_data['title'] =  validated_data['s3_key'].split('/')[-1]


            # Set the file field 
            validated_data['file'] = file
            if file_type == 'audio':
                try:
                    # Extract thumbnail 
                    ext = os.path.splitext(file.name)[1]
                    extractor = MediaThumbnailExtractor(file, ext)
                    thumbnail_data = extractor.extract()

                    if thumbnail_data:
                        from django.core.files.base import ContentFile
                        from userauth.models import Assets 

                        image_file = ContentFile(thumbnail_data, name=f"thumbnail_{file.name}.jpg")
                        asset = Assets.objects.create(image=image_file, asset_types='TimeCapsoul/Thubmnail/Audio')
                        validated_data['thumbnail'] = asset


                        # validated_data['cover_image'] = asset
                        # print(f'S3 url: ',asset.s3_url)
                        # validated_data['thumbnail_url'] = asset.s3_url
                        # print(f'thubmnail: {validated_data['thumbnail_url']}')
                        # validated_data['thumbnail_key'] = asset.s3_key
                except Exception as e:
                    print(f'\n Exception while extracting thumbnail: \n{e}')
            
                
        return super().create(validated_data)



class TimeCapSoulMediaFileReadOnlySerializer(serializers.ModelSerializer):
    thumbnail = AssetSerializer()
    class Meta:
        model = TimeCapSoulMediaFile
        fields = ('id', 'file_type', 's3_url', 'title', 'description', 'thumbnail', 'file_size')

class TimeCapSoulMediaFilesReadOnlySerailizer(serializers.ModelSerializer):
    time_capsoul = TimeCapSoulSerializer()
    media_files = TimeCapSoulMediaFileReadOnlySerializer(many=True)

    class Meta:
        model = TimeCapSoulDetail
        fields = ('time_capsoul', 'media_files')

# class TimeCapsoulMediaFileUpdationSerializer(serializers.ModelSerializer):

#     class Meta:
#         model  = TimeCapSoulMediaFile
#         fields = ('description', 'cover_image_id')
    
#     def validate(self, data):
#         description = data.get('description', None)
#         cover_image_id = data.get('cover_image_id', None)

class TimeCapsoulMediaFileUpdationSerializer(serializers.ModelSerializer):
    cover_image_id = serializers.IntegerField(write_only=True, required=False, allow_null=True)

    class Meta:
        model = TimeCapSoulMediaFile
        fields = ('description', 'cover_image_id')

    def validate(self, data):
        # Optional: Custom validation logic
        cover_image_id = data.get('cover_image_id', None)
        try:
            cover_image = Assets.objects.get(id = cover_image_id)
        except Assets.DoesNotExist:
            raise serializers.ValidationError({'cover_image_id': 'Cover image is invalid'})
        else:
            data['']
        return data

    def update(self, instance, validated_data):
        cover_image_id = validated_data.pop('cover_image', None)

        for attr, value in validated_data.items():
            setattr(instance, attr, value)

        if cover_image_id is not None:
            instance.is_cover_image = True
        else:
            instance.is_cover_image = False

        instance.save()
        return instance