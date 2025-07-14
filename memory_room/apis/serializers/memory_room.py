from rest_framework import serializers
from userauth.models import Assets
from memory_room.models import MemoryRoomTemplateDefault, MemoryRoom, CustomMemoryRoomTemplate, MemoryRoomMediaFile

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

# class MemoryRoomCreationSerializer(serializers.Serializer):
#     template_id = serializers.IntegerField(required = False)
#     name = serializers.CharField(required = False)



# class CustomMemoryRoomTemplateSerializer(serializers.Serializer):
#     template_id = serializers.IntegerField(read_only=True)
#     name = serializers.CharField(max_length=255)
#     summary = serializers.CharField(required=False, allow_null=True, allow_blank=True)
#     cover_image = serializers.IntegerField(required=False, allow_null=True)  

#     def validate(self, data):
#         template_id = data.get('template_id', None)
#         if not template_id:
#             pass
#         else:

        
        


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


class MemoryRoomMediaFileSerializer(serializers.ModelSerializer):
    class Meta:
        model = MemoryRoomMediaFile
        fields = [
            'id', 'file', 'file_type', 'cover_image', 'description',
            'is_cover_image', 'file_size'
        ]
        read_only_fields = ['file_size']

    def create(self, validated_data):
        instance = MemoryRoomMediaFile.objects.create(**validated_data)
        return instance

    def update(self, instance, validated_data):
        for attr, value in validated_data.items():
            setattr(instance, attr, value)
        instance.save()
        return instance
