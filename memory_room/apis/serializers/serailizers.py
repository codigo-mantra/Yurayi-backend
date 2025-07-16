# serializers.py
from rest_framework import serializers
from userauth.models import Assets
from memory_room.models import MemoryRoom, TimeCapSoul, CustomMemoryRoomTemplate, CustomTimeCapSoulTemplate
from django.conf import settings
MODE = settings.MODE

class AssetSerializer(serializers.ModelSerializer):
    image_url = serializers.SerializerMethodField()

    class Meta:
        model = Assets
        fields = ['id', 'title','image_url']

    def get_image_url(self, obj):
        print(f'\n Mode: ',MODE)
        if MODE != 'PROD':
            request = self.context.get('request')
            if obj.image and hasattr(obj.image, 'url'):
                return request.build_absolute_uri(obj.image.url) if request else obj.image.url
            else:
                obj.s3_url
        return None
class CustomMemoryRoomTemplateSerializer(serializers.ModelSerializer):
    cover_image = AssetSerializer()
    class Meta:
        model = CustomMemoryRoomTemplate
        fields = ['id', 'name', 'slug', 'summary', 'cover_image']

class MemoryRoomSerializer(serializers.ModelSerializer):
    room_template = CustomMemoryRoomTemplateSerializer()

    class Meta:
        model = MemoryRoom
        fields = ['id', 'room_template', 'is_created']


class CustomTimeCapSoulTemplateSerializer(serializers.ModelSerializer):
    class Meta:
        model = CustomTimeCapSoulTemplate
        fields = ['id', 'name', 'slug', 'summary']

class TimeCapSoulSerializer(serializers.ModelSerializer):
    capsoul_template = CustomTimeCapSoulTemplateSerializer()

    class Meta:
        model = TimeCapSoul
        fields = ['id', 'capsoul_template', 'is_created']


class MemoryRoomCreateSerializer(serializers.ModelSerializer):
    room_template = serializers.PrimaryKeyRelatedField(
        queryset=CustomMemoryRoomTemplate.objects.all(),
        required=False
    )

    class Meta:
        model = MemoryRoom
        fields = ['room_template']

    def validate(self, attrs):
        user = self.context['request'].user
        if MemoryRoom.objects.filter(user=user, room_template=attrs['room_template'], is_deleted=False).exists():
            raise serializers.ValidationError("You have already created a Memory Room with this template.")
        return attrs

    def create(self, validated_data):
        return MemoryRoom.objects.create(user=self.context['request'].user, **validated_data)
