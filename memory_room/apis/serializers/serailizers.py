# serializers.py
from rest_framework import serializers
from userauth.models import Assets
from memory_room.models import MemoryRoom, TimeCapSoul, CustomMemoryRoomTemplate, CustomTimeCapSoulTemplate,MemoryRoomDetail
from django.conf import settings
import logging
logger = logging.getLogger(__name__)


class AssetSerializer(serializers.ModelSerializer):
    image_url = serializers.SerializerMethodField()

    class Meta:
        model = Assets
        fields = ['id', 'title','image_url']

    def get_image_url(self, obj):
        return obj.s3_url
        
class CustomMemoryRoomTemplateSerializer(serializers.ModelSerializer):
    cover_image = AssetSerializer()
    is_editable = serializers.SerializerMethodField()
    class Meta:
        model = CustomMemoryRoomTemplate
        fields = ['id', 'is_editable', 'name', 'slug', 'summary', 'cover_image']
    
    def get_is_editable(self, obj):
        return False if obj.default_template else True

class MemoryRoomSerializer(serializers.ModelSerializer):
    total_files = serializers.SerializerMethodField()
    room_template = CustomMemoryRoomTemplateSerializer()


    class Meta:
        model = MemoryRoom
        fields = ['id', 'total_files', 'room_template', 'created_at', 'updated_at']
    
    def get_total_files(self, obj):
        try:
            return obj.memory_media_files.filter(is_deleted=False).count()
        except Exception as e:
            logger.error(f'Exception while calculating files count for memory-room {obj.id} error as : {e}')
            return 0



class CustomTimeCapSoulTemplateSerializer(serializers.ModelSerializer):
    class Meta:
        model = CustomTimeCapSoulTemplate
        fields = ['id', 'name', 'slug', 'summary']

class TimeCapSoulSerializer(serializers.ModelSerializer):
    capsoul_template = CustomTimeCapSoulTemplateSerializer()

    class Meta:
        model = TimeCapSoul
        fields = ['id', 'capsoul_template', 'created_at']


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
