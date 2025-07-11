# serializers.py
from rest_framework import serializers
from memory_room.models import MemoryRoom, TimeCapSoul, CustomMemoryRoomTemplate, CustomTimeCapSoulTemplate

class CustomMemoryRoomTemplateSerializer(serializers.ModelSerializer):
    class Meta:
        model = CustomMemoryRoomTemplate
        fields = ['id', 'name', 'slug', 'summary']

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
