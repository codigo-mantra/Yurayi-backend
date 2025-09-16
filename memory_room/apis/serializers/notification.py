from rest_framework import serializers
from memory_room.models import Notification
import logging
logger = logging.getLogger(__name__)

class NotificationSerializer(serializers.ModelSerializer):
    class Meta:
        model = Notification
        fields = [
            "id",
            # "memory_room",
            # "time_capsoul",
            # "category",
            # "category_type",
            "title",
            "message",
            "is_read",
            "created_at",
        ]
        read_only_fields = fields  # all fields are read-only for API


class NotificationUpdateSerializer(serializers.ModelSerializer):
    class Meta:
        model = Notification
        fields = ("id", "is_read", "is_deleted", 'title', 'message')
        read_only_fields = ("id", 'title', 'message')

    def validate(self, attrs):
        logger.info("NotificationUpdateSerializer.validate called")
        # Only allow ONE field to be updated at a time
        update_flags = [field for field in ["is_read", "is_deleted"] if field in attrs]

        if len(update_flags) == 0:
            raise serializers.ValidationError("You must provide at least one update action.")
        if len(update_flags) > 1:
            raise serializers.ValidationError("Only one update action is allowed at a time.")

        return attrs

    def update(self, instance, validated_data):
        logger.info("NotificationUpdateSerializer.update called")
        if "is_read" in validated_data:
            instance.is_read = validated_data["is_read"]
        elif "is_deleted" in validated_data and validated_data["is_deleted"]:
            instance.is_deleted = True
        instance.save()
        return instance
