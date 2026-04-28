from rest_framework import serializers
from memory_map.models import MemoryMediaDetails
import hmac
import hashlib
import time
from django.conf import settings
from django.urls import reverse


class MemoryMediaDetailsSerializer(serializers.ModelSerializer):
    uploader_email = serializers.CharField(source="user.email", read_only=True)
    file_url        = serializers.SerializerMethodField()
    location_type   = serializers.SerializerMethodField()  # tells frontend: "pinned" or "bucket"

    class Meta:
        model  = MemoryMediaDetails
        fields = (
            "id",
            "user",
            "uploader_email",
            "memory_place",       # FK → MemoryMapPinnedLocationInfo (nullable)
            "bucket_item",        # FK → MemoryMapBucketInfo (nullable)
            "location_type",      # derived: "pinned" | "bucket" | None
            "file_type",
            "file_size",
            "title",
            "description",
            "file_url",           # signed URL = never expose raw file path
            "created_at",
            "updated_at",
        )
        read_only_fields = (
            "id",
            "user",
            "created_at",
            "updated_at",
        )

    # ----------------------------------------------------------------
    # Signed URL — expires in 10 min so direct link sharing is blocked
    # ----------------------------------------------------------------
    def _generate_signed_url(self, media_id, expires_in=600):  # 600s = 10 min
        exp  = int(time.time()) + expires_in
        data = f"{media_id}:{exp}"

        sig = hmac.new(
            settings.SECRET_KEY.encode(),
            data.encode(),
            hashlib.sha256
        ).hexdigest()

        base_url    = reverse("serve-memory-map-media", kwargs={"media_id": media_id})
        signed_path = f"{base_url}?exp={exp}&sig={sig}"
        return signed_path

    def get_file_url(self, obj):                               # called by SerializerMethodField
        return self._generate_signed_url(obj.id)

    # ----------------------------------------------------------------
    # location_type = frontend needsss this to know which modal to open
    # and which delete/edit endpoint to call (pinned vs bucket context)
    # -----------------------------------------------------------------
    def get_location_type(self, obj):
        if obj.memory_place_id:                                 # cheap FK id check , no extra DB hit
            return "pinned"
        if obj.bucket_item_id:
            return "bucket"
        return None



#######################################################################################################################################

class MemoryMediaUpdateSerializer(serializers.ModelSerializer):
    title = serializers.CharField(
        max_length=512,
        required=False,
        allow_blank=False
    )
    description = serializers.CharField(
        required=False,
        allow_blank=True,
        allow_null=True
    )

    class Meta:
        model = MemoryMediaDetails
        fields = (
            "title",
            "description",
        )

        def validate_title(self, value):
            value = value.strip()
            if len(value) < 3:
                raise serializers.ValidationError("Title must be at least 3 characters long.")
            return value
    
    def validate_description(self, value):
        value = value.strip()
        if len(value) < 3:
            raise serializers.ValidationError("Description must be at least 3 characters long.")
        return value
    
    def update(self, instance, validated_data):
        instance.title = validated_data.get("title", instance.title)
        instance.description = validated_data.get("description", instance.description)
        instance.save(
            update_fields=[
                "title",
                "description",
                "updated_at",
            ]
        )

        return instance



