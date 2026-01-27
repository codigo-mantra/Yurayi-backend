from rest_framework import serializers
from family_tree.models import FamilyTreeGallery


class FamilyTreeGallerySerializer(serializers.ModelSerializer):
    author_name = serializers.CharField(source="author.email", read_only=True)
    file_url = serializers.SerializerMethodField()
    thumbnail_url = serializers.SerializerMethodField()

    class Meta:
        model = FamilyTreeGallery
        fields = (
            "id",
            "family_tree",
            "author",
            "author_name",
            "file_type",
            "file_size",
            "title",
            "description",
            # "file",
            "file_url",
            "thumbnail_preview",
            "thumbnail_url",
            "created_at",
            "updated_at",
        )
        read_only_fields = (
            "id",
            "author",
            "created_at",
            "updated_at",
        )

    def get_file_url(self, obj):
        return obj.file.url if obj.file else None

    def get_thumbnail_url(self, obj):
        return obj.thumbnail_preview.url if obj.thumbnail_preview else None
    
class GalleryUpdateSerializer(serializers.ModelSerializer):
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
        model = FamilyTreeGallery
        fields = (
            "title",
            "description",
        )

    def validate_title(self, value):
        value = value.strip()
        if len(value) < 3:
            raise serializers.ValidationError(
                "Title must be at least 3 characters long."
            )
        return value
    
    def validate_description(self, value):
        value = value.strip()
        if len(value) < 3:
            raise serializers.ValidationError(
                "Description must be at least 3 characters long."
            )
        return value

    def update(self, instance, validated_data):
        """
        Explicit update control (only title & description)
        """
        instance.title = validated_data.get("title", instance.title)
        instance.description = validated_data.get(
            "description", instance.description
        )

        instance.save(
            update_fields=[
                "title",
                "description",
                "updated_at",
            ]
        )
        return instance