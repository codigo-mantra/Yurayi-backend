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
