

from rest_framework import serializers
from family_tree.models import (
    FamilyTreeDiaryCategory, FamilyTreeDiary
)

class DiaryCategorySearializer(serializers.ModelSerializer):
    class Meta:
        model = FamilyTreeDiaryCategory
        fields = ('id', 'name', 'color_code', 'slug')

class FamilyTreeDiaryCategorySerializer(serializers.ModelSerializer):
    class Meta:
        model = FamilyTreeDiaryCategory
        fields = [
            "id",
            "name",
            "color_code",
            "slug",
        ]


class FamilyTreeDiarySerializer(serializers.ModelSerializer):
    author = serializers.SerializerMethodField()
    category = DiaryCategorySearializer()

    class Meta:
        model = FamilyTreeDiary
        fields = [
            "id",
            "author",
            "category",
            "title",
            "description",
            "created_at",
        ]
    
    def validate(self, attrs):
        category = attrs.get('category')

        try:
            category = FamilyTreeDiaryCategory.objects.get(id = category)
        except FamilyTreeDiaryCategory.DoesNotExist:
            raise serializers.ValidationError({'category': 'Category id is invalid'})
        
        attrs['category'] = category


    
    def get_author(self, obj):
        author_name = None
        if obj.author:
            author_name = {}
            author_name['username'] = obj.author.username
            author_name['full_name'] = f'{obj.author.first_name} {obj.author.last_name}'
        
        return author_name
    
# class FamilyTreeDiaryUpdationSerializer(serializers.ModelSerializer):
#     # category = serializers.PrimaryKeyRelatedField(
#     #     queryset=FamilyTreeDiaryCategory.objects.all(),
#     #     required=False,
#     #     allow_null=True
#     # )
#     category = DiaryCategorySearializer()

    

#     class Meta:
#         model = FamilyTreeDiary
#         fields = ("title", "description", "category")
    
#     def validate(self, attrs):
#         category = attrs.get("category")

#         if category:
#             try:
#                 category = FamilyTreeDiaryCategory.objects.get(id=category)
#             except FamilyTreeDiaryCategory.DoesNotExist:
#                 raise serializers.ValidationError(
#                     {"category": "Category id is invalid"}
#                 )

#             # attrs["category"] = category

#         return attrs


#     def update(self, instance, validated_data):
#         # Update only allowed fields
#         instance.title = validated_data.get("title", instance.title)
#         instance.description = validated_data.get("description", instance.description)
#         instance.category = validated_data.get("category", instance.category)

#         instance.save()
#         return instance

class FamilyTreeDiaryUpdationSerializer(serializers.ModelSerializer):
    category = DiaryCategorySearializer(read_only=True)
    category_id = serializers.UUIDField(write_only=True, required=False)

    class Meta:
        model = FamilyTreeDiary
        fields = ("title", "description", "category", "category_id")

    def validate_category_id(self, value):
        try:
            return FamilyTreeDiaryCategory.objects.get(id=value)
        except FamilyTreeDiaryCategory.DoesNotExist:
            raise serializers.ValidationError("Category id is invalid")

    def update(self, instance, validated_data):
        instance.title = validated_data.get("title", instance.title)
        instance.description = validated_data.get("description", instance.description)

        if "category_id" in validated_data:
            instance.category = validated_data["category_id"]

        instance.save()
        return instance



class FamilyTreeDiaryCreateSerializer(serializers.Serializer):
    category = serializers.IntegerField()
    title = serializers.CharField(max_length=255)
    description = serializers.CharField(required=False, allow_blank=True)

    def validate_category(self, value):
        try:
            return FamilyTreeDiaryCategory.objects.get(
                id=value,
                is_deleted=False
            )
        except FamilyTreeDiaryCategory.DoesNotExist:
            raise serializers.ValidationError("Invalid category id")

    def create(self, validated_data):
        user = self.context["user"]
        family_tree = self.context["family_tree"]
        
        family_tree_diary = FamilyTreeDiary.objects.create(
            family_tree=family_tree,
            author=user,
            category=validated_data["category"],  
            title=validated_data["title"],
            description=validated_data.get("description")
        )

        return family_tree_diary