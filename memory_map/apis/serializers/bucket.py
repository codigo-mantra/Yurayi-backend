from rest_framework import serializers
from django.db import transaction

from memory_map.models import (
    MemoryMapBucketInfo,
    MemoryMediaDetails
)


class BucketListCreateSerializer(serializers.ModelSerializer):
    files = serializers.ListField(
        child=serializers.FileField(),
        write_only=True,
        required=False
    )

    tagged_friends = serializers.ListField(
        child=serializers.CharField(),
        required=False,
        allow_empty=True
    )

    is_visited = serializers.BooleanField(required=False, default=False)

    class Meta:
        model = MemoryMapBucketInfo
        fields = [
            "id",
            "location_name",
            "latitude",
            "longitude",
            "is_visited",
            "tagged_friends",
            "media",
            "media_files",
            "created_at",
        ]
        read_only_fields = ["id","created_at"]

    def validate_location_name(self, value):
        if not value.strip():
            raise serializers.ValidationError("Location name cannot be blank.")
        return value
    
    def validate_latitude(self, value):
        if value < -90 or value > 90:
            raise serializers.ValidationError("Latitude must be between -90 and 90.")
        return value

    def validate_longitude(self, value):
        if value < -180 or value > 180:
            raise serializers.ValidationError("Longitude must be between -180 and 180.")
        return value
    
    def validate_tagged_friends(self, value):
        if not isinstance(value, list):
            raise serializers.ValidationError("tagged_friends must be a list.")
        return [str(f).strip() for f in value if str(f).strip()]
    
    def validate(self, data):
        memory_map = self.context["memory_map"]

        if MemoryMapBucketInfo.objects.filter(
            memory_map=memory_map,
            location_name= data["location_name"],
            latitude=data["latitude"],
            longitude=data["longitude"],
            is_deleted=False
        ).exists():
            raise serializers.ValidationError("This bucket location already exists.")
        
        return data
    
    def create(self, validated_data):
        memory_map = self.context["memory_map"]

        return MemoryMapBucketInfo.objects.create(
            memory_map=memory_map,
            **validated_data
        )
    
    # def create(self, validated_data):
        # user = self.context["user"]
        # memory_map = self.context["memory_map"]

        # files = validated_data.pop("files", [])                       #this will be list of uploaded files from request 
        # tagged_friends = validated_data.pop("tagged_friends", [])     #will show list of tagged friends 
        # is_visited = validated_data.pop("is_visited", False)  

        # with transaction.atomic(): 

        #     bucket = MemoryMapBucketInfo.objects.create(
        #         memory_map=memory_map,
        #         is_visited=False,
        #         tagged_friends=tagged_friends,
        #         **validated_data
        #     )

            
class BucketListSerializer(serializers.ModelSerializer):
    class Meta:
        model = MemoryMapBucketInfo
        fields = [
            "id",
            "location_name",
            "latitude",
            "longitude",
            "is_visited",
            "tagged_friends",
            "created_at",
        ]





            






        







        

        

            









    