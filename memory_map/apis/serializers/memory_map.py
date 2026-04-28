from rest_framework import serializers
from memory_map.models import MemoryMap
from memory_map.models import MemoryMapPinnedLocationInfo


class MemoryMapSerializer(serializers.ModelSerializer):
    title = serializers.CharField(required=False, allow_blank=False)
    description = serializers.CharField(required=False, allow_blank=True)

    class Meta:
        model = MemoryMap
        fields = [
            "id",
            "title",
            "description",
            "created_at",
            "updated_at",
        ]
        #  "user",  = do not expose user in the API response
        read_only_fields = ["id", "user" , "created_at", "updated_at"]
    
    def validate_title(self,value):
        if value is not None and not value.strip():
            raise serializers.ValidationError("Title cannot be blank.")
        return value
        

class MemoryMapLocationCreateSerializer(serializers.ModelSerializer):
    class Meta:
        model = MemoryMapPinnedLocationInfo
        fields = [
            "id",
            "location_name",
            "latitude",
            "longitude",
            "created_at",
        ]
        read_only_fields = ["id", "created_at"]

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
    

    def validate(self, data):

        # memory_map, _ = self.context["memory_map"]
        memory_map = self.context["memory_map"]
        #if loc with same name and cord. raise error to avoid duplicates with exact same details.
        if MemoryMapPinnedLocationInfo.objects.filter(
            memory_map=memory_map,
            location_name=data["location_name"],
            latitude=data["latitude"],
            longitude=data["longitude"],
            is_deleted=False
        ).exists():
            raise serializers.ValidationError("This location already exists.")
        return data
    

    def create(self, validated_data):
        memory_map = self.context["memory_map"]

        return MemoryMapPinnedLocationInfo.objects.create(
            memory_map=memory_map, 
            **validated_data
        )

    
    # def create(self, validated_data):
        # user = self.context["request"].user

        # memory_map, _ = MemoryMap.objects.get_or_create(user=user) # Ensure memory map exist for the user 
        # location = MemoryMapPinnedLocationInfo.objects.create(
        #     memory_map=memory_map,
        #     **validated_data
        # )

        # return location 
    

class MemoryMapLocationListSerializer(serializers.ModelSerializer):
    class Meta:
        model = MemoryMapPinnedLocationInfo
        fields = [
            "id",
            "location_name",
            "latitude",
            "longitude",
            "created_at",
        ]








    

      

        






    
