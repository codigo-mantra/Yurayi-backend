from django.db import models
from django.db.models import Q
from django.core.exceptions import ValidationError

from userauth.models import User

class BaseModel(models.Model):
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    is_deleted = models.BooleanField(default=False)

    class Meta:
        abstract = True

#Memory_map
class MemoryMap(BaseModel):
    user = models.OneToOneField(
        User,
        on_delete=models.CASCADE,
        related_name="memory_map"
    )
    
    title = models.CharField(max_length=255,blank=True, default="")
    description = models.TextField(blank=True, default="")

    def __str__(self):
        return f"{self.user.email}'s Memory Map"
    

# MemoryMapPinnedLocationInfo
class MemoryMapPinnedLocationInfo(BaseModel):
    memory_map = models.ForeignKey(
        MemoryMap,
        on_delete=models.CASCADE,
        related_name="pinned_locations"
    )


    location_name = models.CharField(max_length=255)
    latitude = models.FloatField()
    longitude = models.FloatField()

    def __str__(self):
        return self.location_name


#MemoryMapRecipients
class MemoryMapRecipients(BaseModel):

    PERMISSION_CHOICES = (
        ("view", "View"),
        ("edit", "Edit")
    )

    memory_map = models.ForeignKey(
        MemoryMap,
        on_delete=models.CASCADE,
        related_name="recipients"
    )

    user = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        null=True,
        blank=True,
        related_name="shared_memory_maps"
    )

    name = models.CharField(max_length=255)
    email = models.EmailField()

    permission = models.CharField(
        max_length=10,
        choices=PERMISSION_CHOICES,
        default='view'
    )

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["memory_map", "email"],
                name="unique_memory_map_email"
            )
        ]

    def __str__(self):
        return f"{self.name} ({self.email})"


#MemoryMapBucketInfo
class MemoryMapBucketInfo(BaseModel):
    memory_map = models.ForeignKey(
        MemoryMap,
        on_delete=models.CASCADE,
        related_name="bucket_list"
    )

    location_name = models.CharField(max_length=255)
    latitude = models.FloatField()
    longitude = models.FloatField()
    is_visited = models.BooleanField(default=False)
    tagged_friends = models.JSONField(default=list, blank=True)


    def __str__(self):
        return self.location_name
    


#Common = MemoryMediaDetails
FILE_TYPES = (
    ('image', 'Image'),
    ('video', 'Video'),
    ('audio', 'Audio'),
    ('other', 'Other'),
)


class MemoryMediaDetails(BaseModel):
    user = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        related_name="memory_map_media"
    )

    memory_place = models.ForeignKey(
        MemoryMapPinnedLocationInfo,
        on_delete=models.CASCADE,
        related_name="media_files",
        null=True,
        blank=True
    )

    bucket_item = models.ForeignKey(
        MemoryMapBucketInfo,
        on_delete=models.CASCADE,
        related_name="media_files",
        null=True,
        blank=True
    )

    file = models.FileField(upload_to="memory_map/")
    file_type = models.CharField(
        max_length=20,
        choices=FILE_TYPES,
        default='other'
    )
    thumbnail = models.ImageField(
        upload_to="memory_map/thumbnails/",
        null=True,
        blank=True
  ) 
    title = models.CharField(max_length=255, blank=True ,default="")
    description = models.TextField(blank=True, default="")
    file_size = models.PositiveIntegerField(blank=True,null=True)

    @property
    def memory_map(self):
        if self.memory_place_id:
            return self.memory_place.memory_map
        if self.bucket_item_id:
            return self.bucket_item.memory_map
        return None
        


    def __str__(self):
        return self.title or f"Media {self.id}"
    


    # def clean(self):
    #     if self.memory_place and self.bucket_item:
    #         raise ValidationError("Media cannot belong to both location and bucket.")
        
    #     if not self.memory_place and not self.bucket_item:
    #         raise ValidationError("Media must belong to either location or bucket.")
        

    # class Meta:
    #     constraints = [
    #         models.CheckConstraint(
    #             check=(
    #                 Q(memory_place__isnull=False, bucket_item__isnull=True) |
    #                 Q(memory_place__isnull=True, bucket_item__isnull=False)
    #             ),
    #             name="media_belongs_to_one_place_or_bucket"
    #         )
    #     ]







        










    











    





   
    






