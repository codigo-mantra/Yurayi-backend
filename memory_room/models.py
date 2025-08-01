from django.db import models
from userauth.models import User,Assets
from django.core.exceptions import ValidationError
from memory_room.utils import generate_unique_slug



class BaseModel(models.Model):
    created_at = models.DateTimeField(
        auto_now_add=True,
        verbose_name="Created At"
    )
    updated_at = models.DateTimeField(
        auto_now=True,
        verbose_name="Updated At"
    )
    is_deleted = models.BooleanField(
        default=False,
        verbose_name="Is Deleted"
    )

    class Meta:
        abstract = True


class MemoryRoomTemplateDefault(BaseModel):
    name = models.CharField(max_length=255, verbose_name="Name")
    summary = models.TextField(blank=True, null=True, verbose_name="Summary")
    cover_image = models.ForeignKey(
        Assets,
        on_delete=models.CASCADE,
        null=True,
        blank=True,
        related_name="memory_room_template_covers",
        verbose_name="Cover Image"
    )
    slug = models.SlugField(blank=True, null=True)

    class Meta:
        verbose_name = "Default Memory Room Template"
        verbose_name_plural = "Default Memory Room Templates"

    def __str__(self):
        return self.name
    
    def save(self, *args, **kwargs):
        if not self.slug and self.name:
            self.slug = generate_unique_slug(self)
        super().save(*args, **kwargs)


class CustomMemoryRoomTemplate(BaseModel):
    name = models.CharField(max_length=255, verbose_name="Memory Room Name")
    slug = models.SlugField(blank=True, null=True, verbose_name="Slug")
    summary = models.TextField(blank=True, null=True, verbose_name="Memory Room Summary")
    cover_image = models.ForeignKey(
        Assets,
        on_delete=models.CASCADE,
        null=True,
        blank=True,
        related_name="custom_memory_room_template_covers",
        verbose_name="Cover Image"
    )
    default_template = models.ForeignKey(
        MemoryRoomTemplateDefault,
        on_delete=models.CASCADE,
        null=True,
        blank=True,
        related_name="custom_templates",
        verbose_name="Default Template"
    )

    class Meta:
        verbose_name = "Custom Memory Room Template"
        verbose_name_plural = "Custom Memory Room Templates"

    def __str__(self):
        return self.name
    def save(self, *args, **kwargs):
        if not self.slug and self.name:
            self.slug = generate_unique_slug(self)
        super().save(*args, **kwargs)


class MemoryRoom(BaseModel):
    user = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        related_name="memory_rooms",
        verbose_name="Owner"
    )
    room_template = models.ForeignKey(
        CustomMemoryRoomTemplate,
        on_delete=models.CASCADE,
        null=True,
        blank=True,
        related_name="memory_rooms",
        verbose_name="Room Template"
    )

    class Meta:
        verbose_name = "Memory Room"
        verbose_name_plural = "Memory Rooms"

    def __str__(self):
        return f"{self.user.username}'s {self.room_template.name}"


FILE_TYPES = (
    ('image', 'Image'),
    ('video', 'Video'),
    ('audio', 'Audio'),
    ('document', 'Document'),
    ('other', 'Other'),
)


class MemoryRoomMediaFile(BaseModel):
    user = models.ForeignKey(User, on_delete=models.CASCADE, blank=True, null=True, related_name='user_media_files')
    memory_room = models.ForeignKey(MemoryRoom, on_delete=models.CASCADE, blank=True, null=True, related_name='memory_media_files')

    file = models.FileField(
        upload_to='memory_room_files/',
        verbose_name="Media File"
    )
    file_type = models.CharField(
        max_length=20,
        choices=FILE_TYPES,
        default='other',
        verbose_name="File Type"
    )
    cover_image = models.ForeignKey(
        Assets,
        on_delete=models.CASCADE,
        null=True,
        blank=True,
        related_name="memory_room_media_cover",
        verbose_name="Cover Image"
    )
    description = models.TextField(
        blank=True,
        null=True,
        verbose_name="Description"
    )
    is_cover_image = models.BooleanField(
        default=False,
        verbose_name="Use as Cover"
    )
    thumbnail_url = models.URLField(blank=True, null=True)
    thumbnail_key = models.CharField(blank=True, null=True)
    file_size = models.BigIntegerField(blank=True, null=True, verbose_name='File size')
    s3_url = models.URLField(blank=True, null=True)
    s3_key = models.CharField(blank=True, null=True)





    class Meta:
        verbose_name = "Memory Room Media File"
        verbose_name_plural = "Memory Room Media Files"

    def __str__(self):
        return f"{self.file.name}"


class MemoryRoomDetail(BaseModel):
    memory_room = models.OneToOneField(
        MemoryRoom,
        on_delete=models.CASCADE,
        related_name="details",
        verbose_name="Memory Room"
    )
    media_files = models.ManyToManyField(
        MemoryRoomMediaFile,
        blank=True,
        related_name="memory_room_details",
        verbose_name="Media Files"
    )
    occupied_storage = models.CharField(blank=True, null=True, help_text="Storage used timecap-soul")


    class Meta:
        verbose_name = "Memory Room Detail"
        verbose_name_plural = "Memory Room Details"

    def __str__(self):
        return f"Details for {self.memory_room}"


class TimeCapSoulTemplateDefault(BaseModel):
    name = models.CharField(max_length=255, verbose_name="TimeCapSoul Name")
    summary = models.TextField(blank=True, null=True, verbose_name="TimeCapSoul Summary")
    cover_image = models.ForeignKey(
                Assets,
        on_delete=models.CASCADE,
        null=True,
        blank=True,
        related_name="timecapsoul_template_covers",
        verbose_name="Cover Image"
    )
    slug = models.SlugField(blank=True, null=True, verbose_name="Slug")

    class Meta:
        verbose_name = "Default TimeCapSoul Template"
        verbose_name_plural = "Default TimeCapSoul Templates"

    def __str__(self):
        return self.name
    
    def save(self, *args, **kwargs):
        if not self.slug and self.name:
            self.slug = generate_unique_slug(self)
        super().save(*args, **kwargs)



class CustomTimeCapSoulTemplate(BaseModel):
    name = models.CharField(max_length=255, verbose_name="TimeCapSoul Name")
    slug = models.SlugField(verbose_name="Slug")
    summary = models.TextField(blank=True, null=True, verbose_name="TimeCapSoul Summary")
    cover_image = models.ForeignKey(
        Assets,
        on_delete=models.CASCADE,
        null=True,
        blank=True,
        related_name="custom_timecapsoul_template_covers",
        verbose_name="Cover Image"
    )
    default_template = models.ForeignKey(
        TimeCapSoulTemplateDefault,
        on_delete=models.CASCADE,
        null=True,
        blank=True,
        related_name="custom_templates",
        verbose_name="Default Template"
    )

    class Meta:
        verbose_name = "Custom TimeCapSoul Template"
        verbose_name_plural = "Custom TimeCapSoul Templates"

    def __str__(self):
        return self.name
    
    def save(self, *args, **kwargs):
        if not self.slug and self.name:
            self.slug = generate_unique_slug(self)
        super().save(*args, **kwargs)
     

STATUS_CHOICES = (
    ('sealed', 'Sealed With Love'),
    ('unlocked', 'Unlocked'),
    ('created', 'Being Crafted')

)

class AbstractMediaFile(BaseModel):
    
    file = models.FileField(
        upload_to='media_files/',
        verbose_name="Media File"
    )
    file_type = models.CharField(
        max_length=20,
        choices=FILE_TYPES,
        default='other',
        verbose_name="File Type"
    )
    title = models.CharField(
        max_length=255,
        blank=True,
        null=True
    )
    description = models.TextField(
        blank=True,
        null=True,
        verbose_name="Description"
    )
    file_size = models.BigIntegerField(
        blank=True,
        null=True,
        verbose_name="File Size"
    )
    s3_url = models.URLField(
        blank=True,
        null=True,
        verbose_name="S3 URL"
    )
    s3_key = models.CharField(
        max_length=512,
        blank=True,
        null=True,
        verbose_name="S3 Key"
    )
    is_cover_image = models.BooleanField(
        default=False,
        help_text="Mark if this media is the cover image"
    )
    

    class Meta:
        abstract = True


class TimeCapSoul(BaseModel):
    user = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        related_name="timecapsouls",
        verbose_name="Owner"
    )
    capsoul_template = models.ForeignKey(
        CustomTimeCapSoulTemplate,
        on_delete=models.CASCADE,
        null=True,
        blank=True,
        related_name="timecapsouls",
        verbose_name="CapSoul Template"
    )
    status = models.CharField(choices=STATUS_CHOICES, default='created')


    class Meta:
        verbose_name = "TimeCapSoul"
        verbose_name_plural = "TimeCapSouls"

    def __str__(self):
        return f"{self.user.username}'s TimeCapSoul"

class TimeCapSoulReplica(BaseModel):
    name = models.CharField(max_length=255, verbose_name="TimeCapSoul Name",blank=True, null=True)
    slug = models.SlugField(verbose_name="Slug",blank=True, null=True)
    summary = models.TextField(blank=True, null=True, verbose_name="TimeCapSoul Summary")
    status = models.CharField(choices=STATUS_CHOICES, blank=True, null=True)
    cover_image = models.ForeignKey(
        Assets,
        on_delete=models.CASCADE,
        null=True,
        blank=True,
        related_name="timecapsoul_replica",
        verbose_name="Cover Image"
    )
    user = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        related_name="time_capsoul_replica",
        verbose_name="Owner",
        blank=True, null=True
    )
    parent_time_capsoul  = models.OneToOneField(TimeCapSoul, on_delete=models.CASCADE, related_name='time_capsoul_replica',blank=True, null=True)


class TimeCapSoulMediaFile(AbstractMediaFile):
    user = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        blank=True,
        null=True,
        related_name='time_capsoul_media_files'
    )
    time_capsoul = models.ForeignKey(
        'memory_room.TimeCapSoul',
        on_delete=models.CASCADE,
        blank=True,
        null=True,
        related_name='timecapsoul_media_files'
    )
    thumbnail = models.ForeignKey(
        Assets,
        on_delete=models.CASCADE,
        blank=True,
        null=True,
        related_name='time_capsoul_media_thumbnails',
        verbose_name="Thumbnail"
    )

    class Meta:
        verbose_name = "TimeCapSoul Media File"
        verbose_name_plural = "TimeCapSoul Media Files"
        ordering = ['-created_at']


class TimeCapSoulMediaFileReplica(AbstractMediaFile):
    user = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        blank=True,
        null=True,
        related_name='timecapsoul_media_file_replicas'
    )
    thumbnail = models.ForeignKey(
        Assets,
        on_delete=models.CASCADE,
        blank=True,
        null=True,
        related_name='timecapsoul_media_file_replicas_thumbnails',
        verbose_name="Thumbnail"
    )
    time_capsoul = models.ForeignKey(
        TimeCapSoul,
        on_delete=models.CASCADE,
        blank=True,
        null=True,
        related_name='media_file_replicas'
    )
    parent_media_file = models.OneToOneField(
        TimeCapSoulMediaFile,
        on_delete=models.CASCADE,
        related_name='replica'
    )

    class Meta:
        verbose_name = "TimeCapSoul Media File Replica"
        verbose_name_plural = "TimeCapSoul Media File Replicas"
        ordering = ['-created_at']


class TimeCapSoulDetail(BaseModel):
    time_capsoul = models.OneToOneField(
        TimeCapSoul,
        on_delete=models.CASCADE,
        related_name="details",
        verbose_name="TimeCapSoul"
    )
    media_files = models.ManyToManyField(
        TimeCapSoulMediaFile,
        blank=True,
        related_name="timecapsoul_details",
        verbose_name="Media Files"
    )
    is_locked  = models.BooleanField(default=False)
    unlock_date = models.DateTimeField(verbose_name="Unlock Date", blank=True, null=True)
    occupied_storage = models.CharField(blank=True, null=True, help_text="Storage used timecap-soul")



    class Meta:
        verbose_name = "TimeCapSoul Detail"
        verbose_name_plural = "TimeCapSoul Details"

    def __str__(self):
        return f"Details for {self.time_capsoul}"


class TimeCapSoulRecipient(BaseModel):
     name = models.CharField(max_length=255, verbose_name="Recipient Name")
     email = models.EmailField(verbose_name="Recipient Email")

     class Meta:
         verbose_name = "TimeCapSoul Recipient"
         verbose_name_plural = "TimeCapSoul Recipients"

     def __str__(self):
         return f"{self.name} <{self.email}>"


class RecipientsDetail(BaseModel):
     time_capsoul = models.OneToOneField(
         TimeCapSoul,
         on_delete=models.CASCADE,
         related_name="recipient_details",
         verbose_name="TimeCapSoul"
     )
     recipients = models.ManyToManyField(
         TimeCapSoulRecipient,
         blank=True,
         related_name="recipient_details",
         verbose_name="Recipients"
     )

     class Meta:
         verbose_name = "Recipient Detail"
         verbose_name_plural = "Recipient Details"

     def __str__(self):
         return f"Recipients for {self.time_capsoul}"


class UserMapper(BaseModel):
    user = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        related_name='user_mapper',
        verbose_name='User'
    )
    max_storage_limit = models.CharField(
        max_length=100,
        verbose_name='Max Storage Limit'
    )
    current_storage = models.CharField(
        max_length=100,
        verbose_name='Current Storage'
    )
    memory_room = models.ManyToManyField(
        'MemoryRoom',
        blank=True,
        related_name='user_mappers',
        verbose_name='Memory Rooms'
    )
    time_capsoul = models.ManyToManyField(
        'TimeCapSoul',
        blank=True,
        related_name='user_mappers',
        verbose_name='TimeCapsouls'
    )

    class Meta:
        verbose_name = "User Mapper"
        verbose_name_plural = "User Mappers"

    def __str__(self):
        return f"Storage Mapper for {self.user.username}"
