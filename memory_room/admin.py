from django.contrib import admin
from .models import (
    MemoryRoomTemplateDefault,
    CustomMemoryRoomTemplate,
    MemoryRoom,
    MemoryRoomMediaFile,
    MemoryRoomDetail,
    TimeCapSoulTemplateDefault,
    CustomTimeCapSoulTemplate,
    TimeCapSoul,
    TimeCapSoulMediaFile,
    TimeCapSoulDetail,
    TimeCapSoulRecipient,
    RecipientsDetail,
    UserMapper,
    Notification
)




@admin.register(TimeCapSoulMediaFile)
class TimeCapSoulMediaFileAdmin(admin.ModelAdmin):
    list_display = ("id", "user", "time_capsoul",)


@admin.register(Notification)
class NotificationAdmin(admin.ModelAdmin):
    list_display = ("id", "user", "memory_room",'time_capsoul', 'category', 'title', 'is_read')



@admin.register(MemoryRoomTemplateDefault)
class MemoryRoomTemplateDefaultAdmin(admin.ModelAdmin):
    list_display = ("name", "slug", "created_at", "is_deleted")
    search_fields = ("name", "slug")


@admin.register(CustomMemoryRoomTemplate)
class CustomMemoryRoomTemplateAdmin(admin.ModelAdmin):
    list_display = ("name", "slug", "default_template", "created_at")
    list_filter = ("default_template",)
    search_fields = ("name",)


@admin.register(MemoryRoom)
class MemoryRoomAdmin(admin.ModelAdmin):
    list_display = ("user", "room_template", "created_at")
    list_filter = ("room_template",)
    search_fields = ("user__username",)


@admin.register(MemoryRoomMediaFile)
class MemoryRoomMediaFilesAdmin(admin.ModelAdmin):
    list_display = ('id', 'memory_room_id','file_type',  "file", "is_cover_image", "created_at")
    list_filter = ("file_type", "is_cover_image")
    search_fields = ("file", "description")

    def get_memory_room_id(self, obj):
        return obj.memory_room.id


@admin.register(MemoryRoomDetail)
class MemoryRoomDetailAdmin(admin.ModelAdmin):
    list_display = ("memory_room", "created_at")
    filter_horizontal = ("media_files",)


@admin.register(TimeCapSoulTemplateDefault)
class TimeCapSoulTemplateDefaultAdmin(admin.ModelAdmin):
    list_display = ("name", "slug", "created_at")
    search_fields = ("name",)


@admin.register(CustomTimeCapSoulTemplate)
class CustomTimeCapSoulTemplatesAdmin(admin.ModelAdmin):
    list_display = ("name", "slug", "default_template", "created_at")
    list_filter = ("default_template",)
    search_fields = ("name",)


@admin.register(TimeCapSoul)
class TimeCapSoulAdmin(admin.ModelAdmin):
    list_display = ('id', 'get_name', 'status', "user",  "created_at", 'get_unlock_date')
    list_filter = ("capsoul_template",)
    search_fields = ("user__username",)
    
    def get_name(self, obj):
        return obj.capsoul_template.name
    
    def get_unlock_date(self, obj):
        return obj.details.unlock_date if obj.details.unlock_date else 'Not Available'


@admin.register(TimeCapSoulDetail)
class TimeCapSoulDetailAdmin(admin.ModelAdmin):
    list_display = ('id', "time_capsoul", "unlock_date", "created_at")
    filter_horizontal = ("media_files",)


@admin.register(TimeCapSoulRecipient)
class TimeCapSoulRecipientsAdmin(admin.ModelAdmin):
    list_display = ("name", "email", "time_capsoul", 'is_capsoul_deleted', 'is_opened','is_logged_in')
    search_fields = ("name", "email", "time_capsoul")


@admin.register(RecipientsDetail)
class RecipientsDetailsAdmin(admin.ModelAdmin):
    list_display = ("time_capsoul", "created_at")
    filter_horizontal = ("recipients",)



@admin.register(UserMapper)
class UserMapperAdmin(admin.ModelAdmin):
    list_display = ("user", "max_storage_limit", "current_storage", "is_deleted")