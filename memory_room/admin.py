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
    TimeCapSoulDetail,
    TimeCapSoulRecipient,
    RecipientsDetail,
    UserMapper,
)

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
    list_display = ("user", "capsoul_template", "created_at")
    list_filter = ("capsoul_template",)
    search_fields = ("user__username",)


@admin.register(TimeCapSoulDetail)
class TimeCapSoulDetailAdmin(admin.ModelAdmin):
    list_display = ("time_capsoul", "unlock_date", "created_at")
    filter_horizontal = ("media_files",)


@admin.register(TimeCapSoulRecipient)
class TimeCapSoulRecipientsAdmin(admin.ModelAdmin):
    list_display = ("name", "email", "created_at")
    search_fields = ("name", "email")


@admin.register(RecipientsDetail)
class RecipientsDetailsAdmin(admin.ModelAdmin):
    list_display = ("time_capsoul", "created_at")
    filter_horizontal = ("recipients",)



@admin.register(UserMapper)
class UserMapperAdmin(admin.ModelAdmin):
    list_display = ("user", "max_storage_limit", "current_storage", "is_deleted")