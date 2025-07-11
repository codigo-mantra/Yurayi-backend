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
    list_display = ("name", "slug", "is_created", "is_deleted")
    search_fields = ("name", "slug")


@admin.register(CustomMemoryRoomTemplate)
class CustomMemoryRoomTemplateAdmin(admin.ModelAdmin):
    list_display = ("name", "slug", "default_template", "is_created")
    list_filter = ("default_template",)
    search_fields = ("name",)


@admin.register(MemoryRoom)
class MemoryRoomAdmin(admin.ModelAdmin):
    list_display = ("user", "room_template", "is_created")
    list_filter = ("room_template",)
    search_fields = ("user__username",)


@admin.register(MemoryRoomMediaFile)
class MemoryRoomMediaFilesAdmin(admin.ModelAdmin):
    list_display = ("file", "types", "is_cover_image", "is_created")
    list_filter = ("types", "is_cover_image")
    search_fields = ("file", "description")


@admin.register(MemoryRoomDetail)
class MemoryRoomDetailAdmin(admin.ModelAdmin):
    list_display = ("memory_room", "is_created")
    filter_horizontal = ("media_files",)


@admin.register(TimeCapSoulTemplateDefault)
class TimeCapSoulTemplateDefaultAdmin(admin.ModelAdmin):
    list_display = ("name", "slug", "is_created")
    search_fields = ("name",)


@admin.register(CustomTimeCapSoulTemplate)
class CustomTimeCapSoulTemplatesAdmin(admin.ModelAdmin):
    list_display = ("name", "slug", "default_template", "is_created")
    list_filter = ("default_template",)
    search_fields = ("name",)


@admin.register(TimeCapSoul)
class TimeCapSoulAdmin(admin.ModelAdmin):
    list_display = ("user", "capsoul_template", "is_created")
    list_filter = ("capsoul_template",)
    search_fields = ("user__username",)


@admin.register(TimeCapSoulDetail)
class TimeCapSoulDetailAdmin(admin.ModelAdmin):
    list_display = ("time_capsoul", "unlock_date", "is_created")
    filter_horizontal = ("media_files",)


@admin.register(TimeCapSoulRecipient)
class TimeCapSoulRecipientsAdmin(admin.ModelAdmin):
    list_display = ("name", "email", "is_created")
    search_fields = ("name", "email")


@admin.register(RecipientsDetail)
class RecipientsDetailsAdmin(admin.ModelAdmin):
    list_display = ("time_capsoul", "is_created")
    filter_horizontal = ("recipients",)



@admin.register(UserMapper)
class UserMapperAdmin(admin.ModelAdmin):
    list_display = ("user", "max_storage_limit", "current_storage", "is_deleted")