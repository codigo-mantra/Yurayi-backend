from django.contrib import admin
from django.utils.html import format_html

from .models import (
    FamilyTree,
    FamilyMember,
    Partnership,
    ParentalRelationship,
    FamilyTreeDiaryCategory,
    FamilyTreeDiary,
    FamilyTreeRecipient,
    FamilyTreeGallery
)


@admin.register(FamilyTree)
class FamilyTreeAdmin(admin.ModelAdmin):
    list_display = (
        "id",
        "name",
        "owner",
        "root_member",
        "is_deleted",
        "created_at",
    )
    list_filter = ("is_deleted", "created_at")
    search_fields = ("name", "owner__email")
    autocomplete_fields = ("owner", "root_member")
    readonly_fields = ("id", "created_at", "updated_at")


@admin.register(FamilyMember)
class FamilyMemberAdmin(admin.ModelAdmin):
    list_display = (
        "id",
        'primary_father',
        'primary_mother',
        "first_name",
        "last_name",
        "gender",
        "relation_type",
        "family_tree",
        "is_person_alive",
        "is_married",
        "is_deleted",
    )
    list_filter = (
        "gender",
        "relation_type",
        "is_person_alive",
        "is_married",
        "is_deleted",
    )
    search_fields = (
        "first_name",
        "last_name",
        "email_address",
        "profession",
    )
    autocomplete_fields = ("family_tree", "author")
    readonly_fields = ("created_at", "updated_at")


@admin.register(Partnership)
class PartnershipAdmin(admin.ModelAdmin):
    list_display = (
        "id",
        "family_tree",
        "husband",
        "wife",
        "partner_generation_no",
        "marriage_date",
        "divorce_date",
        "is_deleted",
    )
    list_filter = ("is_deleted", "marriage_date")
    search_fields = (
        "husband__first_name",
        "wife__first_name",
    )
    autocomplete_fields = ("family_tree", "husband", "wife")
    readonly_fields = ("created_at", "updated_at")


@admin.register(ParentalRelationship)
class ParentalRelationshipAdmin(admin.ModelAdmin):
    list_display = (
        "id",
        "family_tree",
        "father",
        "mother",
        "child",
        "parent_type",
        "is_deleted",
    )
    list_filter = ("parent_type", "is_deleted")
    search_fields = (
        "child__first_name",
        "father__first_name",
        "mother__first_name",
    )
    autocomplete_fields = ("family_tree", "father", "mother", "child")


@admin.register(FamilyTreeDiaryCategory)
class FamilyTreeDiaryCategoryAdmin(admin.ModelAdmin):
    list_display = (
        "name",
        "color_code",
        "slug",
        "is_deleted",
        "created_at",
    )
    list_filter = ("is_deleted",)
    search_fields = ("name", "slug")
    prepopulated_fields = {"slug": ("name",)}
    ordering = ("name",)

    fieldsets = (
        ("Category Info", {
            "fields": ("name", "slug", "color_code")
        }),
        ("Status", {
            "fields": ("is_deleted",)
        }),
        ("Timestamps", {
            "fields": ("created_at", "updated_at"),
        }),
    )

    readonly_fields = ("created_at", "updated_at")


@admin.register(FamilyTreeDiary)
class FamilyTreeDiaryAdmin(admin.ModelAdmin):
    list_display = (
        "title",
        "family_tree",
        "author",
        "category",
        "is_deleted",
        "created_at",
    )
    list_filter = ("is_deleted", "category", "family_tree")
    search_fields = ("title", "description")
    ordering = ("-created_at",)

    fieldsets = (
        ("Diary Info", {
            "fields": (
                "family_tree",
                "author",
                "category",
                "title",
            )
        }),
        ("Content", {
            "fields": ("description",)
        }),
        ("Status", {
            "fields": ("is_deleted",)
        }),
        ("Timestamps", {
            "fields": ("created_at", "updated_at"),
        }),
    )

    readonly_fields = ("created_at", "updated_at")

    def save_model(self, request, obj, form, change):
        if not obj.author_id:
            obj.author = request.user
        super().save_model(request, obj, form, change)



@admin.register(FamilyTreeRecipient)
class FamilyTreeRecipientAdmin(admin.ModelAdmin):
    list_display = (
        "recipient_email",
        "family_tree",
        "permissions",
        "is_deleted",
        "created_at",
    )

    list_filter = (
        "permissions",
        "is_deleted",
        "family_tree",
    )

    search_fields = (
        "recipient_email",
        "family_tree__name",  # change if your field name differs
    )

    readonly_fields = (
        "created_at",
        "updated_at",
    )

    ordering = ("-created_at",)

    actions = ["restore_recipients", "soft_delete_recipients"]

    def restore_recipients(self, request, queryset):
        queryset.update(is_deleted=False)
        self.message_user(request, "Selected recipients restored successfully.")
    restore_recipients.short_description = "Restore selected recipients"

    def soft_delete_recipients(self, request, queryset):
        queryset.update(is_deleted=True)
        self.message_user(request, "Selected recipients soft-deleted successfully.")
    soft_delete_recipients.short_description = "Soft delete selected recipients"


@admin.register(FamilyTreeGallery)
class FamilyTreeGalleryAdmin(admin.ModelAdmin):
    list_display = (
        "id",
        "title",
        "family_tree",
        "author",
        "file_type",
        "file_size",
        "file_preview",
        "thumbnail_preview_admin",
        "is_deleted",
        "created_at",
    )

    list_filter = (
        "file_type",
        "is_deleted",
        "created_at",
    )

    search_fields = (
        "title",
        "description",
        "family_tree__id",
        "author__email",
    )

    readonly_fields = (
        "id",
        "file_preview",
        "thumbnail_preview_admin",
        "created_at",
        "updated_at",
    )

    ordering = ("-created_at",)
    list_per_page = 25

    fieldsets = (
        ("Basic Info", {
            "fields": (
                "id",
                "family_tree",
                "author",
                "title",
                "description",
                "file_type",
                "file_size",
                "is_deleted",
            )
        }),
        ("Media", {
            "fields": (
                "file",
                "file_preview",
                "thumbnail_preview",
                "thumbnail_preview_admin",
            )
        }),
        ("Timestamps", {
            "fields": (
                "created_at",
                "updated_at",
            )
        }),
    )

    # --------------------------------------------------
    # Admin helpers
    # --------------------------------------------------

    def file_preview(self, obj):
        if not obj.file:
            return "-"
        return format_html(
            '<a href="{}" target="_blank">Download</a>',
            obj.file.url
        )

    file_preview.short_description = "File"

    def thumbnail_preview_admin(self, obj):
        if not obj.thumbnail_preview:
            return "-"
        return format_html(
            '<img src="{}" style="height:80px;border-radius:4px;" />',
            obj.thumbnail_preview.url
        )

    thumbnail_preview_admin.short_description = "Thumbnail"

    def get_queryset(self, request):
        """Show deleted items too (admin only)"""
        qs = super().get_queryset(request)
        return qs.select_related("family_tree", "author")