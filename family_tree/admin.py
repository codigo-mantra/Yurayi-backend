from django.contrib import admin
from .models import (
    FamilyTree,
    FamilyMember,
    Partnership,
    ParentalRelationship,
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
