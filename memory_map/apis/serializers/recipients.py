from rest_framework import serializers
from memory_map.models import MemoryMapRecipients
from userauth.models import User


class RecipientSerializer(serializers.ModelSerializer):
    class Meta:
        model = MemoryMapRecipients
        fields = [
            "id",
            "name",
            "email",
            "permission",
            "created_at",
        ]



class RecipientBulkSerializer(serializers.Serializer):
    recipients = serializers.ListField(
        child=serializers.DictField(),                   #child =What type each item inside the list should be
        allow_empty=True
    )


    def validate_recipients(self, value):
        owner = self.context.get("owner")
        owner_email = owner.email.lower() if owner else None

        emails = set()

        for item in value:
            email = item.get("email", "").lower().strip()
            name = item.get("name", "").strip()
            permission = item.get("permission", "view")

            # email required
            if not email:
                raise serializers.ValidationError({"email": "Email is required."})

            # name required
            if not name:
                raise serializers.ValidationError({"name": f"Name required for {email}"})

            # permission check
            if permission not in ["view", "edit"]:
                raise serializers.ValidationError({
                    "permission": f"Invalid permission for {email}"
                })

            # owner cannot be recipient
            if owner_email and email == owner_email:
                raise serializers.ValidationError({
                    "email": "Owner cannot be added as recipient."
                })

            # duplicate emails
            if email in emails:
                raise serializers.ValidationError({
                    "email": f"Duplicate email: {email}"
                })

            emails.add(email)

            # normalize values
            item["email"] = email
            item["name"] = name

        return value
    

    def save(self):
        memory_map = self.context["memory_map"]
        recipients_data = self.validated_data["recipients"]
        
        incoming_emails = {item["email"] for item in recipients_data}

        # Soft-delete removed recipients
        MemoryMapRecipients.objects.filter(
            memory_map=memory_map
        ).exclude(email__in=incoming_emails).update(is_deleted=True)

        # Pre-fetch all matching users in one query
        user_map = {
            u.email: u 
            for u in User.objects.filter(email__in=incoming_emails)
        }

        saved = []
        for item in recipients_data:
            email = item["email"]
            obj, _ = MemoryMapRecipients.objects.update_or_create(
                memory_map=memory_map,
                email=email,
                defaults={
                    "user": user_map.get(email),  # None if not registered
                    "name": item["name"],
                    "permission": item.get("permission", "view"),
                    "is_deleted": False,
                }
            )
            saved.append(obj)

        return saved

    # def save(self):
    #     memory_map = self.context["memory_map"]
    #     recipients_data = self.validated_data["recipients"]

    #     # 1. soft delete all existing
    #     MemoryMapRecipients.objects.filter(
    #         memory_map=memory_map
    #     ).update(is_deleted=True)

    #     new_objects = []
    #     for item in recipients_data:
    #         email = item["email"]

    #         linked_user = User.objects.filter(email=email).first()

    #         new_objects.append(
    #             MemoryMapRecipients(
    #                 memory_map=memory_map,
    #                 user=linked_user,
    #                 name=item["name"],
    #                 email=email,
    #                 permission=item.get("permission", "view"),
    #             )
    #         )

    #     # 2. bulk create
    #     MemoryMapRecipients.objects.bulk_create(new_objects)

    #     return new_objects



