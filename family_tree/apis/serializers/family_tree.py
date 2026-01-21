from rest_framework import serializers
from datetime import date
from django.db.models import Q
from django.db import models

from family_tree.models import FamilyMember, Partnership, ParentalRelationship, FamilyTree, FamilyTreeRecipient

def calculate_age(birth_date):
    if not birth_date:
        return None
    today = date.today()
    return today.year - birth_date.year - (
        (today.month, today.day) < (birth_date.month, birth_date.day)
    )



class FamilyTreeSerializer(serializers.ModelSerializer):
    is_owner = serializers.SerializerMethodField()

    class Meta:
        model = FamilyTree
        fields = (
            "id",
            "slug",
            "is_owner",
            "name",
            "description",
            "created_at",
            "updated_at",
        )
    
    def get_is_owner(self, obj):
        user = self.context['user']
        return  True if obj.owner == user else False


class FamilyTreeCreateSerializer(serializers.Serializer):
    first_name = serializers.CharField(max_length=100)
    last_name = serializers.CharField(max_length=100, required=False, allow_blank=True)
    gender = serializers.ChoiceField(choices=["male", "female", "other"])
    is_married = serializers.BooleanField(required=False, default=False)
    married_date = serializers.DateField(required=False, allow_null=True)
    is_person_alive = serializers.BooleanField(default=True)
    death_date = serializers.DateField(required=False, allow_null=True)
    email_address = serializers.EmailField(required=False, allow_blank=True, allow_null=True)
    profession = serializers.CharField(required=False, allow_blank=True, allow_null=True)
    birth_date = serializers.DateField(required=False, allow_null=True)
    profile_image_s3_key = serializers.CharField(
        required=False,
        allow_blank=True,
        allow_null=True
    )

    def validate(self, attrs):
        today = date.today()

        is_married = attrs.get("is_married")
        married_date = attrs.get("married_date")

        is_alive = attrs.get("is_person_alive")
        death_date = attrs.get("death_date")
        birth_date = attrs.get("birth_date")
        email = attrs.get("email_address")

        errors = {}

        required_fields = [
            "first_name",
            "last_name",
            "gender",
            "is_person_alive",
            "email_address",
            "birth_date",
        ]

        for field in required_fields:
            value = attrs.get(field)

            if value in [None, "", []]:
                errors[field] = f"{field.replace('_', ' ').capitalize()} is required."

        if errors:
            raise serializers.ValidationError(errors)

        if is_married:
            if not married_date:
                raise serializers.ValidationError(
                    {"married_date": "Married date is required if person is married."}
                )

            if married_date > today:
                raise serializers.ValidationError(
                    {"married_date": "Married date must be a past date."}
                )

        if not is_alive:
            if not death_date:
                raise serializers.ValidationError(
                    {"death_date": "Death date is required if person is not alive."}
                )
            if death_date > today:
                raise serializers.ValidationError(
                    {"death_date": "Death date must be a past date."}
                )
        if birth_date and death_date:
            if birth_date > death_date:
                raise serializers.ValidationError(
                    "Birth date cannot be after death date."
                )
        if birth_date and married_date:
            if married_date <= birth_date:
                raise serializers.ValidationError(
                    "Married date must be after birth date."
                )
        if is_alive and death_date:
            raise serializers.ValidationError(
                {"death_date": "Death date should not be provided for a living person."}
            )

        return attrs


class AddNewFamilyMemberSerializer(serializers.ModelSerializer):
    parent_node_id = serializers.IntegerField(write_only=True, required=False, allow_null=True)

    
    class Meta:
        model = FamilyMember
        fields = (
            "parent_node_id",
            "first_name",
            "last_name",
            "gender",
            "is_married",
            "married_date",
            "is_person_alive",
            "email_address",
            "profession",
            "relation_type",
            "birth_date",
            "death_date",
            "profile_image_s3_key",
        )

    
    def validate(self, attrs):
        errors = {}

        required_fields = [
            "parent_node_id",
            "first_name",
            "last_name",
            "gender",
            "is_person_alive",
            "email_address",
            "birth_date",
        ]

        for field in required_fields:
            value = attrs.get(field)

            if value in [None, "", []]:
                errors[field] = f"{field.replace('_', ' ').capitalize()} is required."

        if errors:
            raise serializers.ValidationError(errors)

        return attrs

    
    def has_father(self, child):
        return bool(child.primary_father)

    def has_mother(self, child):
        return bool(child.primary_mother)

    def get_existing_father(self, child):
        return child.primary_father

    def get_existing_mother(self, child):
        return child.primary_mother

    
    def create_family_member(self, user, family_tree, validated_data):
        member = FamilyMember.objects.create(
            family_tree=family_tree,
            author=user,
            **validated_data
        )
        return member
    
    def create_parental_relationship(self, family_tree, child, father=None, mother=None):
        relation = ParentalRelationship.objects.create(
            family_tree=family_tree,
            child=child,
            father=father,
            mother=mother
        )
        return relation
    
    def get_or_create_partnership(self, husband, wife,family_tree, marriage_date):
        partnership, created = Partnership.objects.get_or_create(
            family_tree=family_tree,
            husband=husband,
            wife=wife,
            defaults={"marriage_date": marriage_date}
        )

        if created:
            partnership_count =  family_tree.partnerships.filter(is_deleted = False).exclude(id = partnership.id)
            partnership.partner_generation_no = partnership_count.count() + 1
            partnership.save()
        
        return partnership



    def create(self, validated_data):
        user = self.context["user"] 
        family_tree = self.context.get("family_tree")
        email = validated_data.get("email_address")
        relation_type = validated_data.get("relation_type").lower()
        parent_node_id = (validated_data.get("parent_node_id"))
        is_married = validated_data.get("is_married", False)
        married_date = validated_data.get("married_date", None)
        validated_data.pop("parent_node_id", None)
        gender = validated_data.get("gender").lower()

        if not parent_node_id :
            raise serializers.ValidationError({'parent_node_id': 'Parent member id is required'})
        
        parent_member_node = int(parent_node_id)

        if relation_type in ['father', 'mother', 'spouse']:
            if not is_married:
                raise serializers.ValidationError(
                    {"is_married": "Parent must be married to add father or mother."}
                )
            
            if not married_date:
                raise serializers.ValidationError(
                    {"married_date": "Married date is required when parent is married."}
                )
            
            if gender not in ['male', 'female']:
                raise serializers.ValidationError({
                    'gender': 'Member gender is invalid'
                })

        member = FamilyMember.objects.filter(
            family_tree=family_tree,
            email_address=email,
            first_name=validated_data.get("first_name"),
            last_name=validated_data.get("last_name"),
            is_deleted=False
        ).first()

        if member:
            raise serializers.ValidationError(
                {"email_address": "Family member with this email already exists in the family tree."}
            )
        # here we create and add relation here 
        try:
            parent_member_node = FamilyMember.objects.get(
                id=parent_node_id,
                is_deleted=False
            )
        except FamilyMember.DoesNotExist:
            raise serializers.ValidationError(
                {"parent_node_id": "Parent family member not found."}
            )
        else:
            
            if relation_type == 'father':

                if gender != 'male':
                    raise serializers.ValidationError({"gender": "Father must have male gender."})

                is_father_exists = self.has_father(
                    child=parent_member_node,
                )
                if is_father_exists:
                    raise serializers.ValidationError({"relation_type": "Father already exists for this parent node."})

                else:
                    # create family -tree member
                    father_as_member = self.create_family_member(
                        user, family_tree, validated_data
                    )
                    member = father_as_member
                    # add father relation here
                    parental_relation = self.create_parental_relationship(
                        family_tree=family_tree,
                        child=parent_member_node,
                        father=father_as_member
                    )
                    parent_member_node.primary_father = father_as_member
                    parent_member_node.save()

                    # add here marriage relation if married
                    mother = self.get_existing_mother(parent_member_node)

                    if mother:
                        # partnership= Partnership.objects.get_or_create(
                        #     family_tree=family_tree,
                        #     husband=father_as_member,
                        #     wife=mother,
                        #     defaults={"marriage_date": married_date}
                        # )
                        partnership = self.get_or_create_partnership(husband=father_as_member, wife=mother, marriage_date=married_date ,family_tree=family_tree)

                    else:
                        partnership = self.get_or_create_partnership(husband=father_as_member, wife=mother, marriage_date=married_date,family_tree=family_tree)

                        # partnership= Partnership.objects.get_or_create(
                        #     family_tree=family_tree,
                        #     husband=father_as_member,
                        #     defaults={"marriage_date": married_date}
                        # )
            
            elif relation_type == 'mother':

                if gender != 'female':
                    raise serializers.ValidationError({"gender": "Mother must have female gender."})

                is_mother_exists = self.has_mother(
                    child=parent_member_node,
                )
                if is_mother_exists:
                    raise serializers.ValidationError({"relation_type": "Mother already exists for this parent node."})
                else:
                        # create family -tree member
                    mother_as_member = self.create_family_member(
                        user, family_tree, validated_data
                    )
                    member = mother_as_member
                    # add mother relation here
                    parental_relation = self.create_parental_relationship(
                        family_tree=family_tree,
                        child=parent_member_node,
                        mother=mother_as_member
                    )
                    parent_member_node.primary_mother = mother_as_member
                    parent_member_node.save()

                    father = self.get_existing_father(parent_member_node)

                    if father:
                        # partnership =  Partnership.objects.get_or_create(
                        #     family_tree=family_tree,
                        #     husband=father,
                        #     wife=mother_as_member,
                        #     defaults={"marriage_date": married_date}
                        # )
                        partnership = self.get_or_create_partnership(husband=father, wife=mother_as_member, marriage_date=married_date,family_tree=family_tree)
                    else:
                        # partnership =  Partnership.objects.get_or_create(
                        #     family_tree=family_tree,
                        #     wife=mother_as_member,
                        #     defaults={"marriage_date": married_date}
                        # )
                        partnership = self.get_or_create_partnership(husband=father, wife=mother_as_member, marriage_date=married_date,family_tree=family_tree)



            elif relation_type == 'child':
                child_as_member = self.create_family_member(
                    user, family_tree, validated_data
                )
                member = child_as_member

                if parent_member_node.gender == "male":
                    child_as_member.primary_father = parent_member_node

                elif parent_member_node.gender == "female":
                    child_as_member.primary_mother = parent_member_node
                    
                child_as_member.save()

                parental_relation = self.create_parental_relationship(
                    family_tree=family_tree,
                    child=child_as_member,
                    father=parent_member_node if parent_member_node.gender == 'male' else None,
                    mother=parent_member_node if parent_member_node.gender == 'female' else None
                )

            elif relation_type == 'siblings':

                father  = parent_member_node.primary_father
                mother  = parent_member_node.primary_mother

                if father or mother:
                    sibling_as_member = self.create_family_member(
                        user, family_tree, validated_data
                    )
                    member = sibling_as_member
                    sibling_as_member.primary_father = father
                    sibling_as_member.primary_mother = mother
                    sibling_as_member.save()

                    parental_relation = self.create_parental_relationship(
                        family_tree=family_tree,
                        child=sibling_as_member,
                        father=father,
                        mother=mother
                    )
                else:
                    raise serializers.ValidationError({"parent_node_id": "Parent node is required to add sibling."})


            elif relation_type == 'spouse':

                wife = None 
                husband = None
                spouse = None

                if parent_member_node.gender == "male":
                    husband = parent_member_node

                    # existing_partnership = Partnership.objects.filter(
                    #     husband = parent_member_node,
                    #     family_tree=family_tree,
                    #     is_deleted=False,
                    # ).first()

                    existing_partnership = self.get_or_create_partnership(husband=parent_member_node, wife=wife, marriage_date=married_date,family_tree=family_tree)

                else:
                    wife = parent_member_node

                    # existing_partnership = Partnership.objects.filter(
                    #     wife = parent_member_node,
                    #     family_tree=family_tree,
                    #     is_deleted=False,
                    # ).first()

                    existing_partnership = self.get_or_create_partnership(husband=husband, wife=parent_member_node, marriage_date=married_date,family_tree=family_tree)

                    
                if existing_partnership and existing_partnership.husband and existing_partnership.wife:
                    raise serializers.ValidationError("This person is already married and partner already added.")
                
                spouse = self.create_family_member(
                    user, family_tree, validated_data
                )
                member = spouse
                                
                if existing_partnership:
                    # fill missing spouse
                    if not existing_partnership.husband:
                        existing_partnership.husband = spouse
                    elif not existing_partnership.wife:
                        existing_partnership.wife = spouse

                    existing_partnership.marriage_date = married_date
                    existing_partnership.save()
                else:
                    # no partnership exists → create new
                    if husband:
                        wife = spouse
                    else:
                        husband = spouse

                    # partnership_obj = Partnership.objects.create(
                    #     family_tree=family_tree,
                    #     husband=husband,
                    #     wife=wife,
                    #     marriage_date=married_date
                    # )  
                    existing_partnership = self.get_or_create_partnership(husband=husband, wife=wife, marriage_date=married_date,family_tree=family_tree)

            else:
                raise serializers.ValidationError(
                    {"relation_type": "Invalid relation type."}
                )
        return member


class FamilyMemberUpdateSerializer(serializers.ModelSerializer):

    class Meta:
        model = FamilyMember
        fields = (
            "first_name",
            "last_name",
            "gender"
            "is_married",
            "married_date"
            "is_person_alive",
            "email_address",
            "profession",
            "relation_type",
            "birth_date",
            "death_date",
            "profile_image_s3_key",
        )
            

class FamilyTreeNodeSerializer(serializers.ModelSerializer):
    id = serializers.CharField(source="pk", read_only=True)
    name = serializers.SerializerMethodField()
    age = serializers.SerializerMethodField()
    dateofbirth = serializers.SerializerMethodField()
    role = serializers.SerializerMethodField()
    partner = serializers.SerializerMethodField()
    parents = serializers.SerializerMethodField()
    children = serializers.SerializerMethodField()
    is_onwer = serializers.SerializerMethodField()
    is_root_node = serializers.SerializerMethodField()

    class Meta:
        model = FamilyMember
        fields = (
            "family_tree",
            "id",
            "is_onwer",
            "is_root_node",
            "name",
            "gender",
            "role",
            "age",
            "dateofbirth",
            "partner",
            "parents",
            "children",
        )
    def get_is_root_node(self, obj):
        root_node_id = self.context.get("root_node_id")
        return root_node_id == obj.id

    def get_name(self, obj):
        return f"{obj.first_name} {obj.last_name}".strip()

    def get_age(self, obj):
        return calculate_age(obj.birth_date) if obj.birth_date else None

    def get_dateofbirth(self, obj):
        return obj.birth_date.strftime("%d %b %Y") if obj.birth_date else None

    def get_is_onwer(self, obj):
        root_node_id = self.context.get("root_node_id")
        return root_node_id == obj.id


    def get_role(self, obj):
        return obj.relation_type

   

    def get_partner(self, obj):
        """
        Returns partner member ID or None
        """
        partnership = (
            Partnership.objects.filter(
                family_tree=obj.family_tree,
                is_deleted=False
            )
            .filter(models.Q(husband=obj) | models.Q(wife=obj))
            .select_related("husband", "wife")
            .first()
        )

        if not partnership:
            return None

        if partnership.husband_id == obj.id:
            return str(partnership.wife_id) if partnership.wife_id else None
        return str(partnership.husband_id) if partnership.husband_id else None

    # ----------------------------
    # PARENTS
    # ----------------------------

    def get_parents(self, obj):
        """
        Returns list of parent IDs or None
        """
        parents = []

        view_type = self.context['view_type']
        root_node_id = self.context.get("root_node_id")

        father = obj.primary_father
        mother = obj.primary_mother

        if father or mother:

            if view_type =='maternal' and root_node_id:
                # parents.append(str(mother.id))
                if father and mother:
                    parents.append(str(mother.id))
                    parents.append(str(father.id))
                else:
                    if mother:
                        parents.append(str(mother.id))
                    
                    if father:
                        parents.append(str(father.id))

            else:
                if view_type in ['all', 'paternal'] and not father:
                    partnership =Partnership.objects.filter(
                        family_tree=obj.family_tree,
                        is_deleted=False,
                        wife = mother
                    ).first()
                    
                    if partnership and  partnership.husband:
                        parents.append(str(partnership.husband.id))
                    
                    elif  partnership and  partnership.wife:
                        parents.append(str(partnership.wife.id))
                else:
                    if father:
                        parents.append(str(father.id))
                    
                    if mother:
                        parents.append(str(mother.id))


            return parents or None

    # ----------------------------
    # CHILDREN
    # ----------------------------

    def get_children(self, obj):
        """
        Returns list of child IDs or None
        """
        view_type = self.context.get('view_type')
        root_node_id = self.context.get("root_node_id")
        

        child_ids = []
        partnership = (
            Partnership.objects.filter(
                family_tree=obj.family_tree,
                is_deleted=False
            )
            .filter(models.Q(husband=obj) | models.Q(wife=obj))
            .select_related("husband", "wife")
            .first()
        )
        if partnership:
            wife = partnership.wife
            husband = partnership.husband

            if wife:
                maternal_childs = FamilyMember.objects.filter(
                    primary_mother = wife,
                    is_deleted = False,
                    family_tree = obj.family_tree
                )
                combin_childs = maternal_childs
            if husband:
                paternal_childs = FamilyMember.objects.filter(
                    primary_father = husband,
                    is_deleted = False,
                    family_tree = obj.family_tree

                )
                combin_childs = paternal_childs
            

            if  husband and wife:
                combin_childs = maternal_childs | paternal_childs

            child_ids = [str(child.id) for child in combin_childs]


        return child_ids or None


class FamilyTreeUpdateSerializer(serializers.ModelSerializer):
    class Meta:
        model = FamilyTree
        fields = ("name", "description")

    def validate(self, attrs):
        user = self.context.get("user")
        tree = self.instance

        # ownership check
        if not user or tree.owner != user:
            raise serializers.ValidationError(
                "You do not have permission to update this family tree."
            )

        # optional: prevent empty updates
        if not attrs.get("name") and not attrs.get("description"):
            raise serializers.ValidationError(
                "At least one field (name or description) must be provided."
            )

        return attrs

    def update(self, instance, validated_data):
        instance.name = validated_data.get("name", instance.name)
        instance.description = validated_data.get("description", instance.description)
        instance.save(update_fields=["name", "description", "updated_at"])
        return instance


# class FamilyTreeRecipientBulkSerializer(serializers.Serializer):
#     recipient_emails = serializers.ListField(
#         child=serializers.EmailField(),
#         allow_empty=False
#     )
#     permissions = serializers.CharField()

#     def validate_permissions(self, value):
#         allowed_permissions = dict(FamilyTreeRecipient.PERMISSION_CHOICES)

#         if value not in allowed_permissions:
#             raise serializers.ValidationError(
#                 f"Invalid permission '{value}'. "
#                 f"Allowed values are: {list(allowed_permissions.keys())}"
#             )

#         return value

#     def create(self, validated_data):
#         family_tree = self.context.get("family_tree")
#         if not family_tree:
#             raise serializers.ValidationError("Family tree context is required.")

#         emails = validated_data["recipient_emails"]
#         permissions = validated_data["permissions"]

#         recipients = []

#         for email in emails:
#             recipient, created = FamilyTreeRecipient.objects.get_or_create(
#                 family_tree=family_tree,
#                 recipient_email=email,
#                 defaults={"permissions": permissions}
#             )

#             if not created and recipient.is_deleted:
#                 recipient.is_deleted = False
#                 recipient.permissions = permissions
#                 recipient.save()

#             recipients.append(recipient)

#         return recipients


class RecipientItemSerializer(serializers.Serializer):
    email = serializers.EmailField()
    permissions = serializers.CharField(required = True)

    def validate_permissions(self, value):
        allowed_permissions = dict(FamilyTreeRecipient.PERMISSION_CHOICES)
        if value not in allowed_permissions:
            raise serializers.ValidationError(
                f"Invalid permission '{value}'. "
                f"Allowed values are: {list(allowed_permissions.keys())}"
            )
        return value


class FamilyTreeRecipientBulkSerializer(serializers.Serializer):
    recipients = serializers.ListField(
        child=RecipientItemSerializer(),
        allow_empty=False
    )

    def create(self, validated_data):
        family_tree = self.context.get("family_tree")
        if not family_tree:
            raise serializers.ValidationError("Family tree context is required.")

        recipients_data = validated_data["recipients"]
        created_recipients = []

        for item in recipients_data:
            email = item["email"]
            permissions = item.get("permissions", "view")

            recipient, created = FamilyTreeRecipient.objects.get_or_create(
                family_tree=family_tree,
                recipient_email=email,
                defaults={"permissions": permissions}
            )
            if created:
                # bind here celery task to send email to recipients

                pass

           
            created_recipients.append(recipient)

        return created_recipients
    

class FamilyTreeRecipientListSerializer(serializers.Serializer):
    id = serializers.IntegerField()
    recipient_email = serializers.EmailField()
    permissions = serializers.CharField()
    is_deleted = serializers.BooleanField()
    created_at = serializers.DateTimeField()

class FamilyTreeRecipientManageSerializer(serializers.Serializer):
    recipients = serializers.ListField(allow_empty=False)

    def validate(self, data):
        recipients = data["recipients"]
        allowed_permissions = dict(FamilyTreeRecipient.PERMISSION_CHOICES)

        for index, item in enumerate(recipients):
            if "recipient_id" not in item:
                raise serializers.ValidationError(
                    {f"recipients[{index}]": "recipient_id is required."}
                )

            operation = item.get("operation")
            if operation not in ("update", "remove"):
                raise serializers.ValidationError(
                    {f"recipients[{index}]": "operation must be 'update' or 'remove'."}
                )

            if operation == "update":
                if "permissions" not in item:
                    raise serializers.ValidationError(
                        {f"recipients[{index}]": "permissions is required for update."}
                    )

                if item["permissions"] not in allowed_permissions:
                    raise serializers.ValidationError(
                        {
                            f"recipients[{index}]":
                            f"Invalid permission '{item['permissions']}'. "
                            f"Allowed values are {list(allowed_permissions.keys())}"
                        }
                    )

        return data