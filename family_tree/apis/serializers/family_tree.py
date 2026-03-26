from rest_framework import serializers
from datetime import date
from django.db.models import Q
from django.db import models
from userauth.tasks import send_html_email_task
import uuid
import os 
from django.conf import settings
from django.utils.text import get_valid_filename
from family_tree.tasks import process_encrypted_upload
from userauth.apis.serializers.serializers import UniversalImageField
from family_tree.models import FamilyMember, Partnership, ParentalRelationship, FamilyTree, FamilyTreeRecipient, UploadSession

def calculate_age(birth_date):
    if not birth_date:
        return None
    today = date.today()
    return today.year - birth_date.year - (
        (today.month, today.day) < (birth_date.month, birth_date.day)
    )



class FamilyTreeSerializer(serializers.ModelSerializer):
    is_owner = serializers.SerializerMethodField()
    is_editable = serializers.SerializerMethodField()


    class Meta:
        model = FamilyTree
        fields = (
            "id",
            "slug",
            "is_owner",
            'is_editable',
            "name",
            "description",
            "created_at",
            "updated_at",
        )
    
    def get_is_owner(self, obj):
        user = self.context['user']
        return  True if obj.owner == user else False
    
    def get_is_editable(self, obj):
        is_editable = False
        current_user = self.context['user']

        if obj.owner == current_user:
            is_editable = True

        elif obj.family_tree_recipients.filter(is_deleted = False, recipient_email=current_user.email, permissions='edit').first():
            is_editable = True
        
        return is_editable


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
    profile_image = UniversalImageField(required = False)
    gallery_media = serializers.ListField(
        child=serializers.FileField(allow_empty_file=False),
        required=False,
        allow_empty=True,
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
            
        if birth_date:
            age = today.year - birth_date.year - (
                (today.month, today.day) < (birth_date.month, birth_date.day)
            )
            if age <= 14:
                raise serializers.ValidationError(
                    {"birth_date":"Age must be 14 years for the root member."}
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

#######################################################################################################################################
class AddNewFamilyMemberSerializer(serializers.ModelSerializer):
    parent_node_id = serializers.IntegerField(write_only=True, required=False, allow_null=True)
    gallery_media = serializers.ListField(
        child=serializers.FileField(allow_empty_file=False),
        required=False,
        allow_empty=True,
    )
    profile_image = UniversalImageField(required = False)

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
            "profile_image",
            "gallery_media",
        )

    
    def validate(self, attrs):
        errors = {}

        required_fields = [
            # "parent_node_id",
            "first_name",
            "last_name",
            "gender",
            "is_person_alive",
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
        member = None
        upload_sessions = []
        user = self.context["user"] 
        family_tree = self.context.get("family_tree")
        email = validated_data.get("email_address")
        relation_type = validated_data.get("relation_type", "").strip().lower()
        print("RELATION TYPE:", relation_type)
        # relation_type = validated_data.get("relation_type").lower()
        parent_node_id = (validated_data.get("parent_node_id"))
        is_married = validated_data.get("is_married", False)
        married_date = validated_data.get("married_date", None)
        validated_data.pop("parent_node_id", None)
        gender = validated_data.get("gender").lower()
        gallery_media = validated_data.pop("gallery_media", None)

        # if not parent_node_id :
        #     raise serializers.ValidationError({'parent_node_id': 'Parent member id is required'})
        
        # parent_member_node = int(parent_node_id)
        parent_member_node = None

        if parent_node_id:
            try:
                parent_member_node = FamilyMember.objects.get(
                    id=parent_node_id,
                    is_deleted=False
                )
            except FamilyMember.DoesNotExist:
                raise serializers.ValidationError(
                    {"parent_node_id": "Parent family member not found."}
                )
            
        if not parent_member_node:
            member = self.create_family_member(user, family_tree, validated_data)
            self._upload_sessions = []
            return member

        # if relation_type in ['father', 'mother', 'spouse']:
        if relation_type in ['father', 'mother', 'spouse'] and parent_member_node:
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
            
            if relation_type == 'mother' and gender != 'female':
                raise serializers.ValidationError({
                    'gender': 'Member gender is invalid must be female'
                })
            
            if relation_type == 'father' and gender != 'male':
                raise serializers.ValidationError({
                    'gender': 'Member gender is invalid must be male'
                })


        member = FamilyMember.objects.filter(
            family_tree=family_tree,
            email_address=email,
            first_name=validated_data.get("first_name"),
            last_name=validated_data.get("last_name"),
            birth_date=validated_data.get("birth_date"),
            is_deleted=False
        ).first()

        if member:
            raise serializers.ValidationError(
                {"user_already_exists": "Family member with this email already exists in the family tree."}
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

                    #changeddd
                    # Assign father to all existing parentless siblings 
                    # existing_siblings = FamilyMember.objects.filter(
                    #     family_tree=family_tree,
                    #     relation_type__in=['siblings', 'sibling'],
                    #     primary_father__isnull=True,   #  filter by father
                    #     is_deleted=False
                    # )
                    #changedd 2
                    # FIX — only same group
                    existing_siblings = FamilyMember.objects.filter(
                        family_tree=family_tree,
                        relation_type__in=['siblings', 'sibling'],
                        primary_father__isnull=True,
                        sibling_group_id=parent_member_node.sibling_group_id,
                        is_deleted=False
                    )
                    for sibling in existing_siblings:
                        sibling.primary_father = father_as_member  #  assign father
                        sibling.sibling_group_id = None            # if real parents assigned , group no longer needed
                        sibling.save()
                        self.create_parental_relationship(
                            family_tree=family_tree,
                            child=sibling,
                            father=father_as_member,   #  father variable
                            mother=sibling.primary_mother
                        )
            

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

                    # changeddd — Assign mother to all existing parentless siblings
                    # existing_siblings = FamilyMember.objects.filter(
                    #     family_tree=family_tree,
                    #     relation_type__in=['siblings', 'sibling'],
                    #     primary_mother__isnull=True,
                    #     is_deleted=False
                    # )
                    # FIX
                    existing_siblings = FamilyMember.objects.filter(
                        family_tree=family_tree,
                        relation_type__in=['siblings', 'sibling'],
                        primary_mother__isnull=True,
                        sibling_group_id=parent_member_node.sibling_group_id,
                        is_deleted=False
                    )
                    for sibling in existing_siblings:
                        sibling.primary_mother = mother_as_member
                        sibling.sibling_group_id = None            # if real parents assigned , group no longer needed
                        sibling.save()
                        self.create_parental_relationship(
                            family_tree=family_tree,
                            child=sibling,
                            father=sibling.primary_father,
                            mother=mother_as_member
                        )

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



            # elif relation_type == 'child':
            elif relation_type == 'child' and parent_member_node:
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

            #changedd 
            elif relation_type in ['siblings','sibling']:

                # import uuid

                father = parent_member_node.primary_father if parent_member_node else None
                mother = parent_member_node.primary_mother if parent_member_node else None

                sibling_as_member = self.create_family_member(
                    user, family_tree, validated_data
                )
                member = sibling_as_member

                #assign parents if exist
                sibling_as_member.primary_father = father
                sibling_as_member.primary_mother = mother

                group_id = None

                if father or mother:
                    group_id = None    ## if real parents exist → NO group needed
                else:
                    if parent_member_node.sibling_group_id:                # parentless siblings → use group
                        group_id = parent_member_node.sibling_group_id     # re-use parents exiting group if exists
                    else:
                        group_id = uuid.uuid4()                            #else crate new group for parentless siblings
                        parent_member_node.sibling_group_id = group_id     # assign group to parent node also
                        parent_member_node.save()

                sibling_as_member.sibling_group_id = group_id
                sibling_as_member.save()

                #parental relation(only if parents exist) for sibling is optional and only created if parents exist, as sibling relation can be inferred via shared parents or sibling_group_id
                if father or mother:
                    self.create_parental_relationship(
                        family_tree=family_tree,
                        child=sibling_as_member,
                        father=father,
                        mother=mother
                    )

            #changedd
            # elif relation_type in ['siblings', 'sibling']:

            #     father = parent_member_node.primary_father if parent_member_node else None
            #     mother = parent_member_node.primary_mother if parent_member_node else None

            #     sibling_as_member = self.create_family_member(
            #         user, family_tree, validated_data
            #     )
            #     member = sibling_as_member

            #     sibling_as_member.primary_father = father
            #     sibling_as_member.primary_mother = mother
            #     sibling_as_member.save()

            #     parental_relation = self.create_parental_relationship(
            #         family_tree=family_tree,
            #         child=sibling_as_member,
            #         father=father,
            #         mother=mother
            #     )
            # elif relation_type in ['siblings', 'sibling']:

            #     father  = parent_member_node.primary_father
            #     mother  = parent_member_node.primary_mother

            #     if father or mother:
            #         sibling_as_member = self.create_family_member(
            #             user, family_tree, validated_data
            #         )
            #         member = sibling_as_member
            #         sibling_as_member.primary_father = father
            #         sibling_as_member.primary_mother = mother
            #         sibling_as_member.save()

            #         parental_relation = self.create_parental_relationship(
            #             family_tree=family_tree,
            #             child=sibling_as_member,
            #             father=father,
            #             mother=mother
            #         )
                # else:
                #     raise serializers.ValidationError({"parent_node_id": "Parent node is required to add sibling."})


            elif relation_type == 'spouse':

                wife = None 
                husband = None
                spouse = None
                if not parent_member_node.is_married:
                    raise serializers.ValidationError(
                        {
                            "message": "Parent Node is currently marked as unmarried.",
                            "action": "OPEN_MARITAL_STATUS_MODAL"
                        }
                    )   
                if parent_member_node.gender == 'male' and gender != 'female':
                    raise serializers.ValidationError({'gender': "Spouse gender is invalid"})
                
                elif parent_member_node.gender == 'female' and gender != 'male':
                    raise serializers.ValidationError({'gender': "Spouse gender is invalid"})


                if not parent_member_node.is_married:
                    parent_member_node.is_married = True
                    parent_member_node.save()

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
        from family_tree.apis.views.family_tree import set_upload_filename
        if gallery_media is not None:
            files = gallery_media if isinstance(gallery_media, list) else [gallery_media]
        else:
            files = []

        family_tree_obj = FamilyTree.objects.get(id=uuid.UUID(str(family_tree.id)))

        for file in files:
            if not file:
                continue

            session = UploadSession.objects.create(
                user=user,
                member=member,
                target_type="gallery_media",
                status="pending",
                family_tree=family_tree_obj,
            )
            upload_id = str(session.id)
            set_upload_filename(upload_id, get_valid_filename(file.name))
            temp_path = os.path.join(
                settings.MEDIA_ROOT,
                str(family_tree.id),
                "temp_uploads",
                upload_id,
            )
            os.makedirs(temp_path, exist_ok=True)

            file_path = os.path.join(temp_path, get_valid_filename(file.name))
            with open(file_path, "wb+") as destination:
                for chunk in file.chunks():
                    destination.write(chunk)
            process_encrypted_upload.delay(upload_id)

            upload_sessions.append(session)

        self._upload_sessions = upload_sessions

        if member is None:
            raise serializers.ValidationError(
                {"error": f"Member not created for relation_type: {relation_type}"}
            )

        return member

        # self._upload_sessions = upload_sessions
        # return member


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
            "profile_image",
        )
            

# class FamilyTreeNodeSerializer(serializers.ModelSerializer):
#     id = serializers.CharField(source="pk", read_only=True)
#     name = serializers.SerializerMethodField()
#     age = serializers.SerializerMethodField()
#     dateofbirth = serializers.SerializerMethodField()
#     role = serializers.SerializerMethodField()
#     partner = serializers.SerializerMethodField()
#     parents = serializers.SerializerMethodField()
#     children = serializers.SerializerMethodField()
#     is_onwer = serializers.SerializerMethodField()
#     is_root_node = serializers.SerializerMethodField()

#     class Meta:
#         model = FamilyMember
#         fields = (
#             "family_tree",
#             "id",
#             "is_onwer",
#             "is_root_node",
#             "name",
#             "gender",
#             "role",
#             "age",
#             "dateofbirth",
#             "partner",
#             "parents",
#             "children",
#         )
#     def get_is_root_node(self, obj):
#         root_node_id = self.context.get("root_node_id")
#         return root_node_id == obj.id

#     def get_name(self, obj):
#         return f"{obj.first_name} {obj.last_name}".strip()

#     def get_age(self, obj):
#         return calculate_age(obj.birth_date) if obj.birth_date else None

#     def get_dateofbirth(self, obj):
#         return obj.birth_date.strftime("%d %b %Y") if obj.birth_date else None

#     def get_is_onwer(self, obj):
#         root_node_id = self.context.get("root_node_id")
#         return root_node_id == obj.id


#     def get_role(self, obj):
#         return obj.relation_type

   

#     def get_partner(self, obj):
#         """
#         Returns partner member ID or None
#         """
#         partnership = (
#             Partnership.objects.filter(
#                 family_tree=obj.family_tree,
#                 is_deleted=False
#             )
#             .filter(models.Q(husband=obj) | models.Q(wife=obj))
#             .select_related("husband", "wife")
#             .first()
#         )

#         if not partnership:
#             return None

#         if partnership.husband_id == obj.id:
#             return str(partnership.wife_id) if partnership.wife_id else None
#         return str(partnership.husband_id) if partnership.husband_id else None

#     # ----------------------------
#     # PARENTS
#     # ----------------------------

#     def get_parents(self, obj):
#         """
#         Returns list of parent IDs or None
#         """
#         parents = []

#         view_type = self.context['view_type']
#         root_node_id = self.context.get("root_node_id")

#         father = obj.primary_father
#         mother = obj.primary_mother

#         if father or mother:

#             if mother:
#                 partnership =Partnership.objects.filter(
#                     family_tree=obj.family_tree,
#                     is_deleted=False,
#                     wife = mother
#                 ).first()
                
#                 if partnership and  partnership.husband:
#                     parents.append(str(partnership.husband.id))

#                     if partnership.wife:
#                         parents.append(str(partnership.wife.id))

                
#                 elif  partnership and  partnership.wife:
#                     parents.append(str(partnership.wife.id))

#                     if partnership.husband:
#                         parents.append(str(partnership.husband.id))
#             else:
#                 partnership =Partnership.objects.filter(
#                     family_tree=obj.family_tree,
#                     is_deleted=False,
#                     husband = father
#                 ).first()
                
#                 if partnership and  partnership.husband:
#                     parents.append(str(partnership.husband.id))

#                     if partnership.wife:
#                         parents.append(str(partnership.wife.id))

                
#                 elif  partnership and  partnership.wife:
#                     parents.append(str(partnership.wife.id))

#                     if partnership.husband:
#                         parents.append(str(partnership.husband.id))
#             return parents or None

#     # ----------------------------
#     # CHILDREN
#     # ----------------------------

#     def get_children(self, obj):
#         """
#         Returns list of child IDs or None
#         """
#         view_type = self.context.get('view_type')
#         root_node_id = self.context.get("root_node_id")
        

#         child_ids = []
#         partnership = (
#             Partnership.objects.filter(
#                 family_tree=obj.family_tree,
#                 is_deleted=False
#             )
#             .filter(models.Q(husband=obj) | models.Q(wife=obj))
#             .select_related("husband", "wife")
#             .first()
#         )
#         if partnership:
#             wife = partnership.wife
#             husband = partnership.husband

#             if wife:
#                 maternal_childs = FamilyMember.objects.filter(
#                     primary_mother = wife,
#                     is_deleted = False,
#                     family_tree = obj.family_tree
#                 )
#                 combin_childs = maternal_childs
#             if husband:
#                 paternal_childs = FamilyMember.objects.filter(
#                     primary_father = husband,
#                     is_deleted = False,
#                     family_tree = obj.family_tree

#                 )
#                 combin_childs = paternal_childs
            

#             if  husband and wife:
#                 combin_childs = maternal_childs | paternal_childs

#             child_ids = [str(child.id) for child in combin_childs]


#         return child_ids or None
###################################################################################################################
class FamilyTreeNodeSerializer(serializers.ModelSerializer):
    id = serializers.CharField(source="pk", read_only=True)
    name = serializers.SerializerMethodField()
    age = serializers.SerializerMethodField()
    dateofbirth = serializers.SerializerMethodField()
    role = serializers.SerializerMethodField()
    partner = serializers.SerializerMethodField()
    parents = serializers.SerializerMethodField()
    children = serializers.SerializerMethodField()
    siblings = serializers.SerializerMethodField()  # changedd added
    is_onwer = serializers.SerializerMethodField()
    is_root_node = serializers.SerializerMethodField()

    class Meta:
        model = FamilyMember
        fields = (
            "family_tree",
            "id",
            "is_married",
            "married_date",
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
            "siblings",    #changed added 
            "profile_image",
        )

    # ==================================================
    # INIT → CACHE EVERYTHING
    # ==================================================

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.view_type = self.context.get("view_type")
        self.root_node_id = self.context.get("root_node_id")
        family_tree = self.context.get("family_tree")

        self.partnership_map = {}   # member_id → Partnership
        self.children_map = {}      # parent_id → [children]

        if not family_tree:
            return

        # ----------------------------
        # Cache Partnerships
        # ----------------------------
        partnerships = Partnership.objects.filter(
            family_tree=family_tree,
            is_deleted=False
        ).select_related("husband", "wife")

        for p in partnerships:
            if p.husband_id:
                self.partnership_map[p.husband_id] = p
            if p.wife_id:
                self.partnership_map[p.wife_id] = p

        # ----------------------------
        # Cache Children by Father/Mother
        # ----------------------------
        # members = FamilyMember.objects.filter(
        #     family_tree=family_tree,
        #     is_deleted=False
        # ).only("id", "primary_father_id", "primary_mother_id")
        # members = self.instance if self.instance else []
        #changedd for filter issue 
        # members = self.instance or []
        # if not isinstance(members, list):
        #     members = [members]
        instance = self.instance or []
        if hasattr(instance, '__iter__') and not isinstance(instance, (list,)):
            members = list(instance)
        else:
            members = instance if isinstance(instance, list) else [instance]

        for child in members:
            if child.primary_father_id:
                self.children_map.setdefault(
                    child.primary_father_id, []
                ).append(child)

            if child.primary_mother_id:
                self.children_map.setdefault(
                    child.primary_mother_id, []
                ).append(child)

    # ==================================================
    # BASIC FIELDS
    # ==================================================

    def get_is_root_node(self, obj):
        return self.root_node_id == obj.id

    def get_is_onwer(self, obj):
        return self.root_node_id == obj.id

    def get_name(self, obj):
        return f"{obj.first_name} {obj.last_name}".strip()

    def get_age(self, obj):
        return calculate_age(obj.birth_date) if obj.birth_date else None

    def get_dateofbirth(self, obj):
        return obj.birth_date.strftime("%d %b %Y") if obj.birth_date else None

    def get_role(self, obj):
        return obj.relation_type

    # ==================================================
    # PARTNER (NO DB)
    # ==================================================

    def get_partner(self, obj):
        partnership = self.partnership_map.get(obj.id)
        if not partnership:
            return None

        if partnership.husband_id == obj.id:
            return str(partnership.wife_id) if partnership.wife_id else None
        return str(partnership.husband_id) if partnership.husband_id else None

    # ==================================================
    # PARENTS (NO DB)
    # ==================================================

    def get_parents(self, obj):
        parents = []

        father = obj.primary_father
        mother = obj.primary_mother

        if not (father or mother):
            return None
        
        # FILTER by view_type added for filternig 
        if self.view_type == "paternal":
            if father:
                parents.append(str(father.id))
            return parents or None

        elif self.view_type == "maternal":
            if mother:
                parents.append(str(mother.id))
            return parents or None

        if father:
            partnership = self.partnership_map.get(father.id)
        else:
            partnership = self.partnership_map.get(mother.id)

        if partnership:
            if partnership.husband_id:
                parents.append(str(partnership.husband_id))
            if partnership.wife_id:
                parents.append(str(partnership.wife_id))
        else:
            if obj.primary_mother:
                parents.append(str(obj.primary_mother.id))
            
            if obj.primary_father:
                parents.append(str(obj.primary_father.id))

        return parents or None

    # ==================================================
    # CHILDREN (NO DB)
    # ==================================================

    def get_children(self, obj):
        children = self.children_map.get(obj.id, [])

        if self.view_type == "paternal":
            children = [
                c for c in children if c.primary_father_id == obj.id
            ]

        elif self.view_type == "maternal":
            children = [
                c for c in children if c.primary_mother_id == obj.id
            ]

        return [str(c.id) for c in children] or None
    

    #changedd 
    def get_siblings(self, obj):

    # CASE 1: REAL SIBLINGS (via parents)
        if obj.primary_father_id or obj.primary_mother_id:
            sibling_ids = []
            for member_id, children in self.children_map.items():
                if member_id in (obj.primary_father_id, obj.primary_mother_id):
                    for child in children:
                        if child.id != obj.id:
                            sid = str(child.id)
                            if sid not in sibling_ids:
                                sibling_ids.append(sid)
            return sibling_ids or None

        # CASE 2: GROUP SIBLINGS (no parents)
        if obj.sibling_group_id:
            siblings = FamilyMember.objects.filter(
                family_tree=obj.family_tree,
                sibling_group_id=obj.sibling_group_id,
                is_deleted=False
            ).exclude(id=obj.id)
            return [str(s.id) for s in siblings] or None

        return None

    # def get_siblings(self, obj):
        # root_node_id = self.root_node_id
        # family_tree = self.context.get("family_tree")

        # # CASE 1 — has parents, find via shared primary_father or primary_mother
        # if obj.primary_father_id or obj.primary_mother_id:
        #     sibling_ids = []
        #     for member_id, children in self.children_map.items():
        #         if member_id in (obj.primary_father_id, obj.primary_mother_id):
        #             for child in children:
        #                 if child.id != obj.id:
        #                     sid = str(child.id)
        #                     if sid not in sibling_ids:
        #                         sibling_ids.append(sid)
        #     return sibling_ids or None

        # # CASE 2 — no parents, connect self object and siblings via role
        # # TL rule: all siblings share same parents, assume direct connection
        # if str(obj.id) == str(root_node_id):
        #     # this is self object, return all members with role=siblings
        #     sibling_ids = [
        #         str(child.id)
        #         for children in self.children_map.values()
        #         for child in children
        #         if child.relation_type in ['siblings', 'sibling']
        #     ]
        #     # children_map won't have them if no parents, query siblings directly
        #     if not sibling_ids and family_tree:
        #         from family_tree.models import FamilyMember as FM
        #         sibling_ids = list(
        #             FM.objects.filter(
        #                 family_tree=family_tree,
        #                 relation_type__in=['siblings', 'sibling'],
        #                 is_deleted=False
        #             ).exclude(id=obj.id).values_list('id', flat=True)
        #         )
        #         return [str(i) for i in sibling_ids] or None
        #     return sibling_ids or None

        # if obj.relation_type in ['siblings', 'sibling']:
        #     # return self object (root) as sibling
        #     return [str(root_node_id)] if root_node_id else None

        # return None


class FamilyTreeUpdateSerializer(serializers.ModelSerializer):
    class Meta:
        model = FamilyTree
        fields = ("name", "description")

    def validate(self, attrs):
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
            permissions = item.get("permissions", "view").lower()

            recipient, created = FamilyTreeRecipient.objects.get_or_create(
                family_tree=family_tree,
                recipient_email=email,
                defaults={"permissions": permissions}
            )
            if created:
                # bind here celery task to send email to recipients
                send_html_email_task.apply_async(
                    kwargs={
                        "subject": "You’ve received a Time Capsoul sealed with love.",
                        "to_email": email,
                        "template_name": "userauth/time_capsoul_tagged.html",
                        "context": {
                            "user": email,
                            "sender_name": email,
                            "unlock_date": None
                        }
                    }
                )

           
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


class UploadSessionSerializer(serializers.ModelSerializer):
    class Meta:
        model = UploadSession
        fields = "__all__"

class ReplaceFamilyMemberSerializer(serializers.ModelSerializer):
    gallery_media = serializers.ListField(
        child=serializers.FileField(allow_empty_file=False),
        required=False,
        allow_empty=True,
    )
    profile_image = UniversalImageField(required = False)
    class Meta:
        model = FamilyMember
        fields = (
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
            "profile_image",
            "gallery_media"
        )
    
    def validate(self, attrs):
        errors = {}

        required_fields = [
            "first_name",
            "last_name",
            "gender",
            "is_person_alive",
            "birth_date",
        ]

        for field in required_fields:
            value = attrs.get(field)

            if value in [None, "", []]:
                errors[field] = f"{field.replace('_', ' ').capitalize()} is required."

        if errors:
            raise serializers.ValidationError(errors)

        return attrs
    
    def update(self, instance, validated_data):
        upload_sessions = []
        user = self.context["user"] 
        gallery_media = validated_data.pop("gallery_media", [])

        for attr, value in validated_data.items():
            setattr(instance, attr, value)

        instance.save()
        if gallery_media is not None:
            files = gallery_media if isinstance(gallery_media, list) else [gallery_media]
        else:
            files = []

        family_tree_obj = FamilyTree.objects.get(id=uuid.UUID(str(instance.family_tree.id)))
        from family_tree.apis.views.family_tree import set_upload_filename

        for file in files:
            if not file:
                continue

            session = UploadSession.objects.create(
                user=user,
                member=instance,
                target_type="gallery_media",
                status="pending",
                family_tree=family_tree_obj,
            )
            upload_id = str(session.id)
            set_upload_filename(upload_id, get_valid_filename(file.name))
            temp_path = os.path.join(
                settings.MEDIA_ROOT,
                str(instance.family_tree.id),
                "temp_uploads",
                upload_id,
            )
            os.makedirs(temp_path, exist_ok=True)

            file_path = os.path.join(temp_path, get_valid_filename(file.name))
            with open(file_path, "wb+") as destination:
                for chunk in file.chunks():
                    destination.write(chunk)
            process_encrypted_upload.delay(upload_id)

            upload_sessions.append(session)

        self._upload_sessions = upload_sessions
        return instance
    
class PartnerMaritalStatusSerializer(serializers.ModelSerializer):
    class Meta:
        model = FamilyMember
        fields =("is_married", "married_date")
    
    def update(self, instance, validated_data):
        for attr, value in validated_data.items():
            setattr(instance, attr, value)

        instance.save()
        return instance