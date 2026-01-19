import uuid
from django.db import models
from userauth.models import User 
from uuid6 import uuid7



class TimeStampedModel(models.Model):
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        abstract = True


class FamilyTree(TimeStampedModel):
    id = models.UUIDField(primary_key=True, default=uuid7, editable=False)
    slug = models.SlugField(max_length=255, unique=True, blank=True, null=True)
    owner = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        related_name="family_trees"
    )
    root_member = models.OneToOneField(
        "FamilyMember",
        on_delete=models.CASCADE,
        null=True,
        blank=True,
        related_name="root_of_tree"
    )
    name = models.CharField(max_length=255, blank=True, null=True)
    description = models.TextField(blank=True)
    is_deleted = models.BooleanField(default=False)

    def __str__(self):
        return f'{self.id}'
    

    def get_root_node_id(self):
        node_id = None
        if self.root_member:
            node_id = self.root_member.id 
        return node_id



class FamilyMember(TimeStampedModel):
    GENDER_CHOICES = (
        ("male", "Male"),
        ("female", "Female"),
        ("other", "Other"),
    )

    RELATION_TYPE_CHOICES = (
        ("father", "Father"),
        ("mother", "Mother"),
        ("siblings", "Siblings"),
        ("spouse", "Spouse"),
        ("child", "Child"),
    )

    family_tree = models.ForeignKey(
        FamilyTree,
        on_delete=models.CASCADE,
        related_name="members"
    )
    author = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        null=True,
        related_name="created_family_members"
    )
    #  CACHED / DENORMALIZED (NOT SOURCE OF TRUTH)
    primary_father = models.ForeignKey(
        "self",
        null=True,
        blank=True,
        related_name="+",              
        on_delete=models.CASCADE      
    )

    primary_mother = models.ForeignKey(
        "self",
        null=True,
        blank=True,
        related_name="+",
        on_delete=models.CASCADE
    )


    first_name = models.CharField(max_length=150)
    last_name = models.CharField(max_length=150, blank=True)
    gender = models.CharField(max_length=10, choices=GENDER_CHOICES)
    is_married = models.BooleanField(default=False)
    married_date = models.DateField(null=True, blank=True)
    is_person_alive = models.BooleanField(default=True)
    email_address = models.EmailField(unique=True)
    profession = models.CharField(max_length=255, blank=True, null=True)
    relation_type = models.CharField(choices=RELATION_TYPE_CHOICES, max_length=51, blank=True)
    death_date = models.DateField(null=True, blank=True)
    birth_date = models.DateField()
    profile_image_s3_key = models.CharField(
        max_length=512,
        null=True,
        blank=True
    )
    is_deleted = models.BooleanField(default=False)

    def __str__(self):
        return f"{self.first_name} {self.last_name}".strip()


class Partnership(TimeStampedModel):
    family_tree = models.ForeignKey(
        FamilyTree,
        on_delete=models.CASCADE,
        related_name="partnerships"
    )
    husband = models.ForeignKey(
        FamilyMember,
        on_delete=models.CASCADE,
        related_name="partnerships_as_husband",
        null=True, blank=True
    )
    wife = models.ForeignKey(
        FamilyMember,
        on_delete=models.CASCADE,
        related_name="partnerships_as_wife",
        null=True, blank=True
    )
    marriage_date = models.DateTimeField(null=True, blank=True)
    divorce_date = models.DateTimeField(null=True, blank=True)
    is_deleted = models.BooleanField(default=False)
    partner_generation_no = models.PositiveSmallIntegerField(blank=True, null=True)


    class Meta:
        unique_together = ("husband", "wife")
    def __str__(self):
        # return f"{self.husband.first_name} ↔ {self.wife.first_name}"
        return f'{self.id}'
    


class ParentalRelationship(models.Model):
    PARENT_TYPE_CHOICES = (
        ("biological", "Biological"),
        ("adopted", "Adopted"),
        ("step", "Step"),
    )

    family_tree = models.ForeignKey(
        FamilyTree,
        on_delete=models.CASCADE,
        related_name="parental_relationships"
    )
    father = models.ForeignKey(
        FamilyMember,
        on_delete=models.CASCADE,
        null=True,
        blank=True,
        related_name="children_as_father"
    )
    mother = models.ForeignKey(
        FamilyMember,
        on_delete=models.CASCADE,
        null=True,
        blank=True,
        related_name="children_as_mother"
    )
    child = models.ForeignKey(
        FamilyMember,
        on_delete=models.CASCADE,
        related_name="parents"
    )
    parent_type = models.CharField(
        max_length=20,
        choices=PARENT_TYPE_CHOICES,
        default="biological"
    )
    is_deleted = models.BooleanField(default=False)


    def __str__(self):
        return f"Parents of {self.child}"
