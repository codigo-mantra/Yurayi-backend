from django.db import models
from django.utils import timezone
from django.contrib.auth.models import AbstractBaseUser, PermissionsMixin
from .managers import UserManager
from memory_room.utils import upload_file_to_s3_bucket,S3FileHandler


class BaseModel(models.Model):
    created_at = models.DateTimeField(auto_now_add=True, verbose_name="Created At")
    updated_at = models.DateTimeField(auto_now=True, verbose_name="Updated At")
    is_deleted = models.BooleanField(default=False, verbose_name="Is Deleted")

    class Meta:
        abstract = True


IMAGES_TYPES = (
    ('Memory Room Cover', 'Memory Room Cover'),
    ('Time CapSoul Cover', 'Time CapSoul Cover'),
    ('Profile Image', 'Profile Image'),
    ('Profile Cover', 'Profile Cover'),
    ('Others', 'Others'),
)


class Assets(BaseModel):
    title = models.CharField(max_length=100, blank=True, null=True, verbose_name="Title")
    # image = models.ImageField(upload_to='assets/', verbose_name="Image File")
    image = models.FileField(upload_to='assets/', verbose_name="Assets File")
    asset_types = models.CharField(
        max_length=100,
        choices=IMAGES_TYPES,
        default="Others",
        verbose_name="Asset Type"
    )
    s3_url = models.URLField(blank=True, null=True)
    s3_key = models.CharField(blank=True, null=True)


    class Meta:
        verbose_name = "Asset"
        verbose_name_plural = "Assets"

    def __str__(self):
        return self.title or self.image.name
    
    def get_image_url(self):
        if self.image and hasattr(self.image, 'url'):
            return self.image.url
        return None
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._original_image = self.image  # Store original for comparison

    def save(self, *args, **kwargs):
        """Upload assets in S3 bucket"""
        if self.image and (not self.s3_url or self.image != self._original_image):
            uploaded_data = upload_file_to_s3_bucket(self.image, folder="assets")
            if uploaded_data:
                self.s3_url = uploaded_data[0]
                self.s3_key = uploaded_data[2]
        super().save(*args, **kwargs)

class ContactUs(BaseModel):
    first_name = models.CharField(max_length=100, verbose_name="First Name")
    last_name = models.CharField(max_length=100, verbose_name="Last Name")
    phone_number = models.CharField(max_length=13, blank=True, null=True, verbose_name="Phone Number")
    email = models.EmailField(verbose_name="Email Address")
    message = models.TextField(verbose_name="Message")

    class Meta:
        verbose_name = "Contact Us Submission"
        verbose_name_plural = "Contact Us Submissions"

    def __str__(self):
        return f"{self.first_name} {self.last_name}"


class User(AbstractBaseUser, PermissionsMixin):
    username = models.CharField(max_length=150, unique=True, verbose_name="Username")
    email = models.EmailField(unique=True, verbose_name="Email")
    first_name = models.CharField(max_length=150, blank=True, null=True, verbose_name="First Name")
    last_name = models.CharField(max_length=150, blank=True, null=True, verbose_name="Last Name")
    phone_number = models.CharField(max_length=13, blank=True, null=True, verbose_name="Phone Number")
    is_active = models.BooleanField(default=True, verbose_name="Is Active")
    is_staff = models.BooleanField(default=False, verbose_name="Is Staff")
    created_at = models.DateTimeField(default=timezone.now, verbose_name="Google Id")
    google_id = models.CharField(
        max_length=255,
        blank=True,
        null=True,
        unique=True,
        verbose_name="Google ID"
    )
    gender = models.CharField(blank=True, null=True)


    objects = UserManager()

    USERNAME_FIELD = 'username'
    REQUIRED_FIELDS = ['email']

    class Meta:
        verbose_name = "User"
        verbose_name_plural = "Users"

    def __str__(self):
        return self.username


class UserProfile(BaseModel):
    user = models.OneToOneField(
        User,
        on_delete=models.CASCADE,
        related_name='profile',
        verbose_name="User"
    )
    profile_image = models.ForeignKey(
        Assets,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='profile_images',
        verbose_name="Profile Image"
    )
    profile_cover_image = models.ForeignKey(
        Assets,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='cover_images',
        verbose_name="Cover Image"
    )
    about = models.TextField(blank=True, null=True, verbose_name="About")

    class Meta:
        verbose_name = "User Profile"
        verbose_name_plural = "User Profiles"

    def __str__(self):
        return f"{self.user.username}'s Profile"


class NewsletterSubscriber(BaseModel):
    email = models.EmailField(
        unique=True,
        verbose_name="Email Address"
    )
    is_active = models.BooleanField(
        default=True,
        verbose_name="Is Active"
    )

    def __str__(self):
        return self.email

    class Meta:
        verbose_name = "Newsletter Subscriber"
        verbose_name_plural = "Newsletter Subscribers"
        ordering = ['-created_at']

class UserAddress(BaseModel):
    user = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        related_name='address',
        verbose_name="User"
    )
    address_line_1 = models.CharField(max_length=255, verbose_name="Address Line 1")
    address_line_2 = models.CharField(max_length=255, blank=True, null=True, verbose_name="Address Line 2 (Optional)")
    city = models.CharField(max_length=100, verbose_name="City")
    state = models.CharField(max_length=100, verbose_name="State")
    postal_code = models.CharField(max_length=20, verbose_name="Postal Code")
    country = models.CharField(max_length=100, default="India", verbose_name="Country")

    class Meta:
        verbose_name = "User Address"
        verbose_name_plural = "User Addresses"

    def __str__(self):
        return f"{self.user.username} - {self.address_line_1}"
