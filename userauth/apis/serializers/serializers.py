import re, requests
from rest_framework import serializers
from userauth.models import ContactUs, User, UserProfile, Assets,UserAddress, YurayiPolicy, Session

from dj_rest_auth.registration.serializers import SocialLoginSerializer
from rest_framework import serializers
from rest_framework_simplejwt.tokens import RefreshToken
from django.conf import settings
from django.contrib.auth.forms import PasswordResetForm
from userauth.models import User, NewsletterSubscriber
from django.core.exceptions import ValidationError
from allauth.socialaccount.providers.google.provider import GoogleProvider
from allauth.socialaccount.models import SocialApp, SocialAccount, SocialLogin


from django.core.exceptions import ValidationError as DjangoValidationError

from userauth.apis.helpers.validators import CustomPasswordValidator, UsernameValidator

from django.utils.encoding import force_str, force_bytes
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from django.contrib.auth.tokens import default_token_generator

from dj_rest_auth.serializers import (
    PasswordResetSerializer,
    PasswordResetConfirmSerializer,
    PasswordChangeSerializer
)

# Regex to check if identifier is an email
EMAIL_REGEX = r"[^@]+@[^@]+\.[^@]+"


class ContactUsSerializer(serializers.ModelSerializer):
    class Meta:
        model = ContactUs
        fields = '__all__'

    def validate_first_name(self, value):
        if not value.isalpha():
            raise serializers.ValidationError("First name should only contain alphabets.")
        return value

    def validate_last_name(self, value):
        if not value.isalpha():
            raise serializers.ValidationError("Last name should only contain alphabets.")
        return value


    def validate_phone_number(self, value):
        if value.startswith('+'):
            # Must start with +91 and followed by exactly 10 digits
            if not re.fullmatch(r'\+91\d{10}', value):
                raise serializers.ValidationError("Phone number must be in the format +91XXXXXXXXXX.")
            digits_only = value[3:]  # remove +91

            if digits_only[0] < '3':
                raise serializers.ValidationError("In +91 format, phone number must start with 3 or higher.")

        else:
            if not re.fullmatch(r'\d{10}', value):
                raise serializers.ValidationError("Phone number must be a 10-digit number without country code.")
            digits_only = value

            if digits_only[0] < '3':
                raise serializers.ValidationError("In +91 format, phone number must start with 3 or higher.")

        return value

from rest_framework import serializers
from allauth.socialaccount.models import SocialAccount
from allauth.socialaccount.providers.google.provider import GoogleProvider
from allauth.socialaccount.models import SocialLogin
from django.contrib.auth import get_user_model
import requests

User = get_user_model()

class GoogleAccessTokenSerializer(serializers.Serializer):
    access_token = serializers.CharField()
    # user location info
    city = serializers.CharField(required=False, allow_blank=True)
    country = serializers.CharField(required=False, allow_blank=True)
    latitude = serializers.CharField(required=False, allow_blank=True)
    longitude = serializers.CharField(required=False, allow_blank=True)


    def validate(self, attrs):
        access_token = attrs.get("access_token")
        if not access_token:
            raise serializers.ValidationError("access_token is required")
        return attrs

    def generate_unique_username(self, first_name):
        base_username = f"{first_name.lower()}" if first_name else "user"
        username = base_username
        counter = 1
        while User.objects.filter(username=username).exists():
            username = f"{base_username}{counter}"
            counter += 1
        return username

    def create(self, validated_data):
        request = self.context.get("request")
        access_token = validated_data.get("access_token")

        # Fetch user info using access_token
        user_info_response = requests.get(
            "https://www.googleapis.com/oauth2/v3/userinfo",
            headers={"Authorization": f"Bearer {access_token}"}
        )
        if not user_info_response.ok:
            raise serializers.ValidationError("Failed to fetch user info from Google")

        user_info = user_info_response.json()
        email = user_info['email'].lower().strip()
        uid = user_info.get("sub")
        first_name = user_info.get("given_name", email).replace(" ", "")
        last_name = user_info.get("family_name", "").replace(" ", "")
        username = self.generate_unique_username(first_name=first_name)

        # Try to get or create the user
        try:
            user = User.objects.get(email=email)
            is_new_user = False
        except User.DoesNotExist:
            user = User.objects.create(
                email=email,
                username=username,
                first_name=first_name,
                last_name=last_name
            )
            user.last_login = None
            user.save()
            is_new_user = True

        # Create SocialAccount object (not saved to DB)
        account = SocialAccount(
            user=user,
            uid=uid,
            provider=GoogleProvider.id,
            extra_data=user_info
        )

        # Create SocialLogin object
        login = SocialLogin(user=user, account=account)
        login.state = SocialLogin.state_from_request(request)

        # Track user status internally (used in view)
        self.is_new_user = is_new_user

        return login


class JWTTokenSerializer(serializers.Serializer):
    access = serializers.CharField(read_only=True)
    refresh = serializers.CharField(read_only=True)

    @classmethod
    def get_token(cls, user):
        refresh = RefreshToken.for_user(user)
        return {
            'access': str(refresh.access_token),
            'refresh': str(refresh)
        }
    


def validate_username(username):
    # Only allow alphanumeric usernames, min 5 characters
    if not re.fullmatch(r'[A-Za-z0-9_]{5,30}', username):
        raise serializers.ValidationError(
            "Username must be 5-30 characters long and can only contain letters, numbers, and underscores."
        )
    return username

class RegistrationSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True, required=True)
    confirm_password = serializers.CharField(write_only=True, required=True)
    device_name = serializers.CharField(required=False, allow_blank=True)
    
    # user location info
    city = serializers.CharField(required=False, allow_blank=True)
    country = serializers.CharField(required=False, allow_blank=True)
    latitude = serializers.CharField(required=False, allow_blank=True)
    longitude = serializers.CharField(required=False, allow_blank=True)

    class Meta:
        model = User
        fields = ['email', 'password', 'confirm_password','device_name', 'city', 'country', 'latitude', 'longitude']

    def generate_unique_username(self, first_name, last_name):
        base_username = f"{first_name.lower()}.{last_name.lower()}" if first_name and last_name else "user"
        username = base_username
        counter = 1
        while User.objects.filter(username=username).exists():
            username = f"{base_username}{counter}"
            counter += 1
        return username

    def validate(self, data):
        email = data.get("email", "").strip()
        password = data.get("password")
        confirm_password = data.get("confirm_password")

        errors = {}
        
        if not email:
            errors["email"] = "Please enter your email address to continue."
            

        if User.objects.filter(email=email).exists():
            errors["email"] = "Email already exists. Please use a different one or log in."

        if not password or not confirm_password:
            errors["password"] = "Please create a password to keep your memories safe."
        elif password != confirm_password:
            errors["password"] = "Passwords don’t match. Let’s try that again."
        
        try:
            validator = CustomPasswordValidator()
            validator.validate(password=password)
        except DjangoValidationError as e:
            errors["password"] = list(e.messages)

        if errors:
            raise serializers.ValidationError(errors)

        return data

    def create(self, validated_data):
        password = validated_data.pop("password")
        validated_data.pop("confirm_password")
        validated_data.pop("city", None)
        validated_data.pop("country", None)
        validated_data.pop("latitude", None)
        validated_data.pop("longitude", None)
        validated_data.pop("device_name",None)

        email = validated_data.get("email")
        base_username = email.split("@")[0]
        username = base_username
        counter = 1

        # Ensure uniqueness
        while User.objects.filter(username=username).exists():
            username = f"{base_username}{counter}"
            counter += 1

        user = User(username=username, **validated_data)
        user.set_password(password)
        user.save()
        return user



    
class UserProfileUpdateSerializer(serializers.ModelSerializer):
    profile_image = serializers.ImageField(required=False, write_only=True)  # accept raw image file

    class Meta:
        model = User
        fields = ['username', 'first_name', 'last_name', 'phone_number', 'profile_image']

    def update(self, instance, validated_data):
        # Handle user update
        for attr in ['username', 'first_name', 'last_name', 'phone_number']:
            if attr in validated_data:
                setattr(instance, attr, validated_data[attr])
        instance.save()

        # Handle profile
        profile, _ = UserProfile.objects.get_or_create(user=instance)

        # Handle uploaded image
        profile_image_file = validated_data.get('profile_image')
        if profile_image_file:
            asset = Assets.objects.create(image=profile_image_file)
            profile.profile_image = asset

        profile.save()
        return instance



# Password Reset Email Request

class CustomPasswordResetSerializer(PasswordResetSerializer):
    def validate_email(self, value):
        if not User.objects.filter(email__iexact=value, is_active=True).exists():
            raise serializers.ValidationError("No user is associated with this email address.")
        return value

    def get_email_options(self):
        return {
            "email_template_name": "userauth/password_reset_email.html",
            "subject_template_name": "userauth/password_reset_subject.txt",
            "extra_email_context": {
                "frontend_url": getattr(settings, "FRONTEND_URL", "http://localhost:3000")
            }
        }

    def save(self):
        request = self.context.get("request")
        email = self.validated_data["email"]
        form = PasswordResetForm(data={"email": email})
        if form.is_valid():
            form.save(
                request=request,
                use_https=request.is_secure(),
                from_email=getattr(settings, "DEFAULT_FROM_EMAIL", None),
                **self.get_email_options(),
            )
        else:
            raise serializers.ValidationError("Invalid email input.")


# Password Reset Confirm
class CustomPasswordResetConfirmSerializer(PasswordResetConfirmSerializer):
    old_password = serializers.CharField()
    def validate(self, attrs):
        return super().validate(attrs)

    def save(self):
        user = super().save()
        # Optionally activate user or log them in
        return user

class CustomPasswordChangeSerializer(serializers.Serializer):
    old_password = serializers.CharField(required=True, write_only=True)
    new_password1 = serializers.CharField(required=True, write_only=True)
    new_password2 = serializers.CharField(required=True, write_only=True)

    def validate_old_password(self, value):
        if not value:
            raise serializers.ValidationError('Old Password is required')
        user = self.context.get('user')
        if not user.check_password(value):
            raise serializers.ValidationError("Your current password is incorrect.")
        return value

    def validate(self, data):
        # Check new passwords match
        if data["new_password1"] != data["new_password2"]:
            raise serializers.ValidationError("The new passwords do not match.")

        # Prevent new password same as old password
        if data["old_password"] == data["new_password1"]:
            raise serializers.ValidationError("The new password cannot be the same as the old password.")
        
        try:
            validator = CustomPasswordValidator()
            validator.validate(password=data["new_password1"])
        except DjangoValidationError as e:
            raise serializers.ValidationError({'new_password1': f'{e.message}'})


        return data

    def save(self):
        user = self.context.get('user')
        new_password = self.validated_data["new_password1"]
        user.set_password(new_password)
        user.save()
        return user


class ForgotPasswordSerializer(serializers.Serializer):
    email = serializers.EmailField()

    def validate_email(self, value):
        if value is None or value== '':
            raise serializers.ValidationError({'email': "Please enter your email address to continue."})
        
        if not User.objects.filter(email=value).exists():
            raise serializers.ValidationError("We couldn’t find an account with that email. Please check and try again  .")
        return value
    

class PasswordResetConfirmSerializer(serializers.Serializer):
    uidb64 = serializers.CharField()
    token = serializers.CharField()
    new_password = serializers.CharField(write_only=True, min_length=8)

    def validate(self, attrs):
        uidb64 = attrs.get("uidb64")
        token = attrs.get("token")
        password = attrs.get("new_password")
        errors = {}

        try:
            uid = force_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(pk=uid)
        except (TypeError, ValueError, OverflowError, User.DoesNotExist):
            raise serializers.ValidationError({"uidb64": "Invalid user identifier."})

        if not default_token_generator.check_token(user, token):
            raise serializers.ValidationError({"token": "Token expire! Please use new token to reset your password"})

        try:
            validator = CustomPasswordValidator()
            validator.validate(password=password, username=user.username)
        except DjangoValidationError as e:
            errors["new_password"] = list(e.messages)

        if errors:
            raise serializers.ValidationError(errors)

        attrs["user"] = user
        return attrs

    def save(self):
        user = self.validated_data["user"]
        password = self.validated_data["new_password"]
        user.set_password(password)
        user.save()
        return user
class NewsletterSubscriberSerializer(serializers.ModelSerializer):
    class Meta:
        model = NewsletterSubscriber
        fields = ['id', 'email', 'is_active', 'created_at']
        read_only_fields = ['id', 'created_at']

    def validate_email(self, value):
        # Override to bypass unique validation
        return value

    def create(self, validated_data):
        email = validated_data.get('email')

        # Get or create without raising unique error
        subscriber, created = NewsletterSubscriber.objects.get_or_create(
            email=email,
            defaults=validated_data
        )

        # If exists and was inactive, reactivate
        if not created and not subscriber.is_active:
            subscriber.is_active = True
            subscriber.save()

        return subscriber

class UserAddressSerializer(serializers.ModelSerializer):
    class Meta:
        model = UserAddress
        fields = [
            'id', 'address_line_1', 'address_line_2',
            'city', 'state', 'country', 'postal_code'
        ]

    def create(self, validated_data):
        user = self.context.get('user')
        validated_data.pop('user', None)  
        return UserAddress.objects.create(user=user, **validated_data)
    
    def to_representation(self, instance):
        if not instance:
            return None
        return super().to_representation(instance)



class AssetSerializer(serializers.ModelSerializer):
    image_url = serializers.SerializerMethodField()

    class Meta:
        model = Assets
        fields = ["id", "title", "asset_types", "image_url", "s3_url", "s3_key"]

    def get_image_url(self, obj):
        return obj.s3_url or obj.get_image_url()
    

class UserProfileDataSerializer(serializers.ModelSerializer):
    profile_image = AssetSerializer(read_only=True)
    profile_image_id = serializers.PrimaryKeyRelatedField(
        queryset=Assets.objects.all(), source='profile_image', write_only=True, required=False
    )
    profile_cover_image = AssetSerializer(read_only=True)
    profile_cover_image_id = serializers.PrimaryKeyRelatedField(
        queryset=Assets.objects.all(), source='profile_cover_image', write_only=True, required=False
    )

    class Meta:
        model = UserProfile
        fields = [
            "about",
            "profile_image", "profile_image_id",
            "profile_cover_image", "profile_cover_image_id"
        ]


class UserProfileUpdateSerializer(serializers.ModelSerializer):
    address = serializers.SerializerMethodField()
    profile = UserProfileDataSerializer(required=False)
    profile_image = serializers.ImageField(required=False, write_only=True)


    class Meta:
        model = User
        fields = [
            "id", "username", "first_name", "last_name", "email", "phone_number",
            "gender", "profile",'profile_image','address', 'created_at'
        ]
        read_only_fields = ["email",]
    
    
    def validate_gender(self,value):
        allowed_values = ["male", "female", "other"]
        if value and value.lower() not in allowed_values:
            raise serializers.ValidationError("Gender must be either 'male', 'female', or 'other'.")
        return value
    
    # def validate_profile_image(self, image):
    #     from PIL import Image, UnidentifiedImageError

    #     try:
    #         img = Image.open(image)
    #         img.verify()  # Validate the image without loading it fully
    #     except UnidentifiedImageError:
    #         raise serializers.ValidationError("Upload a valid image. Unsupported or corrupted file.")
    #     return image

    def validate_profile_image(self, image):
        import pillow_heif
        from PIL import Image, UnidentifiedImageError

        # Register HEIF/HEIC support (once per process)
        pillow_heif.register_heif_opener()

        # Check if image object is valid
        if not image or not hasattr(image, 'file') or not image.file:
            raise serializers.ValidationError("No image file provided.")

        # Try to open and verify the image
        try:
            img = Image.open(image)
            img.verify()  # Checks for corruption
        except UnidentifiedImageError:
            raise serializers.ValidationError("Upload a valid image. Unsupported or corrupted file.")
        except Exception as e:
            raise serializers.ValidationError(f"Image validation failed: {str(e)}")

        return image

    
    
    def get_address(self, obj):
        address_instance = obj.address.first() 
        if address_instance:
            return UserAddressSerializer(address_instance).data
        return None  # or {} if you prefer

    
    def validate_phone_number(self, value):
        if value.startswith('+'):
            # Must start with +91 and followed by exactly 10 digits
            if not re.fullmatch(r'\+91\d{10}', value):
                raise serializers.ValidationError("Phone number must be in the format +91XXXXXXXXXX.")
            digits_only = value[3:]  # remove +91

            if digits_only[0] < '3':
                raise serializers.ValidationError("In +91 format, phone number must start with 3 or higher.")

        else:
            if not re.fullmatch(r'\d{10}', value):
                raise serializers.ValidationError("Phone number must be a 10-digit number without country code.")
            digits_only = value

            if digits_only[0] < '3':
                raise serializers.ValidationError("In +91 format, phone number must start with 3 or higher.")

        return value

    def update(self, instance, validated_data):
        profile_data = validated_data.pop("profile", {})
        address_data = validated_data.pop("address", {})
        instance.gender = validated_data.get('gender', instance.gender)
        instance.phone_number = validated_data.get('phone_number', instance.phone_number)
        instance.first_name = validated_data.get('first_name', instance.first_name)
        instance.last_name = validated_data.get('last_name', instance.last_name)
        instance.username = validated_data.get('username', instance.username)

        # Update User fields
        profile, _ = UserProfile.objects.get_or_create(user=instance)

        profile_image_file = validated_data.get('profile_image')
        if profile_image_file:
            asset = Assets.objects.create(
                image=profile_image_file,
                asset_types='Profile Image',
                title=profile_image_file.name
            )
            profile.profile_image = asset
            profile.save()

        # Update or create related UserProfile
        if profile_data:
            profile_instance, _ = UserProfile.objects.get_or_create(user=instance)
            for attr, value in profile_data.items():
                setattr(profile_instance, attr, value)
            profile_instance.save()

        # Update or create UserAddress
        if address_data:
            address_instance = instance.address.first()
            if address_instance:
                for attr, value in address_data.items():
                    setattr(address_instance, attr, value)
                address_instance.save()
            else:
                UserAddress.objects.create(user=instance, **address_data)
        instance.save()

        return instance



class YurayiPolicySerializer(serializers.ModelSerializer):
    class Meta:
        model = YurayiPolicy
        fields = ["id", "name", "policy_content", "created_at", "updated_at"]

from django.utils.timesince import timesince
from django.utils import timezone

class SessionSerializer(serializers.ModelSerializer):
    last_used_display = serializers.SerializerMethodField()

    class Meta:
        model = Session
        fields = [
            "id",
            "name",
            "city",
            "country",
            "latitude",
            "longitude",
            "user_agent",
            "ip_address",
            "created_at",
            "last_used_at",
            "last_used_display",   
        ]

    def get_last_used_display(self, obj):
        if not obj.last_used_at:
            return None
        
        now = timezone.now()
        diff = now - obj.last_used_at

        if diff.total_seconds() < 60:
            return "Just now"
        elif diff.total_seconds() < 3600:
            minutes = int(diff.total_seconds() // 60)
            return f"{minutes} minute{'s' if minutes > 1 else ''} ago"
        elif diff.total_seconds() < 86400:
            hours = int(diff.total_seconds() // 3600)
            return f"{hours} hour{'s' if hours > 1 else ''} ago"
        else:
            days = diff.days
            return f"{days} day{'s' if days > 1 else ''} ago"
