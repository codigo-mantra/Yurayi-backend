import re
from rest_framework import serializers
from userauth.models import ContactUs, User, UserProfile, Assets

from dj_rest_auth.registration.serializers import SocialLoginSerializer
from rest_framework import serializers
from rest_framework_simplejwt.tokens import RefreshToken
from django.conf import settings
from django.contrib.auth.forms import PasswordResetForm
from userauth.models import User


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
        if not re.match(r'^\+?\d{10,13}$', value):
            raise serializers.ValidationError("Enter a valid phone number with 10-13 digits.")
        return value

class GoogleIDTokenSerializer(SocialLoginSerializer):
    id_token = serializers.CharField()

    def validate(self, attrs):
        request = self.context.get("request")
        id_token = attrs.get("id_token")

        if not id_token:
            raise serializers.ValidationError("Id-token is required")

        attrs["access_token"] = id_token  # 
        return super().validate(attrs)



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
    


class RegistrationSerializer(serializers.ModelSerializer):
    step_no = serializers.IntegerField(write_only=True, required=False)
    password = serializers.CharField(write_only=True, required=False)
    confirm_password = serializers.CharField(write_only=True, required=False)

    class Meta:
        model = User
        fields = [
            'step_no',
            'username',
            'email',
            'first_name',
            'last_name',
            'phone_number',
            'password',
            'confirm_password'
        ]
        extra_kwargs = {
            field: {'required': False, 'allow_blank': True}
            for field in ['username', 'email', 'first_name', 'last_name', 'phone_number']
        }

    def validate(self, data):
        step_no = data.get('step_no')
        errors = {}

        # Common fields
        first_name = data.get('first_name', '').strip()
        last_name = data.get('last_name', '').strip()
        email = data.get('email', '').strip()
        phone_number = data.get('phone_number', '').strip()

        # Step 1 or Step 2: Validate name and email
        if step_no in [1, 2]:
            required_fields = {
                "first_name": first_name,
                "last_name": last_name,
                "email": email,
            }

            if step_no == 2:
                # Additional fields for step 2
                required_fields.update({
                    "username": data.get('username', '').strip(),
                    "password": data.get('password'),
                    "confirm_password": data.get('confirm_password'),
                })

            for field, value in required_fields.items():
                if not value:
                    errors[field] = f"{field.replace('_', ' ').capitalize()} is required."

            if first_name and not first_name.isalpha():
                errors["first_name"] = "First name must contain only letters."
            if last_name and not last_name.isalpha():
                errors["last_name"] = "Last name must contain only letters."

            if step_no == 2:
                username = data.get('username', '').strip()
                if username and User.objects.filter(username=username).exists():
                    errors["username"] = "Username already exists."
                if email and User.objects.filter(email=email).exists():
                    errors["email"] = "Email already exists."
                if data.get('password') != data.get('confirm_password'):
                    errors["password"] = "Passwords do not match."

            # Validate phone number if given
            if phone_number:
                if not re.fullmatch(r'\+?\d+', phone_number) or len(phone_number) > 13:
                    errors["phone_number"] = "Phone number must contain only digits and may start with a '+'. Max 13 digits."

        else:
            errors['step_no'] = 'Invalid step number.'

        if errors:
            raise serializers.ValidationError(errors)

        return data

    
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
    def validate(self, attrs):
        return super().validate(attrs)

    def save(self):
        user = super().save()
        # Optionally activate user or log them in
        return user

# Password Change
class CustomPasswordChangeSerializer(PasswordChangeSerializer):
    def validate_old_password(self, value):
        user = self.context['request'].user
        if not user.check_password(value):
            raise serializers.ValidationError("Your current password is incorrect.")
        return value

    def validate(self, data):
        if data["new_password1"] != data["new_password2"]:
            raise serializers.ValidationError("The new passwords do not match.")
        return data

    def save(self):
        user = self.context['request'].user
        new_password = self.validated_data["new_password1"]
        user.set_password(new_password)
        user.save()
        return user
