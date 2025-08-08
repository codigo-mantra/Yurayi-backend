import re
from rest_framework import serializers
from .models import User, UserProfile, Assets, ContactUs

from dj_rest_auth.registration.serializers import SocialLoginSerializer
from rest_framework import serializers
from rest_framework_simplejwt.tokens import RefreshToken

# Regex to check if identifier is an email
EMAIL_REGEX = r"[^@]+@[^@]+\.[^@]+"

import re

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
    confirm_password = serializers.CharField(write_only=True)
    password = serializers.CharField(write_only=True)

    class Meta:
        model = User
        fields = [
            'username',
            'email',
            'first_name',
            'last_name',
            'phone_number',
            'password',
            'confirm_password'
        ]

    def validate(self, data):
        username = data.get('username', '').strip()
        first_name = data.get('first_name', '').strip()
        last_name = data.get('last_name', '').strip()
        email = data.get('email', '').strip()
        phone_number = data.get('phone_number', '').strip()
        password = data.get('password').strip()
        confirm_password = data.get('confirm_password').strip()

        # Check required fields
        required_fields = {
            "username": username,
            "first_name": first_name,
            "last_name": last_name,
            "email": email,
            "password": password,
            "confirm_password": confirm_password,
        }
        for field, value in required_fields.items():
            if not value:
                raise serializers.ValidationError({field: f"{field.replace('_', ' ').capitalize()} is required."})

        # Format validations
        if not first_name.isalpha():
            raise serializers.ValidationError({"first_name": "First name must contain only letters."})
        if not last_name.isalpha():
            raise serializers.ValidationError({"last_name": "Last name must contain only letters."})

        # Uniqueness checks
        if User.objects.filter(username=username).exists():
            raise serializers.ValidationError({"username": "Username already exists."})
        if User.objects.filter(email=email).exists():
            raise serializers.ValidationError({"email": "Email already exists."})

        # Phone number format
        if phone_number:
            if not re.fullmatch(r'\+?\d+', phone_number) or len(phone_number) > 13:
                raise serializers.ValidationError({
                    "phone_number": "Phone number must contain only digits and may start with a '+'. Max 13 digits."
                })

        # Password match
        if password != confirm_password:
            raise serializers.ValidationError({"password": "Passwords do not match."})

        return data

    def create(self, validated_data):
        validated_data.pop('confirm_password')
        password = validated_data.pop('password')
        user = User(**validated_data)
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
