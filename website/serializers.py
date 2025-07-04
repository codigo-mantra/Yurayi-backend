from rest_framework import serializers
from .models import ContactUs
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

    
