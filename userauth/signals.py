from django.db.models.signals import post_save
from django.dispatch import receiver
from django.conf import settings
from .models import  User, UserProfile
from timecapsoul.utils import send_html_email
import os


@receiver(post_save, sender=User)
def create_user_profile(sender, instance, created, **kwargs):
    if created:
        try:
            user = UserProfile.objects.create(user=instance)
        except Exception as e:
            print(f'\n Exception while creating user profile in signal as: {e}')
        else:
            print(f'Profile created for: {instance}')

