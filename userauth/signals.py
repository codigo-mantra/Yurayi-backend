from django.db.models.signals import post_save,post_delete
from django.dispatch import receiver
from django.conf import settings
from .models import  User, UserProfile,Assets
from django.core.cache import cache
from timecapsoul.utils import send_html_email
import os, uuid


@receiver(post_save, sender=User)
def create_user_profile(sender, instance, created, **kwargs):
    if created:
        try:
            user = UserProfile.objects.create(user=instance)
            instance.s3_storage_id = uuid.uuid4()
            # instance.save(update_fields=["s3_storage_id"])
            instance.save()
        except Exception as e:
            print(f'\n Exception while creating user profile in signal as: {e}')
        else:
            print(f'Profile created for: {instance}')




@receiver([post_save, post_delete], sender=Assets)
def delete_cover_cache(sender, instance, **kwargs):
    # Clear cached data 
    cache_key = f"memory_room_covers"
    capsoul_cover = 'time_capsoul_covers'
    cache.delete(cache_key)
    cache.delete(capsoul_cover)
