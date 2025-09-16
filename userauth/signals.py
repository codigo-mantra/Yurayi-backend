from django.db.models.signals import post_save,post_delete
from django.dispatch import receiver
from django.conf import settings
from .models import  User, UserProfile,Assets
from django.core.cache import cache
from timecapsoul.utils import send_html_email
import logging
logger = logging.getLogger(__name__)
import os, uuid
from memory_room.models import TimeCapSoulRecipient
from memory_room.notification_service import NotificationService



@receiver(post_save, sender=User)
def create_user_profile(sender, instance, created, **kwargs):
    if created:
        try:
            user = UserProfile.objects.create(user=instance)
            instance.s3_storage_id = uuid.uuid4()
            # instance.save(update_fields=["s3_storage_id"])
            instance.save()
            time_capsoul = TimeCapSoulRecipient.objects.filter(email = instance.email)
            for capsoul in time_capsoul:
                # create notification here 
                notif = NotificationService.create_notification_with_key(
                    notification_key='capsoul_invite_received',
                    user=instance,
                    time_capsoul=capsoul.time_capsoul
                )
           
        except Exception as e:
            logger.exception("Exception while creating user profile in signal")
        else:
            logger.info("Profile created for user", extra={"user_id": instance.id})




@receiver([post_save, post_delete], sender=Assets)
def delete_cover_cache(sender, instance, **kwargs):
    # Clear cached data 
    cache_key = f"memory_room_covers"
    capsoul_cover = 'time_capsoul_covers'
    cache.delete(cache_key)
    cache.delete(capsoul_cover)


@receiver(post_save, sender=UserProfile)
def create_profile_update_notification(sender,created, instance, *args, **kwargs):
    if not created:
        notif = NotificationService.create_notification_with_key(
            user=instance.user,
            notification_key='profile_updated'
            )
    