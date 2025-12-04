from django.db.models.signals import post_save,post_delete
from django.dispatch import receiver
from django.conf import settings
from .models import  User, UserProfile,Assets, YurayiPolicy
from django.core.cache import cache
from timecapsoul.utils import send_html_email
import logging
logger = logging.getLogger(__name__)
import os, uuid
from memory_room.models import TimeCapSoulRecipient, Notification
from memory_room.notification_service import NotificationService

def clear_cache(cache_key:str):
    """Clear Cache Using Cache Key It will return as True or False"""
    
    is_cleared = False
    try:
        cache.delete(cache_key)
        is_cleared = True
    except Exception as e:
        logger.error(f'Exception while clearing cache for key {cache_key}')
    finally:
        return is_cleared



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
                time_capsoul_obj = capsoul.time_capsoul
                time_cap_owner = time_capsoul_obj.user.first_name if time_capsoul_obj.user.first_name else time_capsoul_obj.user.email
                
                notification_msg = f"You’ve been invited to a capsoul. {time_cap_owner} special has saved a memory with you in mind — a surprise awaits."
                
                notif = NotificationService.create_notification_with_key(
                    notification_key='capsoul_invite_received',
                    user=instance,
                    time_capsoul=capsoul.time_capsoul,
                    custom_message=notification_msg
                )
           
        except Exception as e:
            logger.exception("Exception while creating user profile in signal")
        else:
            logger.info("Profile created for user")




@receiver([post_save, post_delete], sender=Assets)
def delete_cover_cache(sender, instance, **kwargs):
    # Clear cached data 
    clear_cache("memory_room_covers")
    clear_cache('time_capsoul_covers')


# @receiver(post_save, sender=UserProfile)
# def create_profile_update_notification(sender,created, instance, *args, **kwargs):
#     if not created:
#         notif = NotificationService.create_notification_with_key(
#             user=instance.user,
#             notification_key='profile_updated'
#             )


@receiver([post_delete, post_save], sender=YurayiPolicy)
def delete_policy_cache(sender, instance, **kwargs):
    clear_cache(f"yurayi_policies")
    

@receiver(post_save, sender=Notification)
def delete_notification_cache(sender, instance,created,*args, **kwargs):
    if created:
        cache_key = f'{instance.user.email}__notifications'
        clear_cache(cache_key)

