

import datetime
from celery import shared_task
from userauth.models import User
from django.utils import timezone
from datetime import timedelta
from dateutil.relativedelta import relativedelta
import logging
logger = logging.getLogger(__name__)
from memory_room.utils import convert_file_size
from django.core.cache import cache
from django.db import close_old_connections


from memory_room.models import MemoryRoom, MemoryRoomMediaFile, TimeCapSoulMediaFile

from memory_room.models import TimeCapSoulDetail, TimeCapSoulRecipient, TimeCapSoul
from memory_room.notification_service import NotificationService

@shared_task
def send_report():
    print("Report sent at:", datetime.datetime.now())
    return "Done"


def recipients_nofitication_creator(recipients:TimeCapSoulRecipient, notification_key:str, is_opened=None):
    logger.info("recipients_nofitication_creator called")
    
    for recipient in recipients:
        
        if recipient.is_opened == False:
            person_email = recipient.email
            time_capsoul = recipient.time_capsoul
            
            # create notification at invited for tagged user if exists
            try:
                user = User.objects.get(email = person_email)
            except User.DoesNotExist as e:
                # skip if user not exists
                pass
            else:
                notif = NotificationService.create_notification_with_key(
                    notification_key=notification_key,
                    user=user,
                    time_capsoul=time_capsoul
                )
        

@shared_task
def capsoul_almost_unlock(capsoul_id):
    logger.info("capsoul_almost_unlock task called")
    is_created = False
    try:
        time_capsoul = TimeCapSoul.objects.get(id=capsoul_id)
    except Exception as e:
        pass
    else:
        recipients  = TimeCapSoulRecipient.objects.filter(time_capsoul = time_capsoul, is_deleted = False)
        # create notification for  all tagged recipients 
        recipients_nofitication_creator(recipients=recipients, notification_key='capsoul_almost_unlock')
        is_created = True
    finally:
        return is_created
        

@shared_task
def capsoul_unlocked(capsoul_id):
    logger.info("capsoul_unlocked task called")
    is_created = False
    
    try:
        time_capsoul = TimeCapSoul.objects.get(id=capsoul_id)
    except Exception as e:
        pass
    else:
        # Notify owner 
        notif = NotificationService.create_notification_with_key(
            notification_key='capsoul_unlocked',
            user=time_capsoul.user,
            time_capsoul=time_capsoul
        )
        is_created = True
    finally:
        return is_created
        
        


@shared_task
def capsoul_waiting(capsoul_id):
    """create notification for 24 hour reminder"""
    logger.info("capsoul_waiting task called")
    time_capsoul = TimeCapSoul.objects.get(id=capsoul_id)
    # Notify tagged person after 24 hours if shared capsoul they havent open'd it
    recipients  = TimeCapSoulRecipient.objects.filter(time_capsoul = time_capsoul, is_deleted = False)
    recipients_nofitication_creator(recipients=recipients, notification_key='capsoul_waiting',is_opened=True)


@shared_task
def capsoul_reminder_7_days(capsoul_id):
    """create notification for 7 days reminder"""
    logger.info("capsoul_reminder_7_days task called")
    
    time_capsoul = TimeCapSoul.objects.get(id=capsoul_id)
    # Notify tagged person after 24 hours if shared capsoul they havent open'd it
    recipients  = TimeCapSoulRecipient.objects.filter(time_capsoul = time_capsoul, is_deleted = False)
    recipients_nofitication_creator(recipients=recipients, notification_key='capsoul_waiting',is_opened=True)


@shared_task
def capsoul_memory_one_year_ago(capsoul_id):
    """create notification for 1 years reminder"""
    logger.info("capsoul_memory_one_year_ago task called")
    
    time_capsoul = TimeCapSoul.objects.get(id=capsoul_id)
    # Notify only owner
    notif = NotificationService.create_notification_with_key(
        notification_key='memory_one_year_ago',
        user=time_capsoul.user,
        time_capsoul=time_capsoul
    )


@shared_task
def capsoul_notification_handler():
    logger.info("capsoul_notification_handler task called")
    from datetime import timedelta
    from django.utils import timezone

    now = timezone.now()
    one_hour_ago = now - timedelta(hours=1)

    # Sealed capsouls scheduled for today
    sealed_capsouls = TimeCapSoul.objects.filter(
        unlock_date__date=now.date(),
        status='sealed',
        is_deleted = False,
    )
    
    #  Already unlocked capsouls
    unlocked_capsouls = TimeCapSoul.objects.filter(
        status='unlocked',
        is_deleted = False,
        
    )
    
    for capsoul in sealed_capsouls:
        unlock_date = capsoul.unlock_date

        # If unlock_time lies within the last 1 hour window → trigger unlock
        if one_hour_ago < unlock_date <= now:
            print('--- almost unlock called ---')
            capsoul_almost_unlock.apply_async((capsoul.id,), eta=unlock_date)
            capsoul_unlocked.apply_async((capsoul.id,), eta=unlock_date)

    for capsoul in unlocked_capsouls:
        unlock_date = capsoul.unlock_date

        # 24 hours after unlock → Waiting
        if one_hour_ago < unlock_date + timedelta(hours=24) <= now:
            print('--- capsoul_waiting called ---')
            capsoul_waiting.apply_async((capsoul.id,), eta=unlock_date)

        # 7 days after unlock → Reminder
        if one_hour_ago < unlock_date + timedelta(days=7) <= now:
            print('--- capsoul_reminder_7_days called ---')
            capsoul_reminder_7_days.apply_async((capsoul.id,), eta=unlock_date)

        # 1 year after unlock → Memory One Year Ago
        if one_hour_ago < unlock_date + timedelta(days=365) <= now:
            print('--- capsoul_memory_one_year_ago called ---')
            capsoul_memory_one_year_ago.apply_async((capsoul.id,), eta=unlock_date)

@shared_task
def update_memory_room_occupied_storage(media_file_id, option_type):
    is_updated = False
    
    try:
        media_file = MemoryRoomMediaFile.objects.get(id = media_file_id)
    except MemoryRoomMediaFile.DoesNotExist:
        logger.error(f'Exception while updating memory room storage for media file id: {media_file_id}')
    else:
        room = media_file.memory_room
        file_size_in_kb = convert_file_size(media_file.file_size, 'KB')[0]
        current_occupied_storage_in_kb = convert_file_size(room.occupied_storage, 'KB')[0]
        
        
        if option_type == 'addition':
            updated_storage = current_occupied_storage_in_kb + file_size_in_kb
        else:
            updated_storage = max(0, current_occupied_storage_in_kb - file_size_in_kb)
        room.occupied_storage = f'{updated_storage} KB'
        room.save()
        is_updated = True
    finally:
        close_old_connections()
        return is_updated
        
        
@shared_task
def update_time_capsoul_occupied_storage(media_file_id, option_type):
    is_updated = False
    
    try:
        media_file = TimeCapSoulMediaFile.objects.get(id = media_file_id)
    except TimeCapSoulMediaFile.DoesNotExist:
        logger.error(f'Exception while updating time-capsoul room storage for media file id: {media_file_id}')
    else:
        capsoul = media_file.time_capsoul
        file_size_in_kb = convert_file_size(media_file.file_size, 'KB')[0]
        current_occupied_storage_in_kb = convert_file_size(capsoul.occupied_storage, 'KB')[0]
        if option_type == 'addition':
            updated_storage = current_occupied_storage_in_kb + file_size_in_kb
        else:
            updated_storage = max(0, current_occupied_storage_in_kb - file_size_in_kb)
        capsoul.occupied_storage = f'{updated_storage} KB'
        capsoul.save()
        is_updated = True
    finally:
        # close_old_connections()
        return is_updated
    
    

@shared_task
def clear_all_cache():
    """
    Clear all cache in the system.
    """
    cache.clear()
    return "Cache cleared successfully."

@shared_task
def update_parent_media_refrences_task(media_id):
    try:
        media_file = TimeCapSoulMediaFile.objects.get(id=media_id)
    except TimeCapSoulMediaFile.DoesNotExist:
        logger.error(f"Media file with id {media_id} does not exist.")
        close_old_connections()

        return False
    else:
        time_capsoul = media_file.time_capsoul
        recipients = TimeCapSoulRecipient.objects.filter(time_capsoul=time_capsoul, is_deleted=False)
        media_ids = ','.join(str(m.id) for m in time_capsoul.timecapsoul_media_files.filter(is_deleted=False))
        recipients.update(parent_media_refrences=media_ids)
        close_old_connections()
        return True