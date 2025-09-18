

import datetime
from celery import shared_task
from userauth.models import User
from django.utils import timezone
from datetime import timedelta
from dateutil.relativedelta import relativedelta
import logging
logger = logging.getLogger(__name__)


from memory_room.models import TimeCapSoulDetail, TimeCapSoulRecipient
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
    try:
        detail = TimeCapSoulDetail.objects.get(id=capsoul_id)

    except Exception as e:
        pass
    else:
        recipients  = TimeCapSoulRecipient.objects.filter(time_capsoul = detail.time_capsoul)
        # create notification for  all tagged recipients 
        recipients_nofitication_creator(recipients=recipients, notification_key='capsoul_almost_unlock')

@shared_task
def capsoul_unlocked(capsoul_id):
    logger.info("capsoul_unlocked task called")
    try:
        detail = TimeCapSoulDetail.objects.get(id=capsoul_id)
    except Exception as e:
        pass
    else:
        #  Notify owner 
        notif = NotificationService.create_notification_with_key(
            notification_key='capsoul_unlocked',
            user=detail.time_capsoul.user,
            time_capsoul=detail.time_capsoul
        )


@shared_task
def capsoul_waiting(capsoul_id):
    """create notification for 24 hour reminder"""
    logger.info("capsoul_waiting task called")
    detail = TimeCapSoulDetail.objects.get(id=capsoul_id)
    # Notify tagged person after 24 hours if shared capsoul they havent open'd it
    recipients  = TimeCapSoulRecipient.objects.filter(time_capsoul = detail.time_capsoul)
    recipients_nofitication_creator(recipients=recipients, notification_key='capsoul_waiting',is_opened=True)


@shared_task
def capsoul_reminder_7_days(capsoul_id):
    """create notification for 7 days reminder"""
    logger.info("capsoul_reminder_7_days task called")
    
    detail = TimeCapSoulDetail.objects.get(id=capsoul_id)
    # Notify tagged person after 24 hours if shared capsoul they havent open'd it
    recipients  = TimeCapSoulRecipient.objects.filter(time_capsoul = detail.time_capsoul)
    recipients_nofitication_creator(recipients=recipients, notification_key='capsoul_waiting',is_opened=True)


@shared_task
def capsoul_memory_one_year_ago(capsoul_id):
    """create notification for 1 years reminder"""
    logger.info("capsoul_memory_one_year_ago task called")
    
    detail = TimeCapSoulDetail.objects.get(id=capsoul_id)
    # Notify only owner
    notif = NotificationService.create_notification_with_key(
        notification_key='memory_one_year_ago',
        user=detail.time_capsoul.user,
        time_capsoul=detail.time_capsoul
    )


@shared_task
def capsoul_notification_handler():
    print('---notification task called ---')
    logger.info("capsoul_notification_handler task called")
    now = timezone.now()

    # Sealed capsouls scheduled for today
    sealed_capsouls = TimeCapSoulDetail.objects.filter(
        unlock_date__date=now.date(),
        time_capsoul__status='sealed'
    )
    
    #  Already unlocked capsouls
    unlocked_capsouls = TimeCapSoulDetail.objects.filter(
        time_capsoul__status='unlocked'
    )
    
    for capsoul in sealed_capsouls:
        
        # Exactly at unlock → Unlocked
        if capsoul.unlock_date <= now < capsoul.unlock_date + timedelta(minutes=1):
            print('---almost unlock called ---')
            capsoul_almost_unlock.apply_async((capsoul.id,))
            capsoul_unlocked.apply_async((capsoul.id,))
    
    for capsoul in unlocked_capsouls:
        unlock_date = capsoul.unlock_date

        # 24 hours after unlock → Waiting
        if unlock_date + timedelta(hours=24) <= now < unlock_date + timedelta(hours=24, minutes=1):
            print('--- capsoul_waiting called ---')
            
            capsoul_waiting.apply_async((capsoul.id,))

        # 7 days after unlock → Reminder 7 Days
        if unlock_date + timedelta(days=7) <= now < unlock_date + timedelta(days=7, minutes=1):
            capsoul_reminder_7_days.apply_async((capsoul.id,))
            print('--- capsoul_reminder_7_days called ---')
            

        # 1 year after unlock → Memory One Year Ago
        if unlock_date + timedelta(days=365) <= now < unlock_date + timedelta(days=365, minutes=1):
            print('--- capsoul_memory_one_year_ago called ---')
            
            capsoul_memory_one_year_ago.apply_async((capsoul.id,))

            

    
    
    
    