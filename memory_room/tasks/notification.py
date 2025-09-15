from celery import shared_task
from userauth.models import User
from django.utils import timezone
from memory_room.models import TimeCapSoulDetail, TimeCapSoulRecipient
from memory_room.notification_service import NotificationService


def recipients_nofitication_creator(recipients:TimeCapSoulRecipient, notification_key:str, is_opened=None):
    
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
def capsoul_almost_unlock(detail_id):
    try:
        detail = TimeCapSoulDetail.objects.get(id=detail_id)
    except Exception as e:
        pass
    else:
        recipients  = TimeCapSoulRecipient.objects.filter(time_capsoul = detail.time_capsoul)
        # create notification for  all tagged person 
        recipients_nofitication_creator(recipients=recipients, notification_key='capsoul_almost_unlock')

@shared_task
def capsoul_unlocked(detail_id):
    detail = TimeCapSoulDetail.objects.get(id=detail_id)
    #  Notify owner 
    notif = NotificationService.create_notification_with_key(
            notification_key='capsoul_unlocked',
            user=detail.time_capsoul.user,
            time_capsoul=detail.time_capsoul
        )
    

@shared_task
def capsoul_waiting(detail_id):
    detail = TimeCapSoulDetail.objects.get(id=detail_id)
    # Notify tagged person after 24 hours if shared capsoul they havent open'd it
    recipients  = TimeCapSoulRecipient.objects.filter(time_capsoul = detail.time_capsoul)
    recipients_nofitication_creator(recipients=recipients, notification_key='capsoul_waiting',is_opened=True)

   

@shared_task
def capsoul_reminder_7_days(detail_id):
    detail = TimeCapSoulDetail.objects.get(id=detail_id)
    # Notify tagged person
    recipients  = TimeCapSoulRecipient.objects.filter(time_capsoul = detail.time_capsoul)
    recipients_nofitication_creator(recipients=recipients, notification_key='capsoul_waiting')


@shared_task
def capsoul_memory_one_year_ago(detail_id):
    detail = TimeCapSoulDetail.objects.get(id=detail_id)
    # Notify only owner
    notif = NotificationService.create_notification_with_key(
        notification_key='memory_one_year_ago',
        user=detail.time_capsoul.user,
        time_capsoul=detail.time_capsoul
    )
