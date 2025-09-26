from django.shortcuts import render
from django.http import HttpResponse
from allauth.socialaccount.models import SocialAccount
from memory_room.models import MemoryRoom, MemoryRoomMediaFile, TimeCapSoul, RecipientsDetail, TimeCapSoulDetail,TimeCapSoulMediaFile
from memory_room.utils import get_readable_file_size_from_bytes
from timecapsoul.utils import send_html_email
from userauth.tasks import send_html_email_task
from memory_room.crypto_utils import encrypt_and_upload_file, decrypt_and_get_image, save_and_upload_decrypted_file, decrypt_and_replicat_files, generate_signature, verify_signature
import os
import subprocess
import tempfile

import logging
logger = logging.getLogger(__name__)

# from timecapsoul.utils import MediaThumbnailExtractor
# # Create your views here.

# time_cap_owner = instance.time_capsoul.user.first_name if instance.time_capsoul.user.first_name else instance.time_capsoul.user.email
# try:
#     capsoul_recipients = RecipientsDetail.objects.filter(time_capsoul =instance.time_capsoul).first()
#     if capsoul_recipients:
#         all_recipients = capsoul_recipients.recipients.all()
#         for recipient in all_recipients:
#             try:
#                 send_html_email(
#                     subject="You’ve received a Time Capsoul sealed with love.",
#                     to_email=recipient.email,
#                     template_name="userauth/time_capsoul_tagged.html",
#                     context={
#                         "user": recipient.name,
#                         'sender_name': time_cap_owner,
#                         'unlock_date': str(instance.unlock_date)
#                     },
#                 )
#             except Exception as e:
#                 print('Exception ')
#                 pass
#             else:
#                 # print('yes')
#                 pass
# except Exception as e:
#     pass

import re

def parse_storage_size(size_str, default_unit="MB"):
    """
    Parse a size string like '1.53 MB', '200 kb', '3.4 Gb', '0.75 tb'
    into (float_value, unit in uppercase).
    If size_str is empty or invalid, return (0, default_unit)
    """
    if not size_str or not size_str.strip():
        return 0, default_unit.upper()
    
    match = re.match(r"(\d+(?:\.\d+)?)\s*(KB|MB|GB|TB)", size_str.strip(), re.IGNORECASE)
    if not match:
        return 0, default_unit.upper()
    
    value, unit = match.groups()
    return float(value), unit.upper()


def to_mb(value, unit):
    """
    Convert any size to MB.
    """
    unit = unit.upper()
    if unit == "KB":
        return value / 1024
    elif unit == "MB":
        return value
    elif unit == "GB":
        return value * 1024
    elif unit == "TB":
        return value * 1024 * 1024
    else:
        raise ValueError(f"Unknown unit: {unit}")


def user_storage_calculator():
    
    all_users = User.objects.all()
    for user in all_users:
        user_mapper = user.user_mapper.first() 

        if user_mapper:
            user_mapper.current_storage = '0 MB'
            user_mapper.max_storage_limit = '15 GB'
            user_mapper.save()
                
        try:
            user_capsoul =  TimeCapSoul.objects.filter(user = user, is_deleted = False)
        except Exception as e:
            pass
        else:
            for capsoul in user_capsoul:
                file_size = None
                current_storage_in_mb = parse_storage_size('')[0]
                
                try:
                    media_files = capsoul.timecapsoul_media_files.all()
                    for media in media_files: 
                        file_size = parse_storage_size(media.file_size)[0]
                        current_storage_in_mb += file_size
                    if file_size is None:
                        current_storage_in_mb +=  parse_storage_size('')[0]
                        
                except Exception as e:
                    pass
                else:
                    detail = capsoul.details
                    detail.occupied_storage = str(current_storage_in_mb) + ' MB'
                    detail.save()
                    user_mapper.current_storage =  str(current_storage_in_mb +  parse_storage_size(user_mapper.current_storage)[0]) + ' MB'
                    user_mapper.save()
                    
                    print(f'\n ----Capsoul: {capsoul.capsoul_template.name} is: current_storage_in_mb {current_storage_in_mb} -------')
                
                    
                
        
        # memory-room
        try:
            memory_rooms =  MemoryRoom.objects.filter(user = user, is_deleted = False)
        except Exception as e:
            pass
        else:
            for capsoul in memory_rooms:
                file_size = None
                current_storage_in_mb = parse_storage_size('')[0]
                
                try:
                    media_files = capsoul.memory_media_files.all()
                    for media in media_files: 
                        file_size = parse_storage_size(media.file_size)[0]
                        current_storage_in_mb += file_size
                    if file_size is None:
                        current_storage_in_mb +=  parse_storage_size('')[0]
                        
                except Exception as e:
                    pass
                else:
                    capsoul.occupied_storage = str(current_storage_in_mb) + ' MB'
                    capsoul.save()
                    user_mapper.current_storage =  str(current_storage_in_mb +  parse_storage_size(user_mapper.current_storage)[0]) + ' MB'
                    user_mapper.save()
                    
                    print(f'\n ---- Room: {capsoul.room_template.name} is: current_storage_in_mb  {current_storage_in_mb} -------')
        

from userauth.models import User

def testing_view(request):
    logger.info('testing_view called')
    # media = MediaThumbnailExtractor()
    # return HttpResponse('<h1>All good</h1>')
    # email = 'krishnayadav.codigomantra@gmail.com'
    # email = 'krishnayadavpb07@gmail.com'
    # email = "jaswinder.codigo@gmail.com"
    # email = "krishnayadav.codigomantra@gmail.com"
    email = "gaheme9246@cnguopin.com"
    # email2 = 'jasvir.codigo@gmail.com'
    import uuid
    from userauth.models import User
    # user = User.objects.get(email = email)
    # all_user = User.objects.all()
    # for user in all_user:
    #     user.set_password('Test@1234')
    #     user.save()
    # user_storage_calculator()

    
    # send_html_email_task.apply_async(
    #     kwargs={
    #         "subject": "You’ve received a Time Capsoul sealed with love.",
    #         "to_email": email,
    #         "template_name": "userauth/time_capsoul_tagged.html",
    #         "context": {
    #             "user": "Jasvir Kaur",
    #             "sender_name": "Krishna Yadav",
    #             "unlock_date": "04/02/2025"
    #         }
    #     }
    # )
    media_file = TimeCapSoulMediaFile.objects.get(id = 413)
    try:
        file_bytes, content_type = decrypt_and_get_image(str(media_file.s3_key))
    except Exception as e:
        file_bytes, content_type  = decrypt_and_replicat_files(str(media_file.s3_key))
    except Exception as e:
        pass
    
    
    
    
    # send_html_email(
    #     subject="You’ve received a Time Capsoul sealed with love.",
    #     # to_email='jasvir.codigo@gmail.com',
    #     to_email='krishnayadavpb07@gmail.com',
    #     template_name="userauth/time_capsoul_tagged.html",
    #     context={
    #         "user": 'Jasvir Kaur',
    #         'sender_name': 'Krishna Yadav',
    #         'unlock_date': '04/02/2025'
    #     },
    # )
    
    # email = 'admin@gmail.com'
    
    

    # objs = []
    # for user in User.objects.filter(s3_storage_id__isnull=True):
    #     user.s3_storage_id = uuid.uuid4()
    #     objs.append(user)

    # User.objects.bulk_update(objs, ['s3_storage_id'])
    
    # user = User.objects.get(email = 'krishna123.codigomantra@gmail.com')
    # time_capsoul =TimeCapSoul.objects.filter(user = user, status = 'sealed').first()
    # if time_capsoul:
    #     time_cap_owner = time_capsoul.user.first_name if time_capsoul.user.first_name else time_capsoul.user.email
        
    #     recipients  = RecipientsDetail.objects.filter(time_capsoul = time_capsoul).first()
    #     if recipients:
    #         all_recipients = recipients.recipients.all()
            
    #         tagged_recients = (all_recipients.values_list('name', 'email'))
            
            # for person in tagged_recients:
            #     print(f'\nname: {person[0]} email: {person[-1]} ')
            
            # for recipient in tagged_recients:
                # person_name = recipient[0]
                # person_email = recipient[-1]
                # person_email = 'krishnayadav.codigomantra@gmail.com'
                

                # try:
                    # send_html_email(
                    #     subject="You’ve received a Time Capsoul sealed with love.",
                    #     to_email=person_email,
                    #     template_name="userauth/time_capsoul_tagged.html",
                    #     context={
                    #         "user": person_name,
                    #         'sender_name': time_cap_owner,
                    #         'unlock_date': time_capsoul.details.unlock_date
                    #     },
                    # )
                #     print(f'\n Yes email sent here name: {person_name} email: {person_email} ')

                # except Exception as e:
                #     print('Exception ')
                #     pass
                  

    
    
    # send_html_email(
    #         subject="Time Capsoul Tagged",
    #         to_email=['krishnayadav.codigomantra@gmail.com', 'jasvir.codigo@gmail.com', 'Shubhleencodigomantra@gmail.com' ],
    #         template_name="userauth/time_capsoul_tagged.html",
    #         context={
    #             "user": user,
    #             "reset_url": 'https://app.slack.com/client/T05M10D7PFU/C06EJGP2WDN',
    #             'sender_name': 'Krishna yadav',
    #             'unlock_date': '12-10-2025'
    #         },
            
    #     )

    try:
        is_testing = True
        # if is_testing:
        #     user = User.objects.get(email = email)
        #     is_deletion = False
        #     memory_room_deletion = True
        #     if is_deletion:
        #         user_so = SocialAccount.objects.filter(user = user).first()
        #         if user_so:
        #             user_so.delete()
        #         user.delete()
        #     if memory_room_deletion:
        #         memory_room = MemoryRoom.objects.filter(user = user)
        #         memory_room.delete()
        # media_files = MemoryRoomMediaFile.objects.all()

        
        # for media in media_files:
        #     current_file_size = media.file_size
        #     print(f'\n File size: {current_file_size}')


        #     try:
        #         file_size = int(current_file_size)
        #     except Exception as e:
        #         print(f'\n Exception is', file_size)
        #     else:
        #         try:
        #             size  = get_readable_file_size_from_bytes(media.file_size)
        #         except Exception as e:
        #             print(f'\n Exception {e}')
        #         else:
        #             print(f'\n File size: {size}')
        #             media.file_size  = size
        #             media.save()
        #             print(size)
        # res = generate_notification.apply_async()
    except:
        print('Not deleted')
    else:
        pass
        # capsoul = TimeCapSoulDetail.objects.get(id=25)
        # print('Yes deleted response: ',res)
        # logger.warning(f'Test warnign logger in by user {user.username}')
        # logger.error(f'Test errors logger in by user {user.username}')
        # logger.info(f'Test info here logger in by user {user.username}')
        # logger.critical(f'Test critical  here logger in by user {user.username}')



    # return render(request, 'userauth/time_capsoul_tagged.html', context={
    #     'user': "Krishna yadav",
    #     'sender_name': "Karan",
    #     'unlock_date': capsoul.unlock_date
        
    # })
    return render(request, 'userauth/time_capsoul_tagged.html')