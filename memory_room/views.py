from django.shortcuts import render
from django.http import HttpResponse
from allauth.socialaccount.models import SocialAccount
from memory_room.models import MemoryRoom, MemoryRoomMediaFile, TimeCapSoul, RecipientsDetail, TimeCapSoulDetail
from memory_room.utils import get_readable_file_size_from_bytes
from timecapsoul.utils import send_html_email

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

from userauth.models import User

def testing_view(request):
    # media = MediaThumbnailExtractor()
    # return HttpResponse('<h1>All good</h1>')
    # email = 'krishnayadav.codigomantra@gmail.com'
    email = 'krishnayadavpb07@gmail.com'
    
    # email = 'admin@gmail.com'
    # import uuid
    # from userauth.models import User
    # user = User.objects.get(email = email)

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
    except:
        print('Not deleted')
    else:
        # capsoul = TimeCapSoulDetail.objects.get(id=25)
        print('Yes deleted')
    # return render(request, 'userauth/time_capsoul_tagged.html', context={
    #     'user': "Krishna yadav",
    #     'sender_name': "Karan",
    #     'unlock_date': capsoul.unlock_date
        
    # })
    return render(request, 'userauth/time_capsoul_tagged.html')