from django.shortcuts import render
from django.http import HttpResponse
from allauth.socialaccount.models import SocialAccount
from memory_room.models import MemoryRoom, MemoryRoomMediaFile
from memory_room.utils import get_readable_file_size_from_bytes

# from timecapsoul.utils import MediaThumbnailExtractor
# Create your views here.

from userauth.models import User

def testing_view(request):
    # media = MediaThumbnailExtractor()
    # return HttpResponse('<h1>All good</h1>')
    email = 'krishnayadav.codigomantra@gmail.com'
    email = 'admin@gmail.com'

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
         print('Yes deleted')
    return render(request, 'userauth/new_letter_subscription.html')