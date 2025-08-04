from django.shortcuts import render
from django.http import HttpResponse
# from timecapsoul.utils import MediaThumbnailExtractor
# Create your views here.

from userauth.models import User

def testing_view(request):
    # media = MediaThumbnailExtractor()
    # return HttpResponse('<h1>All good</h1>')
    email = '"krishnayadav.codigomantra@gmail.com'
    try:
        user = User.objects.get(email = email)
    except:
        pass
    else:
         user.delete()
         print('yes user deleted')
    return render(request, 'userauth/new_letter_subscription.html')