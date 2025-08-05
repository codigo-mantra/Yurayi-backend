from django.shortcuts import render
from django.http import HttpResponse
from allauth.socialaccount.models import SocialAccount

# from timecapsoul.utils import MediaThumbnailExtractor
# Create your views here.

from userauth.models import User

def testing_view(request):
    # media = MediaThumbnailExtractor()
    # return HttpResponse('<h1>All good</h1>')
    email = 'krishnayadav.codigomantra@gmail.com'
    try:
        user = User.objects.get(email = email)
        user_so = SocialAccount.objects.filter(user = user).first()
        if user_so:
            user_so.delete()
        user.delete()
    except:
        print('No user not deleted')
    else:
         print('yes user deleted')
    return render(request, 'userauth/new_letter_subscription.html')