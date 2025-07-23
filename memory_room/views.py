from django.shortcuts import render
from django.http import HttpResponse
# from timecapsoul.utils import MediaThumbnailExtractor
# Create your views here.

def testing_view(request):
    # media = MediaThumbnailExtractor()
    # return HttpResponse('<h1>All good</h1>')
    return render(request, 'userauth/reset_password_email.html')