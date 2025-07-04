# urls.py
from django.urls import path
from .views import ContactUsAPIView

urlpatterns = [
    path('contact-us/', ContactUsAPIView.as_view(), name='contact-us'),
]
