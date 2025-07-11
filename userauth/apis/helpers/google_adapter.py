from allauth.socialaccount.adapter import DefaultSocialAccountAdapter
from allauth.socialaccount.models import SocialApp
from django.core.exceptions import MultipleObjectsReturned, ObjectDoesNotExist
from django.conf import settings

class CustomSocialAccountAdapter(DefaultSocialAccountAdapter):
    def get_app(self, request, provider, client_id=None):

        site_id = settings.SITE_ID
        try:
            # Just match by provider and site — skip client_id (that's what causes the error)
            return SocialApp.objects.get(provider=provider, sites__id=site_id)
        except MultipleObjectsReturned:
            # Log and return first match to avoid crash
            apps = SocialApp.objects.filter(provider=provider, sites__id=site_id)
            return apps.first()
        except ObjectDoesNotExist:
            return None

