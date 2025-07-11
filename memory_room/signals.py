from django.db.models.signals import post_save
from django.dispatch import receiver
from .models import User, UserMapper

@receiver(post_save, sender=User)
def create_user_mapper(sender, instance, created, **kwargs):
    if created:
        UserMapper.objects.create(
            user=instance,
            max_storage_limit='100 MB',     # default value
            current_storage='0 MB'         # default usage
        )
