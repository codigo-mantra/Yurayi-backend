from django.db.models.signals import post_save
from django.dispatch import receiver
from .models import User, UserMapper
from memory_room.models import MemoryRoom, MemoryRoomDetail, TimeCapSoulDetail, TimeCapSoul

@receiver(post_save, sender=User)
def create_user_mapper(sender, instance, created, **kwargs):
    if created:
        UserMapper.objects.create(
            user=instance,
            max_storage_limit='100 MB',     # default value
            current_storage='0 MB'          # default usage
        )

# create memory-room detail
@receiver(post_save, sender=MemoryRoom)
def create_user_mapper(sender, instance, created, **kwargs):
    if created:
        MemoryRoomDetail.objects.create(
            memory_room=instance,
        )

# create timecapsoul detail
@receiver(post_save, sender=TimeCapSoul)
def create_user_mapper(sender, instance, created, **kwargs):
    if created:
        TimeCapSoulDetail.objects.create(
            time_capsoul=instance,
        )