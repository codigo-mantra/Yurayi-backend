from django.db.models.signals import post_save, post_delete
from django.dispatch import receiver
from .models import User, UserMapper
from memory_room.models import MemoryRoom, MemoryRoomDetail, TimeCapSoulDetail, TimeCapSoul,TimeCapSoulMediaFile,TimeCapSoulDetail,TimeCapSoulMediaFileReplica,TimeCapSoulReplica, RecipientsDetail, MemoryRoomMediaFile

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
        # also create here recipients-details
        RecipientsDetail.objects.create(
            time_capsoul = instance
            )



@receiver(post_save, sender=TimeCapSoulMediaFile)
def attach_media_to_timecapsoul_detail(sender, instance, created, **kwargs):
    if created and instance.time_capsoul:
        try:
            detail = TimeCapSoulDetail.objects.get(time_capsoul=instance.time_capsoul)
            detail.media_files.add(instance)
        except TimeCapSoulDetail.DoesNotExist:
            # Optionally create the detail if it doesn't exist
            detail = TimeCapSoulDetail.objects.create(time_capsoul=instance.time_capsoul, )
            detail.media_files.add(instance)


@receiver(post_save, sender=MemoryRoomMediaFile)
def attach_memory_room_media__files_detail(sender, instance, created, **kwargs):
    if created and instance.memory_room:
        try:
            detail = MemoryRoomDetail.objects.get(memory_room=instance.memory_room)
            detail.media_files.add(instance)
        except MemoryRoomDetail.DoesNotExist:
            # Optionally create the detail if it doesn't exist
            detail = MemoryRoomDetail.objects.create(memory_room=instance.memory_room, )
            detail.media_files.add(instance)
        else:
            print('media file added')
            pass


@receiver(post_delete, sender=TimeCapSoul)
def delete_all_related_timecapsoul_data(sender, instance, **kwargs):
    """
    Clean up all data associated with a TimeCapSoul when it's deleted.
    """

    # Delete TimeCapSoulDetail
    try:
        detail = instance.details
        if detail:
            # Delete all related media files and their replicas
            for media_file in detail.media_files.all():
                try:
                    if hasattr(media_file, "replica"):
                        media_file.replica.delete()
                except TimeCapSoulMediaFileReplica.DoesNotExist:
                    pass
                media_file.delete()
            detail.delete()
    except TimeCapSoulDetail.DoesNotExist:
        pass

    # Delete associated TimeCapSoulReplica
    try:
        instance.time_capsoul_replica.delete()
    except TimeCapSoulReplica.DoesNotExist:
        pass
