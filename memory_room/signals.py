from django.db.models.signals import post_save, post_delete
from django.dispatch import receiver
from .models import User, UserMapper
from memory_room.models import MemoryRoom, MemoryRoomDetail, TimeCapSoulDetail, TimeCapSoul,TimeCapSoulMediaFile,TimeCapSoulDetail,TimeCapSoulMediaFileReplica, RecipientsDetail, MemoryRoomMediaFile, MemoryRoomTemplateDefault, TimeCapSoulTemplateDefault
from memory_room.utils import to_mb, parse_storage_size,convert_file_size
from django.core.cache import cache
import logging
logger = logging.getLogger(__name__)


# @receiver(post_save, sender=User)
# def create_user_mapper(sender, instance, created, **kwargs):
#     if created:
#         mapper = UserMapper.objects.create(
#             user=instance,
#             max_storage_limit='15 GB',     # default value
#             current_storage='0 MB'          # default usage
#         )
#         mapper.save()

# create memory-room detail
# @receiver(post_save, sender=MemoryRoom)
# def create_user_mapper(sender, instance, created, **kwargs):
#     if created:
#         MemoryRoomDetail.objects.create(
#             memory_room=instance,
#         )

# create timecapsoul detail
# @receiver(post_save, sender=TimeCapSoul)
# def create_user_mapper(sender, instance, created, **kwargs):
#     if created:
#         TimeCapSoulDetail.objects.create(
#             time_capsoul=instance,
#         )



# @receiver(post_save, sender=TimeCapSoulMediaFile)
# def update_user_storage(sender, instance, created, **kwargs):
#     if created and instance.time_capsoul:
#         try:
#             parsed_fle_size = parse_storage_size(instance.file_size)[0]
            
#             user_mapper = instance.user.user_mapper.first()
#             if user_mapper: 
#                 user_mapper.current_storage =  str( parsed_fle_size +  parse_storage_size(user_mapper.current_storage)[0]) + ' GB'
#                 user_mapper.save()
            
#             #  now update capsoul storage here
#             capsoul = instance.time_capsoul
#             capsoul.occupied_storage = str(parse_storage_size(capsoul.occupied_storage)[0] + parsed_fle_size)+ ' GB'
#             capsoul.save()
            
#             # clear cache
#             stored_cached_data = f'user_storage_id_{instance.user.s3_storage_id}'
#             if stored_cached_data:
#                 cache.delete(stored_cached_data)
            
#         except Exception as e:
#             logger.error(f'Exception while updating user storage as: {instance.user.email} media-id: {instance.id} as {e}')
            
            

# @receiver(post_save, sender=MemoryRoomMediaFile)
# def update_user_storage_on_media_creation(sender, instance, created, **kwargs):
#     if created and instance.memory_room:
#         try:
#             # detail = MemoryRoomDetail.objects.get(memory_room=instance.memory_room)
#             # detail.media_files.add(instance)
#             user_mapper = instance.user.user_mapper.first()
#             parsed_file_size = parse_storage_size(instance.file_size)[0]

#             if user_mapper: 
#                 # total usage
#                 user_mapper.current_storage =  str( parsed_file_size +  parse_storage_size(user_mapper.current_storage)[0]) + ' GB'
#                 user_mapper.save()
                
#                 #  now update memory room storage here
#                 room = instance.memory_room
#                 room.occupied_storage = str(parse_storage_size(room.occupied_storage)[0] + parsed_file_size) + + ' GB'
#                 room.save()
                
            
#             # clear cache
#             stored_cached_data = f'user_storage_id_{instance.user.s3_storage_id}'
#             if stored_cached_data:
#                 cache.delete(stored_cached_data)
#         except Exception as e:
#             logger.error(f'Exception while updating user storage as: {instance.user.email} media-id: {instance.id}  as {e}')


# @receiver(post_delete, sender=TimeCapSoul)
# def delete_all_related_timecapsoul_data(sender, instance, **kwargs):
#     """
#     Clean up all data associated with a TimeCapSoul when it's deleted.
#     """

#     # Delete TimeCapSoulDetail
#     try:
#         detail = instance.details
#         if detail:
#             # Delete all related media files and their replicas
#             for media_file in detail.media_files.all():
#                 try:
#                     if hasattr(media_file, "replica"):
#                         media_file.replica.delete()
#                 except TimeCapSoulMediaFileReplica.DoesNotExist:
#                     pass
#                 media_file.delete()
#             detail.delete()
#     except TimeCapSoulDetail.DoesNotExist:
#         pass


@receiver([post_save, post_delete], sender=MemoryRoomTemplateDefault)
def delete_cached_templated_data(sender, instance, **kwargs):
    # Clear cached data 
    cache_key = f"memory_room_default_temlates"
    cache.delete(cache_key)


@receiver([post_save, post_delete], sender=TimeCapSoulTemplateDefault)
def delete_capsoul_template_cached_data(sender, instance, **kwargs):
    # Clear cached data 
    cache_key = f"time_capsoul_templates"
    cache.delete(cache_key)


def create_user_mapper(user):
    try:
        mapper = UserMapper.objects.create(
            user=user,
            max_storage_limit='15 GB',     
            current_storage='0 GB'          
        )
        mapper.save()
        logger.info(f'new user mapper created for {user.email}')
    except Exception as e:
        logger.error(f'Exception while creating profile for {user.email} as error-message: {e}')


def update_user_storage(user, media_id, file_size, cache_key, operation_type):
    
    try:
        file_size_in_kb, _ = convert_file_size(file_size, "KB")  
        user_mapper = user.user_mapper.first()
        if user_mapper: 
            current_storage_occupied, _ = convert_file_size(user_mapper.current_storage, "KB")  
            

            if operation_type == 'addition':
                updated_size = current_storage_occupied + file_size_in_kb
            else:
                updated_size = max(0, current_storage_occupied - file_size_in_kb)  # prevent negative
                
            user_mapper.current_storage = f"{updated_size} KB"
            user_mapper.save()
            logger.info(f'User storage updated successfully for user: {user.email} option type: {operation_type} updated storage: {user_mapper.current_storage}' )
            
            if cache_key:
                cache.delete(cache_key)
                logger.info(f'User storage cached data cleared for user: {user.email}')
    except Exception as e:
        logger.error(f'Exception while updating user storage for user: {user.email} media-file id: {media_id} error-message: {e}')
        

def update_users_storage(operation_type=None, media_updation=None, media_file=None, capsoul=None):
    is_storage_updated = False
    try:
        if media_updation and media_file and operation_type: 
            file_size_in_kb, _ = convert_file_size(media_file.file_size, "KB")  
            user_mapper = media_file.user.user_mapper.first()
            if user_mapper: 
                current_storage_occupied, _ = convert_file_size(user_mapper.current_storage, "KB")  

                if media_updation == 'capsoul':
                    capsoul = media_file.time_capsoul
                else:
                    capsoul = media_file.memory_room
                capsoul_storge_in_kb, _ = convert_file_size(capsoul.occupied_storage, "KB")

                if operation_type == 'addition':
                    updated_size = current_storage_occupied + file_size_in_kb
                    updated_capsoul_size_in_kb = capsoul_storge_in_kb + file_size_in_kb

                else:
                    updated_size = max(0, current_storage_occupied - file_size_in_kb)  # prevent negative
                    updated_capsoul_size_in_kb = max(0, capsoul_storge_in_kb - file_size_in_kb)  # prevent negative

                user_mapper.current_storage = f"{updated_size} KB"
                user_mapper.save()
                capsoul.occupied_storage = f"{updated_capsoul_size_in_kb} KB"
                capsoul.save()
                is_storage_updated = True

        elif capsoul:
                capsoul_storge_in_kb, _ = convert_file_size(capsoul.occupied_storage, "KB")
                user_mapper = capsoul.user.user_mapper.first()
                if user_mapper: 
                    current_storage_occupied, _ = convert_file_size(user_mapper.current_storage, "KB")  
                    updated_storage_size_in_kb = max(0, current_storage_occupied - capsoul_storge_in_kb)  # prevent negative

                    capsoul.occupied_storage = f"{updated_storage_size_in_kb} KB"
                    capsoul.save()
                    is_storage_updated = True

    except Exception as e:
        logger.error(f'Exception while updating user storage for media-file id: {media_file.id if media_file else "N/A"} error-message: {e}')
    else:
        logger.info(f'User storage updated successfully for user: {media_file.user.email if media_file else "N/A"} option type: {operation_type} updated storage: {user_mapper.current_storage if user_mapper else "N/A"}' )
    finally:
        return is_storage_updated
