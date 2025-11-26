

import datetime
from celery import shared_task
from userauth.models import User
from django.utils import timezone
from datetime import timedelta
from dateutil.relativedelta import relativedelta
import logging
logger = logging.getLogger(__name__)
from memory_room.utils import convert_file_size
from django.core.cache import cache
from django.db import close_old_connections
from botocore.exceptions import ClientError
from botocore.config import Config
import math
import time
import mimetypes
from memory_room.models import Notification
from django.conf import settings
from memory_room.notification_message import NOTIFICATIONS


from memory_room.models import MemoryRoom, MemoryRoomMediaFile, TimeCapSoulMediaFile

from memory_room.models import TimeCapSoulDetail, TimeCapSoulRecipient, TimeCapSoul
from memory_room.notification_service import NotificationService
from memory_room.crypto_utils import generate_room_media_s3_key,generate_capsoul_media_s3_key



from celery import Task


class LoggedTask(Task):
    """Automatically stores args, kwargs, results, and errors."""

    # prevents Celery from overwriting your custom metadata
    throws = ()  

    def on_success(self, retval, task_id, args, kwargs):
        self.update_state(
            state="SUCCESS",
            meta={
                "args": args,
                "kwargs": kwargs,
                "result": retval,
                "error": None,
            }
        )
        return retval  # IMPORTANT
        

    def on_failure(self, exc, task_id, args, kwargs, einfo):
        self.update_state(
            state="FAILURE",
            meta={
                "args": args,
                "kwargs": kwargs,
                "result": None,
                "error": str(exc),
                "traceback": einfo.traceback,
            }
        )
        return str(exc)  # IMPORTANT


AWS_KMS_REGION = 'ap-south-1'
AWS_KMS_KEY_ID = '843da3bb-9a57-4d9f-a8ab-879a6109f460'
MEDIA_FILES_BUCKET = 'yurayi-media'
AWS_ACCESS_ID = settings.AWS_ACCESS_KEY_ID
AWS_SECRET_KEY = settings.AWS_SECRET_ACCESS_KEY

s3_config = Config(
        connect_timeout=60*10,      # 5 minutes connection timeout
        read_timeout=60*10,         # 5 minutes read timeout
        retries={
            'max_attempts': 10,   # Retry failed requests
            'mode': 'adaptive'    # Adaptive retry mode
        }
)
    
    # Create a new S3 client with custom config
import boto3
s3_client_with_timeout = boto3.client(
    's3',
    region_name=AWS_KMS_REGION,
    aws_access_key_id=AWS_ACCESS_ID,
    aws_secret_access_key=AWS_SECRET_KEY,
    config=s3_config
)

@shared_task
def send_report():
    print("Report sent at:", datetime.datetime.now())
    return "Done"


def recipients_nofitication_creator(recipients:TimeCapSoulRecipient, notification_key:str, is_opened=None):
    logger.info("recipients_nofitication_creator called")
    
    for recipient in recipients:
        
        if recipient.is_opened == False:
            person_email = recipient.email
            time_capsoul = recipient.time_capsoul
            
            # create notification at invited for tagged user if exists
            try:
                user = User.objects.get(email = person_email)
            except User.DoesNotExist as e:
                # skip if user not exists
                pass
            else:
                notif = NotificationService.create_notification_with_key(
                    notification_key=notification_key,
                    user=user,
                    time_capsoul=time_capsoul
                )
        

@shared_task
def capsoul_almost_unlock(capsoul_id):
    logger.info("capsoul_almost_unlock task called")
    is_created = False
    try:
        time_capsoul = TimeCapSoul.objects.get(id=capsoul_id)
    except Exception as e:
        pass
    else:
        recipients  = TimeCapSoulRecipient.objects.filter(time_capsoul = time_capsoul, is_deleted = False)
        # create notification for  all tagged recipients 
        recipients_nofitication_creator(recipients=recipients, notification_key='capsoul_almost_unlock')
        is_created = True
    finally:
        return is_created
        

@shared_task
def capsoul_unlocked(capsoul_id):
    logger.info("capsoul_unlocked task called")
    is_created = False
    
    try:
        time_capsoul = TimeCapSoul.objects.get(id=capsoul_id)
        media_ids = ','.join(str(m.id) for m in time_capsoul.timecapsoul_media_files.filter(is_deleted=False))
        recipients = TimeCapSoulRecipient.objects.filter(time_capsoul = time_capsoul, is_deleted = False)
        recipients.update(parent_media_refrences = media_ids)
        # Notify owner 
        notif = NotificationService.create_notification_with_key(
            notification_key='capsoul_unlocked',
            user=time_capsoul.user,
            time_capsoul=time_capsoul
        )
        is_created = True
    except Exception as e:
        print(f'Exception in capsoul_unlocked  for capsoul id {capsoul_id} as: {e}')
        
    finally:
        return is_created
        

def capsoul_notification_generator(recipient, notification_key, message=None):
    """Notification generator  """
    try:
        is_created = False
        if recipient.is_opened == False: 
            person_email = recipient.email
            time_capsoul = recipient.time_capsoul
            try:
                user = User.objects.get(email = person_email)
                notification_data = NOTIFICATIONS[f'{notification_key}']
                category = notification_data['category']
                category_type = notification_data['type']
                title = notification_data['title']
                if not  message:
                    message = notification_data['message']
                
                capsoul_notification =  user.notifications.filter(time_capsoul = time_capsoul, category=category, category_type = category_type).first()
                
                if not capsoul_notification:
                    notification = Notification.objects.create(
                    user=user,
                    category=category,
                    category_type=category_type,
                    title=title,
                    message=message,
                    time_capsoul=time_capsoul,
                )
                is_created = True
                return is_created
                
            except User.DoesNotExist as e:
                # skip if user not exists
                return is_created
                
          
    except Exception as e:
        logger.error(f'Exception while creating notification as : {e}')


@shared_task
def capsoul_waiting(capsoul_id):
    """create notification for 24 hour reminder"""
    logger.info("capsoul_waiting task called")
    time_capsoul = TimeCapSoul.objects.get(id=capsoul_id)
    # Notify tagged person after 24 hours if shared capsoul they havent open'd it
    recipients  = TimeCapSoulRecipient.objects.filter(time_capsoul = time_capsoul, is_deleted = False)
    recipients_nofitication_creator(recipients=recipients, notification_key='capsoul_waiting',is_opened=True)


@shared_task
def capsoul_reminder_7_days(capsoul_id):
    """create notification for 7 days reminder"""
    logger.info("capsoul_reminder_7_days task called")
    
    time_capsoul = TimeCapSoul.objects.get(id=capsoul_id)
    # Notify tagged person after 24 hours if shared capsoul they havent open'd it
    recipients  = TimeCapSoulRecipient.objects.filter(time_capsoul = time_capsoul, is_deleted = False)
    recipients_nofitication_creator(recipients=recipients, notification_key='capsoul_waiting',is_opened=True)


@shared_task
def capsoul_memory_one_year_ago(capsoul_id):
    """create notification for 1 years reminder"""
    logger.info("capsoul_memory_one_year_ago task called")
    
    time_capsoul = TimeCapSoul.objects.get(id=capsoul_id)
    # Notify only owner
    notif = NotificationService.create_notification_with_key(
        notification_key='memory_one_year_ago',
        user=time_capsoul.user,
        time_capsoul=time_capsoul
    )

@shared_task(bind=True, track_started=True, name="Notification_for_24_reminder", base=LoggedTask)
def create_24_hour_reminder_notification(self):
    recipeints =  TimeCapSoulRecipient.objects.filter(time_capsoul__status = 'unlocked', is_opened = False,is_capsoul_deleted = False)
    notification_key = 'capsoul_waiting'
    
    for recipient in recipeints:
        try:
            is_created = capsoul_notification_generator(
                recipient=recipient,
                notification_key = notification_key,
            )
        except Exception as e:
            pass
        # print(f'\n Is Notification created: {is_created}')

@shared_task(bind=True, track_started=True, name="Notification_for_7_reminder", base=LoggedTask)
def create_7_days_reminder_notification(self):
    recipeints =  TimeCapSoulRecipient.objects.filter(time_capsoul__status = 'unlocked', is_opened = False,is_capsoul_deleted = False)
    notification_key = 'capsoul_reminder_7_days'
    
    for recipient in recipeints:
        try:
            is_created = capsoul_notification_generator(
                recipient=recipient,
                notification_key = notification_key,
            )
        except Exception as e:
            pass
        # print(f'\n Is Notification created: {is_created}')

          

@shared_task
def capsoul_notification_handler():
    logger.info("capsoul_notification_handler task called")
    from datetime import timedelta
    from django.utils import timezone

    now = timezone.now()
    one_hour_ago = now - timedelta(hours=1)

    # Sealed capsouls scheduled for today
    sealed_capsouls = TimeCapSoul.objects.filter(
        unlock_date__date=now.date(),
        status='sealed',
        is_deleted = False,
    )
    
    # #  Already unlocked capsouls
    unlocked_capsouls = TimeCapSoul.objects.filter(
        status='unlocked',
        is_deleted = False,
        
    )
    create_24_hour_reminder_notification.apply_async() # 24 hour notification generator
    create_7_days_reminder_notification.apply_async()  # 7 days reminder notification generator
    
    for capsoul in sealed_capsouls:
        unlock_date = capsoul.unlock_date

        # If unlock_time lies within the last 1 hour window → trigger unlock
        if one_hour_ago < unlock_date <= now:
            print('--- almost unlock called ---')
            capsoul_almost_unlock.apply_async((capsoul.id,), eta=unlock_date)
            capsoul_unlocked.apply_async((capsoul.id,), eta=unlock_date)

    for capsoul in unlocked_capsouls:
        unlock_date = capsoul.unlock_date

        # # 24 hours after unlock → Waiting
        # if one_hour_ago < unlock_date + timedelta(hours=24) <= now:
        #     print('--- capsoul_waiting called ---')
        #     capsoul_waiting.apply_async((capsoul.id,), eta=unlock_date)

        # # 7 days after unlock → Reminder
        # if one_hour_ago < unlock_date + timedelta(days=7) <= now:
        #     print('--- capsoul_reminder_7_days called ---')
        #     capsoul_reminder_7_days.apply_async((capsoul.id,), eta=unlock_date)

        # 1 year after unlock → Memory One Year Ago
        if one_hour_ago < unlock_date + timedelta(days=365) <= now:
            print('--- capsoul_memory_one_year_ago called ---')
            capsoul_memory_one_year_ago.apply_async((capsoul.id,), eta=unlock_date)

@shared_task
def update_memory_room_occupied_storage(media_file_id, option_type):
    is_updated = False
    
    try:
        media_file = MemoryRoomMediaFile.objects.get(id = media_file_id)
    except MemoryRoomMediaFile.DoesNotExist:
        logger.error(f'Exception while updating memory room storage for media file id: {media_file_id}')
    else:
        room = media_file.memory_room
        file_size_in_kb = convert_file_size(media_file.file_size, 'KB')[0]
        current_occupied_storage_in_kb = convert_file_size(room.occupied_storage, 'KB')[0]
        
        
        if option_type == 'addition':
            updated_storage = current_occupied_storage_in_kb + file_size_in_kb
        else:
            updated_storage = max(0, current_occupied_storage_in_kb - file_size_in_kb)
        room.occupied_storage = f'{updated_storage} KB'
        room.save()
        is_updated = True
    finally:
        close_old_connections()
        return is_updated
        
        
@shared_task
def update_time_capsoul_occupied_storage(media_file_id, option_type):
    is_updated = False
    
    try:
        media_file = TimeCapSoulMediaFile.objects.get(id = media_file_id)
    except TimeCapSoulMediaFile.DoesNotExist:
        logger.error(f'Exception while updating time-capsoul room storage for media file id: {media_file_id}')
    else:
        capsoul = media_file.time_capsoul
        file_size_in_kb = convert_file_size(media_file.file_size, 'KB')[0]
        current_occupied_storage_in_kb = convert_file_size(capsoul.occupied_storage, 'KB')[0]
        if option_type == 'addition':
            updated_storage = current_occupied_storage_in_kb + file_size_in_kb
        else:
            updated_storage = max(0, current_occupied_storage_in_kb - file_size_in_kb)
        capsoul.occupied_storage = f'{updated_storage} KB'
        capsoul.save()
        is_updated = True
    finally:
        # close_old_connections()
        return is_updated
    
    

@shared_task
def clear_all_cache():
    """
    Clear all cache in the system.
    """
    cache.clear()
    return "Cache cleared successfully."

@shared_task
def update_parent_media_refrences_task(media_id):
    try:
        media_file = TimeCapSoulMediaFile.objects.get(id=media_id)
    except TimeCapSoulMediaFile.DoesNotExist:
        logger.error(f"Media file with id {media_id} does not exist.")
        close_old_connections()

        return False
    else:
        time_capsoul = media_file.time_capsoul
        recipients = TimeCapSoulRecipient.objects.filter(time_capsoul=time_capsoul, is_deleted=False)
        media_ids = ','.join(str(m.id) for m in time_capsoul.timecapsoul_media_files.filter(is_deleted=False))
        recipients.update(parent_media_refrences=media_ids)
        close_old_connections()
        return True
    

def calculate_part_size(file_size):
        """
        Dynamically choose S3 multipart copy/upload part size.
        Keeps parts between 5MB and 5GB, under 10,000 parts.
        """
        MIN_PART_SIZE = 5 * 1024 * 1024       # 5 MB
        MAX_PART_SIZE = 5 * 1024 * 1024 * 1024  # 5 GB
        MAX_PARTS = 10000

        # Start small (100 MB), increase if file is huge
        part_size = max(MIN_PART_SIZE, file_size // MAX_PARTS)
        part_size = min(max(part_size, 100 * 1024 * 1024), MAX_PART_SIZE)

        return part_size


# for testing one
@shared_task(bind=True, track_started=True, name="Copy_S3_Object_Preserve_Meta_Kms", base=LoggedTask)
def copy_s3_object_preserve_meta_kms(self, media_file_id, max_retries=5, retry_delay=2, media_type = 'time_capsoul'):
    """
    Copy an S3 object to a new key or bucket, preserving:
    - Metadata, headers, and KMS encryption
    - Automatically uses multipart copy for files >= 100 MB
    - Handles timeouts and connection errors with retry logic
    
    Args:
        max_retries: Maximum retries per part (default: 5)
        retry_delay: Initial delay between retries in seconds (default: 2)
    """
    upload_id = None
    is_copied = False
    source_bucket =  'yurayi-media'
    region = AWS_KMS_REGION
    destination_bucket =  source_bucket
    
    if media_type == 'time_capsoul':
        media = TimeCapSoulMediaFile.objects.get(id = media_file_id)
        new_capsoul = media.time_capsoul
        current_user = media.user
        user_email  = current_user.email
        source_key = media.s3_key
        file_name  = source_key.split('/')[-1]
        destination_key = generate_capsoul_media_s3_key(filename=file_name, user_storage=current_user.s3_storage_id, time_capsoul_id=new_capsoul.id, old_name = file_name) # generate file s3-key
    
    else:
        media = MemoryRoomMediaFile.objects.get(id = media_file_id)
        memory_room = media.memory_room
        current_user = media.user
        user_email  = current_user.email
        source_key = media.s3_key
        file_name  = source_key.split('/')[-1]
        destination_key = generate_room_media_s3_key(filename=file_name, user_storage=current_user.s3_storage_id, room_id=memory_room.id, old_name = file_name) # generate file s3-key
    
    
    if source_key ==  destination_key:
        logger.error(f'Media file s3 obj failed due to source and destination both are same for media-id: {media_file_id}')
        return is_copied
        
    # Configure S3 client with increased timeouts for large files
    # This is critical for files over 1GB
    
    
    try:
        # Get the source object's metadata
        head = s3_client_with_timeout.head_object(Bucket=source_bucket, Key=source_key)
        copy_source = {"Bucket": source_bucket, "Key": source_key}
        size = head["ContentLength"]
        part_size = calculate_part_size(size)
        
        logger.info(
            f'S3 object copying started for user {user_email} - '
            f'Source: {source_key}, Size: {size} bytes ({size/1024/1024:.2f} MB), '
            f'Part size: {part_size/1024/1024:.2f} MB'
        )
        
        # Preserve metadata and headers
        metadata = head.get("Metadata", {})
        content_type = (
            head.get("ContentType") or 
            mimetypes.guess_type(source_key)[0] or 
            "application/octet-stream"
        )
        content_disposition = head.get("ContentDisposition")
        cache_control = head.get("CacheControl")
        content_encoding = head.get("ContentEncoding")

        # Common arguments for both copy methods
        common_args = {
            "Bucket": destination_bucket,
            "Key": destination_key,
            "Metadata": metadata,
            "ContentType": content_type,
        }
        
        if content_disposition:
            common_args["ContentDisposition"] = content_disposition
        if cache_control:
            common_args["CacheControl"] = cache_control
        if content_encoding:
            common_args["ContentEncoding"] = content_encoding

        # Preserve KMS encryption if present
        if head.get("ServerSideEncryption") == "aws:kms":
            common_args["ServerSideEncryption"] = "aws:kms"
            if head.get("SSEKMSKeyId"):
                common_args["SSEKMSKeyId"] = head["SSEKMSKeyId"]

        # For small files (<100 MB) - use simple copy
        if size < 100 * 1024 * 1024:
            copy_args = {**common_args, "MetadataDirective": "REPLACE"}
            response = s3_client_with_timeout.copy_object(
                CopySource=copy_source, 
                **copy_args
            )
            logger.info(
                f"Simple copy completed for user {user_email}: "
                f"{source_key} → {destination_key}"
            )
            media.s3_key = destination_key
            media.save()
            print(f'Media file s3-key updated {source_key} updated key: {destination_key} media-id: {media.id}')
            logger.info(f'media file s3-key refrence updated {source_key} updated key: {destination_key} media-id: {media.id}')
            return True
        

        # For large files (>=100 MB) — use multipart copy with retry
        logger.info(
            f" Large file detected ({size / 1024 / 1024:.2f} MB). "
            f"Using multipart copy..."
        )

        # Create multipart upload
        mpu = s3_client_with_timeout.create_multipart_upload(**common_args)
        upload_id = mpu["UploadId"]
        
        logger.info(f" Multipart upload initiated. Upload ID: {upload_id}")

        num_parts = math.ceil(size / part_size)
        parts = []
        failed_parts = []

        # Copy each part with retry logic
        for i in range(num_parts):
            start = i * part_size
            end = min(start + part_size - 1, size - 1)
            part_num = i + 1
            part_size_mb = (end - start + 1) / 1024 / 1024

            logger.info(
                f"Copying part {part_num}/{num_parts} "
                f"(bytes {start:,}-{end:,}, {part_size_mb:.2f} MB)"
            )

            # Retry logic for each part
            part_uploaded = False
            for attempt in range(max_retries):
                try:
                    part = s3_client_with_timeout.upload_part_copy(
                        Bucket=destination_bucket,
                        Key=destination_key,
                        CopySource=copy_source,
                        CopySourceRange=f"bytes={start}-{end}",
                        PartNumber=part_num,
                        UploadId=upload_id,
                    )

                    parts.append({
                        "PartNumber": part_num, 
                        "ETag": part["CopyPartResult"]["ETag"]
                    })
                    
                    logger.info(f"✓ Part {part_num}/{num_parts} copied successfully")
                    part_uploaded = True
                    break
                    
                except (ClientError, Exception) as part_error:
                    error_msg = str(part_error)
                    
                    # Check if it's a retryable error
                    retryable_errors = [
                        'RequestTimeout', 'ConnectionError', 'ReadTimeout',
                        'ConnectTimeout', 'Connection was closed', 
                        'socket connection', 'timed out', 'Broken pipe'
                    ]
                    
                    is_retryable = any(err in error_msg for err in retryable_errors)
                    
                    if attempt < max_retries - 1 and is_retryable:
                        wait_time = retry_delay * (2 ** attempt)  # Exponential backoff
                        logger.warning(
                            f"⚠️ Part {part_num} failed (attempt {attempt + 1}/{max_retries}): "
                            f"{error_msg}. Retrying in {wait_time}s..."
                        )
                        time.sleep(wait_time)
                    else:
                        logger.error(
                            f"✗ Part {part_num} failed after {attempt + 1} attempts: {error_msg}"
                        )
                        failed_parts.append(part_num)
                        raise

        # Check if all parts were uploaded
        if failed_parts:
            raise Exception(
                f"Failed to upload parts: {failed_parts}. "
                f"Successfully uploaded {len(parts)}/{num_parts} parts."
            )

        # Complete the multipart upload
        logger.info(f" Completing multipart upload with {len(parts)} parts...")
        
        # Sort parts by PartNumber (critical!)
        parts.sort(key=lambda x: x["PartNumber"])
        
        s3_client_with_timeout.complete_multipart_upload(
            Bucket=destination_bucket,
            Key=destination_key,
            UploadId=upload_id,
            MultipartUpload={"Parts": parts},
        )

        logger.info(
            f'S3 object copying completed successfully for user {user_email} - '
            f'Source: {source_key} → Dest: {destination_key}, '
            f'Size: {size} bytes ({size/1024/1024:.2f} MB), '
            f'Parts: {len(parts)}'
        )
        media.s3_key = destination_key
        media.save()
        print(f'Media file s3-key updated {source_key} updated key: {destination_key} media-id: {media.id}')
        logger.info(f'\n Media-file s3-key refrence updated {source_key} updated key: {destination_key} media-id: {media.id}')

        return True

    except ClientError as e:
        error_code = e.response.get('Error', {}).get('Code', 'Unknown')
        error_msg = e.response.get('Error', {}).get('Message', str(e))
        
        logger.error(
            f'❌ S3 copy failed (ClientError) for user {user_email} - '
            f'Source: {source_key}, Size: {size if "size" in locals() else "unknown"} - '
            f'Error Code: {error_code}, Message: {error_msg}'
        )
        
        # Abort multipart upload
        if upload_id:
            try:
                logger.info(f" Aborting incomplete multipart upload: {upload_id}")
                s3_client_with_timeout.abort_multipart_upload(
                    Bucket=destination_bucket,
                    Key=destination_key,
                    UploadId=upload_id,
                )
                logger.info(f"✓ Successfully aborted upload: {upload_id}")
            except Exception as abort_error:
                logger.error(f"Failed to abort upload {upload_id}: {abort_error}")
        
        raise
    
    except Exception as e:
        logger.error(
            f'❌ Unexpected error during S3 copy for user {user_email} - '
            f'Source: {source_key}, Error: {str(e)}',
            exc_info=True
        )
        # Abort multipart upload
        if upload_id:
            try:
                s3_client_with_timeout.abort_multipart_upload(
                    Bucket=destination_bucket,
                    Key=destination_key,
                    UploadId=upload_id,
                )
            except Exception:
                pass
        
        raise
