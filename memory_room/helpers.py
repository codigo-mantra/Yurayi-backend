import base64, os
import logging
import boto3
from botocore.config import Config
from django.conf import settings
import logging
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from memory_room.signals import update_user_storage, update_users_storage


import re
from django.core.cache import cache

from memory_room.models import TimeCapSoul, TimeCapSoulMediaFile,CustomTimeCapSoulTemplate, TimeCapSoulRecipient, MemoryRoom
from memory_room.tasks import update_time_capsoul_occupied_storage
from memory_room.crypto_utils import get_media_file_bytes_with_content_type,generate_capsoul_media_s3_key

logger = logging.getLogger(__name__)
from memory_room.s3_helpers import s3_helper

from memory_room.media_helper import decrypt_s3_file_chunked,decrypt_upload_and_extract_audio_thumbnail_chunked

AWS_KMS_REGION = 'ap-south-1'
AWS_KMS_KEY_ID = '843da3bb-9a57-4d9f-a8ab-879a6109f460'
MEDIA_FILES_BUCKET = 'yurayi-media'


s3 = boto3.client("s3", region_name=AWS_KMS_REGION,
    aws_access_key_id=settings.AWS_ACCESS_KEY_ID,
    aws_secret_access_key=settings.AWS_SECRET_ACCESS_KEY,
)

kms = boto3.client(
    "kms",
    region_name=AWS_KMS_REGION,
    aws_access_key_id=settings.AWS_ACCESS_KEY_ID,
    aws_secret_access_key=settings.AWS_SECRET_ACCESS_KEY,
)

def upload_file_to_s3_kms(key: str, plaintext_bytes: bytes,
                           content_type="application/octet-stream"):
    """
    Simple function to encrypt and upload file to S3 using KMS data key.

    Args:
        bucket (str): Target S3 bucket name.
        key (str): S3 key (path) where file should be uploaded.
        plaintext_bytes (bytes): Raw file bytes to encrypt.
        kms_key_id (str): AWS KMS key ID or ARN.
        content_type (str): MIME type of the original file.

    Returns:
        dict: S3 put_object response.
    """
    try:

        bucket = MEDIA_FILES_BUCKET
        # Generate data key from KMS
        resp = kms.generate_data_key(KeyId='843da3bb-9a57-4d9f-a8ab-879a6109f460', KeySpec="AES_256")
        data_key_plain = resp["Plaintext"]          # bytes 
        data_key_encrypted = resp["CiphertextBlob"] # bytes

        # Encrypt data with AES-GCM
        aesgcm = AESGCM(data_key_plain)
        nonce = os.urandom(12)
        ciphertext = aesgcm.encrypt(nonce, plaintext_bytes, associated_data=None)

        #  Upload encrypted blob (nonce + ciphertext)
        body = nonce + ciphertext
        response = s3.put_object(
            Bucket=bucket,
            Key=key,
            Body=body,
            ContentType="application/octet-stream",
            Metadata={
                "edk": base64.b64encode(data_key_encrypted).decode(),
                "nonce": base64.b64encode(nonce).decode(),
                "orig-content-type": content_type,
                # "file-category": file_category
            }
        )

        return response
    except Exception as e:
        pass
        # logging.error(f"Error uploading file to S3 with KMS: {e}")
        raise


from botocore.exceptions import ClientError

# def upload_file_to_s3_kms_chunked(
#     key: str,
#     plaintext_bytes: bytes,
#     content_type: str = "application/octet-stream",
#     progress_callback=None,
#     chunk_size: int = 10 * 1024 * 1024,  # 10 MB per chunk
# ):
#     """
#     Encrypts and uploads large files to S3 in chunks using AWS KMS and AES-GCM encryption.

#     Args:
#         key (str): S3 key (path).
#         plaintext_bytes (bytes): Raw file bytes to upload.
#         content_type (str): MIME type of file.
#         progress_callback (callable): Optional, progress callback(percent, message).
#         chunk_size (int): Chunk size in bytes (default 10 MB).

#     Returns:
#         dict: S3 complete_multipart_upload response.
#     """
#     total_size = len(plaintext_bytes)
#     bucket = MEDIA_FILES_BUCKET

#     # Local state tracking
#     parts = []
#     uploaded_bytes = 0

#     try:
#         # Step 1: Generate KMS data key
#         if progress_callback:
#             progress_callback(45, "Requesting KMS data key...")

#         resp = kms.generate_data_key(KeyId=AWS_KMS_KEY_ID, KeySpec="AES_256")
#         data_key_plain = resp["Plaintext"]
#         data_key_encrypted = resp["CiphertextBlob"]
#         aesgcm = AESGCM(data_key_plain)

#         # Step 2: Create multipart upload session
#         multipart_resp = s3.create_multipart_upload(
#             Bucket=bucket,
#             Key=key,
#             ContentType=content_type,
#             Metadata={
#                 "edk": base64.b64encode(data_key_encrypted).decode(),
#                 "orig-content-type": content_type,
#             },
#         )
#         upload_id = multipart_resp["UploadId"]

#         # Step 3: Encrypt and upload each chunk
#         for part_number, start in enumerate(range(0, total_size, chunk_size), start=1):
#             chunk = plaintext_bytes[start:start + chunk_size]
#             chunk_nonce = os.urandom(12)
#             ciphertext_chunk = aesgcm.encrypt(chunk_nonce, chunk, associated_data=None)

#             # Nonce prepended to ciphertext for later decryption
#             body = chunk_nonce + ciphertext_chunk

#             try:
#                 resp = s3.upload_part(
#                     Bucket=bucket,
#                     Key=key,
#                     PartNumber=part_number,
#                     UploadId=upload_id,
#                     Body=body,
#                 )
#                 parts.append({"ETag": resp["ETag"], "PartNumber": part_number})
#             except ClientError as e:
#                 s3.abort_multipart_upload(Bucket=bucket, Key=key, UploadId=upload_id)
#                 raise RuntimeError(f"Failed to upload part {part_number}: {e}")

#             uploaded_bytes += len(chunk)
#             # if progress_callback:
#             #     percent = int((uploaded_bytes / total_size) * 100)
#             #     progress_callback(percent, f"Uploaded chunk {part_number}")

#         # Step 4: Complete the multipart upload
#         result = s3.complete_multipart_upload(
#             Bucket=bucket,
#             Key=key,
#             UploadId=upload_id,
#             MultipartUpload={"Parts": parts},
#         )

#         if progress_callback:
#             progress_callback(80, "Upload completed successfully!")

#         return result

#     except ClientError as e:
#         # if progress_callback:
#         #     progress_callback(-1, f"S3 ClientError: {str(e)}")
#         pass
#         raise

#     except Exception as e:
#         if "upload_id" in locals():
#             # Cleanup if multipart initiated but failed
#             try:
#                 s3.abort_multipart_upload(Bucket=bucket, Key=key, UploadId=upload_id)
#             except Exception:
#                 pass
#         if progress_callback:
#             progress_callback(-1, f"Upload failed: {str(e)}")
#         raise RuntimeError(f"Upload failed: {e}")

#     finally:
#         # Wipe plaintext key from memory
#         try:
#             del data_key_plain
#         except Exception:
#             pass

def upload_file_to_s3_kms_chunked(
    key: str,
    plaintext_bytes: bytes,
    content_type: str = "application/octet-stream",
    progress_callback=None,
    chunk_size: int = 10 * 1024 * 1024,  # 10 MB per chunk
):
    """
    Encrypts and uploads large files to S3 in chunks using AWS KMS and AES-GCM encryption.

    Args:
        key (str): S3 key (path).
        plaintext_bytes (bytes): Raw file bytes to upload.
        content_type (str): MIME type of file.
        progress_callback (callable): Optional, progress callback(percent, message).
        chunk_size (int): Chunk size in bytes (default 10 MB).

    Returns:
        dict: S3 complete_multipart_upload response.
    """
    total_size = len(plaintext_bytes)
    bucket = MEDIA_FILES_BUCKET
    upload_id = None

    # Local state tracking
    parts = []
    uploaded_bytes = 0

    try:
        # Step 1: Generate KMS data key
        if progress_callback:
            progress_callback(5, "Requesting KMS data key...")

        resp = kms.generate_data_key(KeyId=AWS_KMS_KEY_ID, KeySpec="AES_256")
        data_key_plain = resp["Plaintext"]
        data_key_encrypted = resp["CiphertextBlob"]
        aesgcm = AESGCM(data_key_plain)

        # Step 2: Create multipart upload session
        # CRITICAL FIX: Store chunk-size in metadata for decryption
        multipart_resp = s3.create_multipart_upload(
            Bucket=bucket,
            Key=key,
            ContentType=content_type,
            Metadata={
                "edk": base64.b64encode(data_key_encrypted).decode(),
                "orig-content-type": content_type,
                "chunk-size": str(chunk_size),  # ADDED: Required for proper decryption
            },
        )
        upload_id = multipart_resp["UploadId"]

        if progress_callback:
            progress_callback(10, "Starting chunked encryption and upload...")

        # Step 3: Encrypt and upload each chunk
        part_number = 1
        for start in range(0, total_size, chunk_size):
            chunk = plaintext_bytes[start:start + chunk_size]
            
            # Generate unique nonce for each chunk
            chunk_nonce = os.urandom(12)
            
            # Encrypt with AES-GCM (None is clearer than associated_data=None)
            ciphertext_chunk = aesgcm.encrypt(chunk_nonce, chunk, None)

            # Format: [12-byte nonce][ciphertext + 16-byte auth tag]
            body = chunk_nonce + ciphertext_chunk

            try:
                resp = s3.upload_part(
                    Bucket=bucket,
                    Key=key,
                    PartNumber=part_number,
                    UploadId=upload_id,
                    Body=body,
                )
                parts.append({"ETag": resp["ETag"], "PartNumber": part_number})
                
            except ClientError as e:
                logger.error(f"Failed to upload part {part_number}: {e}")
                s3.abort_multipart_upload(Bucket=bucket, Key=key, UploadId=upload_id)
                raise RuntimeError(f"Failed to upload part {part_number}: {e}")

            uploaded_bytes += len(chunk)
            
            if progress_callback:
                # Progress from 10% to 80%
                percent = 10 + int((uploaded_bytes / total_size) * 70)
                total_chunks = (total_size + chunk_size - 1) // chunk_size
                progress_callback(percent, f"Uploaded chunk {part_number}/{total_chunks}")
            
            part_number += 1

        # Step 4: Complete the multipart upload
        # ADDED: Sort parts to ensure correct order
        parts.sort(key=lambda x: x["PartNumber"])
        
        result = s3.complete_multipart_upload(
            Bucket=bucket,
            Key=key,
            UploadId=upload_id,
            MultipartUpload={"Parts": parts},
        )

        if progress_callback:
            progress_callback(100, "Upload completed successfully!")

        return result

    except ClientError as e:
        logger.error(f"S3 ClientError during upload: {e}")
        raise

    except Exception as e:
        # FIXED: More robust cleanup check
        if upload_id is not None:
            try:
                s3.abort_multipart_upload(Bucket=bucket, Key=key, UploadId=upload_id)
                logger.info(f"Aborted multipart upload {upload_id}")
            except Exception as cleanup_error:
                logger.warning(f"Failed to abort multipart upload: {cleanup_error}")
        
        if progress_callback:
            progress_callback(0, f"Upload failed: {str(e)}")
        
        logger.error(f"Upload failed for key '{key}': {e}")
        raise RuntimeError(f"Upload failed: {e}")

    finally:
        # Wipe plaintext key from memory
        try:
            del data_key_plain
        except:
            pass

def audio_thumbnail_generator(file_name, decrypted_bytes):
    import os
    from timecapsoul.utils import MediaThumbnailExtractor
    try:
        ext = os.path.splitext(file_name)[1]
        extractor = MediaThumbnailExtractor(None, ext)
        thumbnail_data = extractor.extract_audio_thumbnail_from_bytes(
            decrypted_bytes=decrypted_bytes, extension=ext
        )
    except Exception as e:
        logger.exception('Exception while media thumbnail extraction')
    else:
        if thumbnail_data:
            from django.core.files.base import ContentFile
            from userauth.models import Assets

            image_file = ContentFile(thumbnail_data, name=f"thumbnail_{file_name}.jpg")
            asset = Assets.objects.create(image=image_file, asset_types='Thubmnail')
            return asset


def create_media(media:TimeCapSoulMediaFile, new_capsoul:TimeCapSoul, current_user,thumbnail):
    try:

        from django.utils import timezone
        created_at = timezone.localtime(timezone.now())
        new_media = TimeCapSoulMediaFile.objects.create(
            user = current_user,
            time_capsoul = new_capsoul,
            thumbnail = thumbnail,
            media_refrence_replica = None,
            media_duplicate = media,
            file = media.file,
            file_type = media.file_type,
            title = media.title,
            description = media.description,
            file_size = media.file_size,
            s3_url = media.s3_url,
            s3_key = media.s3_key,
            is_cover_image = media.is_cover_image,
            created_at = created_at
        )
        return new_media
    except Exception as e:
        logger.error(f'Exception while creating media file duplicate for media: {media.id} and capsoul: {new_capsoul.id} user: {new_capsoul.user.email}')
        return None


def create_duplicate_media_file(media:TimeCapSoulMediaFile, new_capsoul:TimeCapSoul, current_user):
    is_duplicated = False
    import re

    try:
        try:
            # here we upload file to s3 and update user storage and create new duplicate file
            file_bytes, content_type = get_media_file_bytes_with_content_type(media, current_user)
            if not file_bytes or not content_type:
                raise Exception('File decryption failed')
            
            else:
                file_name  = f'{media.title.split(".", 1)[0].replace(" ", "_")}.{media.s3_key.split(".")[-1]}' # get file name 
                file_name = re.sub(r'[^A-Za-z0-9_]', '', file_name) # remove special characters from file name

                s3_key = generate_capsoul_media_s3_key(filename=file_name, user_storage=current_user.s3_storage_id, time_capsoul_id=new_capsoul.id) # generate file s3-key
                
                upload_file_to_s3_kms(
                    key=s3_key,
                    plaintext_bytes=file_bytes,
                    content_type=content_type,
                )
                thumbnail = None 
                if media.file_type == 'audio': # generate thumbnail for audio file
                    thumbnail = audio_thumbnail_generator(file_name=file_name, decrypted_bytes=file_bytes)
                    
                new_media = create_media(media=media, new_capsoul=new_capsoul, current_user=current_user, thumbnail=thumbnail) # create media file in db
                if new_media:
                    # update_time_capsoul_occupied_storage.apply_async( # update capsoul storage
                    #     args=[new_media.id, 'addition'],
                    # )
                    # update_user_storage( # update user storage
                    #     user=current_user,
                    #     media_id=new_media.id,
                    #     file_size=new_media.file_size,
                    #     cache_key=f'user_storage_id_{current_user.id}',
                    #     operation_type='addition'
                    # )
                    update_users_storage(
                        operation_type='addition',
                        media_updation='capsoul',
                        media_file=new_media
                    )
                    is_duplicated = True
        except Exception as e:
            logger.error(f'Exception while uploading duplicate media file to s3 for media id: {media.id} user: {current_user.email} error-message: {e}')
            return None
    except Exception as e:
        logger.error(f'Exception while creating media file duplicate for media: {media.id} and capsoul: {new_capsoul.id} user: {new_capsoul.user.email}')
        return None
    finally:
        return is_duplicated


def create_duplicate_capsoul(time_capsoul:TimeCapSoul, capsoul_duplication_number:str, current_user:str):   
    try:
        # create duplicate room here
        from django.utils import timezone
        created_at = timezone.localtime(timezone.now())
        old_capsoul_template = time_capsoul.capsoul_template
        new_custom_template  =  CustomTimeCapSoulTemplate.objects.create(
            name= old_capsoul_template.name + capsoul_duplication_number,
            slug = old_capsoul_template,
            summary = old_capsoul_template.summary,
            cover_image = old_capsoul_template.cover_image,
            default_template = old_capsoul_template.default_template,
            created_at = created_at
        )
        
        new_capsoul = TimeCapSoul.objects.create(
            user = current_user,
            capsoul_template = new_custom_template,
            room_duplicate = time_capsoul,
            created_at = created_at
        )
        return new_capsoul
    except Exception as e:
        logger.error(f'Exception while create duplicate capsoul for {current_user.email} capsoul id: {time_capsoul.id}')
        return None


def create_duplicate_time_capsoul(time_capsoul:TimeCapSoul, current_user, creation_type='replica_creation'):
    new_capsoul = None
    logger.info(f'Timecapsoul duplication creation started for user: {time_capsoul.user.email} capsoul-id: {time_capsoul.id}')
    try:
        duplicate_capsoul = TimeCapSoul.objects.filter(room_duplicate = time_capsoul, is_deleted = False, user = current_user)
        capsoul_duplication_number = f' ({1 + duplicate_capsoul.count()})'
        new_capsoul = create_duplicate_capsoul(time_capsoul, capsoul_duplication_number, current_user)
    except Exception as e:
        logger.error(f'Exception while create duplicate capsoul for {current_user.email} capsoul id: {time_capsoul.id}')
    else:
            try:
                # now create duplicate media files here
                media_files = TimeCapSoulMediaFile.objects.filter(
                    time_capsoul=time_capsoul,
                    is_deleted=False,
                )
                old_media_count = media_files.count()   
                new_media_count = 0
                
                for media in media_files:
                    try:
                        new_media = create_duplicate_media_file(media, new_capsoul, current_user)
                    except Exception as e:
                        logger.error(f'Exception while creating media file duplicate for media: {media.id} and capsoul: {time_capsoul.id} user: {time_capsoul.user.email}')
                    else:
                        new_media_count += 1 
                        pass
            except Exception as e:
                logger.error(f'Exception while creating room media duplica for {time_capsoul.id}')
            finally:
                print(f'\n old media count: {old_media_count} new media count: {new_media_count}')
                logger.info(f'Timecapsoul duplication completed for user: {time_capsoul.user.email} capsoul-id: {time_capsoul.id} duplicate-capsoul-id: {new_capsoul.id} old-media-count: {old_media_count} new-media-count: {new_media_count}')
            
            return new_capsoul
    


def create_parent_media_files_replica_upload_to_s3_bucket(old_capsoul, new_capsoul, current_user):
    try:
        # now create media files here
        if current_user != old_capsoul.user: # if current user is not owner of tha capsoul 
            media_files = TimeCapSoulMediaFile.objects.filter(
                time_capsoul=old_capsoul,
                media_duplicate__isnull=True
            )
        else:
            media_files = TimeCapSoulMediaFile.objects.filter(
                time_capsoul=old_capsoul,
                is_deleted = False,
                media_duplicate__isnull=True
            )
            
        new_media_count = 0
        old_media_count = media_files.count()   
        
        for media in media_files:
            try:
                new_media = create_duplicate_media_file(media, new_capsoul, current_user)
            except Exception as e:
                logger.error(f'Exception while creating media file duplicate for media: {media.id} and capsoul: {old_capsoul.id} user: {new_capsoul.user.email}')
            else:
                new_media_count += 1 
                pass
    except Exception as e:
        logger.error(f'Exception while creating room media duplica for {old_capsoul.id}')
    finally:
        print(f'\n old media count: {old_media_count} new media count: {new_media_count}')
        logger.info(f'Timecapsoul duplication completed for user: {old_capsoul.user.email} capsoul-id: {new_capsoul.id} duplicate-capsoul-id: {new_capsoul.id} old-media-count: {old_media_count} new-media-count: {new_media_count}')
            

def user_capsoul_name_list(user):
    
    existing_capsouls = TimeCapSoul.objects.filter(
        user=user,
        is_deleted=False,
    ).values_list("capsoul_template__name", flat=True)
    
    recipient_capsouls = TimeCapSoulRecipient.objects.filter(
        email=user.email,
        is_capsoul_deleted=False,
    ).values_list("time_capsoul__capsoul_template__name", flat=True)
    existing_names = set(name.lower() for name in list(existing_capsouls) + list(recipient_capsouls))
    
    return existing_names


def generate_unique_capsoul_name(user, base_name):
    """
    Generate a unique capsoul name for a given user.
    Uses Django cache to avoid repeated DB queries.
    """
    base_name = str(base_name).lower()
   
    existing_capsouls = TimeCapSoul.objects.filter(
        user=user,
        is_deleted=False,
        # capsoul_template__name__iexact=base_name,
    ).values_list("capsoul_template__name", flat=True)
    
    recipient_capsouls = TimeCapSoulRecipient.objects.filter(
        email=user.email,
        is_capsoul_deleted=False,
        # time_capsoul__is_deleted=False,
        # time_capsoul__capsoul_template__name__iexact=base_name,
    ).values_list("time_capsoul__capsoul_template__name", flat=True)
    # existing_names = set(name.lower() for name in list(existing_capsouls) + list(recipient_capsouls))
    existing_names = set(
        (name.lower() for name in list(existing_capsouls) + list(recipient_capsouls) if name)
    )


    # If base_name not used, return directly
    if base_name not in existing_names:
        # existing_names.append(base_name)
        return base_name

    # Extract numeric suffixes like base_name_1, base_name_2
    pattern = re.compile(rf"^{re.escape(base_name)} \((\d+)\)$", re.IGNORECASE)
    counters = [
        int(match.group(1))
        for name in existing_names
        if (match := pattern.match(name))
    ]
    next_counter = (max(counters) + 1) if counters else 1
    unique_name = f"{base_name} ({next_counter})"
    return unique_name


def generate_unique_memory_room_name(user, base_name):
    """
    Generate a unique memoy room name for a given user.
    Uses Django cache to avoid repeated DB queries.
    """
    base_name = str(base_name).lower()
   
    existing_capsouls = MemoryRoom.objects.filter(
        user=user,
        is_deleted=False,
    ).values_list("room_template__name", flat=True)
    
    
    # existing_names = set(name.lower() for name in list(existing_capsouls))
    existing_names = set(
        name.lower() for name in list(existing_capsouls) if name
    )



    # If base_name not used, return directly
    if base_name not in existing_names:
        # existing_names.append(base_name)
        return base_name

    # Extract numeric suffixes like base_name_1, base_name_2
    pattern = re.compile(rf"^{re.escape(base_name)} \((\d+)\)$", re.IGNORECASE)
    counters = [
        int(match.group(1))
        for name in existing_names
        if (match := pattern.match(name))
    ]
    next_counter = (max(counters) + 1) if counters else 1
    unique_name = f"{base_name} ({next_counter})"
    return unique_name

def generate_unique_file_name(existing_file_name, base_name, memory_room=False):
    try:
        existing_names = set(name.lower() for name in list(existing_file_name))


        # If base_name not used, return directly
        if memory_room == True:
            if base_name.lower() not in existing_names:
            # existing_names.append(base_name)
                return base_name.lower()
        else:
            if base_name.lower().replace('.', '') not in existing_names:
                # existing_names.append(base_name)
                return base_name.lower()
            

        # Extract numeric suffixes like base_name_1, base_name_2
        pattern = re.compile(rf"^{re.escape(base_name)} \((\d+)\)$", re.IGNORECASE)
        counters = [
            int(match.group(1))
            for name in existing_names
            if (match := pattern.match(name))
        ]
        next_counter = (max(counters) + 1) if counters else 1
        # unique_name = f"{base_name} ({next_counter})"
        full_name = base_name.split('.') 
        unique_name =f' {full_name[0]}{next_counter}.{full_name[-1]}'
        return unique_name
    except Exception as e:
        return None
   

def create_time_capsoul(old_time_capsoul:TimeCapSoul, current_user:str, option_type='replica_creation', capsoul_name=None, capsoul_summary=None, cover_image=None):  

    try:
        capsoul_name = capsoul_name if capsoul_name else old_time_capsoul.capsoul_template.name
        capsoul_summary = capsoul_summary if capsoul_summary else old_time_capsoul.capsoul_template.summary
        cover_image = cover_image if cover_image else old_time_capsoul.capsoul_template.cover_image
        
        new_capsoul_name = capsoul_name
        unique_capsoul_name = generate_unique_capsoul_name(current_user, new_capsoul_name)

        if option_type == 'replica_creation':
            capsoul_replica = old_time_capsoul
            duplicate_capsoul = None
        else:
            capsoul_replica = None
            duplicate_capsoul = old_time_capsoul

        # create new time-capsoul here
        from django.utils import timezone
        created_at = timezone.localtime(timezone.now())
        
        old_capsoul_template = old_time_capsoul.capsoul_template
        new_custom_template  =  CustomTimeCapSoulTemplate.objects.create(
            name= unique_capsoul_name,
            slug = old_capsoul_template.slug,
            summary = capsoul_summary,
            cover_image = cover_image,
            default_template = old_capsoul_template.default_template,
            created_at = created_at
        )
        new_custom_template.save()
        new_capsoul = TimeCapSoul.objects.create(
            user = current_user,
            capsoul_template = new_custom_template,
            capsoul_replica_refrence = capsoul_replica,
            room_duplicate = duplicate_capsoul,
            created_at = created_at
        )
        return new_capsoul
    except Exception as e:
        logger.error(f'Exception while creating {option_type}  for time-capsoul for  user {current_user.email} capsoul id: {old_capsoul_template.id}')
        return None


def create_time_capsoul_media_file(old_media:TimeCapSoulMediaFile, new_capsoul:TimeCapSoul, current_user, option_type='replica_creation',updated_media_title=None, updated_media_description=None, set_as_cover=False):
    is_created = False

    try:
        if option_type == 'replica_creation':
            media_replica = old_media
            media_duplicate = None
        else:
            media_replica = None
            media_duplicate = old_media

        media_title = updated_media_title if updated_media_title else old_media.title
        media_description = updated_media_description if updated_media_description else old_media.description
        set_as_cover_image = set_as_cover if set_as_cover else old_media.is_cover_image
        
        
        # file_bytes, content_type = get_media_file_bytes_with_content_type(old_media, current_user)
        # file_bytes, content_type = decrypt_s3_file_chunked(old_media.s3_key)
        
        # if not file_bytes or not content_type:
            # raise Exception('File decryption failed')
        # else:
        # file_name  = f'{old_media.title.split(".", 1)[0].replace(" ", "_")}.{old_media.s3_key.split(".")[-1]}' # get file name 
        file_name  = old_media.s3_key.split('/')[-1]
        
        # file_name = re.sub(r'[^A-Za-z0-9_]', '', file_name) # remove special characters from file name
        s3_key = generate_capsoul_media_s3_key(filename=file_name, user_storage=current_user.s3_storage_id, time_capsoul_id=new_capsoul.id) # generate file s3-key
        
        res = s3_helper.copy_s3_object_preserve_meta_kms(
            source_key=old_media.s3_key,
            destination_key=s3_key
        )
        
        thumbnail = old_media.thumbnail 
        # if old_media.file_type == 'audio': # generate thumbnail for audio file
        #     thumbnail = audio_thumbnail_generator(file_name=file_name, decrypted_bytes=file_bytes)
        
        from django.utils import timezone
        created_at = timezone.localtime(timezone.now())
        new_media = TimeCapSoulMediaFile.objects.create(
            user = current_user,
            time_capsoul = new_capsoul,
            thumbnail = thumbnail,
            media_refrence_replica = media_replica,
            media_duplicate = media_duplicate,
            # file = media.file,
            file_type = old_media.file_type,
            title = media_title,
            description = media_description,
            file_size = old_media.file_size,
            s3_url = None,
            s3_key = s3_key,
            is_cover_image = set_as_cover_image,
            created_at = created_at
        )
            
        # new_media = create_media(media=old_media, new_capsoul=new_capsoul, current_user=current_user, thumbnail=thumbnail) # create media file in db
        if new_media:
            is_updated = update_users_storage(
                operation_type='addition',
                media_updation='capsoul', # update user storage
                media_file=new_media
            )
            is_created = True
    except Exception as e:
            logger.error(f'Exception while create media fiele {option_type} for media id: {old_media.id} user: {current_user.email} error-message: {e}')
            return None
    finally:
        return is_created
    


def get_recipient_capsoul_ids(capsoul_recipients):
    capsoul_ids = []
    try:
        existing_media_ids =  eval(capsoul_recipients.parent_media_refrences)
        if existing_media_ids and  type(existing_media_ids) is list:
            return existing_media_ids
    except Exception as e:
        logger.error(f'Exception while getting recipient capsoul ids for recipient id: {capsoul_recipients.id}')
    return capsoul_ids
