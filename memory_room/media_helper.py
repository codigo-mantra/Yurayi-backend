from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import base64
from django.conf import settings

import threading
import tempfile
from queue import Queue, Empty


from io import BytesIO
import base64, os, re 
import logging
import boto3
from timecapsoul.utils import MediaThumbnailExtractor
from rest_framework import status

from botocore.config import Config
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from botocore.exceptions import NoCredentialsError, ClientError
from cryptography.exceptions import InvalidTag
from memory_room.crypto_utils import get_file_bytes


logger = logging.getLogger(__name__)

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

# def decrypt_upload_and_extract_audio_thumbnail_chunked(
#     key: str,
#     encrypted_file,
#     iv_str: str,
#     content_type: str = "application/octet-stream",
#     file_ext: str = "",
#     progress_callback=None,
#     chunk_size: int = 10 * 1024 * 1024,  # 10 MB default
#     file_type=None,
#     ):
#     """
#     Decrypt AES-256-GCM encrypted audio file chunk-by-chunk with streaming,
#     upload decrypted chunks to S3 with KMS encryption using threading,
#     and extract embedded audio thumbnail while streaming.
#     """

#     bucket = MEDIA_FILES_BUCKET
#     parts = []
#     uploaded_bytes = 0
#     thumbnail_data = None
#     upload_error = None

#     try:
#         # === Step 1: Prepare decryption cipher ===
#         s3_key = key
#         if progress_callback:
#             progress_callback(15, "Initializing decryption...")

#         # Convert IV (Base64 or Hex)
#         try:
#             if all(c in "0123456789abcdefABCDEF" for c in iv_str.strip()):
#                 iv = bytes.fromhex(iv_str)
#             else:
#                 iv = base64.b64decode(iv_str)
#         except Exception as e:
#             raise ValueError(f"Invalid IV format: {e}")

#         # Decode key
#         key = settings.ENCRYPTION_KEY
#         if isinstance(key, str):
#             key = base64.b64decode(key)
#         if len(key) != 32:
#             raise ValueError(f"Key must be 32 bytes for AES-256, got {len(key)} bytes")

#         # Determine file size and auth tag
#         encrypted_file.seek(0, 2)
#         total_size = encrypted_file.tell()
#         if total_size < 16:
#             raise ValueError("Encrypted file too short (missing GCM tag).")

#         encrypted_data_size = total_size - 16
        
#         # Dynamic chunk size based on file size for optimal performance
#         if encrypted_data_size <= 20 * 1024 * 1024:  # <= 20MB - small files
#             chunk_size = chunk_size  # Use original 10MB or provided chunk_size
#             use_threading = False  # Skip threading overhead for small files
#         elif encrypted_data_size > 100 * 1024 * 1024:  # > 100MB
#             chunk_size = 5 * 1024 * 1024  # 2MB chunks
#             use_threading = True
#         elif encrypted_data_size > 50 * 1024 * 1024:  # > 50MB
#             chunk_size = 8 * 1024 * 1024  # 5MB chunks
#             use_threading = True
#         else:  # 20-50MB
#             chunk_size = 8 * 1024 * 1024  # 8MB chunks
#             use_threading = True
        
#         encrypted_file.seek(encrypted_data_size)
#         auth_tag = encrypted_file.read(16)

#         cipher = Cipher(algorithms.AES(key), modes.GCM(iv, auth_tag), backend=default_backend())
#         decryptor = cipher.decryptor()

#         encrypted_file.seek(0)
#         if progress_callback:
#             progress_callback(20, "Starting chunked decrypt & upload...")

#         # === Step 2: Prepare S3 multipart upload ===
#         resp = kms.generate_data_key(KeyId=AWS_KMS_KEY_ID, KeySpec="AES_256")
#         data_key_plain = resp["Plaintext"]
#         data_key_encrypted = resp["CiphertextBlob"]
#         aesgcm = AESGCM(data_key_plain)

#         multipart_resp = s3.create_multipart_upload(
#             Bucket=bucket,
#             Key=s3_key,
#             ContentType=content_type,
#             Metadata={
#                 "edk": base64.b64encode(data_key_encrypted).decode(),
#                 "orig-content-type": content_type,
#                 "chunk-size": str(chunk_size),  # ADD THIS

#             },
#         )
#         upload_id = multipart_resp["UploadId"]

#         # === Step 3: Setup threading for upload (only for large files) ===
#         upload_queue = None
#         upload_thread = None
#         parts_lock = threading.Lock() if use_threading else None

#         if use_threading:
#             upload_queue = Queue(maxsize=3)  # Limit queue to prevent memory bloat

#             def upload_worker():
#                 """Worker thread to handle S3 uploads"""
#                 nonlocal upload_error, uploaded_bytes
                
#                 while True:
#                     try:
#                         item = upload_queue.get(timeout=1)
#                         if item is None:  # Poison pill to stop thread
#                             break
                        
#                         part_num, encrypted_body, decrypted_size = item
                        
#                         try:
#                             resp = s3.upload_part(
#                                 Bucket=bucket,
#                                 Key=s3_key,
#                                 PartNumber=part_num,
#                                 UploadId=upload_id,
#                                 Body=encrypted_body,
#                             )
                            
#                             with parts_lock:
#                                 parts.append({"ETag": resp["ETag"], "PartNumber": part_num})
#                                 uploaded_bytes += decrypted_size
                                
#                                 if progress_callback:
#                                     percent = int((uploaded_bytes / encrypted_data_size) * 100)
#                                     progress_callback(min(percent, 80), f"Uploaded chunk {part_num}")
                        
#                         except Exception as e:
#                             upload_error = e
#                             break
#                         finally:
#                             upload_queue.task_done()
                            
#                     except Empty:
#                         continue

#             # Start upload worker thread
#             upload_thread = threading.Thread(target=upload_worker, daemon=True)
#             upload_thread.start()

#         # === Step 4: Process chunks with streaming ===
#         part_number = 1
#         total_read = 0
#         collected_bytes = BytesIO()
#         thumbnail_extracted = False

#         while total_read < encrypted_data_size:
#             # Check for upload errors (only if threading)
#             if use_threading and upload_error:
#                 raise upload_error
            
#             to_read = min(chunk_size, encrypted_data_size - total_read)
#             chunk = encrypted_file.read(to_read)
#             total_read += len(chunk)

#             # Decrypt chunk
#             decrypted_chunk = decryptor.update(chunk)
            
#             if decrypted_chunk:
#                 # Thumbnail extraction (non-blocking, only first chunks)
#                 if not thumbnail_extracted and thumbnail_data is None:
#                     if collected_bytes.tell() < 512 * 1024:
#                         collected_bytes.write(decrypted_chunk)
                        
#                         # Attempt extraction if enough data buffered
#                         if collected_bytes.tell() >= 128 * 1024:
#                             try:
#                                 thumb = None
#                                 if file_type in ['video', 'audio']:
                                
#                                     extractor = MediaThumbnailExtractor(file='', file_ext=file_ext)
                                    
#                                     if file_type and file_type == 'video':
#                                         video_thumb = extractor.extract_video_thumbnail_from_bytes(
#                                             decrypted_bytes=collected_bytes.getvalue(),
#                                             extension=file_ext,
#                                         )
#                                         thumb = video_thumb
#                                     else:
#                                         thumb = extractor.extract_audio_thumbnail_from_bytes(
#                                             decrypted_bytes=collected_bytes.getvalue(),
#                                             extension=file_ext,
#                                         )
#                                 if thumb:
#                                     thumbnail_data = thumb
#                                     thumbnail_extracted = True
#                                     collected_bytes.close()
#                             except Exception:
#                                 pass  # Continue without thumbnail

#                 # Encrypt chunk for S3
#                 chunk_nonce = os.urandom(12)
#                 ciphertext_chunk = aesgcm.encrypt(chunk_nonce, decrypted_chunk, None)
#                 body = chunk_nonce + ciphertext_chunk

#                 if use_threading:
#                     # Queue upload for threaded processing
#                     upload_queue.put((part_number, body, len(decrypted_chunk)))
#                 else:
#                     # Direct upload for small files (faster, no threading overhead)
#                     resp = s3.upload_part(
#                         Bucket=bucket,
#                         Key=s3_key,
#                         PartNumber=part_number,
#                         UploadId=upload_id,
#                         Body=body,
#                     )
#                     parts.append({"ETag": resp["ETag"], "PartNumber": part_number})
#                     uploaded_bytes += len(decrypted_chunk)
                    
#                     if progress_callback:
#                         percent = int((uploaded_bytes / encrypted_data_size) * 100)
#                         progress_callback(min(percent, 80), f"Uploaded chunk {part_number}")
                
#                 part_number += 1
            
#             # Yield control periodically to prevent blocking (only for large files)
#             if use_threading and part_number % 5 == 0:
#                 threading.Event().wait(0.001)  # Tiny sleep to yield

#         # Finalize decryption
#         decryptor.finalize()

#         # Signal upload thread to stop and wait for completion (only if threading was used)
#         if use_threading:
#             upload_queue.put(None)
#             upload_thread.join(timeout=30)

#             # Check final upload status
#             if upload_error:
#                 raise upload_error

#         # === Step 5: Complete upload ===
#         # Sort parts by PartNumber to ensure correct order
#         parts.sort(key=lambda x: x["PartNumber"])
        
#         result = s3.complete_multipart_upload(
#             Bucket=bucket,
#             Key=s3_key,
#             UploadId=upload_id,
#             MultipartUpload={"Parts": parts},
#         )

#         if progress_callback:
#             progress_callback(90, "Decryption & upload completed successfully!")

#         return {
#             "s3_result": result,
#             "uploaded_size": uploaded_bytes,
#             "thumbnail_data": thumbnail_data,
#         }

#     except Exception as e:
#         if "upload_id" in locals():
#             try:
#                 s3.abort_multipart_upload(Bucket=bucket, Key=s3_key, UploadId=upload_id)
#             except Exception:
#                 pass
#         if progress_callback:
#             progress_callback(0, f"Decrypt/upload failed: {e}")
#         raise RuntimeError(f"Decrypt/upload failed: {e}")

#     finally:
#         try:
#             del data_key_plain
#         except Exception:
#             pass
#         try:
#             collected_bytes.close()
#         except Exception:
#             pass
        
# working one
# def decrypt_upload_and_extract_audio_thumbnail_chunked(
#         key: str,
#         encrypted_file,
#         iv_str: str,
#         content_type: str = "application/octet-stream",
#         file_ext: str = "",
#         progress_callback=None,
#         chunk_size: int = 10 * 1024 * 1024,  # 10 MB default
#         file_type=None,
#         thumbnail_buffer_size: int =512 * 1024,  # 3 MB buffer for thumbnail
#     ):
#     """
#     Decrypt AES-256-GCM encrypted file chunk-by-chunk, upload decrypted chunks to S3, 
#     and extract embedded audio/video thumbnail while streaming.
#     Handles small and large files efficiently with improved thumbnail extraction.
#     """

#     bucket = MEDIA_FILES_BUCKET
#     parts = []
#     uploaded_bytes = 0
#     thumbnail_data = None
#     upload_error = None
#     buffer_for_thumbnail = BytesIO()
    
#     # Thumbnail extraction control variables
#     thumbnail_extracted = False
#     thumbnail_attempts = 0
#     MAX_THUMBNAIL_ATTEMPTS = 3  # Try only 3 times
#     MIN_BUFFER_FOR_ATTEMPT = 512 * 1024  # Wait for at least 256KB before trying
    
#     try:
#         s3_key = key
#         if progress_callback:
#             progress_callback(15, "Initializing decryption...")

#         # Parse IV
#         try:
#             if all(c in "0123456789abcdefABCDEF" for c in iv_str.strip()):
#                 iv = bytes.fromhex(iv_str)
#             else:
#                 iv = base64.b64decode(iv_str)
#         except Exception as e:
#             raise ValueError(f"Invalid IV format: {e}")

#         # Decode AES key
#         key_bytes = settings.ENCRYPTION_KEY
#         if isinstance(key_bytes, str):
#             key_bytes = base64.b64decode(key_bytes)
#         if len(key_bytes) != 32:
#             raise ValueError(f"Key must be 32 bytes for AES-256, got {len(key_bytes)} bytes")

#         # Determine file size and auth tag
#         encrypted_file.seek(0, 2)
#         total_size = encrypted_file.tell()
#         if total_size < 16:
#             raise ValueError("Encrypted file too short (missing GCM tag).")
#         encrypted_data_size = total_size - 16
#         encrypted_file.seek(encrypted_data_size)
#         auth_tag = encrypted_file.read(16)
#         encrypted_file.seek(0)

#         # Dynamic chunk size and threading
#         if encrypted_data_size <= 20 * 1024 * 1024:
#             effective_chunk_size = chunk_size
#             use_threading = False
#         elif encrypted_data_size > 100 * 1024 * 1024:
#             effective_chunk_size = 5 * 1024 * 1024
#             use_threading = True
#         elif encrypted_data_size > 50 * 1024 * 1024:
#             effective_chunk_size = 8 * 1024 * 1024
#             use_threading = True
#         else:
#             effective_chunk_size = 8 * 1024 * 1024
#             use_threading = True

#         # Initialize decryptor
#         cipher = Cipher(algorithms.AES(key_bytes), modes.GCM(iv, auth_tag), backend=default_backend())
#         decryptor = cipher.decryptor()

#         if progress_callback:
#             progress_callback(20, "Starting chunked decrypt & upload...")

#         # Generate KMS data key & AESGCM encryptor for S3
#         resp = kms.generate_data_key(KeyId=AWS_KMS_KEY_ID, KeySpec="AES_256")
#         data_key_plain = resp["Plaintext"]
#         data_key_encrypted = resp["CiphertextBlob"]
#         aesgcm = AESGCM(data_key_plain)

#         # Prepare S3 multipart upload
#         multipart_resp = s3.create_multipart_upload(
#             Bucket=bucket,
#             Key=s3_key,
#             ContentType=content_type,
#             Metadata={
#                 "edk": base64.b64encode(data_key_encrypted).decode(),
#                 "orig-content-type": content_type,
#                 "chunk-size": str(effective_chunk_size),
#             },
#         )
#         upload_id = multipart_resp["UploadId"]

#         upload_queue = None
#         upload_thread = None
#         parts_lock = threading.Lock() if use_threading else None

#         if use_threading:
#             upload_queue = Queue(maxsize=3)

#             def upload_worker():
#                 nonlocal upload_error, uploaded_bytes
#                 while True:
#                     try:
#                         item = upload_queue.get(timeout=1)
#                         if item is None:
#                             break
#                         part_num, encrypted_body, decrypted_len = item
#                         try:
#                             resp = s3.upload_part(
#                                 Bucket=bucket,
#                                 Key=s3_key,
#                                 PartNumber=part_num,
#                                 UploadId=upload_id,
#                                 Body=encrypted_body,
#                             )
#                             with parts_lock:
#                                 parts.append({"ETag": resp["ETag"], "PartNumber": part_num})
#                                 uploaded_bytes += decrypted_len
#                                 if progress_callback:
#                                     percent = int((uploaded_bytes / encrypted_data_size) * 100)
#                                     progress_callback(min(percent, 80), f"Uploaded chunk {part_num}")
#                         except Exception as e:
#                             upload_error = e
#                             break
#                         finally:
#                             upload_queue.task_done()
#                     except Empty:
#                         continue

#             upload_thread = threading.Thread(target=upload_worker, daemon=True)
#             upload_thread.start()

#         # Process chunks
#         part_number = 1
#         total_read = 0

#         while total_read < encrypted_data_size:
#             if use_threading and upload_error:
#                 raise upload_error

#             to_read = min(effective_chunk_size, encrypted_data_size - total_read)
#             chunk = encrypted_file.read(to_read)
#             total_read += len(chunk)

#             decrypted_chunk = decryptor.update(chunk)

#             # === IMPROVED THUMBNAIL EXTRACTION ===
#             if not thumbnail_extracted and file_type in ['video', 'audio'] and buffer_for_thumbnail:
#                 buffer_for_thumbnail.write(decrypted_chunk)
#                 current_buffer_size = buffer_for_thumbnail.tell()
                
#                 # Only attempt extraction when:
#                 # 1. Buffer has meaningful data (512+)
#                 # 2. Haven't exceeded max attempts
#                 # 3. Either buffer is full OR we've read entire file
                
#                 # should_attempt = (
#                 #     current_buffer_size >= MIN_BUFFER_FOR_ATTEMPT and
#                 #     thumbnail_attempts < MAX_THUMBNAIL_ATTEMPTS and
#                 #     (current_buffer_size >= thumbnail_buffer_size or total_read >= encrypted_data_size)
#                 # )
                
#                 should_attempt = (
#                     current_buffer_size >= MIN_BUFFER_FOR_ATTEMPT and
#                     thumbnail_attempts < MAX_THUMBNAIL_ATTEMPTS and
#                     (
#                         current_buffer_size >= thumbnail_buffer_size
#                         or total_read >= encrypted_data_size  # full file read (even if < buffer)
#                     )
#                 )
                
#                 if should_attempt:
#                     thumbnail_attempts += 1
#                     try:
#                         if progress_callback:
#                             progress_callback(
#                                 min(int((total_read / encrypted_data_size) * 100), 79),
#                                 f"Extracting thumbnail (attempt {thumbnail_attempts})..."
#                             )
                        
#                         extractor = MediaThumbnailExtractor(file='', file_ext=file_ext)
#                         buffer_data = buffer_for_thumbnail.getvalue()
                        
#                         if file_type == 'video':
#                             thumb = extractor.extract_video_thumbnail_from_bytes(
#                                 extension=file_ext,
#                                 decrypted_bytes=buffer_data,
#                             )
#                         else:  # audio
#                             thumb = extractor.extract_audio_thumbnail_from_bytes(
#                                 extension=file_ext,
#                                 decrypted_bytes=buffer_data,
#                             )
                        
#                         if thumb:
#                             thumbnail_data = thumb
#                             thumbnail_extracted = True
#                             buffer_for_thumbnail.close()
#                             buffer_for_thumbnail = None  # Free memory
#                             if progress_callback:
#                                 progress_callback(
#                                     min(int((total_read / encrypted_data_size) * 100), 79),
#                                     "Thumbnail extracted successfully"
#                                 )
#                         else:
#                             # Extraction returned None - log and continue
#                             logger.info(f"Thumbnail extraction attempt {thumbnail_attempts} returned None")
                            
#                     except Exception as e:
#                         # Log the actual error instead of silent failure
#                         logger.warning(f"Thumbnail extraction attempt {thumbnail_attempts} failed: {str(e)}")
#                         # Continue processing - thumbnail is optional
#                         pass
                
#                 # Stop buffering if we've exceeded attempts or buffer limit
#                 if thumbnail_attempts >= MAX_THUMBNAIL_ATTEMPTS or current_buffer_size >= thumbnail_buffer_size * 2:
#                     if not thumbnail_extracted and buffer_for_thumbnail:
#                         logger.warning(f"Stopping thumbnail extraction after {thumbnail_attempts} attempts")
#                         buffer_for_thumbnail.close()
#                         buffer_for_thumbnail = None

#             # Encrypt chunk for S3 upload
#             nonce = os.urandom(12)
#             ciphertext_chunk = aesgcm.encrypt(nonce, decrypted_chunk, None)
#             body = nonce + ciphertext_chunk

#             if use_threading:
#                 upload_queue.put((part_number, body, len(decrypted_chunk)))
#             else:
#                 resp = s3.upload_part(
#                     Bucket=bucket,
#                     Key=s3_key,
#                     PartNumber=part_number,
#                     UploadId=upload_id,
#                     Body=body,
#                 )
#                 parts.append({"ETag": resp["ETag"], "PartNumber": part_number})
#                 uploaded_bytes += len(decrypted_chunk)
#                 if progress_callback:
#                     percent = int((uploaded_bytes / encrypted_data_size) * 100)
#                     progress_callback(min(percent, 80), f"Uploaded chunk {part_number}")

#             part_number += 1

#         decryptor.finalize()

#         if use_threading:
#             upload_queue.put(None)
#             upload_thread.join(timeout=30)
#             if upload_error:
#                 raise upload_error

#         # Complete S3 upload
#         parts.sort(key=lambda x: x["PartNumber"])
#         result = s3.complete_multipart_upload(
#             Bucket=bucket,
#             Key=s3_key,
#             UploadId=upload_id,
#             MultipartUpload={"Parts": parts},
#         )

#         if progress_callback:
#             progress_callback(90, "Decryption & upload completed successfully!")

#         return {
#             "s3_result": result,
#             "uploaded_size": uploaded_bytes,
#             "thumbnail_data": thumbnail_data,
#         }

#     except Exception as e:
#         if "upload_id" in locals():
#             try:
#                 s3.abort_multipart_upload(Bucket=bucket, Key=s3_key, UploadId=upload_id)
#             except Exception:
#                 pass
#         if progress_callback:
#             progress_callback(0, f"Decrypt/upload failed: {e}")
#         raise RuntimeError(f"Decrypt/upload failed: {e}")

#     finally:
#         try:
#             del data_key_plain
#         except Exception:
#             pass
#         try:
#             if buffer_for_thumbnail:
#                 buffer_for_thumbnail.close()
#         except Exception:
#             pass

# small file thumbnail
# def decrypt_upload_and_extract_audio_thumbnail_chunked(
#         key: str,
#         encrypted_file,
#         iv_str: str,
#         content_type: str = "application/octet-stream",
#         file_ext: str = "",
#         progress_callback=None,
#         chunk_size: int = 10 * 1024 * 1024,  # 10 MB default
#         file_type=None,
#         thumbnail_buffer_size: int = 512 * 1024,  # 512 KB buffer for thumbnail
#     ):
#     """
#     Decrypt AES-256-GCM encrypted file chunk-by-chunk, upload decrypted chunks to S3, 
#     and extract embedded audio/video thumbnail while streaming.
#     Handles small and large files efficiently with improved thumbnail extraction.
#     """

#     bucket = MEDIA_FILES_BUCKET
#     parts = []
#     uploaded_bytes = 0
#     thumbnail_data = None
#     upload_error = None
#     buffer_for_thumbnail = BytesIO()
    
#     # Thumbnail extraction control variables
#     thumbnail_extracted = False
#     thumbnail_attempts = 0
#     MAX_THUMBNAIL_ATTEMPTS = 3  # Try only 3 times
#     MIN_BUFFER_FOR_ATTEMPT = 64 * 1024  # Lower threshold: 64KB (reasonable for small files)
    
#     try:
#         s3_key = key
#         if progress_callback:
#             progress_callback(15, "Initializing decryption...")

#         # Parse IV
#         try:
#             if all(c in "0123456789abcdefABCDEF" for c in iv_str.strip()):
#                 iv = bytes.fromhex(iv_str)
#             else:
#                 iv = base64.b64decode(iv_str)
#         except Exception as e:
#             raise ValueError(f"Invalid IV format: {e}")

#         # Decode AES key
#         key_bytes = settings.ENCRYPTION_KEY
#         if isinstance(key_bytes, str):
#             key_bytes = base64.b64decode(key_bytes)
#         if len(key_bytes) != 32:
#             raise ValueError(f"Key must be 32 bytes for AES-256, got {len(key_bytes)} bytes")

#         # Determine file size and auth tag
#         encrypted_file.seek(0, 2)
#         total_size = encrypted_file.tell()
#         if total_size < 16:
#             raise ValueError("Encrypted file too short (missing GCM tag).")
#         encrypted_data_size = total_size - 16
#         encrypted_file.seek(encrypted_data_size)
#         auth_tag = encrypted_file.read(16)
#         encrypted_file.seek(0)

#         # Dynamic chunk size and threading
#         if encrypted_data_size <= 20 * 1024 * 1024:
#             effective_chunk_size = chunk_size
#             use_threading = False
#         elif encrypted_data_size > 100 * 1024 * 1024:
#             effective_chunk_size = 5 * 1024 * 1024
#             use_threading = True
#         elif encrypted_data_size > 50 * 1024 * 1024:
#             effective_chunk_size = 8 * 1024 * 1024
#             use_threading = True
#         else:
#             effective_chunk_size = 8 * 1024 * 1024
#             use_threading = True

#         # Initialize decryptor
#         cipher = Cipher(algorithms.AES(key_bytes), modes.GCM(iv, auth_tag), backend=default_backend())
#         decryptor = cipher.decryptor()

#         if progress_callback:
#             progress_callback(20, "Starting chunked decrypt & upload...")

#         # Generate KMS data key & AESGCM encryptor for S3
#         resp = kms.generate_data_key(KeyId=AWS_KMS_KEY_ID, KeySpec="AES_256")
#         data_key_plain = resp["Plaintext"]
#         data_key_encrypted = resp["CiphertextBlob"]
#         aesgcm = AESGCM(data_key_plain)

#         # Prepare S3 multipart upload
#         multipart_resp = s3.create_multipart_upload(
#             Bucket=bucket,
#             Key=s3_key,
#             ContentType=content_type,
#             Metadata={
#                 "edk": base64.b64encode(data_key_encrypted).decode(),
#                 "orig-content-type": content_type,
#                 "chunk-size": str(effective_chunk_size),
#             },
#         )
#         upload_id = multipart_resp["UploadId"]

#         upload_queue = None
#         upload_thread = None
#         parts_lock = threading.Lock() if use_threading else None

#         if use_threading:
#             upload_queue = Queue(maxsize=3)

#             def upload_worker():
#                 nonlocal upload_error, uploaded_bytes
#                 while True:
#                     try:
#                         item = upload_queue.get(timeout=1)
#                         if item is None:
#                             break
#                         part_num, encrypted_body, decrypted_len = item
#                         try:
#                             resp = s3.upload_part(
#                                 Bucket=bucket,
#                                 Key=s3_key,
#                                 PartNumber=part_num,
#                                 UploadId=upload_id,
#                                 Body=encrypted_body,
#                             )
#                             with parts_lock:
#                                 parts.append({"ETag": resp["ETag"], "PartNumber": part_num})
#                                 uploaded_bytes += decrypted_len
#                                 if progress_callback:
#                                     percent = int((uploaded_bytes / encrypted_data_size) * 100)
#                                     progress_callback(min(percent, 80), f"Uploaded chunk {part_num}")
#                         except Exception as e:
#                             upload_error = e
#                             break
#                         finally:
#                             upload_queue.task_done()
#                     except Empty:
#                         continue

#             upload_thread = threading.Thread(target=upload_worker, daemon=True)
#             upload_thread.start()

#         # Process chunks
#         part_number = 1
#         total_read = 0

#         while total_read < encrypted_data_size:
#             if use_threading and upload_error:
#                 raise upload_error

#             to_read = min(effective_chunk_size, encrypted_data_size - total_read)
#             chunk = encrypted_file.read(to_read)
#             total_read += len(chunk)

#             decrypted_chunk = decryptor.update(chunk)

#             # === IMPROVED THUMBNAIL EXTRACTION FOR ALL FILE SIZES ===
#             if not thumbnail_extracted and file_type in ['video', 'audio'] and buffer_for_thumbnail:
#                 buffer_for_thumbnail.write(decrypted_chunk)
#                 current_buffer_size = buffer_for_thumbnail.tell()
                
#                 # Attempt extraction when:
#                 # 1. Buffer has minimum meaningful data (64KB+) OR entire file is read
#                 # 2. Haven't exceeded max attempts
#                 # 3. Either buffer reached target size OR entire file is read (for small files)
                
#                 should_attempt = (
#                     thumbnail_attempts < MAX_THUMBNAIL_ATTEMPTS and
#                     (
#                         (current_buffer_size >= MIN_BUFFER_FOR_ATTEMPT and current_buffer_size >= thumbnail_buffer_size) or
#                         total_read >= encrypted_data_size  # Always try when full file is read
#                     )
#                 )
                
#                 if should_attempt:
#                     thumbnail_attempts += 1
#                     try:
#                         if progress_callback:
#                             progress_callback(
#                                 min(int((total_read / encrypted_data_size) * 100), 79),
#                                 f"Extracting thumbnail (attempt {thumbnail_attempts})..."
#                             )
                        
#                         extractor = MediaThumbnailExtractor(file='', file_ext=file_ext)
#                         buffer_data = buffer_for_thumbnail.getvalue()
                        
#                         if file_type == 'video':
#                             thumb = extractor.extract_video_thumbnail_from_bytes(
#                                 extension=file_ext,
#                                 decrypted_bytes=buffer_data,
#                             )
#                         else:  # audio
#                             thumb = extractor.extract_audio_thumbnail_from_bytes(
#                                 extension=file_ext,
#                                 decrypted_bytes=buffer_data,
#                             )
                        
#                         if thumb:
#                             thumbnail_data = thumb
#                             thumbnail_extracted = True
#                             buffer_for_thumbnail.close()
#                             buffer_for_thumbnail = None  # Free memory
#                             if progress_callback:
#                                 progress_callback(
#                                     min(int((total_read / encrypted_data_size) * 100), 79),
#                                     "Thumbnail extracted successfully"
#                                 )
#                         else:
#                             # Extraction returned None - log and continue
#                             logger.info(f"Thumbnail extraction attempt {thumbnail_attempts} returned None (buffer size: {current_buffer_size} bytes)")
                            
#                     except Exception as e:
#                         # Log the actual error instead of silent failure
#                         logger.warning(f"Thumbnail extraction attempt {thumbnail_attempts} failed: {str(e)} (buffer size: {current_buffer_size} bytes)")
#                         # Continue processing - thumbnail is optional
#                         pass
                
#                 # Stop buffering if we've exceeded attempts or buffer limit
#                 if thumbnail_attempts >= MAX_THUMBNAIL_ATTEMPTS or current_buffer_size >= thumbnail_buffer_size * 2:
#                     if not thumbnail_extracted and buffer_for_thumbnail:
#                         logger.warning(f"Stopping thumbnail extraction after {thumbnail_attempts} attempts (final buffer size: {current_buffer_size} bytes)")
#                         buffer_for_thumbnail.close()
#                         buffer_for_thumbnail = None

#             # Encrypt chunk for S3 upload
#             nonce = os.urandom(12)
#             ciphertext_chunk = aesgcm.encrypt(nonce, decrypted_chunk, None)
#             body = nonce + ciphertext_chunk

#             if use_threading:
#                 upload_queue.put((part_number, body, len(decrypted_chunk)))
#             else:
#                 resp = s3.upload_part(
#                     Bucket=bucket,
#                     Key=s3_key,
#                     PartNumber=part_number,
#                     UploadId=upload_id,
#                     Body=body,
#                 )
#                 parts.append({"ETag": resp["ETag"], "PartNumber": part_number})
#                 uploaded_bytes += len(decrypted_chunk)
#                 if progress_callback:
#                     percent = int((uploaded_bytes / encrypted_data_size) * 100)
#                     progress_callback(min(percent, 80), f"Uploaded chunk {part_number}")

#             part_number += 1

#         decryptor.finalize()

#         if use_threading:
#             upload_queue.put(None)
#             upload_thread.join(timeout=30)
#             if upload_error:
#                 raise upload_error

#         # Complete S3 upload
#         parts.sort(key=lambda x: x["PartNumber"])
#         result = s3.complete_multipart_upload(
#             Bucket=bucket,
#             Key=s3_key,
#             UploadId=upload_id,
#             MultipartUpload={"Parts": parts},
#         )

#         if progress_callback:
#             progress_callback(90, "Decryption & upload completed successfully!")

#         return {
#             "s3_result": result,
#             "uploaded_size": uploaded_bytes,
#             "thumbnail_data": thumbnail_data,
#         }

#     except Exception as e:
#         if "upload_id" in locals():
#             try:
#                 s3.abort_multipart_upload(Bucket=bucket, Key=s3_key, UploadId=upload_id)
#             except Exception:
#                 pass
#         if progress_callback:
#             progress_callback(0, f"Decrypt/upload failed: {e}")
#         raise RuntimeError(f"Decrypt/upload failed: {e}")

#     finally:
#         try:
#             del data_key_plain
#         except Exception:
#             pass
#         try:
#             if buffer_for_thumbnail:
#                 buffer_for_thumbnail.close()
#         except Exception:
#             pass

# best one
# def decrypt_upload_and_extract_audio_thumbnail_chunked(
#         key: str,
#         encrypted_file,
#         iv_str: str,
#         content_type: str = "application/octet-stream",
#         file_ext: str = "",
#         progress_callback=None,
#         chunk_size: int = 10 * 1024 * 1024,  # 10 MB default
#         file_type=None,
#         thumbnail_buffer_size: int = 512 * 1024,  # 512 KB buffer for thumbnail
#     ):
#     """
#     Decrypt AES-256-GCM encrypted file chunk-by-chunk, upload decrypted chunks to S3, 
#     and extract embedded audio/video thumbnail while streaming.
#     Optimized for fast upload with minimal RAM usage for all file sizes.
#     """

#     bucket = MEDIA_FILES_BUCKET
#     parts = []
#     uploaded_bytes = 0
#     thumbnail_data = None
#     upload_error = None
#     buffer_for_thumbnail = BytesIO()
    
#     # Thumbnail extraction control variables
#     thumbnail_extracted = False
#     thumbnail_attempts = 0
#     MAX_THUMBNAIL_ATTEMPTS = 5
#     MIN_BUFFER_FOR_ATTEMPT = 64 * 1024
    
#     try:
#         s3_key = key
#         # if progress_callback:
#         #     progress_callback(15, "Initializing decryption...")

#         # Parse IV
#         try:
#             if all(c in "0123456789abcdefABCDEF" for c in iv_str.strip()):
#                 iv = bytes.fromhex(iv_str)
#             else:
#                 iv = base64.b64decode(iv_str)
#         except Exception as e:
#             raise ValueError(f"Invalid IV format: {e}")

#         # Decode AES key
#         key_bytes = settings.ENCRYPTION_KEY
#         if isinstance(key_bytes, str):
#             key_bytes = base64.b64decode(key_bytes)
#         if len(key_bytes) != 32:
#             raise ValueError(f"Key must be 32 bytes for AES-256, got {len(key_bytes)} bytes")

#         # Determine file size and auth tag
#         encrypted_file.seek(0, 2)
#         total_size = encrypted_file.tell()
#         if total_size < 16:
#             raise ValueError("Encrypted file too short (missing GCM tag).")
#         encrypted_data_size = total_size - 16
#         encrypted_file.seek(encrypted_data_size)
#         auth_tag = encrypted_file.read(16)
#         encrypted_file.seek(0)

#         # OPTIMIZED: Adaptive chunk size and threading strategy
#         if encrypted_data_size <= 5 * 1024 * 1024:  # < 5MB
#             # Small files: single thread, larger chunks for speed
#             effective_chunk_size = max(encrypted_data_size, 1 * 1024 * 1024)
#             use_threading = False
#             max_workers = 1
#         elif encrypted_data_size <= 50 * 1024 * 1024:  # 5-50MB
#             # Medium files: 2 workers, balanced chunks
#             effective_chunk_size = 5 * 1024 * 1024
#             use_threading = True
#             max_workers = 2
#         elif encrypted_data_size <= 200 * 1024 * 1024:  # 50-200MB
#             # Large files: 3 workers, smaller chunks
#             effective_chunk_size = 8 * 1024 * 1024
#             use_threading = True
#             max_workers = 3
#         else:  # > 200MB
#             # Very large files: 4 workers, optimized chunk size
#             effective_chunk_size = 10 * 1024 * 1024
#             use_threading = True
#             max_workers = 4

#         # Initialize decryptor
#         cipher = Cipher(algorithms.AES(key_bytes), modes.GCM(iv, auth_tag), backend=default_backend())
#         decryptor = cipher.decryptor()

#         if progress_callback:
#             progress_callback(16, "Starting chunked decrypt & upload...")

#         # Generate KMS data key & AESGCM encryptor for S3
#         resp = kms.generate_data_key(KeyId=AWS_KMS_KEY_ID, KeySpec="AES_256")
#         data_key_plain = resp["Plaintext"]
#         data_key_encrypted = resp["CiphertextBlob"]
#         aesgcm = AESGCM(data_key_plain)

#         # Prepare S3 multipart upload
#         multipart_resp = s3.create_multipart_upload(
#             Bucket=bucket,
#             Key=s3_key,
#             ContentType=content_type,
#             Metadata={
#                 "edk": base64.b64encode(data_key_encrypted).decode(),
#                 "orig-content-type": content_type,
#                 "chunk-size": str(effective_chunk_size),
#             },
#         )
#         upload_id = multipart_resp["UploadId"]

#         upload_queue = None
#         upload_threads = []
#         parts_lock = threading.Lock() if use_threading else None

#         if use_threading:
#             # OPTIMIZED: Larger queue for better throughput, multiple workers
#             upload_queue = Queue(maxsize=max_workers * 2)

#             def upload_worker():
#                 nonlocal upload_error, uploaded_bytes
#                 while True:
#                     try:
#                         item = upload_queue.get(timeout=1)
#                         if item is None:
#                             break
#                         part_num, encrypted_body, decrypted_len = item
#                         try:
#                             resp = s3.upload_part(
#                                 Bucket=bucket,
#                                 Key=s3_key,
#                                 PartNumber=part_num,
#                                 UploadId=upload_id,
#                                 Body=encrypted_body,
#                             )
#                             with parts_lock:
#                                 parts.append({"ETag": resp["ETag"], "PartNumber": part_num})
#                                 uploaded_bytes += decrypted_len
#                                 if progress_callback:
#                                     percent = int((uploaded_bytes / encrypted_data_size) * 100)
#                                     progress_callback(min(percent, 80), f"Uploaded chunk {part_num}")
#                         # except Exception as e:
#                         #     upload_error = e
#                         #     break
#                         except ClientError as e:
#                             logger.error(f"S3 ClientError: - {str(e)}")
#                             upload_error = e
#                         except Exception as e:
#                             logger.error(f"Unexpected error in upload worker: {str(e)}", exc_info=True)
#                             upload_error = e
#                         finally:
#                             upload_queue.task_done()
#                     except Empty:
#                         continue

#             # OPTIMIZED: Start multiple worker threads
#             for _ in range(max_workers):
#                 thread = threading.Thread(target=upload_worker, daemon=True)
#                 thread.start()
#                 upload_threads.append(thread)

#         # Process chunks
#         part_number = 1
#         total_read = 0

#         while total_read < encrypted_data_size:
#             if use_threading and upload_error:
#                 raise upload_error

#             to_read = min(effective_chunk_size, encrypted_data_size - total_read)
#             chunk = encrypted_file.read(to_read)
#             total_read += len(chunk)

#             decrypted_chunk = decryptor.update(chunk)

#             # Thumbnail extraction (unchanged)
#             if not thumbnail_extracted and file_type in ['video', 'audio'] and buffer_for_thumbnail:
#                 buffer_for_thumbnail.write(decrypted_chunk)
#                 current_buffer_size = buffer_for_thumbnail.tell()
                
#                 should_attempt = (
#                     thumbnail_attempts < MAX_THUMBNAIL_ATTEMPTS and
#                     (
#                         (current_buffer_size >= MIN_BUFFER_FOR_ATTEMPT and current_buffer_size >= thumbnail_buffer_size) or
#                         total_read >= encrypted_data_size
#                     )
#                 )
                
#                 if should_attempt:
#                     thumbnail_attempts += 1
#                     try:
#                         # if progress_callback:
#                         #     progress_callback(
#                         #         min(int((total_read / encrypted_data_size) * 100), 79),
#                         #         f"Extracting thumbnail (attempt {thumbnail_attempts})..."
#                         #     )
                        
#                         extractor = MediaThumbnailExtractor(file='', file_ext=file_ext)
#                         buffer_data = buffer_for_thumbnail.getvalue()
                        
#                         if file_type == 'video':
#                             thumb = extractor.extract_video_thumbnail_from_bytes(
#                                 extension=file_ext,
#                                 decrypted_bytes=buffer_data,
#                             )
#                         else:
#                             thumb = extractor.extract_audio_thumbnail_from_bytes(
#                                 extension=file_ext,
#                                 decrypted_bytes=buffer_data,
#                             )
                        
#                         if thumb:
#                             thumbnail_data = thumb
#                             thumbnail_extracted = True
#                             buffer_for_thumbnail.close()
#                             buffer_for_thumbnail = None
#                             if progress_callback:
#                                 progress_callback(
#                                     min(int((total_read / encrypted_data_size) * 80), 83),
#                                     "Thumbnail extracted successfully"
#                                 )
#                         else:
#                             logger.info(f"Thumbnail extraction attempt {thumbnail_attempts} returned None (buffer size: {current_buffer_size} bytes)")
                            
#                     except Exception as e:
#                         logger.warning(f"Thumbnail extraction attempt {thumbnail_attempts} failed: {str(e)} (buffer size: {current_buffer_size} bytes)")
#                         pass
                
#                 if thumbnail_attempts >= MAX_THUMBNAIL_ATTEMPTS or current_buffer_size >= thumbnail_buffer_size * 2:
#                     if not thumbnail_extracted and buffer_for_thumbnail:
#                         logger.warning(f"Stopping thumbnail extraction after {thumbnail_attempts} attempts (final buffer size: {current_buffer_size} bytes)")
#                         buffer_for_thumbnail.close()
#                         buffer_for_thumbnail = None

#             # Encrypt chunk for S3 upload
#             nonce = os.urandom(12)
#             ciphertext_chunk = aesgcm.encrypt(nonce, decrypted_chunk, None)
#             body = nonce + ciphertext_chunk

#             if use_threading:
#                 upload_queue.put((part_number, body, len(decrypted_chunk)))
#             else:
#                 resp = s3.upload_part(
#                     Bucket=bucket,
#                     Key=s3_key,
#                     PartNumber=part_number,
#                     UploadId=upload_id,
#                     Body=body,
#                 )
#                 parts.append({"ETag": resp["ETag"], "PartNumber": part_number})
#                 uploaded_bytes += len(decrypted_chunk)
#                 if progress_callback:
#                     percent = int((uploaded_bytes / encrypted_data_size) * 80)
#                     progress_callback(min(percent, 83), f"Uploaded chunk {part_number}")



#             part_number += 1
            
#             # OPTIMIZED: Free memory immediately after queueing
#             del decrypted_chunk, ciphertext_chunk, body

#         decryptor.finalize()

#         if use_threading:
#             # Signal all workers to stop
#             for _ in range(max_workers):
#                 upload_queue.put(None)
            
#             # Wait for all workers with timeout
#             for thread in upload_threads:
#                 thread.join(timeout=120)  
            
#             if upload_error:
#                 raise upload_error

#         # Complete S3 upload
#         parts.sort(key=lambda x: x["PartNumber"])
#         result = s3.complete_multipart_upload(
#             Bucket=bucket,
#             Key=s3_key,
#             UploadId=upload_id,
#             MultipartUpload={"Parts": parts},
#         )
        
        
#         if not thumbnail_data:
#             print('\n -------- thumbnail extraction failed ---------,')
#             try:
#                 temp_s3_path = tempfile.mktemp(suffix=f"_s3{file_ext}")
#                 extractor = MediaThumbnailExtractor(file=temp_s3_path, file_ext=file_ext)
                
#                 with ChunkedDecryptor(s3_key) as decryptor:
                    
#                     # If no chunk-size present in metadata => full decryption mode
#                     if not decryptor.metadata.get("chunk-size"):
#                         full_plaintext, content = get_file_bytes(s3_key)
                        
#                         if file_type == 'video':
#                             # Try FFmpeg first (most reliable)
#                             thumbnail_data = extractor.extract_video_thumbnail_ffmpeg(
#                                 extension=file_ext,
#                                 decrypted_bytes=full_plaintext
#                             )
                            
#                             # Fallback to enhanced moviepy if FFmpeg fails
#                             if not thumbnail_data:
#                                 logger.info("FFmpeg failed, trying moviepy fallback")
#                                 thumbnail_data = extractor.extract_video_thumbnail_moviepy_enhanced(
#                                     extension=file_ext,
#                                     decrypted_bytes=full_plaintext
#                                 )
#                         else:
#                             thumbnail_data = extractor.extract_audio_thumbnail_from_bytes(
#                                 extension=file_ext,
#                                 decrypted_bytes=full_plaintext
#                             )
#                     else:
#                         # Chunked mode (large files)
#                         with open(temp_s3_path, 'wb') as f:
#                             for chunk in decryptor.decrypt_chunks():
#                                 f.write(chunk)
                        
#                         if file_type == 'video':
#                             # Read the temp file for FFmpeg processing
#                             with open(temp_s3_path, 'rb') as f:
#                                 video_bytes = f.read()
                            
#                             thumbnail_data = extractor.extract_video_thumbnail_ffmpeg(
#                                 extension=file_ext,
#                                 decrypted_bytes=video_bytes
#                             )
                            
#                             if not thumbnail_data:
#                                 thumbnail_data = extractor.extract_video_thumbnail_moviepy_enhanced(
#                                     extension=file_ext,
#                                     decrypted_bytes=video_bytes
#                                 )
#                         else:
#                             thumbnail_data = extractor.extract_audio_thumbnail()
                        
#                         try:
#                             os.remove(temp_s3_path)
#                         except Exception:
#                             pass
                
#                 if thumbnail_data:
#                 # logger.error(f'Thumbnail extraction failed as : {e}')
#                     pass 
                    
                    
#             except Exception as e:
#                 logger.error(f'Thumbnail extraction failed as : {e}')


#         # if progress_callback:
#         #     progress_callback(90, "Decryption & upload completed successfully!")

#         return {
#             "s3_result": result,
#             "uploaded_size": uploaded_bytes,
#             "thumbnail_data": thumbnail_data,
#         }

#     except Exception as e:
#         if "upload_id" in locals():
#             try:
#                 s3.abort_multipart_upload(Bucket=bucket, Key=s3_key, UploadId=upload_id)
#             except Exception:
#                 pass
#         if progress_callback:
#             progress_callback(0, f"Decrypt/upload failed: {e}")
#         raise RuntimeError(f"Decrypt/upload failed: {e}")

#     finally:
#         try:
#             del data_key_plain
#         except Exception:
#             pass
#         try:
#             if buffer_for_thumbnail:
#                 buffer_for_thumbnail.close()
#         except Exception:
#             pass

def decrypt_upload_and_extract_audio_thumbnail_chunked(
        key: str,
        encrypted_file,
        iv_str: str,
        content_type: str = "application/octet-stream",
        file_ext: str = "",
        progress_callback=None,
        chunk_size: int = 10 * 1024 * 1024,  # 10 MB default
        file_type=None,
        thumbnail_buffer_size: int = 512 * 1024,  # 512 KB buffer for thumbnail
    ):
    """
    Decrypt AES-256-GCM encrypted file chunk-by-chunk, upload decrypted chunks to S3, 
    and extract embedded audio/video thumbnail while streaming.
    Optimized for fast upload with minimal RAM usage for all file sizes.
    """

    bucket = MEDIA_FILES_BUCKET
    parts = []
    uploaded_bytes = 0
    thumbnail_data = None
    upload_error = None
    buffer_for_thumbnail = BytesIO()
    
    # Thumbnail extraction control variables
    thumbnail_extracted = False
    thumbnail_attempts = 0
    MAX_THUMBNAIL_ATTEMPTS = 3
    MIN_BUFFER_FOR_ATTEMPT = 64 * 1024
    
    try:
        s3_key = key
        # if progress_callback:
        #     progress_callback(15, "Initializing decryption...")

        # Parse IV
        try:
            if all(c in "0123456789abcdefABCDEF" for c in iv_str.strip()):
                iv = bytes.fromhex(iv_str)
            else:
                iv = base64.b64decode(iv_str)
        except Exception as e:
            raise ValueError(f"Invalid IV format: {e}")

        # Decode AES key
        key_bytes = settings.ENCRYPTION_KEY
        if isinstance(key_bytes, str):
            key_bytes = base64.b64decode(key_bytes)
        if len(key_bytes) != 32:
            raise ValueError(f"Key must be 32 bytes for AES-256, got {len(key_bytes)} bytes")

        # Determine file size and auth tag
        encrypted_file.seek(0, 2)
        total_size = encrypted_file.tell()
        if total_size < 16:
            raise ValueError("Encrypted file too short (missing GCM tag).")
        encrypted_data_size = total_size - 16
        encrypted_file.seek(encrypted_data_size)
        auth_tag = encrypted_file.read(16)
        encrypted_file.seek(0)

        # OPTIMIZED: Adaptive chunk size and threading strategy
        if encrypted_data_size <= 5 * 1024 * 1024:  # < 5MB
            # Small files: single thread, larger chunks for speed
            effective_chunk_size = max(encrypted_data_size, 1 * 1024 * 1024)
            use_threading = False
            max_workers = 1
        elif encrypted_data_size <= 50 * 1024 * 1024:  # 5-50MB
            # Medium files: 2 workers, balanced chunks
            effective_chunk_size = 5 * 1024 * 1024
            use_threading = True
            max_workers = 2
        elif encrypted_data_size <= 200 * 1024 * 1024:  # 50-200MB
            # Large files: 3 workers, smaller chunks
            effective_chunk_size = 8 * 1024 * 1024
            use_threading = True
            max_workers = 3
        else:  # > 200MB
            # Very large files: 4 workers, optimized chunk size
            effective_chunk_size = 10 * 1024 * 1024
            use_threading = True
            max_workers = 4

        # Initialize decryptor
        cipher = Cipher(algorithms.AES(key_bytes), modes.GCM(iv, auth_tag), backend=default_backend())
        decryptor = cipher.decryptor()

        if progress_callback:
            progress_callback(16, "Starting chunked decrypt & upload...")

        # Generate KMS data key & AESGCM encryptor for S3
        resp = kms.generate_data_key(KeyId=AWS_KMS_KEY_ID, KeySpec="AES_256")
        data_key_plain = resp["Plaintext"]
        data_key_encrypted = resp["CiphertextBlob"]
        aesgcm = AESGCM(data_key_plain)

        # Prepare S3 multipart upload
        multipart_resp = s3.create_multipart_upload(
            Bucket=bucket,
            Key=s3_key,
            ContentType=content_type,
            Metadata={
                "edk": base64.b64encode(data_key_encrypted).decode(),
                "orig-content-type": content_type,
                "chunk-size": str(effective_chunk_size),
            },
        )
        upload_id = multipart_resp["UploadId"]

        upload_queue = None
        upload_threads = []
        parts_lock = threading.Lock() if use_threading else None

        if use_threading:
            # OPTIMIZED: Larger queue for better throughput, multiple workers
            upload_queue = Queue(maxsize=max_workers * 2)

            def upload_worker():
                nonlocal upload_error, uploaded_bytes
                while True:
                    try:
                        item = upload_queue.get(timeout=1)
                        if item is None:
                            break
                        part_num, encrypted_body, decrypted_len = item
                        try:
                            resp = s3.upload_part(
                                Bucket=bucket,
                                Key=s3_key,
                                PartNumber=part_num,
                                UploadId=upload_id,
                                Body=encrypted_body,
                            )
                            with parts_lock:
                                parts.append({"ETag": resp["ETag"], "PartNumber": part_num})
                                uploaded_bytes += decrypted_len
                                if progress_callback:
                                    percent = 16 + int((uploaded_bytes / encrypted_data_size) * 67)
                                    progress_callback(min(percent, 83), f"Uploaded chunk {part_num}")
                        except ClientError as e:
                            logger.error(f"S3 ClientError: - {str(e)}")
                            upload_error = e
                        except Exception as e:
                            logger.error(f"Unexpected error in upload worker: {str(e)}", exc_info=True)
                            upload_error = e
                        finally:
                            upload_queue.task_done()
                    except Empty:
                        continue

            # OPTIMIZED: Start multiple worker threads
            for _ in range(max_workers):
                thread = threading.Thread(target=upload_worker, daemon=True)
                thread.start()
                upload_threads.append(thread)

        # Process chunks
        part_number = 1
        total_read = 0

        while total_read < encrypted_data_size:
            if use_threading and upload_error:
                raise upload_error

            to_read = min(effective_chunk_size, encrypted_data_size - total_read)
            chunk = encrypted_file.read(to_read)
            total_read += len(chunk)

            decrypted_chunk = decryptor.update(chunk)

            # Thumbnail extraction (unchanged)
            if not thumbnail_extracted and file_type in ['video', 'audio'] and buffer_for_thumbnail:
                buffer_for_thumbnail.write(decrypted_chunk)
                current_buffer_size = buffer_for_thumbnail.tell()
                
                should_attempt = (
                    thumbnail_attempts < MAX_THUMBNAIL_ATTEMPTS and
                    (
                        (current_buffer_size >= MIN_BUFFER_FOR_ATTEMPT and current_buffer_size >= thumbnail_buffer_size) or
                        total_read >= encrypted_data_size
                    )
                )
                
                if should_attempt:
                    thumbnail_attempts += 1
                    try:
                        # if progress_callback:
                        #     progress_callback(
                        #         min(int((total_read / encrypted_data_size) * 100), 79),
                        #         f"Extracting thumbnail (attempt {thumbnail_attempts})..."
                        #     )
                        
                        extractor = MediaThumbnailExtractor(file='', file_ext=file_ext)
                        buffer_data = buffer_for_thumbnail.getvalue()
                        
                        if file_type == 'video':
                            thumb = extractor.extract_video_thumbnail_from_bytes(
                                extension=file_ext,
                                decrypted_bytes=buffer_data,
                            )
                        else:
                            thumb = extractor.extract_audio_thumbnail_from_bytes(
                                extension=file_ext,
                                decrypted_bytes=buffer_data,
                            )
                        
                        if thumb:
                            thumbnail_data = thumb
                            thumbnail_extracted = True
                            buffer_for_thumbnail.close()
                            buffer_for_thumbnail = None
                            if progress_callback:
                                progress_callback(
                                    min(16 + int((total_read / encrypted_data_size) * 67), 83),
                                    "Thumbnail extracted successfully"
                                )
                        else:
                            logger.info(f"Thumbnail extraction attempt {thumbnail_attempts} returned None (buffer size: {current_buffer_size} bytes)")
                            
                    except Exception as e:
                        logger.warning(f"Thumbnail extraction attempt {thumbnail_attempts} failed: {str(e)} (buffer size: {current_buffer_size} bytes)")
                        pass
                
                if thumbnail_attempts >= MAX_THUMBNAIL_ATTEMPTS or current_buffer_size >= thumbnail_buffer_size * 2:
                    if not thumbnail_extracted and buffer_for_thumbnail:
                        logger.warning(f"Stopping thumbnail extraction after {thumbnail_attempts} attempts (final buffer size: {current_buffer_size} bytes)")
                        buffer_for_thumbnail.close()
                        buffer_for_thumbnail = None

            # Encrypt chunk for S3 upload
            nonce = os.urandom(12)
            ciphertext_chunk = aesgcm.encrypt(nonce, decrypted_chunk, None)
            body = nonce + ciphertext_chunk

            if use_threading:
                upload_queue.put((part_number, body, len(decrypted_chunk)))
            else:
                resp = s3.upload_part(
                    Bucket=bucket,
                    Key=s3_key,
                    PartNumber=part_number,
                    UploadId=upload_id,
                    Body=body,
                )
                parts.append({"ETag": resp["ETag"], "PartNumber": part_number})
                uploaded_bytes += len(decrypted_chunk)
                if progress_callback:
                    percent = 16 + int((uploaded_bytes / encrypted_data_size) * 67)
                    progress_callback(min(percent, 83), f"Uploaded chunk {part_number}")

            part_number += 1
            
            # OPTIMIZED: Free memory immediately after queueing
            del decrypted_chunk, ciphertext_chunk, body

        decryptor.finalize()

        if use_threading:
            # Signal all workers to stop
            for _ in range(max_workers):
                upload_queue.put(None)
            
            # Wait for all workers with timeout
            for thread in upload_threads:
                thread.join(timeout=120)
            
            if upload_error:
                raise upload_error

        # Complete S3 upload
        parts.sort(key=lambda x: x["PartNumber"])
        result = s3.complete_multipart_upload(
            Bucket=bucket,
            Key=s3_key,
            UploadId=upload_id,
            MultipartUpload={"Parts": parts},
        )
        
        
        if not thumbnail_data:
            print('\n -------- thumbnail extraction failed ---------,')
            try:
                temp_s3_path = tempfile.mktemp(suffix=f"_s3{file_ext}")
                extractor = MediaThumbnailExtractor(file=temp_s3_path, file_ext=file_ext)
                
                with ChunkedDecryptor(s3_key) as decryptor:
                    
                    # If no chunk-size present in metadata => full decryption mode
                    if not decryptor.metadata.get("chunk-size"):
                        full_plaintext, content = get_file_bytes(s3_key)
                        
                        if file_type == 'video':
                            # Try FFmpeg first (most reliable)
                            thumbnail_data = extractor.extract_video_thumbnail_ffmpeg(
                                extension=file_ext,
                                decrypted_bytes=full_plaintext
                            )
                            
                            # Fallback to enhanced moviepy if FFmpeg fails
                            if not thumbnail_data:
                                logger.info("FFmpeg failed, trying moviepy fallback")
                                thumbnail_data = extractor.extract_video_thumbnail_moviepy_enhanced(
                                    extension=file_ext,
                                    decrypted_bytes=full_plaintext
                                )
                        else:
                            thumbnail_data = extractor.extract_audio_thumbnail_from_bytes(
                                extension=file_ext,
                                decrypted_bytes=full_plaintext
                            )
                    else:
                        # Chunked mode (large files)
                        with open(temp_s3_path, 'wb') as f:
                            for chunk in decryptor.decrypt_chunks():
                                f.write(chunk)
                        
                        if file_type == 'video':
                            # Read the temp file for FFmpeg processing
                            with open(temp_s3_path, 'rb') as f:
                                video_bytes = f.read()
                            
                            thumbnail_data = extractor.extract_video_thumbnail_ffmpeg(
                                extension=file_ext,
                                decrypted_bytes=video_bytes
                            )
                            
                            if not thumbnail_data:
                                thumbnail_data = extractor.extract_video_thumbnail_moviepy_enhanced(
                                    extension=file_ext,
                                    decrypted_bytes=video_bytes
                                )
                        else:
                            thumbnail_data = extractor.extract_audio_thumbnail_from_bytes(
                                extension=file_ext,
                                decrypted_bytes=video_bytes
                            )
                        
                        try:
                            os.remove(temp_s3_path)
                        except Exception:
                            pass
                
                if thumbnail_data:
                # logger.error(f'Thumbnail extraction failed as : {e}')
                    pass 
                    
                    
            except Exception as e:
                logger.error(f'Thumbnail extraction failed as : {e}')

        if progress_callback:
            progress_callback(90, "Decryption & upload completed successfully!")

        return {
            "s3_result": result,
            "uploaded_size": uploaded_bytes,
            "thumbnail_data": thumbnail_data,
        }

    except Exception as e:
        if "upload_id" in locals():
            try:
                s3.abort_multipart_upload(Bucket=bucket, Key=s3_key, UploadId=upload_id)
            except Exception:
                pass
        if progress_callback:
            progress_callback(0, f"Decrypt/upload failed: {e}")
        raise RuntimeError(f"Decrypt/upload failed: {e}")

    finally:
        try:
            del data_key_plain
        except Exception:
            pass
        try:
            if buffer_for_thumbnail:
                buffer_for_thumbnail.close()
        except Exception:
            pass

def decrypt_s3_file_chunked2(key: str,  chunk_size: int = 10 * 1024 * 1024 + 28):
    """
    Decrypts S3 file uploaded using decrypt_upload_and_extract_audio_thumbnail_chunked().
    Each chunk = 12-byte nonce + ciphertext_chunk.
    """
    try:
        bucket = MEDIA_FILES_BUCKET
        obj = s3.get_object(Bucket=bucket, Key=key)
        encrypted_blob = obj["Body"].read()
        metadata = obj.get("Metadata", {})

        if "edk" not in metadata:
            raise ValueError("Missing encrypted data key (edk) in metadata")

        # --- Decrypt KMS data key ---
        encrypted_data_key = base64.b64decode(metadata["edk"])
        data_key = kms.decrypt(CiphertextBlob=encrypted_data_key)["Plaintext"]
        aesgcm = AESGCM(data_key)

        plaintext = BytesIO()
        offset = 0
        total_len = len(encrypted_blob)
        orig_content_type = metadata.get("orig-content-type", "application/octet-stream")

        # --- Iterate through all nonce + ciphertext chunks ---
        while offset < total_len:
            if offset + 12 > total_len:
                logger.warning(f"Incomplete nonce found at offset {offset}, skipping remaining bytes.")
                break

            nonce = encrypted_blob[offset:offset + 12]
            offset += 12

            next_nonce = encrypted_blob.find(nonce, offset + 12)
            if next_nonce == -1:
                ciphertext_chunk = encrypted_blob[offset:]
                offset = total_len
            else:
                ciphertext_chunk = encrypted_blob[offset:next_nonce]
                offset = next_nonce

            try:
                decrypted_chunk = aesgcm.decrypt(nonce, ciphertext_chunk, None)
                plaintext.write(decrypted_chunk)
            except InvalidTag as e:
                logger.error(f"InvalidTag while decrypting chunk at offset {offset}: {e}")
                raise

        plaintext.seek(0)
        return plaintext.read(), orig_content_type

    except Exception as e:
        logger.error(f"Error decrypting chunked file '{key}': {e}")
        return None, None

def decrypt_s3_file_chunked(key: str):
    """
    Decrypts file uploaded using upload_file_to_s3_kms_chunked() or 
    encrypt_upload_and_extract_audio_thumbnail_chunked().
    
    Each chunk layout:
        [12-byte nonce][ciphertext+16-byte tag]
    
    CRITICAL: This function reads the actual chunk size from S3 metadata.
    It does NOT assume fixed chunk sizes.
    """
    data_key = None
    
    try:
        bucket = MEDIA_FILES_BUCKET
        obj = s3.get_object(Bucket=bucket, Key=key)
        encrypted_blob = obj["Body"].read()
        metadata = obj.get("Metadata", {})

        if "edk" not in metadata:
            raise ValueError("Missing encrypted data key (edk) in metadata")

        # Decrypt the KMS data key
        encrypted_data_key = base64.b64decode(metadata["edk"])
        data_key = kms.decrypt(CiphertextBlob=encrypted_data_key)["Plaintext"]
        aesgcm = AESGCM(data_key)

        # Try to get chunk size from metadata (may not exist for old files)
        chunk_size_str = metadata.get("chunk-size")
        if chunk_size_str:
            expected_chunk_size = int(chunk_size_str)
            logger.info(f"Using stored chunk size: {expected_chunk_size}")
        else:
            # For files without chunk-size metadata, we'll determine it dynamically
            expected_chunk_size = None
            logger.warning("No chunk-size in metadata, will detect dynamically")

        plaintext = BytesIO()
        total_len = len(encrypted_blob)
        offset = 0
        chunk_num = 0
        detected_chunk_sizes = []

        logger.info(f"Starting decryption: total_size={total_len} bytes, expected_chunk_size={expected_chunk_size}")

        # Process each encrypted chunk
        while offset < total_len:
            chunk_num += 1
            
            # Check if we have enough data for nonce
            if offset + 12 > total_len:
                logger.warning(f"Incomplete nonce at offset {offset}, stopping.")
                break

            # Read 12-byte nonce
            nonce = encrypted_blob[offset:offset + 12]
            offset += 12

            # Calculate remaining data after nonce
            remaining = total_len - offset
            
            # CRITICAL FIX: Determine ciphertext size for this chunk
            if expected_chunk_size is not None:
                # Use stored chunk size (ciphertext = plaintext + 16-byte tag)
                expected_ciphertext_size = min(expected_chunk_size + 16, remaining)
            else:
                # Dynamic detection: Try to read all remaining as one chunk
                # This handles variable chunk sizes from encrypt_upload_and_extract_audio_thumbnail_chunked
                expected_ciphertext_size = remaining
            
            # Must have at least the 16-byte tag
            if expected_ciphertext_size < 16:
                logger.warning(f"Insufficient data for auth tag at offset {offset}")
                break
            
            # Read ciphertext + tag
            ciphertext_chunk = encrypted_blob[offset:offset + expected_ciphertext_size]
            offset += expected_ciphertext_size

            # Decrypt chunk
            try:
                try:
                    decrypted_chunk = aesgcm.decrypt(nonce, ciphertext_chunk, None)
                except Exception as e:
                    return None, None
                plaintext.write(decrypted_chunk)
                
                # Track detected chunk sizes for debugging
                detected_chunk_sizes.append(len(decrypted_chunk))
                
                logger.debug(
                    f"✓ Chunk {chunk_num}: "
                    f"nonce={len(nonce)}B, "
                    f"ciphertext={len(ciphertext_chunk)}B, "
                    f"plaintext={len(decrypted_chunk)}B"
                )
                
            except InvalidTag as e:
                logger.error(
                    f"❌ InvalidTag at chunk {chunk_num} (offset {offset}): "
                    f"nonce_len={len(nonce)}, "
                    f"ciphertext_len={len(ciphertext_chunk)}, "
                    f"expected_chunk_size={expected_chunk_size}, "
                    f"remaining={remaining}"
                )
                
                # If we don't have expected chunk size, try alternative sizes
                if expected_chunk_size is None and remaining > expected_ciphertext_size:
                    logger.info("Attempting to detect correct chunk size...")
                    
                    # Common chunk sizes used in encrypt_upload_and_extract_audio_thumbnail_chunked
                    alternative_sizes = [
                        10 * 1024 * 1024,  # 10MB
                        8 * 1024 * 1024,   # 8MB
                        5 * 1024 * 1024,   # 5MB
                        2 * 1024 * 1024,   # 2MB
                    ]
                    
                    decryption_succeeded = False
                    for alt_size in alternative_sizes:
                        alt_ciphertext_size = min(alt_size + 16, remaining)
                        if alt_ciphertext_size == expected_ciphertext_size:
                            continue  # Already tried this
                        
                        # Reset offset to retry with different size
                        retry_offset = offset - expected_ciphertext_size
                        alt_ciphertext = encrypted_blob[retry_offset:retry_offset + alt_ciphertext_size]
                        
                        try:
                            alt_decrypted = aesgcm.decrypt(nonce, alt_ciphertext, None)
                            plaintext.write(alt_decrypted)
                            offset = retry_offset + alt_ciphertext_size
                            expected_chunk_size = alt_size
                            detected_chunk_sizes.append(len(alt_decrypted))
                            logger.info(f"✓ Found correct chunk size: {alt_size} bytes")
                            decryption_succeeded = True
                            break
                        except InvalidTag:
                            continue
                    
                    if not decryption_succeeded:
                        raise ValueError(f"Failed to decrypt chunk {chunk_num} with any known chunk size")
                else:
                    raise

        plaintext.seek(0)
        decrypted_data = plaintext.read()
        
        # Log statistics
        if detected_chunk_sizes:
            unique_sizes = set(detected_chunk_sizes)
            logger.info(
                f"✓ Successfully decrypted {len(decrypted_data)} bytes from {chunk_num} chunks. "
                f"Chunk sizes used: {unique_sizes}"
            )
        
        return decrypted_data, metadata.get("orig-content-type", "application/octet-stream")

    except Exception as e:
        logger.error(f"Error decrypting chunked file '{key}': {e}", exc_info=True)
        return None, None
    
    finally:
        try:
            if data_key:
                del data_key
        except:
            pass
        
def decrypt_s3_file_chunked_range(key: str, start: int = 0, end: int | None = None):
    """
    Stream-decrypt only the requested byte range from an encrypted S3 file.
    Works with files uploaded by upload_file_to_s3_kms_chunked().
    """
    data_key = None
    try:
        bucket = MEDIA_FILES_BUCKET

        # Get metadata to retrieve chunk size and data key
        head = s3.head_object(Bucket=bucket, Key=key)
        metadata = head.get("Metadata", {})
        total_size = head["ContentLength"]

        if "edk" not in metadata:
            raise ValueError("Missing encrypted data key (edk) in metadata")

        # Decrypt data key
        encrypted_data_key = base64.b64decode(metadata["edk"])
        data_key = kms.decrypt(CiphertextBlob=encrypted_data_key)["Plaintext"]
        aesgcm = AESGCM(data_key)

        # Get stored chunk size (same used during encryption)
        chunk_size = int(metadata.get("chunk-size", 10 * 1024 * 1024))  # default 10MB
        ciphertext_chunk_size = chunk_size + 12 + 16  # nonce + ciphertext + tag

        # Calculate chunk boundaries
        start_chunk = start // chunk_size
        end_chunk = (end // chunk_size) if end else (total_size // chunk_size)

        decrypted_data = BytesIO()

        for chunk_index in range(start_chunk, end_chunk + 1):
            # Determine byte range in S3 for this chunk
            chunk_start = chunk_index * ciphertext_chunk_size
            chunk_end = min(chunk_start + ciphertext_chunk_size - 1, total_size - 1)
            range_header = f"bytes={chunk_start}-{chunk_end}"

            # Fetch encrypted chunk from S3
            part = s3.get_object(Bucket=bucket, Key=key, Range=range_header)
            encrypted_part = part["Body"].read()

            # Extract nonce + ciphertext + tag
            if len(encrypted_part) < 12 + 16:
                continue  # incomplete chunk, skip
            nonce = encrypted_part[:12]
            ciphertext = encrypted_part[12:]
            try:
                decrypted_chunk = aesgcm.decrypt(nonce, ciphertext, None)
            except Exception as e:
                logger.error(f"Failed to decrypt chunk {chunk_index}: {e}")
                continue

            decrypted_data.write(decrypted_chunk)

        decrypted_data.seek(0)
        plaintext_bytes = decrypted_data.read()

        content_type = metadata.get("orig-content-type", "application/octet-stream")
        return plaintext_bytes, content_type

    except Exception as e:
        logger.error(f"Error decrypting S3 range for '{key}': {e}", exc_info=True)
        return None, None

    finally:
        if data_key:
            del data_key





class ChunkedDecryptor:
    """
    Generator-based decryptor that yields plaintext chunks on-demand.
    Minimizes memory usage by streaming decryption.
    """
    def __init__(self, s3_key):
        self.s3_key = s3_key
        self.kms = kms
        self.s3 = s3
        self.bucket = MEDIA_FILES_BUCKET
        self.data_key = None
        self.aesgcm = None
        self.chunk_size = None
        self.total_size = 0
        self.metadata = {}
        
    def __enter__(self):
        """Initialize decryption context."""
        try:
            # Get metadata without reading body
            obj = self.s3.get_object(Bucket=self.bucket, Key=self.s3_key)
            self.metadata = obj.get("Metadata", {})
            self.total_size = obj['ContentLength']
            
            if "edk" not in self.metadata:
                raise ValueError("Missing encrypted data key (edk) in metadata")
            
            # Decrypt KMS data key
            encrypted_data_key = base64.b64decode(self.metadata["edk"])
            self.data_key = self.kms.decrypt(CiphertextBlob=encrypted_data_key)["Plaintext"]
            self.aesgcm = AESGCM(self.data_key)
            
            # # Get chunk size from metadata
            # chunk_size_str = self.metadata.get("chunk-size")
            # if chunk_size_str:
            #     self.chunk_size = int(chunk_size_str)
            #     logger.info(f"Using stored chunk size: {self.chunk_size}")
            # else:
            #     # Default fallback
            #     self.chunk_size = 10 * 1024 * 1024  # 10MB
            #     logger.warning(f"No chunk-size in metadata, using default: {self.chunk_size}")
            
            # 3️⃣ Detect chunked vs non-chunked
            chunk_size_str = self.metadata.get("chunk-size")
            if chunk_size_str:
                self.chunk_size = int(chunk_size_str)
                logger.info(f"[{self.s3_key}] Using chunked decryption with chunk size: {self.chunk_size}")
            else:
                logger.info(f"[{self.s3_key}] Non-chunked AES-GCM file detected (single nonce mode)")

            
            # Store the streaming body for later use
            self.s3_stream = obj["Body"]
            
            return self
            
        except Exception as e:
            logger.error(f"Failed to initialize decryptor for {self.s3_key}: {e}")
            self.cleanup()
            raise
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Cleanup resources."""
        self.cleanup()
    
    def cleanup(self):
        """Securely cleanup sensitive data."""
        if hasattr(self, 's3_stream') and self.s3_stream:
            self.s3_stream.close()
        if self.data_key:
            del self.data_key
        if self.aesgcm:
            del self.aesgcm
    
    def decrypt_chunks(self, start_byte=0, end_byte=None):
        """
        Generator that yields decrypted chunks.
        
        Args:
            start_byte: Starting byte position in decrypted data (for Range requests)
            end_byte: Ending byte position in decrypted data (for Range requests)
        
        Yields:
            bytes: Decrypted plaintext chunks
        """
        if end_byte is None:
            end_byte = float('inf')
        
        # Calculate encrypted chunk size (plaintext + 16-byte tag + 12-byte nonce)
        # encrypted_chunk_size = self.chunk_size + 16 + 12
        
        decrypted_offset = 0  # Track position in decrypted stream
        chunk_num = 0
        
        # Read encrypted data in chunks from S3
        while True:
            chunk_num += 1
            
            # Read nonce (12 bytes)
            nonce = self.s3_stream.read(12)
            if len(nonce) < 12:
                logger.debug(f"End of stream at chunk {chunk_num}")
                break
            
            # Read ciphertext + tag
            ciphertext_with_tag = self.s3_stream.read(self.chunk_size + 16)
            if len(ciphertext_with_tag) < 16:
                logger.warning(f"Insufficient data for auth tag at chunk {chunk_num}")
                break
            
            try:
                # Decrypt chunk
                decrypted_chunk = self.aesgcm.decrypt(nonce, ciphertext_with_tag, None)
                chunk_size = len(decrypted_chunk)
                chunk_end = decrypted_offset + chunk_size
                
                # Check if this chunk overlaps with requested range
                if chunk_end > start_byte and decrypted_offset < end_byte:
                    # Calculate slice within this chunk
                    slice_start = max(0, start_byte - decrypted_offset)
                    slice_end = min(chunk_size, end_byte - decrypted_offset)
                    
                    yield decrypted_chunk[slice_start:slice_end]
                
                decrypted_offset = chunk_end
                
                # Stop if we've passed the requested end
                if decrypted_offset >= end_byte:
                    break
                    
            except InvalidTag as e:
                logger.error(f"InvalidTag at chunk {chunk_num}: {e} for media file: {self.s3_key}")
                raise ValueError(f"Decryption failed at chunk {chunk_num}")
            
from django.core.cache import cache
from typing import Generator, Optional, Tuple


class S3MediaDecryptor:
    """
    Handles decryption of encrypted media files stored in S3.
    Matches the exact upload implementation with chunk-wise encryption.
    Supports both full file download and streaming chunk-wise decryption.
    """
    
    # Default streaming chunk size (1MB for output)
    DEFAULT_STREAM_CHUNK_SIZE = 1024 * 1024
    
    # Cache timeout for decryption keys (15 minutes)
    KEY_CACHE_TIMEOUT = 900
    
    def __init__(self, s3_key: str, bucket: str = MEDIA_FILES_BUCKET):
        """
        Initialize the decryptor with S3 key and bucket.
        
        Args:
            s3_key: The S3 object key
            bucket: S3 bucket name (default: MEDIA_FILES_BUCKET)
        """
        self.s3_key = s3_key
        self.bucket = bucket
        self.metadata = None
        self.aesgcm = None
        self._file_size = None
        self._encrypted_file_size = None
        
    def _get_cache_key(self, suffix: str = '') -> str:
        """Generate cache key for decryption key."""
        import hashlib
        digest = hashlib.sha256(self.s3_key.encode()).hexdigest()
        return f"decrypt_key:{digest}{suffix}"
    
    def _load_metadata_and_key(self) -> None:
        """Load S3 object metadata and decrypt the data encryption key."""
        if self.aesgcm is not None:
            return  # Already loaded
        
        try:
            # Check cache first
            cache_key = self._get_cache_key()
            cached_key = cache.get(cache_key)
            
            if cached_key:
                plain_key = base64.b64decode(cached_key)
                self.aesgcm = AESGCM(plain_key)
                
                # Still need to load metadata for chunk info
                response = s3.head_object(Bucket=self.bucket, Key=self.s3_key)
                self.metadata = response.get('Metadata', {})
                self._encrypted_file_size = response.get('ContentLength', 0)
                self._file_size = int(self.metadata.get('file_size', 0))
                
                logger.info(f"Using cached decryption key for {self.s3_key}")
            else:
                # Get metadata from S3
                response = s3.head_object(Bucket=self.bucket, Key=self.s3_key)
                self.metadata = response.get('Metadata', {})
                self._encrypted_file_size = response.get('ContentLength', 0)
                self._file_size = int(self.metadata.get('file_size', 0))
                
                # Get encrypted data key from metadata
                edk_b64 = self.metadata.get('edk')
                if not edk_b64:
                    raise ValueError(f"No encryption key found in metadata for {self.s3_key}")
                
                # Decrypt the data key using KMS
                encrypted_key = base64.b64decode(edk_b64)
                kms_response = kms.decrypt(CiphertextBlob=encrypted_key)
                plain_key = kms_response['Plaintext']
                
                # Initialize AESGCM cipher
                self.aesgcm = AESGCM(plain_key)
                
                # Cache the plain key
                cache.set(cache_key, base64.b64encode(plain_key).decode(), 
                         self.KEY_CACHE_TIMEOUT)
                
                logger.info(f"Loaded and cached decryption key for {self.s3_key}")
                
        except Exception as e:
            logger.exception(f"Failed to load metadata/key for {self.s3_key}: {e}")
            raise
    
    def _decrypt_s3_chunk(self, encrypted_chunk: bytes) -> bytes:
        """
        Decrypt a chunk that was encrypted for S3 storage using AESGCM.
        Format: [12-byte nonce][ciphertext with auth tag]
        
        Args:
            encrypted_chunk: Encrypted bytes (nonce + ciphertext)
            
        Returns:
            Decrypted bytes
        """
        if len(encrypted_chunk) < 12:
            raise ValueError("Encrypted chunk too short (missing nonce)")
        
        # Extract nonce (first 12 bytes) and ciphertext (rest includes auth tag)
        nonce = encrypted_chunk[:12]
        ciphertext = encrypted_chunk[12:]
        
        # Decrypt using AESGCM (auth tag is handled internally)
        try:
            decrypted = self.aesgcm.decrypt(nonce, ciphertext, None)
            return decrypted
        except Exception as e:
            logger.error(f"Decryption failed: {e}")
            raise ValueError(f"Failed to decrypt chunk: {e}")
    
    def get_full_decrypted_bytes(self) -> bytes:
        """
        Download and decrypt the entire file, returning all bytes.
        Uses chunk-wise decryption based on upload metadata.
        
        Returns:
            Complete decrypted file as bytes
        """
        self._load_metadata_and_key()
        
        try:
            # Get chunk metadata from S3 object (stored during upload)
            upload_chunk_size = self.metadata.get('chunk_size')
            total_chunks = self.metadata.get('totalchunks')
            
            if not upload_chunk_size or not total_chunks:
                logger.warning("No chunk metadata found, downloading as single file")
                # Fallback: download entire file and decrypt
                response = s3.get_object(Bucket=self.bucket, Key=self.s3_key)
                encrypted_data = response['Body'].read()
                return self._decrypt_s3_chunk(encrypted_data)
            
            # Convert to integers (metadata values are strings)
            upload_chunk_size = int(upload_chunk_size)
            total_chunks = int(total_chunks)
            
            logger.info(f"Decrypting file with {total_chunks} chunks of {upload_chunk_size} bytes each")
            
            # Calculate encrypted chunk size
            # Each chunk: 12 bytes (nonce) + upload_chunk_size + 16 bytes (GCM auth tag)
            encrypted_chunk_size = 12 + upload_chunk_size + 16
            
            # Download and decrypt chunk by chunk
            decrypted_chunks = []
            
            for chunk_index in range(total_chunks):
                # Calculate byte range for this encrypted chunk in S3
                start_byte = chunk_index * encrypted_chunk_size
                
                # Last chunk might be smaller
                if chunk_index == total_chunks - 1:
                    # Read to end of file
                    range_header = f'bytes={start_byte}-'
                else:
                    end_byte = start_byte + encrypted_chunk_size - 1
                    range_header = f'bytes={start_byte}-{end_byte}'
                
                # Download this encrypted chunk from S3
                response = s3.get_object(
                    Bucket=self.bucket, 
                    Key=self.s3_key,
                    Range=range_header
                )
                
                encrypted_chunk = response['Body'].read()
                
                # Decrypt this chunk
                decrypted_chunk = self._decrypt_s3_chunk(encrypted_chunk)
                decrypted_chunks.append(decrypted_chunk)
                
                logger.debug(f"Decrypted chunk {chunk_index + 1}/{total_chunks}")
            
            # Combine all decrypted chunks
            full_decrypted = b''.join(decrypted_chunks)
            
            logger.info(f"Successfully decrypted {len(full_decrypted)} bytes from {total_chunks} chunks")
            return full_decrypted
            
        except Exception as e:
            logger.exception(f"Failed to download/decrypt full file: {e}")
            raise
    
    def stream_decrypted_chunks(
        self, 
        output_chunk_size: int = DEFAULT_STREAM_CHUNK_SIZE
    ) -> Generator[bytes, None, None]:
        """
        Stream decrypted file in chunks. Decrypts uploaded chunks on-the-fly.
        
        This uses the chunk metadata stored during upload to decrypt each
        encrypted chunk independently, enabling true streaming without loading
        the entire file into memory.
        
        Args:
            output_chunk_size: Size of output chunks to yield (default: 1MB)
            
        Yields:
            Decrypted data chunks
        """
        self._load_metadata_and_key()
        
        try:
            logger.info(f"Starting streaming download from S3: {self.s3_key}")
            
            # Get chunk metadata from S3 object (stored during upload)
            upload_chunk_size = self.metadata.get('chunk_size')
            total_chunks = self.metadata.get('totalchunks')
            
            if not upload_chunk_size or not total_chunks:
                # Fallback to full file decryption if no chunk metadata
                logger.warning("No chunk metadata found, falling back to full file decryption")
                response = s3.get_object(Bucket=self.bucket, Key=self.s3_key)
                encrypted_data = response['Body'].read()
                decrypted_data = self._decrypt_s3_chunk(encrypted_data)
                
                offset = 0
                while offset < len(decrypted_data):
                    yield decrypted_data[offset:offset + output_chunk_size]
                    offset += output_chunk_size
                return
            
            # Convert to integers (metadata values are strings)
            upload_chunk_size = int(upload_chunk_size)
            total_chunks = int(total_chunks)
            
            logger.info(f"Streaming {total_chunks} chunks of {upload_chunk_size} bytes each")
            
            # Calculate encrypted chunk size
            # Each chunk: 12 bytes (nonce) + upload_chunk_size + 16 bytes (GCM auth tag)
            encrypted_chunk_size = 12 + upload_chunk_size + 16
            
            # Buffer for accumulating decrypted data
            buffer = BytesIO()
            bytes_processed = 0
            
            for chunk_index in range(total_chunks):
                # Calculate byte range for this encrypted chunk in S3
                start_byte = chunk_index * encrypted_chunk_size
                
                # Last chunk might be smaller
                if chunk_index == total_chunks - 1:
                    # Read to end of file
                    range_header = f'bytes={start_byte}-'
                else:
                    end_byte = start_byte + encrypted_chunk_size - 1
                    range_header = f'bytes={start_byte}-{end_byte}'
                
                # Download this encrypted chunk from S3
                response = s3.get_object(
                    Bucket=self.bucket, 
                    Key=self.s3_key,
                    Range=range_header
                )
                
                encrypted_chunk = response['Body'].read()
                
                # Decrypt this chunk
                decrypted_chunk = self._decrypt_s3_chunk(encrypted_chunk)
                bytes_processed += len(decrypted_chunk)
                
                # Write to buffer
                buffer.write(decrypted_chunk)
                
                # Yield output chunks from buffer when we have enough data
                buffer.seek(0)
                buffered_data = buffer.read()
                
                # Yield complete output chunks
                offset = 0
                while offset + output_chunk_size <= len(buffered_data):
                    yield buffered_data[offset:offset + output_chunk_size]
                    offset += output_chunk_size
                
                # Keep remaining data in buffer for next iteration
                remaining_data = buffered_data[offset:]
                buffer = BytesIO()
                buffer.write(remaining_data)
            
            # Yield any remaining data in buffer
            buffer.seek(0)
            remaining = buffer.read()
            if remaining:
                yield remaining
                
            logger.info(f"Streaming complete: {bytes_processed} bytes decrypted from {total_chunks} chunks")
            
        except Exception as e:
            logger.exception(f"Failed during streaming: {e}")
            raise
    
    def get_decrypted_range(
        self, 
        start_byte: int, 
        end_byte: Optional[int] = None
    ) -> bytes:
        """
        Get a specific byte range from the decrypted file.
        Useful for HTTP range requests (e.g., video seeking).
        
        Note: Due to chunk-based encryption, we need to decrypt relevant chunks.
        This is more efficient than decrypting the entire file.
        
        Args:
            start_byte: Starting byte position (0-indexed) in decrypted file
            end_byte: Ending byte position (inclusive) in decrypted file. None means to end.
            
        Returns:
            Decrypted bytes for the requested range
        """
        self._load_metadata_and_key()
        
        try:
            upload_chunk_size = self.metadata.get('chunk_size')
            total_chunks = self.metadata.get('totalchunks')
            
            if not upload_chunk_size or not total_chunks:
                # Fallback: decrypt entire file
                full_data = self.get_full_decrypted_bytes()
                if end_byte is None:
                    return full_data[start_byte:]
                else:
                    return full_data[start_byte:end_byte + 1]
            
            upload_chunk_size = int(upload_chunk_size)
            total_chunks = int(total_chunks)
            
            # Determine which chunks contain the requested byte range
            start_chunk = start_byte // upload_chunk_size
            if end_byte is None:
                end_chunk = total_chunks - 1
                actual_end_byte = self._file_size - 1
            else:
                end_chunk = min(end_byte // upload_chunk_size, total_chunks - 1)
                actual_end_byte = end_byte
            
            logger.info(f"Range request: bytes {start_byte}-{actual_end_byte}, chunks {start_chunk}-{end_chunk}")
            
            # Calculate encrypted chunk size
            encrypted_chunk_size = 12 + upload_chunk_size + 16
            
            # Decrypt only the necessary chunks
            decrypted_chunks = []
            
            for chunk_index in range(start_chunk, end_chunk + 1):
                s3_start_byte = chunk_index * encrypted_chunk_size
                
                if chunk_index == total_chunks - 1:
                    range_header = f'bytes={s3_start_byte}-'
                else:
                    s3_end_byte = s3_start_byte + encrypted_chunk_size - 1
                    range_header = f'bytes={s3_start_byte}-{s3_end_byte}'
                
                response = s3.get_object(
                    Bucket=self.bucket,
                    Key=self.s3_key,
                    Range=range_header
                )
                
                encrypted_chunk = response['Body'].read()
                decrypted_chunk = self._decrypt_s3_chunk(encrypted_chunk)
                decrypted_chunks.append(decrypted_chunk)
            
            # Combine chunks
            combined_data = b''.join(decrypted_chunks)
            
            # Extract the exact byte range requested
            offset_in_first_chunk = start_byte % upload_chunk_size
            if end_byte is None:
                return combined_data[offset_in_first_chunk:]
            else:
                total_bytes_needed = actual_end_byte - start_byte + 1
                return combined_data[offset_in_first_chunk:offset_in_first_chunk + total_bytes_needed]
            
        except Exception as e:
            logger.exception(f"Failed to get range: {e}")
            raise
    
    def get_file_info(self) -> dict:
        """
        Get metadata information about the encrypted file.
        
        Returns:
            Dictionary with file information
        """
        self._load_metadata_and_key()
        
        return {
            's3_key': self.s3_key,
            'bucket': self.bucket,
            'encrypted_size': self._encrypted_file_size,
            'decrypted_size': self._file_size,
            'chunk_size': int(self.metadata.get('chunk_size', 0)),
            'total_chunks': int(self.metadata.get('totalchunks', 0)),
            'metadata': self.metadata,
        }

