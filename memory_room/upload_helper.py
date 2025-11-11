import os
import base64
import tempfile
from typing import Optional, Callable
import gc
import logging

import boto3
from django.conf import settings
from timecapsoul.utils import MediaThumbnailExtractor

from boto3.s3.transfer import TransferConfig
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend
from botocore.config import Config
from memory_room.media_helper import ChunkedDecryptor


logger = logging.getLogger(__name__)

AWS_KMS_REGION = 'ap-south-1'
AWS_KMS_KEY_ID = '843da3bb-9a57-4d9f-a8ab-879a6109f460'
MEDIA_FILES_BUCKET = 'yurayi-media'


boto_config = Config(
    retries={
        'max_attempts': 5,
        'mode': 'adaptive'  # Uses exponential backoff
    },
    max_pool_connections=50,
)

s3 = boto3.client(
    's3',
    region_name=AWS_KMS_REGION,
    aws_access_key_id=settings.AWS_ACCESS_KEY_ID,
    aws_secret_access_key=settings.AWS_SECRET_ACCESS_KEY,
    config=boto_config
)

kms = boto3.client(
    "kms",
    region_name=AWS_KMS_REGION,
    aws_access_key_id=settings.AWS_ACCESS_KEY_ID,
    aws_secret_access_key=settings.AWS_SECRET_ACCESS_KEY,
)


import os
import base64
import tempfile
import threading
from queue import Queue, Empty
from io import BytesIO
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import time
import logging

logger = logging.getLogger(__name__)



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
    Decrypt AES-256-GCM encrypted file chunk-by-chunk, upload decrypted chunks to S3 with AESGCM encryption,
    and extract embedded audio/video thumbnail while streaming.
    Optimized for fast upload with minimal RAM usage, retry logic, and race condition fixes.
    """

    bucket = MEDIA_FILES_BUCKET
    parts = []
    uploaded_bytes = 0
    thumbnail_data = None
    upload_error = None
    buffer_for_thumbnail = BytesIO()
    temp_decrypted_path = None
    
    # Thumbnail extraction control variables
    thumbnail_extracted = False
    thumbnail_attempts = 0
    MAX_THUMBNAIL_ATTEMPTS = 3
    MIN_BUFFER_FOR_ATTEMPT = 64 * 1024
    
    try:
        s3_key = key
        if progress_callback:
            progress_callback(14, "Initializing decryption...")

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
            effective_chunk_size = max(encrypted_data_size, 1 * 1024 * 1024)
            use_threading = False
            max_workers = 1
        elif encrypted_data_size <= 50 * 1024 * 1024:  # 5-50MB
            effective_chunk_size = 5 * 1024 * 1024
            use_threading = True
            max_workers = 2
        elif encrypted_data_size <= 200 * 1024 * 1024:  # 50-200MB
            effective_chunk_size = 8 * 1024 * 1024
            use_threading = True
            max_workers = 3
        else:  # > 200MB
            effective_chunk_size = 10 * 1024 * 1024
            use_threading = True
            max_workers = 4

        # Initialize decryptor
        cipher = Cipher(algorithms.AES(key_bytes), modes.GCM(iv, auth_tag), backend=default_backend())
        decryptor = cipher.decryptor()

        if progress_callback:
            progress_callback(18, "Starting chunked decrypt & upload...")

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
        # FIX: Always create locks for thread-safe operations
        parts_lock = threading.Lock()
        error_lock = threading.Lock()

        # OPTIMIZATION: Create temp file for thumbnail extraction fallback
        if file_type in ['video', 'audio']:
            temp_decrypted_path = tempfile.mktemp(suffix=file_ext)

        if use_threading:
            upload_queue = Queue(maxsize=max_workers * 2)

            def upload_worker():
                nonlocal upload_error, uploaded_bytes
                MAX_RETRIES = 3
                
                while True:
                    item = None
                    try:
                        item = upload_queue.get(timeout=1)
                    except Empty:
                        # FIX: Check for errors from other threads
                        with error_lock:
                            if upload_error:
                                break
                        continue
                    
                    # FIX: Only call task_done() once per get(), in a single finally block
                    try:
                        if item is None:
                            break
                        
                        part_num, encrypted_body, decrypted_len = item
                        
                        # FIX: Retry logic for failed parts
                        upload_succeeded = False
                        for attempt in range(MAX_RETRIES):
                            try:
                                resp = s3.upload_part(
                                    Bucket=bucket,
                                    Key=s3_key,
                                    PartNumber=part_num,
                                    UploadId=upload_id,
                                    Body=encrypted_body,
                                )
                                # FIX: Proper locking for shared state
                                with parts_lock:
                                    parts.append({"ETag": resp["ETag"], "PartNumber": part_num})
                                    uploaded_bytes += decrypted_len

                                upload_succeeded = True
                                if progress_callback:
                                    progress_callback(45, 'File upload completed')
                                break  # Success, exit retry loop
                                
                            except Exception as e:
                                if attempt < MAX_RETRIES - 1:
                                    time.sleep(2 ** attempt)  # Exponential backoff
                                    logger.warning(f"Retry {attempt + 1}/{MAX_RETRIES} for part {part_num}: {str(e)}")
                                else:
                                    # FIX: Thread-safe error handling
                                    logger.error(f"Part {part_num} failed after {MAX_RETRIES} attempts: {str(e)}")
                                    with error_lock:
                                        if not upload_error:
                                            upload_error = e
                        
                        # If upload failed after all retries, stop processing
                        if not upload_succeeded:
                            break
                            
                    finally:
                        # CRITICAL: Only call task_done() if we successfully got an item
                        if item is not None:
                            upload_queue.task_done()

            # Start multiple worker threads
            for _ in range(max_workers):
                thread = threading.Thread(target=upload_worker, daemon=True)
                thread.start()
                upload_threads.append(thread)

        # Process chunks
        part_number = 1
        total_read = 0

        while total_read < encrypted_data_size:
            # FIX: Early exit on error
            if use_threading:
                with error_lock:
                    if upload_error:
                        raise upload_error

            to_read = min(effective_chunk_size, encrypted_data_size - total_read)
            chunk = encrypted_file.read(to_read)
            total_read += len(chunk)

            decrypted_chunk = decryptor.update(chunk)

            # Thumbnail extraction with streaming buffer
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
                        if progress_callback:
                            progress_callback(65, 'Thumbnail extraction started')
                        
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
                            # if progress_callback:
                            #     progress_callback(
                            #         min(int((total_read / encrypted_data_size) * 100), 79),
                            #         "Thumbnail extracted successfully"
                            #     )
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

            # OPTIMIZATION: Write decrypted chunk to temp file for fallback extraction
            if temp_decrypted_path and not thumbnail_extracted:
                try:
                    with open(temp_decrypted_path, 'ab') as f:
                        f.write(decrypted_chunk)
                except Exception as e:
                    logger.warning(f"Failed to write to temp file: {e}")

            # Encrypt chunk for S3 upload with AESGCM
            nonce = os.urandom(12)
            ciphertext_chunk = aesgcm.encrypt(nonce, decrypted_chunk, None)
            body = nonce + ciphertext_chunk

            if use_threading:
                upload_queue.put((part_number, body, len(decrypted_chunk)))
            else:
                # FIX: Add retry logic for single-threaded uploads
                MAX_RETRIES = 3
                for attempt in range(MAX_RETRIES):
                    try:
                        resp = s3.upload_part(
                            Bucket=bucket,
                            Key=s3_key,
                            PartNumber=part_number,
                            UploadId=upload_id,
                            Body=body,
                        )
                        parts.append({"ETag": resp["ETag"], "PartNumber": part_number})
                        uploaded_bytes += len(decrypted_chunk)
                        # if progress_callback:
                        #     percent = int((uploaded_bytes / encrypted_data_size) * 100)
                        #     progress_callback(min(percent, 80), f"Uploaded chunk {part_number}")
                        break
                    except Exception as e:
                        if attempt < MAX_RETRIES - 1:
                            time.sleep(2 ** attempt)
                            logger.warning(f"Retry {attempt + 1}/{MAX_RETRIES} for part {part_number}: {str(e)}")
                        else:
                            raise

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
                thread.join(timeout=30)
            
            # Check for errors after all threads complete
            with error_lock:
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

        if progress_callback:
            progress_callback(70, "Upload completed. Finalizing thumbnail...")

        # FALLBACK: If thumbnail not extracted during streaming, try from temp file
        if not thumbnail_data and temp_decrypted_path and os.path.exists(temp_decrypted_path):
            extraction_attempts = []
            
            try:
                # if progress_callback:
                #     progress_callback(86, "Extracting thumbnail (fallback: from temp file)...")
                
                # Strategy 1: From file path
                try:
                    extractor = MediaThumbnailExtractor(file=temp_decrypted_path, file_ext=file_ext)
                    
                    if file_type == 'video':
                        thumbnail_data = extractor.extract_video_thumbnail()
                    else:
                        thumbnail_data = extractor.extract_audio_thumbnail()
                    
                    if thumbnail_data:
                        extraction_attempts.append("temp_file_success")
                        logger.info("Thumbnail extracted from temp file")
                    else:
                        extraction_attempts.append("temp_file_none")
                        
                except Exception as e:
                    extraction_attempts.append(f"temp_file_failed:{str(e)[:50]}")
                    logger.warning(f"Temp file extraction failed: {str(e)}")
                
                # Strategy 2: From bytes
                if not thumbnail_data:
                    try:
                        with open(temp_decrypted_path, 'rb') as f:
                            file_bytes = f.read()
                        
                        extractor = MediaThumbnailExtractor(file='', file_ext=file_ext)
                        
                        if file_type == 'video':
                            thumbnail_data = extractor.extract_video_thumbnail_from_bytes(
                                extension=file_ext,
                                decrypted_bytes=file_bytes,
                            )
                        else:
                            thumbnail_data = extractor.extract_audio_thumbnail_from_bytes(
                                extension=file_ext,
                                decrypted_bytes=file_bytes,
                            )
                        
                        if thumbnail_data:
                            extraction_attempts.append("temp_bytes_success")
                            logger.info("Thumbnail extracted from temp file bytes")
                        else:
                            extraction_attempts.append("temp_bytes_none")
                            
                    except Exception as e:
                        extraction_attempts.append(f"temp_bytes_failed:{str(e)[:50]}")
                        logger.warning(f"Temp bytes extraction failed: {str(e)}")
                
                # Strategy 3: From S3 (last resort)
                if not thumbnail_data:
                    try:
                        if progress_callback:
                            progress_callback(73, "Extracting thumbnail (fallback: from S3)...")
                        
                        temp_s3_path = tempfile.mktemp(suffix=f"_s3{file_ext}")
                        
                        with ChunkedDecryptor(s3_key) as decryptor:
                            with open(temp_s3_path, 'wb') as f:
                                for chunk in decryptor.decrypt_chunks():
                                    f.write(chunk)
                        
                        extractor = MediaThumbnailExtractor(file=temp_s3_path, file_ext=file_ext)
                        
                        if file_type == 'video':
                            thumbnail_data = extractor.extract_video_thumbnail()
                        else:
                            thumbnail_data = extractor.extract_audio_thumbnail()
                        
                        try:
                            os.remove(temp_s3_path)
                        except:
                            pass
                        
                        if thumbnail_data:
                            extraction_attempts.append("s3_success")
                            logger.info("Thumbnail extracted from S3")
                        else:
                            extraction_attempts.append("s3_none")
                            
                    except Exception as e:
                        extraction_attempts.append(f"s3_failed:{str(e)[:50]}")
                        logger.error(f"All thumbnail extraction attempts failed: {extraction_attempts}")
                
            except Exception as e:
                logger.error(f"Thumbnail fallback extraction failed: {str(e)}")

        if progress_callback:
            progress_callback(75, "Complete!")

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
        raise RuntimeError(f"Decrypt/upload failed: {e}")

    finally:
        try:
            if 'data_key_plain' in locals():
                del data_key_plain
        except Exception:
            pass
        try:
            if buffer_for_thumbnail:
                buffer_for_thumbnail.close()
        except Exception:
            pass
        try:
            if temp_decrypted_path and os.path.exists(temp_decrypted_path):
                os.remove(temp_decrypted_path)
        except Exception as e:
            logger.warning(f"Failed to cleanup temp file: {e}")