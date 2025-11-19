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
from memory_room.crypto_utils import get_file_bytes
from contextlib import nullcontext
import time


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



def decrypt_upload_and_extract_audio_thumbnail_chunked_working_test(
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
        if progress_callback:
            progress_callback(15, "Initializing decryption...")

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
            progress_callback(20, "Starting chunked decrypt & upload...")

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
                if progress_callback:
                    progress_callback(45, 'File upload completed')

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
                            progress_callback(35, 'Thumbnail extraction started')
                        
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
            progress_callback(65, "Upload completed. Finalizing thumbnail...")

        # FALLBACK: If thumbnail not extracted during streaming, try from temp file
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
                        thumbnail_data = extractor.extract_audio_thumbnail()
                    
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
        # FIX: Comprehensive cleanup to prevent memory leaks
        try:
            if 'data_key_plain' in locals():
                del data_key_plain
        except Exception:
            pass
        try:
            if buffer_for_thumbnail:
                buffer_for_thumbnail.close()
                buffer_for_thumbnail = None
        except Exception:
            pass
        try:
            # Free any remaining large objects
            if 'decrypted_chunk' in locals():
                del decrypted_chunk
            if 'ciphertext_chunk' in locals():
                del ciphertext_chunk
            if 'body' in locals():
                del body
        except Exception:
            pass


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
        max_retries: int = 3,  # Retry failed uploads
    ):
    """
    Decrypt AES-256-GCM encrypted file chunk-by-chunk, upload decrypted chunks to S3, 
    and extract embedded audio/video thumbnail while streaming.
    Optimized for minimal RAM usage with retry logic.
    
    IMPROVEMENTS:
    - Fixed race conditions with proper thread synchronization
    - Ultra-low RAM usage with streaming and aggressive cleanup
    - Max 4 workers for optimal performance/resource balance
    - Exponential backoff retry logic for failed uploads
    - Strategic thumbnail extraction at start, middle, and end (7 attempts)
    - Progress updates from 15-85% during processing
    """

    bucket = MEDIA_FILES_BUCKET
    parts = []
    uploaded_bytes = 0
    thumbnail_data = None
    upload_error = None
    buffer_for_thumbnail = None
    
    # Thread-safe thumbnail extraction
    thumbnail_extracted = False
    thumbnail_lock = threading.Lock()
    MAX_THUMBNAIL_ATTEMPTS = 7
    MIN_BUFFER_FOR_ATTEMPT = 256 * 1024
    
    # Strategic extraction points
    thumbnail_extraction_points = []
    
    # Retry configuration
    MAX_RETRIES = max_retries
    RETRY_DELAY_BASE = 1  # seconds
    
    try:
        s3_key = key
        if progress_callback:
            progress_callback(15, "Initializing decryption...")

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

        # RAM-OPTIMIZED: Conservative adaptive strategy (max 4 workers)
        if encrypted_data_size <= 5 * 1024 * 1024:  # < 5MB
            effective_chunk_size = max(encrypted_data_size, 2 * 1024 * 1024)
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
        else:  # > 200MB - CAPPED at 4 workers for RAM efficiency
            effective_chunk_size = 12 * 1024 * 1024  # Balanced chunk size
            use_threading = True
            max_workers = 4  # HARD CAP

        # Calculate strategic thumbnail extraction points
        if file_type in ['video', 'audio']:
            buffer_for_thumbnail = BytesIO()
            total_chunks = (encrypted_data_size + effective_chunk_size - 1) // effective_chunk_size
            
            # 7 attempts: 2 start, 3 middle, 2 end
            thumbnail_extraction_points = [
                1,  # Start - chunk 1
                2,  # Start - chunk 2
                total_chunks // 3,  # Early middle
                total_chunks // 2,  # Middle
                (total_chunks * 2) // 3,  # Late middle
                max(total_chunks - 1, 3),  # Near end
                total_chunks  # End
            ]
            thumbnail_extraction_points = sorted(set(thumbnail_extraction_points))[:MAX_THUMBNAIL_ATTEMPTS]
            logger.info(f"Thumbnail extraction planned at chunks: {thumbnail_extraction_points}")

        # Initialize decryptor
        cipher = Cipher(algorithms.AES(key_bytes), modes.GCM(iv, auth_tag), backend=default_backend())
        decryptor = cipher.decryptor()

        if progress_callback:
            progress_callback(17, "Starting chunked decrypt & upload...")

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
        
        # Single lock for all shared state (prevents race conditions)
        state_lock = threading.Lock() if use_threading else None

        # RAM-OPTIMIZED: Retry logic with exponential backoff
        def upload_part_with_retry(bucket, key, part_num, upload_id, body, max_retries=MAX_RETRIES):
            """Upload a part with exponential backoff retry logic"""
            for attempt in range(max_retries):
                try:
                    resp = s3.upload_part(
                        Bucket=bucket,
                        Key=key,
                        PartNumber=part_num,
                        UploadId=upload_id,
                        Body=body,
                    )
                    return resp
                except Exception as e:
                    if attempt == max_retries - 1:
                        raise  # Last attempt failed
                    
                    # Exponential backoff: 1s, 2s, 4s, 8s...
                    delay = RETRY_DELAY_BASE * (2 ** attempt)
                    logger.warning(f"Upload part {part_num} failed (attempt {attempt + 1}/{max_retries}), retrying in {delay}s: {str(e)}")
                    time.sleep(delay)
            
            raise RuntimeError(f"Failed to upload part {part_num} after {max_retries} attempts")

        if use_threading:
            # RAM-OPTIMIZED: Minimal queue size (only 1 slot per worker)
            upload_queue = Queue(maxsize=max_workers)

            def upload_worker():
                nonlocal upload_error, uploaded_bytes
                while True:
                    item = None
                    try:
                        item = upload_queue.get(timeout=2)
                        if item is None:
                            break
                        
                        part_num, encrypted_body, decrypted_len = item
                        
                        try:
                            # Upload with retry logic
                            resp = upload_part_with_retry(
                                bucket, s3_key, part_num, upload_id, encrypted_body
                            )
                            
                            # Thread-safe state update
                            with state_lock:
                                if upload_error:  # Stop if another thread failed
                                    break
                                    
                                parts.append({"ETag": resp["ETag"], "PartNumber": part_num})
                                uploaded_bytes += decrypted_len
                                
                                # Progress from 20-85
                                percent = 20 + int((uploaded_bytes / encrypted_data_size) * 65)
                                if progress_callback:
                                    progress_callback(min(percent, 85), None)
                                    
                        except Exception as e:
                            with state_lock:
                                if not upload_error:
                                    upload_error = e
                                    logger.error(f"Part {part_num} upload failed after retries: {str(e)}")
                            break
                            
                    except Empty:
                        continue
                    finally:
                        if item:
                            upload_queue.task_done()
                            # RAM-OPTIMIZED: Immediately free memory
                            del item
                            if 'encrypted_body' in locals():
                                del encrypted_body

            # Start worker threads (max 4)
            for _ in range(max_workers):
                thread = threading.Thread(target=upload_worker, daemon=True)
                thread.start()
                upload_threads.append(thread)

        # Process chunks
        part_number = 1
        total_read = 0
        current_chunk_number = 0

        while total_read < encrypted_data_size:
            # Check for errors before processing more
            if use_threading:
                with state_lock if state_lock else nullcontext():
                    if upload_error:
                        raise upload_error

            to_read = min(effective_chunk_size, encrypted_data_size - total_read)
            chunk = encrypted_file.read(to_read)
            total_read += len(chunk)
            current_chunk_number += 1

            # Decrypt chunk
            decrypted_chunk = decryptor.update(chunk)
            
            # RAM-OPTIMIZED: Free encrypted chunk immediately
            del chunk

            # Strategic thumbnail extraction
            if (not thumbnail_extracted and 
                file_type in ['video', 'audio'] and 
                buffer_for_thumbnail is not None and
                current_chunk_number in thumbnail_extraction_points):
                
                with thumbnail_lock:
                    if not thumbnail_extracted:
                        buffer_for_thumbnail.write(decrypted_chunk)
                        current_buffer_size = buffer_for_thumbnail.tell()
                        
                        if current_buffer_size >= MIN_BUFFER_FOR_ATTEMPT:
                            attempt_num = thumbnail_extraction_points.index(current_chunk_number) + 1
                            
                            try:
                                logger.info(f"Thumbnail extraction attempt {attempt_num} at chunk {current_chunk_number} (buffer: {current_buffer_size} bytes)")
                                
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
                                    # RAM-OPTIMIZED: Free buffer immediately
                                    buffer_for_thumbnail.close()
                                    buffer_for_thumbnail = None
                                    del buffer_data
                                    logger.info(f"Thumbnail extracted successfully on attempt {attempt_num}")
                                else:
                                    del buffer_data
                                    logger.info(f"Attempt {attempt_num} returned None")
                                    
                            except Exception as e:
                                logger.warning(f"Attempt {attempt_num} failed: {str(e)}")
                        
                        # RAM-OPTIMIZED: Aggressive buffer management
                        # Clear buffer if too large OR if we've passed half the attempts
                        if buffer_for_thumbnail:
                            should_clear = (
                                current_buffer_size > thumbnail_buffer_size * 2 or
                                attempt_num > MAX_THUMBNAIL_ATTEMPTS // 2
                            )
                            if should_clear:
                                buffer_for_thumbnail.seek(0)
                                buffer_for_thumbnail.truncate()
                                logger.info(f"Buffer cleared at {current_buffer_size} bytes (attempt {attempt_num})")

            # Encrypt chunk for S3 upload
            nonce = os.urandom(12)
            ciphertext_chunk = aesgcm.encrypt(nonce, decrypted_chunk, None)
            body = nonce + ciphertext_chunk
            
            # RAM-OPTIMIZED: Delete intermediate data
            del ciphertext_chunk, nonce

            if use_threading:
                # Block if queue full (natural backpressure)
                upload_queue.put((part_number, body, len(decrypted_chunk)))
                # Don't delete body - needed by worker thread
            else:
                # Direct upload with retry for single-threaded mode
                try:
                    resp = upload_part_with_retry(
                        bucket, s3_key, part_number, upload_id, body
                    )
                    parts.append({"ETag": resp["ETag"], "PartNumber": part_number})
                    uploaded_bytes += len(decrypted_chunk)
                    
                    # Progress from 20-85
                    percent = 20 + int((uploaded_bytes / encrypted_data_size) * 65)
                    if progress_callback:
                        progress_callback(min(percent, 85), None)
                except Exception as e:
                    raise RuntimeError(f"Failed to upload part {part_number}: {str(e)}")
                finally:
                    del body

            # RAM-OPTIMIZED: Free decrypted chunk
            del decrypted_chunk
            part_number += 1

        # Finalize decryption
        decryptor.finalize()

        if use_threading:
            # Signal all workers to stop
            for _ in range(max_workers):
                upload_queue.put(None)
            
            # Wait for all workers
            timeout = 60 if encrypted_data_size > 1024 * 1024 * 1024 else 30
            for thread in upload_threads:
                thread.join(timeout=timeout)
            
            # Check final error state
            with state_lock if state_lock else nullcontext():
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
                            thumbnail_data = extractor.extract_audio_thumbnail()
                        
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
            progress_callback(85, None)

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
        # RAM-OPTIMIZED: Aggressive cleanup
        try:
            del data_key_plain
        except Exception:
            pass
        try:
            if buffer_for_thumbnail:
                buffer_for_thumbnail.close()
        except Exception:
            pass
        try:
            del decryptor, aesgcm
        except Exception:
            pass
        try:
            if 'cipher' in locals():
                del cipher
        except Exception:
            pass


