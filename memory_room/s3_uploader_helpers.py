import base64
import boto3
import os
import threading
import time
import subprocess
from io import BytesIO
from queue import Queue, Empty
from typing import Optional, Callable, Dict, Any, List
from dataclasses import dataclass
import logging
from botocore.config import Config

from concurrent.futures import ThreadPoolExecutor, Future
from django.conf import settings
from timecapsoul.utils import MediaThumbnailExtractor


from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

logger = logging.getLogger(__name__)


AWS_KMS_REGION = 'ap-south-1'
AWS_KMS_KEY_ID = '843da3bb-9a57-4d9f-a8ab-879a6109f460'
MEDIA_FILES_BUCKET = 'yurayi-media'


# s3 = boto3.client("s3", region_name=AWS_KMS_REGION,
#     aws_access_key_id=settings.AWS_ACCESS_KEY_ID,
#     aws_secret_access_key=settings.AWS_SECRET_ACCESS_KEY,
# )

# s3_config = Config(
#     region_name=AWS_KMS_REGION,
#     max_pool_connections=20,  # adjust based on workload
#     connect_timeout=10,
#     read_timeout=90,
#     retries={'max_attempts': 3}  # reasonable retry count
# )

# s3 = boto3.client(
#     "s3",
#     aws_access_key_id=settings.AWS_ACCESS_KEY_ID,
#     aws_secret_access_key=settings.AWS_SECRET_ACCESS_KEY,
#     config=s3_config
# )

kms = boto3.client(
    "kms",
    region_name=AWS_KMS_REGION,
    aws_access_key_id=settings.AWS_ACCESS_KEY_ID,
    aws_secret_access_key=settings.AWS_SECRET_ACCESS_KEY,
)

import time
import random
import hashlib
from botocore.config import Config
from botocore.exceptions import ClientError

# Configure S3 client with connection pooling and timeouts
def get_configured_s3_client(max_workers):
    try:
        
        s3_config = Config(
            region_name=AWS_KMS_REGION,
            max_pool_connections=max_workers,  
            connect_timeout=10,
            read_timeout=90,
            retries={'max_attempts': 3}  # reasonable retry count
        )
        s3 = boto3.client(
            "s3",
            aws_access_key_id=settings.AWS_ACCESS_KEY_ID,
            aws_secret_access_key=settings.AWS_SECRET_ACCESS_KEY,
            config=s3_config
        )
        return s3
    except Exception as e:
        raise e
    

def decrypt_upload_and_extract_audio_thumbnail_chunked_updated(
        key: str,
        encrypted_file,
        iv_str: str,
        content_type: str = "application/octet-stream",
        file_ext: str = "",
        progress_callback=None,
        chunk_size: int = 10 * 1024 * 1024,
        file_type=None,
        thumbnail_buffer_size: int = 2 * 1024 * 1024,
        enable_adaptive_chunk_sizing: bool = True,
    ):
    """
    PRODUCTION-READY: Decrypt AES-256-GCM encrypted file chunk-by-chunk, 
    upload decrypted chunks to S3, and extract embedded audio/video thumbnail.
    
    Handles: race conditions, S3 rate limits, adaptive chunking, proper error handling.
    """

    bucket = MEDIA_FILES_BUCKET
    parts = []
    uploaded_bytes = 0
    thumbnail_data = None
    upload_errors = []  # Collect all errors, not just first
    upload_error_lock = threading.Lock()
    buffer_for_thumbnail = BytesIO()
    shutdown_event = threading.Event()  # Graceful shutdown signal
    
    # Thumbnail extraction configuration
    thumbnail_extracted = False
    thumbnail_attempts = 0
    MAX_THUMBNAIL_ATTEMPTS = 5
    MIN_BUFFER_FOR_ATTEMPT = 256 * 1024
    MAX_BUFFER_SIZE = 4 * 1024 * 1024
    thumbnail_lock = threading.Lock()
    thumbnail_thread = None
    thumbnail_extraction_active = False
    
    # Retry configuration with exponential backoff + jitter
    MAX_PART_RETRIES = 3
    RETRY_BACKOFF_BASE = 2
    MAX_JITTER = 1.0
    
    # S3 rate limiting (conservative defaults)
    rate_limiter = {
        'last_request_time': 0,
        'min_interval': 0.001,  # 1000 req/sec per prefix (conservative)
        'lock': threading.Lock()
    }
    
    # Network performance tracking for adaptive chunk sizing
    upload_stats = {
        'total_time': 0,
        'total_bytes': 0,
        'chunk_times': [],
        'lock': threading.Lock()
    }
    
    def rate_limited_s3_call(func, *args, **kwargs):
        """Apply rate limiting to S3 calls to avoid throttling"""
        with rate_limiter['lock']:
            now = time.time()
            time_since_last = now - rate_limiter['last_request_time']
            if time_since_last < rate_limiter['min_interval']:
                time.sleep(rate_limiter['min_interval'] - time_since_last)
            rate_limiter['last_request_time'] = time.time()
        
        return func(*args, **kwargs)
    
    def adaptive_chunk_size_adjustment(current_size, encrypted_data_size, stats):
        """Adjust chunk size based on network performance"""
        if not enable_adaptive_chunk_sizing or len(stats['chunk_times']) < 3:
            return current_size
        
        with stats['lock']:
            recent_times = stats['chunk_times'][-5:]  # Last 5 chunks
            avg_time = sum(recent_times) / len(recent_times)
        
        # Target: 2-5 seconds per chunk for optimal throughput
        if avg_time < 2.0 and current_size < 20 * 1024 * 1024:
            # Chunks uploading too fast, increase size
            new_size = int(current_size * 1.5)
            logger.info(f"Increasing chunk size: {current_size//1024//1024}MB → {new_size//1024//1024}MB (avg time: {avg_time:.2f}s)")
            return min(new_size, 20 * 1024 * 1024)
        elif avg_time > 5.0 and current_size > 5 * 1024 * 1024:
            # Chunks uploading too slow, decrease size
            new_size = int(current_size * 0.75)
            logger.info(f"Decreasing chunk size: {current_size//1024//1024}MB → {new_size//1024//1024}MB (avg time: {avg_time:.2f}s)")
            return max(new_size, 5 * 1024 * 1024)
        
        return current_size
    
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

        # Adaptive chunk size and threading strategy
        if encrypted_data_size <= 5 * 1024 * 1024:
            effective_chunk_size = max(encrypted_data_size, 1 * 1024 * 1024)
            use_threading = False
            max_workers = 1
        elif encrypted_data_size <= 50 * 1024 * 1024:
            effective_chunk_size = 5 * 1024 * 1024
            use_threading = True
            max_workers = 2
        elif encrypted_data_size <= 200 * 1024 * 1024:
            effective_chunk_size = 8 * 1024 * 1024
            use_threading = True
            max_workers = 3
        elif encrypted_data_size <= 1024 * 1024 * 1024:
            effective_chunk_size = 10 * 1024 * 1024
            use_threading = True
            max_workers = 4
        else:
            effective_chunk_size = 15 * 1024 * 1024
            use_threading = True
            max_workers = 5

        # Initialize S3 client with proper connection pooling
        s3 = get_configured_s3_client(max_workers)

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
        
        # FIXED: Check metadata size limit (2KB for S3)
        encrypted_key_b64 = base64.b64encode(data_key_encrypted).decode()
        if len(encrypted_key_b64) > 1500:  # Conservative limit
            logger.warning(f"Encrypted data key size: {len(encrypted_key_b64)} bytes (near 2KB S3 limit)")
            # Use alternative: store key in separate S3 object or use S3-SSE
            raise ValueError("Encrypted key too large for S3 metadata. Consider using S3-SSE-KMS instead.")

        # Prepare S3 multipart upload
        multipart_resp = rate_limited_s3_call(
            s3.create_multipart_upload,
            Bucket=bucket,
            Key=s3_key,
            ContentType=content_type,
            Metadata={
                "edk": encrypted_key_b64,
                "orig-content-type": content_type,
                "chunk-size": str(effective_chunk_size),
            }
        )
        upload_id = multipart_resp["UploadId"]
        logger.info(f"Started multipart upload: {upload_id}, file size: {encrypted_data_size // 1024 // 1024}MB")

        upload_queue = None
        upload_threads = []
        parts_lock = threading.Lock() if use_threading else None
        last_progress_update = [0]

        if use_threading:
            upload_queue = Queue(maxsize=max_workers * 4)

            def thumbnail_extraction_worker():
                """Background thread for non-blocking thumbnail extraction"""
                nonlocal thumbnail_data, thumbnail_extracted, thumbnail_extraction_active
                
                while not shutdown_event.is_set():
                    try:
                        with thumbnail_lock:
                            if thumbnail_extracted or not buffer_for_thumbnail:
                                break
                            
                            current_buffer_size = buffer_for_thumbnail.tell()
                            if current_buffer_size < MIN_BUFFER_FOR_ATTEMPT:
                                time.sleep(0.1)  # Wait for more data
                                continue
                            
                            # Copy buffer data for extraction
                            buffer_data = buffer_for_thumbnail.getvalue()
                        
                        # Extract outside lock to avoid blocking main thread
                        try:
                            logger.debug(f"Background extraction attempt with {current_buffer_size // 1024}KB buffer")
                            extractor = MediaThumbnailExtractor(file='', file_ext=file_ext)
                            
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
                                with thumbnail_lock:
                                    thumbnail_data = thumb
                                    thumbnail_extracted = True
                                    if buffer_for_thumbnail:
                                        buffer_for_thumbnail.close()
                                        buffer_for_thumbnail = None
                                logger.info(f"Background thumbnail extraction succeeded ({current_buffer_size // 1024}KB)")
                                break
                            else:
                                logger.debug(f"Background extraction returned None ({current_buffer_size // 1024}KB)")
                                time.sleep(0.5)  # Wait before retry
                                
                        except Exception as e:
                            logger.warning(f"Background thumbnail extraction failed: {str(e)[:200]}")
                            time.sleep(0.5)
                            
                    except Exception as e:
                        logger.error(f"Thumbnail worker error: {str(e)}", exc_info=True)
                        break
                
                thumbnail_extraction_active = False
                logger.debug("Thumbnail extraction worker shutting down")

            def upload_worker(worker_id):
                nonlocal uploaded_bytes
                while not shutdown_event.is_set():
                    try:
                        item = upload_queue.get(timeout=5)
                        if item is None:
                            break
                        
                        part_num, encrypted_body, decrypted_len = item
                        upload_start_time = time.time()
                        last_exception = None
                        
                        # Retry logic with exponential backoff + jitter
                        for attempt in range(MAX_PART_RETRIES):
                            if shutdown_event.is_set():
                                break
                            
                            try:
                                # FIXED: Rate-limited S3 call
                                resp = rate_limited_s3_call(
                                    s3.upload_part,
                                    Bucket=bucket,
                                    Key=s3_key,
                                    PartNumber=part_num,
                                    UploadId=upload_id,
                                    Body=encrypted_body
                                )
                                
                                upload_time = time.time() - upload_start_time
                                
                                with parts_lock:
                                    parts.append({"ETag": resp["ETag"], "PartNumber": part_num})
                                    uploaded_bytes += decrypted_len
                                    
                                    # Track performance for adaptive sizing
                                    with upload_stats['lock']:
                                        upload_stats['chunk_times'].append(upload_time)
                                        upload_stats['total_time'] += upload_time
                                        upload_stats['total_bytes'] += decrypted_len
                                    
                                    # Throttled progress updates
                                    current_percent = int((uploaded_bytes / encrypted_data_size) * 100)
                                    if progress_callback and current_percent - last_progress_update[0] >= 5:
                                        last_progress_update[0] = current_percent
                                        avg_speed = (uploaded_bytes / upload_stats['total_time']) / (1024 * 1024) if upload_stats['total_time'] > 0 else 0
                                        progress_callback(
                                            min(current_percent, 80), 
                                            f"Uploaded {uploaded_bytes // (1024*1024)}MB ({avg_speed:.1f}MB/s)"
                                        )
                                
                                logger.debug(f"Worker {worker_id}: Part {part_num} uploaded in {upload_time:.2f}s")
                                break  # Success
                                
                            except ClientError as e:
                                error_code = e.response.get('Error', {}).get('Code', '')
                                last_exception = e
                                
                                # FIXED: Handle S3 rate limiting specifically
                                if error_code in ['SlowDown', 'RequestLimitExceeded']:
                                    backoff = (RETRY_BACKOFF_BASE ** (attempt + 2)) + random.uniform(0, MAX_JITTER)
                                    logger.warning(f"Worker {worker_id}: S3 rate limit hit on part {part_num}, backing off {backoff:.2f}s")
                                    time.sleep(backoff)
                                    continue
                                elif error_code in ['RequestTimeout', 'InternalError']:
                                    backoff = (RETRY_BACKOFF_BASE ** attempt) + random.uniform(0, MAX_JITTER)
                                    logger.warning(f"Worker {worker_id}: Transient error on part {part_num} (attempt {attempt + 1}/{MAX_PART_RETRIES}), retrying in {backoff:.2f}s")
                                    time.sleep(backoff)
                                    continue
                                else:
                                    # Non-retryable error
                                    logger.error(f"Worker {worker_id}: Non-retryable S3 error on part {part_num}: {error_code} - {str(e)}")
                                    break
                                    
                            except Exception as e:
                                last_exception = e
                                if attempt < MAX_PART_RETRIES - 1:
                                    backoff = (RETRY_BACKOFF_BASE ** attempt) + random.uniform(0, MAX_JITTER)
                                    logger.warning(f"Worker {worker_id}: Retrying part {part_num} (attempt {attempt + 2}/{MAX_PART_RETRIES}) in {backoff:.2f}s: {str(e)[:200]}")
                                    time.sleep(backoff)
                                else:
                                    logger.error(f"Worker {worker_id}: Part {part_num} failed after {MAX_PART_RETRIES} attempts: {str(e)}")
                        
                        # FIXED: Store ALL errors, not just first
                        if last_exception:
                            with upload_error_lock:
                                upload_errors.append({
                                    'part': part_num,
                                    'worker': worker_id,
                                    'error': str(last_exception),
                                    'full_exception': last_exception
                                })
                            shutdown_event.set()  # Signal other workers to stop
                            
                    except Empty:
                        continue
                    except Exception as e:
                        logger.error(f"Worker {worker_id}: Unexpected error: {str(e)}", exc_info=True)
                        with upload_error_lock:
                            upload_errors.append({
                                'worker': worker_id,
                                'error': f"Worker exception: {str(e)}",
                                'full_exception': e
                            })
                        shutdown_event.set()
                        break
                    finally:
                        upload_queue.task_done()
                
                logger.debug(f"Worker {worker_id}: Shutting down")

            # Start worker threads (non-daemon for proper cleanup)
            for i in range(max_workers):
                thread = threading.Thread(target=upload_worker, args=(i,), daemon=False)
                thread.start()
                upload_threads.append(thread)
            
            # Start thumbnail extraction thread if needed
            if file_type in ['video', 'audio']:
                thumbnail_thread = threading.Thread(target=thumbnail_extraction_worker, daemon=False)
                thumbnail_thread.start()
                thumbnail_extraction_active = True
                logger.info("Started background thumbnail extraction thread")

        # Process chunks
        part_number = 1
        total_read = 0
        chunks_since_adjustment = 0

        while total_read < encrypted_data_size:
            # Check for shutdown signal (from worker errors)
            if shutdown_event.is_set():
                raise RuntimeError("Upload aborted due to worker errors")

            to_read = min(effective_chunk_size, encrypted_data_size - total_read)
            chunk = encrypted_file.read(to_read)
            total_read += len(chunk)

            decrypted_chunk = decryptor.update(chunk)

            # Thumbnail extraction (unchanged logic, optimized buffer)
            if not thumbnail_extracted and file_type in ['video', 'audio'] and buffer_for_thumbnail:
                current_buffer_size = buffer_for_thumbnail.tell()
                
                if current_buffer_size < MAX_BUFFER_SIZE:
                    buffer_for_thumbnail.write(decrypted_chunk[:MAX_BUFFER_SIZE - current_buffer_size])
                    current_buffer_size = buffer_for_thumbnail.tell()
                
                should_attempt = (
                    thumbnail_attempts < MAX_THUMBNAIL_ATTEMPTS and
                    (
                        (current_buffer_size >= MIN_BUFFER_FOR_ATTEMPT and 
                         current_buffer_size >= thumbnail_buffer_size) or
                        total_read >= encrypted_data_size or
                        current_buffer_size >= MAX_BUFFER_SIZE
                    )
                )
                
                if should_attempt:
                    thumbnail_attempts += 1
                    try:
                        if progress_callback and thumbnail_attempts == 1:
                            progress_callback(
                                min(int((total_read / encrypted_data_size) * 100), 79),
                                f"Extracting thumbnail ({current_buffer_size // 1024}KB buffer)..."
                            )
                        
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
                                    min(int((total_read / encrypted_data_size) * 100), 79),
                                    "Thumbnail extracted"
                                )
                            logger.info(f"Thumbnail extracted on attempt {thumbnail_attempts} ({current_buffer_size // 1024}KB)")
                        else:
                            logger.debug(f"Thumbnail attempt {thumbnail_attempts} returned None ({current_buffer_size // 1024}KB)")
                            
                    except Exception as e:
                        # FIXED: Don't truncate error messages in logs
                        logger.warning(f"Thumbnail attempt {thumbnail_attempts} failed ({current_buffer_size // 1024}KB): {str(e)}", exc_info=True)
                
                if (thumbnail_attempts >= MAX_THUMBNAIL_ATTEMPTS or current_buffer_size >= MAX_BUFFER_SIZE):
                    if not thumbnail_extracted and buffer_for_thumbnail:
                        logger.info(f"Stopping thumbnail extraction after {thumbnail_attempts} attempts ({current_buffer_size // 1024}KB)")
                        buffer_for_thumbnail.close()
                        buffer_for_thumbnail = None

            # Encrypt chunk for S3 upload
            nonce = os.urandom(12)
            ciphertext_chunk = aesgcm.encrypt(nonce, decrypted_chunk, None)
            body = nonce + ciphertext_chunk

            if use_threading:
                # FIXED: Add timeout to prevent deadlock
                try:
                    upload_queue.put((part_number, body, len(decrypted_chunk)), timeout=60)
                except Exception as e:
                    logger.error("Upload queue full after 60s timeout - workers may be stalled")
                    raise RuntimeError("Upload queue blocked - check network connectivity")
            else:
                resp = rate_limited_s3_call(
                    s3.upload_part,
                    Bucket=bucket,
                    Key=s3_key,
                    PartNumber=part_number,
                    UploadId=upload_id,
                    Body=body
                )
                parts.append({"ETag": resp["ETag"], "PartNumber": part_number})
                uploaded_bytes += len(decrypted_chunk)
                if progress_callback:
                    percent = int((uploaded_bytes / encrypted_data_size) * 100)
                    progress_callback(min(percent, 80), f"Uploaded chunk {part_number}")

            part_number += 1
            chunks_since_adjustment += 1
            
            # FIXED: Adaptive chunk sizing based on network performance
            if chunks_since_adjustment >= 10 and enable_adaptive_chunk_sizing:
                new_chunk_size = adaptive_chunk_size_adjustment(
                    effective_chunk_size, 
                    encrypted_data_size, 
                    upload_stats
                )
                if new_chunk_size != effective_chunk_size:
                    effective_chunk_size = new_chunk_size
                    chunks_since_adjustment = 0
            
            # Free memory immediately
            del decrypted_chunk, ciphertext_chunk, body, chunk

        # Finalize decryption (validates GCM tag)
        try:
            decryptor.finalize()
        except Exception as e:
            raise ValueError(f"Decryption verification failed - file may be corrupted: {str(e)}")

        if use_threading:
            # Signal all workers to stop
            logger.info("Signaling workers to shutdown...")
            for _ in range(max_workers):
                upload_queue.put(None)
            
            # Wait for upload workers with generous timeout
            timeout_per_worker = 300
            for i, thread in enumerate(upload_threads):
                thread.join(timeout=timeout_per_worker)
                if thread.is_alive():
                    logger.error(f"Worker {i} failed to complete within {timeout_per_worker}s")
                    shutdown_event.set()
            
            # Wait for thumbnail extraction thread if running
            if thumbnail_thread and thumbnail_thread.is_alive():
                logger.info("Waiting for thumbnail extraction to complete...")
                thumbnail_thread.join(timeout=10)  # Max 10s wait
                if thumbnail_thread.is_alive():
                    logger.warning("Thumbnail extraction still running, proceeding anyway")
            
            # FIXED: Check for ANY errors from workers
            with upload_error_lock:
                if upload_errors:
                    error_summary = f"{len(upload_errors)} upload errors occurred:\n"
                    for err in upload_errors[:5]:  # Show first 5
                        error_summary += f"  Part {err.get('part', 'N/A')}: {err['error'][:200]}\n"
                    if len(upload_errors) > 5:
                        error_summary += f"  ... and {len(upload_errors) - 5} more errors"
                    raise RuntimeError(error_summary)

        # Validate all parts uploaded
        if len(parts) != part_number - 1:
            raise RuntimeError(f"Part count mismatch: expected {part_number - 1}, got {len(parts)}")

        # Complete S3 upload
        parts.sort(key=lambda x: x["PartNumber"])
        result = rate_limited_s3_call(
            s3.complete_multipart_upload,
            Bucket=bucket,
            Key=s3_key,
            UploadId=upload_id,
            MultipartUpload={"Parts": parts}
        )

        if progress_callback:
            progress_callback(90, "Upload completed successfully!")

        total_time = upload_stats['total_time'] if upload_stats['total_time'] > 0 else 1
        avg_speed = (uploaded_bytes / total_time) / (1024 * 1024)
        logger.info(f"Upload completed: {uploaded_bytes // (1024*1024)}MB in {part_number - 1} parts, avg speed: {avg_speed:.2f}MB/s")

        return {
            "s3_result": result,
            "uploaded_size": uploaded_bytes,
            "thumbnail_data": thumbnail_data,
            "upload_stats": {
                "total_time": total_time,
                "avg_speed_mbps": avg_speed,
                "parts_count": len(parts)
            }
        }

    except Exception as e:
        # FIXED: Full error logging, truncated display
        logger.error(f"Upload failed: {str(e)}", exc_info=True)
        
        # FIXED: Proper cleanup - prevent race condition
        shutdown_event.set()  # Signal all threads immediately
        
        if "upload_id" in locals():
            try:
                # Wait briefly for workers to finish current uploads
                if use_threading and upload_threads:
                    time.sleep(2)
                    for thread in upload_threads:
                        if thread.is_alive():
                            logger.warning("Forcing abort while workers still active")
                            break
                
                s3.abort_multipart_upload(Bucket=bucket, Key=s3_key, UploadId=upload_id)
                logger.info(f"Aborted multipart upload {upload_id}")
            except Exception as abort_error:
                logger.error(f"Failed to abort upload {upload_id}: {str(abort_error)}")
        
        if progress_callback:
            # FIXED: Truncate error message for UI, but log full error
            display_error = str(e)[:150] + "..." if len(str(e)) > 150 else str(e)
            progress_callback(0, f"Upload failed: {display_error}")
        
        raise RuntimeError(f"Decrypt/upload failed: {e}")

    finally:
        # Cleanup
        try:
            del data_key_plain
        except Exception:
            pass
        try:
            if buffer_for_thumbnail:
                buffer_for_thumbnail.close()
        except Exception:
            pass
        
        # Ensure all threads are properly terminated
        if use_threading:
            shutdown_event.set()
            for thread in upload_threads:
                if thread.is_alive():
                    thread.join(timeout=5)
            if thumbnail_thread and thumbnail_thread.is_alive():
                thumbnail_thread.join(timeout=2)