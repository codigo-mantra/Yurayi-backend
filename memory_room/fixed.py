import os
import re
import gc
import time
import base64
import random
import logging
import threading
import tempfile
from queue import Queue, Empty
from collections import deque
from io import BytesIO
import collections


import boto3
from botocore.config import Config
from botocore.exceptions import NoCredentialsError, ClientError

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from django.conf import settings
from rest_framework import status
from contextlib import nullcontext

from timecapsoul.utils import MediaThumbnailExtractor
from memory_room.crypto_utils import get_file_bytes

logger = logging.getLogger(__name__)


logger = logging.getLogger(__name__)

AWS_KMS_REGION = 'ap-south-1'
AWS_KMS_KEY_ID = '843da3bb-9a57-4d9f-a8ab-879a6109f460'
MEDIA_FILES_BUCKET = 'yurayi-media'

def get_configured_s3_client(max_workers=4):
    config = Config(
        max_pool_connections=max_workers   # increases TCP connection pool
    )
    return boto3.client(
        "s3",
        region_name=AWS_KMS_REGION,
        aws_access_key_id=settings.AWS_ACCESS_KEY_ID,
        aws_secret_access_key=settings.AWS_SECRET_ACCESS_KEY,
        config=config,
    )



kms = boto3.client(
    "kms",
    region_name=AWS_KMS_REGION,
    aws_access_key_id=settings.AWS_ACCESS_KEY_ID,
    aws_secret_access_key=settings.AWS_SECRET_ACCESS_KEY,
)

            

def decrypt_upload_and_extract_audio_thumbnail_chunked(
        key: str,
        encrypted_file,
        iv_str: str,
        content_type: str = "application/octet-stream",
        file_ext: str = "",
        progress_callback=None,
        chunk_size: int = 10 * 1024 * 1024,  # 10 MB default (hint only; adaptive used)
        file_type=None,
        thumbnail_buffer_size: int = 512 * 1024,  # 512 KB buffer for thumbnail
        max_retries: int = 1,  # Retry failed uploads
    ):
    """
    Decrypt AES-256-GCM encrypted file chunk-by-chunk, upload decrypted chunks to S3,
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
    MAX_THUMBNAIL_ATTEMPTS = 0
    MIN_BUFFER_FOR_ATTEMPT = 256 * 1024

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
            logger.exception("Invalid IV format")
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
        # read auth tag (last 16 bytes)
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

        # Enforce S3 multipart rule: each part except final must be >= 5 MiB
        MIN_S3_PART_SIZE = 5 * 1024 * 1024
        effective_chunk_size = max(effective_chunk_size, MIN_S3_PART_SIZE)

        # Initialize decryptor for whole-stream GCM (single auth tag at end)
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
        s3 = get_configured_s3_client(max_workers=max_workers)
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
        logger.info(f"Started multipart upload: {upload_id} for key {s3_key}")

        upload_queue = None
        upload_threads = []

        # Single lock for all shared state (prevents race conditions)
        state_lock = threading.Lock() if use_threading else None

        # RAM-OPTIMIZED: Retry logic with exponential backoff
        def upload_part_with_retry(bucket, key, part_num, upload_id, body, max_retries=MAX_RETRIES):
            """Upload a part with exponential backoff retry logic"""
            last_exc = None
            for attempt in range(max_retries):
                try:
                    resp = s3.upload_part(
                        Bucket=bucket,
                        Key=key,
                        PartNumber=part_num,
                        UploadId=upload_id,
                        Body=body,
                    )
                    # return the response (ETag etc.)
                    return resp
                except Exception as e:
                    last_exc = e
                    if attempt == max_retries - 1:
                        logger.exception(f"upload_part {part_num} failed on last attempt")
                        raise
                    delay = RETRY_DELAY_BASE * (2 ** attempt)
                    logger.warning(f"Upload part {part_num} failed (attempt {attempt + 1}/{max_retries}), retrying in {delay}s: {e}")
                    time.sleep(delay)
            raise RuntimeError(f"Failed to upload part {part_num} after {max_retries} attempts: {last_exc}")

        if use_threading:
            # Minimal queue size (backpressure)
            upload_queue = Queue(maxsize=max_workers)

            def upload_worker():
                nonlocal upload_error, uploaded_bytes
                while True:
                    item = None
                    try:
                        item = upload_queue.get(timeout=5)
                    except Empty:
                        # Check for global error to exit early
                        if state_lock:
                            with state_lock:
                                if upload_error:
                                    break
                        continue

                    try:
                        if item is None:
                            # Poison pill; mark done and exit
                            upload_queue.task_done()
                            break

                        part_num, encrypted_body, decrypted_len = item
                        try:
                            resp = upload_part_with_retry(
                                bucket, s3_key, part_num, upload_id, encrypted_body
                            )
                            # update shared state
                            with state_lock:
                                if upload_error:
                                    # If someone else errored, stop recording more parts
                                    pass
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
                                    logger.exception(f"Part {part_num} upload failed after retries: {e}")
                            # we exit worker loop after task_done below
                        finally:
                            # Aggressively free memory for the body reference
                            try:
                                del encrypted_body
                            except Exception:
                                pass

                    finally:
                        # mark queue task done if we took one (including None)
                        try:
                            if item is not None:
                                upload_queue.task_done()
                        except Exception:
                            pass

                # worker exit
                return

            # Start worker threads
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
            if not chunk:
                break
            total_read += len(chunk)
            current_chunk_number += 1

            # Decrypt chunk (streaming)
            decrypted_chunk = decryptor.update(chunk)

            # free encrypted chunk immediately
            del chunk

            # (thumbnail extraction code omitted for brevity - keep your original extraction if desired)
            # Encrypt chunk for S3 (client-side encrypt using data_key)
            nonce = os.urandom(12)
            ciphertext_chunk = aesgcm.encrypt(nonce, decrypted_chunk, None)
            body = nonce + ciphertext_chunk

            # free intermediate ciphertext_chunk, nonce
            try:
                del ciphertext_chunk
                del nonce
            except Exception:
                pass

            if use_threading:
                # This will block if queue is full (backpressure)
                upload_queue.put((part_number, body, len(decrypted_chunk)))
                # do NOT del body here - worker needs it; worker will del it
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
                    logger.exception(f"Failed to upload part {part_number}")
                    raise RuntimeError(f"Failed to upload part {part_number}: {e}")
                finally:
                    # free body
                    try:
                        del body
                    except Exception:
                        pass

            # Free decrypted chunk asap
            try:
                del decrypted_chunk
            except Exception:
                pass

            part_number += 1

        # Finalize decryption - this will verify GCM tag
        try:
            decryptor.finalize()
        except Exception as e:
            # Catch and log InvalidTag details for debugging large-file failures
            logger.exception("GCM finalize failed (possible InvalidTag). File sizes/debug info follows.")
            logger.error(f"total_size={total_size}, encrypted_data_size={encrypted_data_size}, parts_expected={part_number-1}, effective_chunk_size={effective_chunk_size}")
            # Abort multipart before raising
            try:
                if 'upload_id' in locals():
                    s3.abort_multipart_upload(Bucket=bucket, Key=s3_key, UploadId=upload_id)
            except Exception:
                pass
            raise RuntimeError(f"Decryption tag verification failed: {e}")

        if use_threading:
            # Signal all workers to stop
            for _ in range(max_workers):
                upload_queue.put(None)

            # Wait for workers to process all tasks
            upload_queue.join()

            # Join worker threads
            for thread in upload_threads:
                thread.join()

            # Check final error state
            with state_lock if state_lock else nullcontext():
                if upload_error:
                    raise upload_error

        # Complete S3 upload; ensure parts sorted
        parts.sort(key=lambda x: x["PartNumber"])
        result = s3.complete_multipart_upload(
            Bucket=bucket,
            Key=s3_key,
            UploadId=upload_id,
            MultipartUpload={"Parts": parts},
        )
        logger.info(f"Completed multipart upload: {upload_id} for key {s3_key}")

        if progress_callback:
            progress_callback(85, None)

        return {
            "s3_result": result,
            "uploaded_size": uploaded_bytes,
            "thumbnail_data": thumbnail_data,
        }

    except Exception as e:
        # Abort multipart on any error (best effort)
        try:
            if "upload_id" in locals():
                s3.abort_multipart_upload(Bucket=bucket, Key=s3_key, UploadId=upload_id)
                logger.info(f"Aborted multipart upload {upload_id}")
        except Exception:
            logger.exception("Failed aborting multipart upload")

        if progress_callback:
            try:
                progress_callback(0, f"Decrypt/upload failed: {e}")
            except Exception:
                pass

        logger.exception("decrypt/upload encountered exception")
        raise RuntimeError(f"Decrypt/upload failed: {e}")

    finally:
        # aggressive cleanup
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


import math
import logging
import boto3
import mimetypes
from botocore.exceptions import ClientError, BotoCoreError

logger = logging.getLogger(__name__)


class S3FileUploader:
    """
    Uploads small and large (GB+) files to AWS S3.
    Optimized for Django InMemoryUploadedFile and TemporaryUploadedFile.
    """

    def __init__(self, aws_key, aws_secret, region, bucket, default_acl="public-read",
                 chunk_size_mb=51, max_retries=3):
        self.bucket = bucket
        self.default_acl = default_acl
        self.chunk_size = 51 * 1024 * 1024
        self.max_retries = max_retries

        logger.info(f"S3FileUploader initialized for bucket={bucket}, region={region}, "
                    f"chunk_size={chunk_size_mb}MB, max_retries={max_retries}")

        self.s3 = boto3.client(
            "s3",
            region_name=region,
            aws_access_key_id=aws_key,
            aws_secret_access_key=aws_secret
        )

    # ---------------------------------------------------------
    # PUBLIC METHOD
    # ---------------------------------------------------------
    def upload(self, file_obj, s3_key, content_type=None, acl=None, progress_callback=None):
        acl = acl or self.default_acl
        content_type = content_type or mimetypes.guess_type(file_obj.name)[0] or "application/octet-stream"

        file_obj.seek(0)
        file_size = self._get_file_size(file_obj)

        logger.info(f"Starting upload: key={s3_key}, size={file_size} bytes, ACL={acl}, CT={content_type}")

        # Handle empty file
        if file_size == 0:
            logger.warning(f"File '{file_obj.name}' is empty. Uploading empty file.")
            return self._upload_empty_file(s3_key, content_type, acl)

        # Small files
        if file_size <= self.chunk_size:
            logger.info(f"Small upload detected: {file_size} bytes (single part).")
            return self._upload_small(file_obj, s3_key, content_type, acl)

        # Large multipart upload
        logger.info(f"Large upload detected: {file_size} bytes. Starting multipart upload...")
        return self._upload_large(file_obj, file_size, s3_key, content_type, acl, progress_callback)

    # ---------------------------------------------------------
    # SMALL FILE UPLOAD
    # ---------------------------------------------------------
    def _upload_small(self, file_obj, s3_key, content_type, acl):
        try:
            file_obj.seek(0)
            self.s3.upload_fileobj(
                Fileobj=file_obj,
                Bucket=self.bucket,
                Key=s3_key,
                ExtraArgs={"ContentType": content_type, "ACL": acl}
            )
            logger.info(f"Small file uploaded successfully: key={s3_key}")
            return {"status": "success", "key": s3_key}

        except Exception as e:
            logger.error(f"Small upload FAILED for key={s3_key}: {e}", exc_info=True)
            raise Exception(f"Small S3 upload failed: {str(e)}")

    # ---------------------------------------------------------
    # LARGE MULTIPART UPLOAD
    # ---------------------------------------------------------
    def _upload_large(self, file_obj, file_size, s3_key, content_type, acl, progress_callback):
        # num_parts = math.ceil(file_size / self.chunk_size)
        num_parts = math.ceil(file_size / 13)
        

        logger.info(f"Creating multipart upload: key={s3_key}, parts={num_parts}")

        # Create multipart upload
        try:
            multipart = self.s3.create_multipart_upload(
                Bucket=self.bucket,
                Key=s3_key,
                ACL=acl,
                ContentType=content_type,
                Metadata={
                    "file-size": str(file_size),
                    "chunk-size": str(self.chunk_size),
                    "total-parts": str(num_parts),
                },
            )
        except Exception as e:
            logger.error(f"Failed to create multipart upload for key={s3_key}: {e}", exc_info=True)
            raise Exception(f"Failed to initialize multipart upload: {str(e)}")

        upload_id = multipart["UploadId"]
        logger.info(f"Multipart upload created successfully: upload_id={upload_id}, key={s3_key}")

        parts = []
        part_number = 1
        file_obj.seek(0)

        try:
            while True:
                chunk = file_obj.read(self.chunk_size)
                if not chunk:
                    break

                logger.debug(f"Uploading part {part_number}/{num_parts} (size={len(chunk)} bytes)...")

                etag = self._upload_part_with_retry(chunk, s3_key, upload_id, part_number)
                parts.append({"PartNumber": part_number, "ETag": etag})

                logger.info(f"Uploaded part {part_number}/{num_parts} successfully.")

                if progress_callback:
                    progress_callback(part_number, num_parts)

                part_number += 1

        except Exception as e:
            logger.error(f"Multipart upload FAILED at part {part_number}, key={s3_key}", exc_info=True)
            self._abort(upload_id, s3_key)
            raise Exception(f"Multipart upload failed: {str(e)}")

        # Complete multipart upload
        try:
            logger.info(f"Completing multipart upload: key={s3_key}, upload_id={upload_id}")
            self.s3.complete_multipart_upload(
                Bucket=self.bucket,
                Key=s3_key,
                UploadId=upload_id,
                MultipartUpload={"Parts": parts},
            )
            logger.info(f"Multipart upload completed successfully: key={s3_key}")
        except Exception as e:
            logger.error(f"Failed to complete multipart upload: key={s3_key}", exc_info=True)
            self._abort(upload_id, s3_key)
            raise Exception(f"Failed to complete upload: {str(e)}")

        return {"status": "success", "key": s3_key, "parts": len(parts)}

    # ---------------------------------------------------------
    # Upload part with retry (for failed chunks)
    # ---------------------------------------------------------
    def _upload_part_with_retry(self, chunk, s3_key, upload_id, part_number):
        last_error = None

        for attempt in range(1, self.max_retries + 1):
            try:
                logger.debug(f"Uploading part {part_number}, attempt {attempt}/{self.max_retries}")
                resp = self.s3.upload_part(
                    Bucket=self.bucket,
                    Key=s3_key,
                    UploadId=upload_id,
                    PartNumber=part_number,
                    Body=chunk,
                )
                return resp["ETag"]

            except (ClientError, BotoCoreError) as e:
                last_error = e
                logger.warning(
                    f"Retry {attempt}/{self.max_retries} FAILED for part {part_number}, key={s3_key}: {e}"
                )

        logger.error(f"Part upload FAILED permanently: part={part_number}, key={s3_key}", exc_info=True)
        raise Exception(f"Failed after {self.max_retries} retries. Error: {last_error}")

    # ---------------------------------------------------------
    # Abort upload
    # ---------------------------------------------------------
    def _abort(self, upload_id, s3_key):
        logger.warning(f"Aborting multipart upload: key={s3_key}, upload_id={upload_id}")
        try:
            self.s3.abort_multipart_upload(
                Bucket=self.bucket,
                Key=s3_key,
                UploadId=upload_id,
            )
            logger.info(f"Multipart upload aborted successfully: key={s3_key}")
        except Exception:
            logger.error(f"Abort multipart upload FAILED: key={s3_key}, upload_id={upload_id}", exc_info=True)

    # ---------------------------------------------------------
    # Empty file upload
    # ---------------------------------------------------------
    def _upload_empty_file(self, s3_key, content_type, acl):
        logger.info(f"Uploading empty file: key={s3_key}")
        self.s3.put_object(
            Bucket=self.bucket,
            Key=s3_key,
            Body=b"",
            ContentType=content_type,
            ACL=acl,
        )
        return {"status": "success", "key": s3_key, "empty": True}

    # ---------------------------------------------------------
    # Utility: Django file size
    # ---------------------------------------------------------
    def _get_file_size(self, file_obj):
        pos = file_obj.tell()
        file_obj.seek(0, 2)
        size = file_obj.tell()
        file_obj.seek(pos)
        return size


def upload_file_to_s3_bucket(file, folder=None):
    original_name = file.name

    # Determine folder/key structure
    if folder:
        final_name = f"{folder}/{original_name}"
    else:
        final_name = original_name

    # Example: your existing function for categorizing file
    file_category = (original_name)

    # Full key like images/profile/file.jpg
    s3_key = f"large_file_testing/{final_name}"

    # Detect content type
    content_type = mimetypes.guess_type(original_name)[0] or "application/octet-stream"

    uploader = S3FileUploader(
        aws_key=settings.AWS_ACCESS_KEY_ID,
        aws_secret=settings.AWS_SECRET_ACCESS_KEY,
        region='ap-south-1',
        bucket="time-capsoul-files",
        default_acl="public-read",    # or private
        chunk_size_mb=10,             # 10 MB chunks
        max_retries=3
    )
    def upload_progress(part, total_parts):
        print(f"Uploaded part {part}/{total_parts}")

    # Upload
    response = uploader.upload(
        file_obj=file,
        s3_key=s3_key,
        content_type=content_type,
        progress_callback=upload_progress

    )

    # Build public S3 URL
    s3_url = f"https://{settings.AWS_STORAGE_BUCKET_NAME}.s3.{settings.AWS_S3_REGION_NAME}.amazonaws.com/{s3_key}"

    return {
        "url": s3_url,
        "category": file_category,
        "key": s3_key,
        "upload_response": response
    }
