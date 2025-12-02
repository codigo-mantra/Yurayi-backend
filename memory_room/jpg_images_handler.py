import os
import base64
import time
from io import BytesIO
import math
import logging
import boto3
import mimetypes
from django.conf import settings
import io
import boto3
from botocore.config import Config
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from PIL import Image, UnidentifiedImageError
import numpy as np
import cv2
from memory_room.crypto_utils import get_file_bytes
from memory_room.media_helper import ChunkedDecryptor
from timecapsoul.utils import MediaThumbnailExtractor

from queue import Queue, Empty

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend


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


s3 = get_configured_s3_client()

kms = boto3.client(
    "kms",
    region_name=AWS_KMS_REGION,
    aws_access_key_id=settings.AWS_ACCESS_KEY_ID,
    aws_secret_access_key=settings.AWS_SECRET_ACCESS_KEY,
)



def decrypt_full_file(key: str, encrypted_file, iv_str: str) -> bytes:
    """
    Fully decrypt AES-256-GCM encrypted file and return plaintext bytes.
    The file contains:  [ciphertext ...][16-byte GCM tag]
    """

    # ---------- Decode IV ----------
    try:
        iv_str = iv_str.strip()
        if all(c in "0123456789abcdefABCDEF" for c in iv_str):
            iv = bytes.fromhex(iv_str)
        else:
            iv = base64.b64decode(iv_str)
    except Exception as e:
        raise ValueError(f"Invalid IV format: {e}")

    # ---------- Decode AES-256 key ----------
    key_bytes = base64.b64decode(key) if isinstance(key, str) else key
    if len(key_bytes) != 32:
        raise ValueError(f"AES-256 key must be 32 bytes. Got {len(key_bytes)} bytes")

    # ---------- Read encrypted data ----------
    encrypted_file.seek(0, 2)
    total_size = encrypted_file.tell()
    if total_size < 16:
        raise ValueError("Encrypted file too short, missing GCM tag")

    encrypted_data_size = total_size - 16
    encrypted_file.seek(0)
    ciphertext = encrypted_file.read(encrypted_data_size)

    # ---------- Read GCM auth tag ----------
    encrypted_file.seek(encrypted_data_size)
    auth_tag = encrypted_file.read(16)

    # ---------- Create decryptor ----------
    cipher = Cipher(
        algorithms.AES(key_bytes),
        modes.GCM(iv, auth_tag),
        backend=default_backend()
    )
    decryptor = cipher.decryptor()

    # ---------- Decrypt ----------
    try:
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    except Exception as e:
        print(f'\n------Decryption failed: {e}------')
        raise ValueError(f"Decryption failed: {e}")

    return plaintext


def upload_file_to_s3_bucket(file, folder=None):
    original_name = file.name

    # Determine folder/key structure
    if folder:
        final_name = f"{folder}/{original_name}"
    else:
        final_name = original_name

    file_category = (original_name)
    s3_key = f"large_file_testing/{final_name}"
    content_type = mimetypes.guess_type(original_name)[0] or "application/octet-stream"
    
    # READ original file
    file.seek(0)
    original_bytes = file.read()

    # Process JPEG corruption
    if original_name.lower().endswith((".jpg", ".jpeg")):
        print("[LOG] Checking JPG corruption...")

        if is_image_corrupted(original_bytes):
            print("[LOG] JPG corrupted → Trying Pillow repair...")
            repaired = try_fix_corrupted_jpg(original_bytes)

            if repaired:
                final_bytes = repaired
            else:
                print("[LOG] Pillow failed → Trying OpenCV repair...")
                cv_fixed = opencv_repair_jpg(original_bytes)

                if cv_fixed:
                    final_bytes = cv_fixed
                else:
                    print("[LOG] OpenCV failed → Trying extreme header rebuild...")
                    extreme_fix = force_repair_jpeg(original_bytes)

                    if extreme_fix:
                        final_bytes = extreme_fix
                    else:
                        print("[LOG] All repair attempts failed → Re-encoding as last resort...")
                        try:
                            final_bytes = reencode_jpg(original_bytes)
                        except Exception:
                            raise Exception("Image totally unrecoverable.")
        else:
            # Image is not corrupted, use original
            final_bytes = original_bytes
    else:
        final_bytes = original_bytes

    # 🔥 KEY FIX: Create a new BytesIO buffer from final_bytes
    file_to_upload = BytesIO(final_bytes)
    file_to_upload.name = original_name  # Preserve the filename
    file_to_upload.seek(0)  # Reset position to start

    uploader = S3FileUploader(
        aws_key=settings.AWS_ACCESS_KEY_ID,
        aws_secret=settings.AWS_SECRET_ACCESS_KEY,
        region='ap-south-1',
        bucket="time-capsoul-files",
        default_acl="public-read",
        chunk_size_mb=10,
        max_retries=3
    )
    
    def upload_progress(part, total_parts):
        print(f"Uploaded part {part}/{total_parts}")

    # 🔥 Upload the repaired file_to_upload, not the original file
    response = uploader.upload(
        file_obj=file_to_upload,
        s3_key=s3_key,
        content_type=content_type,
        progress_callback=upload_progress
    )

    s3_url = f"https://{settings.AWS_STORAGE_BUCKET_NAME}.s3.{settings.AWS_S3_REGION_NAME}.amazonaws.com/{s3_key}"

    return {
        "url": s3_url,
        "category": file_category,
        "key": s3_key,
        "upload_response": response
    }
    


def is_image_corrupted(file_bytes: bytes) -> bool:
    """Multi-step strong corruption detection."""
    try:
        # Must start with valid JPEG signature
        if not (file_bytes.startswith(b"\xFF\xD8")):
            return True  # Not a valid JPEG start

        # Must end with valid JPEG end marker
        if not (file_bytes.endswith(b"\xFF\xD9")):
            return True  # File truncated or corrupted

        # Step 2: Try opening
        try:
            img = Image.open(io.BytesIO(file_bytes))
            img.verify()
        except Exception:
            return True

        # Step 3: Try full decode (very important)
        try:
            img = Image.open(io.BytesIO(file_bytes))
            img.load()
        except Exception:
            return True

        # If we reached here → safe
        return False

    except Exception:
        return True
    
def try_fix_corrupted_jpg(file_bytes: bytes) -> bytes | None:
    """
    Attempt JPG repair safely.
    Always re-open after verify() since Pillow destroys decoder state.
    """
    try:
        # Step 1: Validate but do NOT trust the decoded image
        try:
            img = Image.open(io.BytesIO(file_bytes))
            img.verify()  # corrupts the decoder state internally
        except Exception:
            # Still attempt repair (broken EXIF etc.)
            pass

        # Step 2: REOPEN clean decode (critical!)
        img = Image.open(io.BytesIO(file_bytes))
        img.load()

        # Step 3: Save repaired version
        output = io.BytesIO()
        img.save(output, format="JPEG", quality=95)

        repaired_bytes = output.getvalue()

        # Step 4: Make sure repaired version is not corrupted
        Image.open(io.BytesIO(repaired_bytes)).load()

        return repaired_bytes

    except Exception:
        return None


# Default Huffman tables used by most JPG encoders
DEFAULT_DHT = bytes.fromhex(
    "FFC4 01A2 0000 0105 0101 0101 0101 0101 0000 0000 0001"
    "0203 0405 0607 0809 0A0B 1000 0201 0303 0204 0305 0504"
    "0400 017D 0102 0300 0405 1106 1213 2107 3141 0814 5161"
    "2232 71 15 42 91 A1 B1 C1 09 23 33 52 F0 24 62 72 D1"
    "0A 16 34 E1 25 F1 17 18 19 1A 26 27 28 29 2A 35 36 37"
    "38 39 3A 43 44 45 46 47 48 49 4A 53 54 55 56 57 58 59"
    "5A 63 64 65 66 67 68 69 6A 73 74 75 76 77 78 79 7A 83"
    "84 85 86 87 88 89 8A 92 93 94 95 96 97 98 99 9A A2 A3"
    "A4 A5 A6 A7 A8 A9 AA B2 B3 B4 B5 B6 B7 B8 B9 BA C2 C3"
    "C4 C5 C6 C7 C8 C9 CA D2 D3 D4 D5 D6 D7 D8 D9 DA E2 E3"
    "E4 E5 E6 E7 E8 E9 EA F2 F3 F4 F5 F6 F7 F8 F9 FA"
)


def force_repair_jpeg(file_bytes: bytes) -> bytes | None:
    """
    Final-attempt JPEG recovery by rebuilding missing headers & markers.
    Works even when Pillow & OpenCV both fail.
    """
    try:
        # Ensure file begins with SOI
        if not file_bytes.startswith(b"\xFF\xD8"):
            file_bytes = b"\xFF\xD8" + file_bytes

        # Insert missing Huffman table if needed
        if b"\xFF\xC4" not in file_bytes:
            file_bytes = file_bytes.replace(b"\xFF\xDA", DEFAULT_DHT + b"\xFF\xDA")

        # Ensure ends with EOI
        if not file_bytes.endswith(b"\xFF\xD9"):
            file_bytes += b"\xFF\xD9"

        # Try decode now
        np_arr = np.frombuffer(file_bytes, np.uint8)
        decoded = cv2.imdecode(np_arr, cv2.IMREAD_COLOR)

        if decoded is None:
            return None

        success, encoded = cv2.imencode(".jpg", decoded)
        if not success:
            return None

        return encoded.tobytes()

    except Exception:
        return None


def reencode_jpg(file_bytes: bytes) -> bytes:
    """JPG → JPG rebuilding even if original has broken metadata."""
    img = Image.open(io.BytesIO(file_bytes)).convert("RGB")
    buff = io.BytesIO()
    img.save(buff, "JPEG", quality=90)
    return buff.getvalue()


def opencv_repair_jpg(file_bytes: bytes) -> bytes | None:
    """Try to repair corrupted JPEG using OpenCV."""
    try:
        np_arr = np.frombuffer(file_bytes, np.uint8)

        # Attempt decode ignoring errors
        img = cv2.imdecode(np_arr, cv2.IMREAD_COLOR)

        if img is None:
            return None  # OpenCV also failed

        # Re-encode as JPEG
        success, encoded = cv2.imencode(".jpg", img)

        if not success:
            return None

        return encoded.tobytes()

    except Exception as e:
        return None


def upload_encrypted_jpg_to_s3(
        s3_key: str,
        jpg_bytes: bytes,
        content_type: str = "image/jpeg",
        chunk_size: int = 6 * 1024 * 1024,     # 6MB default
        max_retries: int = 3,
        progress_callback = None
):
    """
    Encrypt JPG bytes with AES-GCM using KMS-generated data key and upload to S3
    using the same multipart upload + metadata format used in the main system.
    """

    bucket = MEDIA_FILES_BUCKET

    # ---------- 1. Generate KMS Data Key ----------
    kms_resp = kms.generate_data_key(KeyId=AWS_KMS_KEY_ID, KeySpec="AES_256")
    data_key_plain = kms_resp["Plaintext"]
    data_key_encrypted = kms_resp["CiphertextBlob"]

    aesgcm = AESGCM(data_key_plain)

    # ---------- 2. Initialize Multipart Upload ----------
    multipart = s3.create_multipart_upload(
        Bucket=bucket,
        Key=s3_key,
        ContentType=content_type,
        Metadata={
            "edk": base64.b64encode(data_key_encrypted).decode(),
            "orig-content-type": content_type,
            "chunk-size": str(chunk_size),
        },
    )
    upload_id = multipart["UploadId"]

    parts = []
    part_number = 1
    total_size = len(jpg_bytes)
    
    if progress_callback:
        progress_callback(35, 'Upload starting...')

    # ---------- 3. Retry Wrapper ----------
    def upload_part_retry(part_num, body):
        for attempt in range(max_retries):
            try:
                resp = s3.upload_part(
                    Bucket=bucket,
                    Key=s3_key,
                    PartNumber=part_num,
                    UploadId=upload_id,
                    Body=body,
                )
                return resp
            except Exception as e:
                if attempt == max_retries - 1:
                    raise e
                delay = 1 * (2 ** attempt)
                time.sleep(delay)

    # ---------- 4. Encrypt + Upload Multipart ----------
    offset = 0
    if progress_callback:
        progress_callback(55, None)
    
    while offset < total_size:

        chunk = jpg_bytes[offset: offset + chunk_size]
        offset += len(chunk)

        # AES-GCM encrypt chunk
        nonce = os.urandom(12)
        ciphertext = aesgcm.encrypt(nonce, chunk, None)
        encrypted_body = nonce + ciphertext

        # Upload with retry
        resp = upload_part_retry(part_number, encrypted_body)

        parts.append({"PartNumber": part_number, "ETag": resp["ETag"]})
        part_number += 1
        

        del chunk, ciphertext, encrypted_body

    # ---------- 5. Complete Multipart Upload ----------
    parts.sort(key=lambda x: x["PartNumber"])
    if progress_callback:
        progress_callback(65, None)

    result = s3.complete_multipart_upload(
        Bucket=bucket,
        Key=s3_key,
        UploadId=upload_id,
        MultipartUpload={"Parts": parts},
    )

    # Cleanup security-sensitive data
    del aesgcm, data_key_plain
    if progress_callback:
        progress_callback(80, None)

    return {
        "s3_result": result,
        "uploaded_size": total_size,
        "content_type": content_type,
    }


def jpg_images_handler(s3_key, encrypted_file,iv_str,file_ext,progress_callback=None):
    
    if file_ext in (".jpg", ".jpeg"):
        print("[LOG] Checking JPG corruption...")
        key_bytes = settings.ENCRYPTION_KEY
        final_bytes = None
        
        original_bytes = decrypt_full_file(
            encrypted_file=encrypted_file,
            iv_str=iv_str,
            key=key_bytes
            
        )
        if progress_callback:
            progress_callback(20, 'JPG File Decryted')
        if is_image_corrupted(original_bytes):
            print("[LOG] JPG corrupted → Trying Pillow repair...")
        
            repaired = try_fix_corrupted_jpg(original_bytes)
            
            if repaired:
                final_bytes = repaired
            else:
                print("[LOG] Pillow failed → Trying OpenCV repair...")
                cv_fixed = opencv_repair_jpg(original_bytes)

                if cv_fixed:
                    final_bytes = cv_fixed
                else:
                    print("[LOG] OpenCV failed → Trying extreme header rebuild...")
                    extreme_fix = force_repair_jpeg(original_bytes)

                    if extreme_fix:
                        final_bytes = extreme_fix
                    else:
                        print("[LOG] All repair attempts failed → Re-encoding as last resort...")
                        try:
                            final_bytes = reencode_jpg(original_bytes)
                        except Exception:
                            raise Exception("Image totally unrecoverable.")
                if progress_callback:
                    progress_callback(25, 'JPG File Fixed')

        else:
            if progress_callback:
                progress_callback(25, 'JPG File')
        
        if final_bytes is None:
            final_bytes = original_bytes
        
        res = upload_encrypted_jpg_to_s3(
            s3_key=s3_key,
            jpg_bytes=final_bytes,
            progress_callback = progress_callback
        )
        return res
        
                    
                    
        
import os
import base64
import time
import tempfile
import threading
import gc
import contextlib
from io import BytesIO
from queue import Empty
from concurrent.futures import ThreadPoolExecutor, as_completed, wait, FIRST_EXCEPTION, TimeoutError
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from contextlib import nullcontext

# Ensure these names are defined in your module scope: s3, kms, settings, AWS_KMS_KEY_ID, MEDIA_FILES_BUCKET, logger
# Also ensures MediaThumbnailExtractor, ChunkedDecryptor, get_file_bytes exist in scope if you need fallback thumbnail extraction.

def decrypt_upload_and_extract_audio_thumbnail_chunked_test(
        key: str,
        encrypted_file,
        iv_str: str,
        content_type: str = "application/octet-stream",
        file_ext: str = "",
        progress_callback=None,
        chunk_size: int = 10 * 1024 * 1024,
        file_type=None,
        thumbnail_buffer_size: int = 512 * 1024,
        max_retries: int = 3,
    ):

    bucket = MEDIA_FILES_BUCKET
    parts = []
    uploaded_bytes = 0
    thumbnail_data = None
    upload_id = None
    s3_key = key

    # Thread-safety
    parts_lock = threading.Lock()
    progress_lock = threading.Lock()

    # Thumbnail extraction config
    thumbnail_extracted = False
    thumbnail_lock = threading.Lock()
    MAX_THUMBNAIL_ATTEMPTS = 5
    MIN_BUFFER_FOR_ATTEMPT = 256 * 1024
    thumbnail_extraction_points = []

    RETRY_DELAY_BASE = 1

    # sentinel for upload task exception propagation
    upload_exception = None

    # local references we'll want to zero later
    data_key_plain = None
    aesgcm = None
    decryptor = None
    cipher = None

    # Helpers
    def safe_progress(percent, msg=None):
        if progress_callback:
            with progress_lock:
                try:
                    progress_callback(percent, msg)
                except Exception:
                    # don't let progress callback break the process
                    logger.exception("Progress callback failed")

    def upload_part_with_retry(bucket_, key_, part_num_, upload_id_, body_, max_retries_=max_retries):
        """Uploads part with exponential backoff. Returns dict with 'ETag'."""
        last_exc = None
        for attempt in range(max_retries_):
            try:
                resp = s3.upload_part(
                    Bucket=bucket_,
                    Key=key_,
                    PartNumber=part_num_,
                    UploadId=upload_id_,
                    Body=body_,
                )
                # resp typically contains 'ETag'
                return resp
            except Exception as e:
                last_exc = e
                if attempt == max_retries_ - 1:
                    logger.exception(f"upload_part failed for part {part_num_}")
                    raise
                delay = RETRY_DELAY_BASE * (2 ** attempt)
                logger.warning(f"upload_part part {part_num_} failed (attempt {attempt+1}/{max_retries_}), retry in {delay}s: {e}")
                time.sleep(delay)
        raise last_exc

    try:
        safe_progress(15, "Initializing decryption...")

        # Parse IV
        try:
            s = iv_str.strip()
            if all(c in "0123456789abcdefABCDEF" for c in s):
                iv = bytes.fromhex(s)
            else:
                iv = base64.b64decode(s)
        except Exception as e:
            raise ValueError(f"Invalid IV format: {e}")

        # Decode AES key (input encryption key for file)
        key_bytes = settings.ENCRYPTION_KEY
        if isinstance(key_bytes, str):
            key_bytes = base64.b64decode(key_bytes)
        if len(key_bytes) != 32:
            raise ValueError(f"Key must be 32 bytes for AES-256, got {len(key_bytes)} bytes")

        # Determine sizes and GCM tag location
        encrypted_file.seek(0, os.SEEK_END)
        total_size = encrypted_file.tell()
        if total_size < 16:
            raise ValueError("Encrypted file too short (missing GCM tag).")
        encrypted_data_size = total_size - 16

        # Read auth tag safely
        encrypted_file.seek(encrypted_data_size)
        auth_tag = encrypted_file.read(16)
        encrypted_file.seek(0)

        # Adaptive chunk sizing & worker policy (same heuristics as before)
        if encrypted_data_size <= 5 * 1024 * 1024:
            effective_chunk_size = max(encrypted_data_size, 2 * 1024 * 1024)
            max_workers = 1
        elif encrypted_data_size <= 50 * 1024 * 1024:
            effective_chunk_size = 5 * 1024 * 1024
            max_workers = 2
        elif encrypted_data_size <= 200 * 1024 * 1024:
            effective_chunk_size = 8 * 1024 * 1024
            max_workers = 3
        else:
            effective_chunk_size = 12 * 1024 * 1024
            max_workers = 4

        # thumbnail extraction planning
        if file_type in ("video", "audio"):
            buffer_for_thumbnail = BytesIO()
            total_chunks = (encrypted_data_size + effective_chunk_size - 1) // effective_chunk_size
            points = [
                1, 2,
                max(1, total_chunks // 3),
                max(1, total_chunks // 2),
                max(1, (total_chunks * 2) // 3),
                max(3, total_chunks - 1),
                max(1, total_chunks),
            ]
            thumbnail_extraction_points = sorted(set(points))[:MAX_THUMBNAIL_ATTEMPTS]
            logger.info(f"Thumbnail extraction planned at chunks: {thumbnail_extraction_points}")
        else:
            buffer_for_thumbnail = None

        # Initialize decryptor (same core logic)
        cipher = Cipher(algorithms.AES(key_bytes), modes.GCM(iv, auth_tag), backend=default_backend())
        decryptor = cipher.decryptor()

        safe_progress(20, "Starting chunked decrypt & upload...")

        # KMS data key generation (same scheme)
        resp = kms.generate_data_key(KeyId=AWS_KMS_KEY_ID, KeySpec="AES_256")
        data_key_plain = resp["Plaintext"]
        data_key_encrypted = resp["CiphertextBlob"]
        # use bytearray to be able to zero it later
        if not isinstance(data_key_plain, (bytes, bytearray)):
            data_key_plain = bytes(data_key_plain)
        data_key_ba = bytearray(data_key_plain)
        aesgcm = AESGCM(bytes(data_key_ba))  # AESGCM needs bytes

        # Prepare multipart upload
        metadata = {
            "edk": base64.b64encode(data_key_encrypted).decode(),
            "orig-content-type": content_type,
            "chunk-size": str(effective_chunk_size),
        }
        multipart_resp = s3.create_multipart_upload(Bucket=bucket, Key=s3_key, ContentType=content_type, Metadata=metadata)
        upload_id = multipart_resp["UploadId"]

        # We'll submit upload tasks to executor and collect futures.
        executor = ThreadPoolExecutor(max_workers=max_workers)
        futures = {}
        part_number = 1
        total_read = 0
        current_chunk_number = 0

        # We'll keep track of outstanding body objects to help delete them ASAP
        # mapping future -> body for explicit cleanup after completion
        future_to_body = {}

        try:
            while total_read < encrypted_data_size:
                to_read = min(effective_chunk_size, encrypted_data_size - total_read)
                chunk = encrypted_file.read(to_read)
                read_len = len(chunk)
                if read_len == 0:
                    break
                total_read += read_len
                current_chunk_number += 1

                # decrypt chunk
                decrypted_chunk = decryptor.update(chunk)

                # free encrypted chunk ASAP
                del chunk

                # thumbnail extraction (attempts at strategic points)
                if (not thumbnail_extracted and buffer_for_thumbnail is not None and current_chunk_number in thumbnail_extraction_points):
                    with thumbnail_lock:
                        if not thumbnail_extracted:
                            buffer_for_thumbnail.write(decrypted_chunk)
                            current_buf_size = buffer_for_thumbnail.tell()

                            if current_buf_size >= MIN_BUFFER_FOR_ATTEMPT:
                                attempt_num = thumbnail_extraction_points.index(current_chunk_number) + 1
                                try:
                                    logger.info(f"Thumbnail extraction attempt {attempt_num} at chunk {current_chunk_number} (buffer: {current_buf_size} bytes)")
                                    extractor = MediaThumbnailExtractor(file='', file_ext=file_ext)
                                    buf_data = buffer_for_thumbnail.getvalue()
                                    if file_type == 'video':
                                        thumb = extractor.extract_video_thumbnail_from_bytes(extension=file_ext, decrypted_bytes=buf_data)
                                    else:
                                        thumb = extractor.extract_audio_thumbnail_from_bytes(extension=file_ext, decrypted_bytes=buf_data)

                                    if thumb:
                                        thumbnail_data = thumb
                                        thumbnail_extracted = True
                                        buffer_for_thumbnail.close()
                                        buffer_for_thumbnail = None
                                        del buf_data
                                        logger.info(f"Thumbnail extracted successfully on attempt {attempt_num}")
                                    else:
                                        del buf_data
                                        logger.info(f"Attempt {attempt_num} returned None")
                                except Exception as e:
                                    logger.warning(f"Attempt {attempt_num} failed: {e}")

                            # clear buffer if too big
                            if buffer_for_thumbnail:
                                should_clear = (current_buf_size > thumbnail_buffer_size * 2)
                                if should_clear:
                                    buffer_for_thumbnail.seek(0)
                                    buffer_for_thumbnail.truncate()
                                    logger.info(f"Thumbnail buffer cleared at {current_buf_size} bytes")

                # encrypt for S3
                nonce = os.urandom(12)
                ciphertext_chunk = aesgcm.encrypt(nonce, decrypted_chunk, None)
                body = nonce + ciphertext_chunk

                # schedule upload
                if max_workers > 1:
                    # submit to executor
                    fut = executor.submit(upload_part_with_retry, bucket, s3_key, part_number, upload_id, body)
                    futures[fut] = part_number
                    future_to_body[fut] = body  # keep reference to free later
                else:
                    # single-threaded immediate upload (synchronous)
                    resp = upload_part_with_retry(bucket, s3_key, part_number, upload_id, body)
                    with parts_lock:
                        parts.append({"ETag": resp["ETag"], "PartNumber": part_number})
                        uploaded_bytes += len(decrypted_chunk)
                    # update progress
                    percent = 20 + int((uploaded_bytes / encrypted_data_size) * 65)
                    safe_progress(min(percent, 85), None)
                    # free body immediately
                    del body

                # free decrypted bytes ASAP
                del decrypted_chunk

                part_number += 1

            # All chunks submitted. Now collect results from futures (if any)
            if futures:
                # Wait for first exception or all succeed
                done, not_done = wait(futures.keys(), return_when=FIRST_EXCEPTION)

                # If any future raised, retrieve and raise to trigger abort+cleanup
                for fut in done:
                    exc = fut.exception()
                    pn = futures[fut]
                    if exc:
                        logger.error(f"Upload future for part {pn} raised: {exc}")
                        upload_exception = exc
                        break
                    else:
                        resp = fut.result()
                        with parts_lock:
                            parts.append({"ETag": resp["ETag"], "PartNumber": pn})
                            # we don't have decrypted len here; approximate progress by parts done
                            uploaded_bytes += effective_chunk_size if uploaded_bytes + effective_chunk_size <= encrypted_data_size else (encrypted_data_size - uploaded_bytes)
                        # free body reference to allow GC
                        if fut in future_to_body:
                            try:
                                del future_to_body[fut]
                            except Exception:
                                pass
                        percent = 20 + int((uploaded_bytes / encrypted_data_size) * 65)
                        safe_progress(min(percent, 85), None)

                if upload_exception:
                    # cancel remaining futures
                    for fut in not_done:
                        try:
                            fut.cancel()
                        except Exception:
                            pass
                    raise upload_exception

                # collect remaining futures normally
                for fut in not_done:
                    try:
                        resp = fut.result()
                        pn = futures[fut]
                        with parts_lock:
                            parts.append({"ETag": resp["ETag"], "PartNumber": pn})
                            uploaded_bytes += effective_chunk_size if uploaded_bytes + effective_chunk_size <= encrypted_data_size else (encrypted_data_size - uploaded_bytes)
                        # free body ref
                        if fut in future_to_body:
                            try:
                                del future_to_body[fut]
                            except Exception:
                                pass
                        percent = 20 + int((uploaded_bytes / encrypted_data_size) * 65)
                        safe_progress(min(percent, 85), None)
                    except Exception as e:
                        logger.exception("Upload future failed during final collection")
                        raise

        finally:
            # Always shutdown executor (wait for running tasks to finish or be cancelled)
            try:
                executor.shutdown(wait=False)
            except Exception:
                # Forceful cleanup attempt
                try:
                    executor.shutdown(wait=True)
                except Exception:
                    pass

        # finalize decryption - this will raise InvalidTag if tag mismatch
        try:
            decryptor.finalize()
        except Exception as e:
            # If tag invalid, we must abort upload and raise
            logger.exception("Decryptor finalize failed (invalid tag?)")
            raise

        # Complete multipart upload
        parts.sort(key=lambda x: x["PartNumber"])
        result = s3.complete_multipart_upload(Bucket=bucket, Key=s3_key, UploadId=upload_id, MultipartUpload={"Parts": parts})

        # If thumbnail missing for media, fallback to decrypting whole file or chunked decryptor paths
        if file_type in ("video", "audio") and not thumbnail_data:
            logger.info("Thumbnail extraction failed during streaming; attempting fallback")
            try:
                # Use secure temporary file, remove after usage
                with tempfile.NamedTemporaryFile(suffix=f"_s3{file_ext}", delete=False) as tf:
                    temp_s3_path = tf.name
                # Attempt to use ChunkedDecryptor if available
                with ChunkedDecryptor(s3_key) as chunked:
                        with open(temp_s3_path, 'wb') as f:
                            for chunk in chunked.decrypt_chunks():
                                f.write(chunk)
                        with open(temp_s3_path, 'rb') as f:
                            video_bytes = f.read()
                        extractor = MediaThumbnailExtractor(file='', file_ext=file_ext)
                        if file_type == 'video':
                            thumbnail_data = extractor.extract_video_thumbnail_ffmpeg(extension=file_ext, decrypted_bytes=video_bytes)
                            if not thumbnail_data:
                                thumbnail_data = extractor.extract_video_thumbnail_moviepy_enhanced(extension=file_ext, decrypted_bytes=video_bytes)
                        else:
                            thumbnail_data = extractor.extract_audio_thumbnail_from_bytes(extension=file_ext, decrypted_bytes=video_bytes)
                # remove temp file
                with contextlib.suppress(Exception):
                    os.remove(temp_s3_path)
            except Exception as e:
                logger.exception(f"Fallback thumbnail extraction failed: {e}")

        safe_progress(85, None)

        return {
            "s3_result": result,
            "uploaded_size": uploaded_bytes,
            "thumbnail_data": thumbnail_data,
        }

    except Exception as e:
        logger.exception("decrypt/upload failed, aborting multipart upload if present")
        # abort multipart upload on any failure
        if upload_id:
            with contextlib.suppress(Exception):
                s3.abort_multipart_upload(Bucket=bucket, Key=s3_key, UploadId=upload_id)
        safe_progress(0, f"Decrypt/upload failed: {e}")
        raise RuntimeError(f"Decrypt/upload failed: {e}")
    finally:
        # Aggressive cleanup of sensitive material and temporary buffers
        try:
            # zero data_key_plain if present
            if 'data_key_ba' in locals() and isinstance(data_key_ba, bytearray):
                for i in range(len(data_key_ba)):
                    data_key_ba[i] = 0
                del data_key_ba
        except Exception:
            pass

        try:
            if 'data_key_plain' in locals():
                del data_key_plain
        except Exception:
            pass

        try:
            if aesgcm is not None:
                del aesgcm
        except Exception:
            pass

        try:
            if decryptor is not None:
                del decryptor
        except Exception:
            pass

        try:
            if cipher is not None:
                del cipher
        except Exception:
            pass

        try:
            # Thumbnail buffer
            if 'buffer_for_thumbnail' in locals() and buffer_for_thumbnail:
                try:
                    buffer_for_thumbnail.close()
                except Exception:
                    pass
                try:
                    del buffer_for_thumbnail
                except Exception:
                    pass
        except Exception:
            pass

        # hint to GC
        try:
            gc.collect()
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
    MAX_THUMBNAIL_ATTEMPTS = 5
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
        
        if file_type in ['video', 'audio'] and  not thumbnail_data:
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
                                decrypted_bytes=video_bytes,
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

