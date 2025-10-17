from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import base64
from django.conf import settings

import threading
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

def decrypt_upload_and_extract_audio_thumbnail_chunked(
    key: str,
    encrypted_file,
    iv_str: str,
    content_type: str = "application/octet-stream",
    file_ext: str = "",
    progress_callback=None,
    chunk_size: int = 10 * 1024 * 1024,  # 10 MB default
    file_type=None,
    ):
    """
    Decrypt AES-256-GCM encrypted audio file chunk-by-chunk with streaming,
    upload decrypted chunks to S3 with KMS encryption using threading,
    and extract embedded audio thumbnail while streaming.
    """

    bucket = MEDIA_FILES_BUCKET
    parts = []
    uploaded_bytes = 0
    thumbnail_data = None
    upload_error = None

    try:
        # === Step 1: Prepare decryption cipher ===
        s3_key = key
        if progress_callback:
            progress_callback(15, "Initializing decryption...")

        # Convert IV (Base64 or Hex)
        try:
            if all(c in "0123456789abcdefABCDEF" for c in iv_str.strip()):
                iv = bytes.fromhex(iv_str)
            else:
                iv = base64.b64decode(iv_str)
        except Exception as e:
            raise ValueError(f"Invalid IV format: {e}")

        # Decode key
        key = settings.ENCRYPTION_KEY
        if isinstance(key, str):
            key = base64.b64decode(key)
        if len(key) != 32:
            raise ValueError(f"Key must be 32 bytes for AES-256, got {len(key)} bytes")

        # Determine file size and auth tag
        encrypted_file.seek(0, 2)
        total_size = encrypted_file.tell()
        if total_size < 16:
            raise ValueError("Encrypted file too short (missing GCM tag).")

        encrypted_data_size = total_size - 16
        
        # Dynamic chunk size based on file size for optimal performance
        if encrypted_data_size <= 20 * 1024 * 1024:  # <= 20MB - small files
            chunk_size = chunk_size  # Use original 10MB or provided chunk_size
            use_threading = False  # Skip threading overhead for small files
        elif encrypted_data_size > 100 * 1024 * 1024:  # > 100MB
            chunk_size = 5 * 1024 * 1024  # 2MB chunks
            use_threading = True
        elif encrypted_data_size > 50 * 1024 * 1024:  # > 50MB
            chunk_size = 8 * 1024 * 1024  # 5MB chunks
            use_threading = True
        else:  # 20-50MB
            chunk_size = 8 * 1024 * 1024  # 8MB chunks
            use_threading = True
        
        encrypted_file.seek(encrypted_data_size)
        auth_tag = encrypted_file.read(16)

        cipher = Cipher(algorithms.AES(key), modes.GCM(iv, auth_tag), backend=default_backend())
        decryptor = cipher.decryptor()

        encrypted_file.seek(0)
        if progress_callback:
            progress_callback(20, "Starting chunked decrypt & upload...")

        # === Step 2: Prepare S3 multipart upload ===
        resp = kms.generate_data_key(KeyId=AWS_KMS_KEY_ID, KeySpec="AES_256")
        data_key_plain = resp["Plaintext"]
        data_key_encrypted = resp["CiphertextBlob"]
        aesgcm = AESGCM(data_key_plain)

        multipart_resp = s3.create_multipart_upload(
            Bucket=bucket,
            Key=s3_key,
            ContentType=content_type,
            Metadata={
                "edk": base64.b64encode(data_key_encrypted).decode(),
                "orig-content-type": content_type,
            },
        )
        upload_id = multipart_resp["UploadId"]

        # === Step 3: Setup threading for upload (only for large files) ===
        upload_queue = None
        upload_thread = None
        parts_lock = threading.Lock() if use_threading else None

        if use_threading:
            upload_queue = Queue(maxsize=3)  # Limit queue to prevent memory bloat

            def upload_worker():
                """Worker thread to handle S3 uploads"""
                nonlocal upload_error, uploaded_bytes
                
                while True:
                    try:
                        item = upload_queue.get(timeout=1)
                        if item is None:  # Poison pill to stop thread
                            break
                        
                        part_num, encrypted_body, decrypted_size = item
                        
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
                                uploaded_bytes += decrypted_size
                                
                                if progress_callback:
                                    percent = int((uploaded_bytes / encrypted_data_size) * 100)
                                    progress_callback(min(percent, 80), f"Uploaded chunk {part_num}")
                        
                        except Exception as e:
                            upload_error = e
                            break
                        finally:
                            upload_queue.task_done()
                            
                    except Empty:
                        continue

            # Start upload worker thread
            upload_thread = threading.Thread(target=upload_worker, daemon=True)
            upload_thread.start()

        # === Step 4: Process chunks with streaming ===
        part_number = 1
        total_read = 0
        collected_bytes = BytesIO()
        thumbnail_extracted = False

        while total_read < encrypted_data_size:
            # Check for upload errors (only if threading)
            if use_threading and upload_error:
                raise upload_error
            
            to_read = min(chunk_size, encrypted_data_size - total_read)
            chunk = encrypted_file.read(to_read)
            total_read += len(chunk)

            # Decrypt chunk
            decrypted_chunk = decryptor.update(chunk)
            
            if decrypted_chunk:
                # Thumbnail extraction (non-blocking, only first chunks)
                if not thumbnail_extracted and thumbnail_data is None:
                    if collected_bytes.tell() < 512 * 1024:
                        collected_bytes.write(decrypted_chunk)
                        
                        # Attempt extraction if enough data buffered
                        if collected_bytes.tell() >= 128 * 1024:
                            try:
                                extractor = MediaThumbnailExtractor(file='', file_ext=file_ext)
                                
                                if file_type and file_type == 'video':
                                    video_thumb = extractor.extract_video_thumbnail_from_bytes(
                                        decrypted_bytes=collected_bytes.getvalue(),
                                        extension=file_ext,
                                    )
                                    thumb = video_thumb
                                else:
                                    thumb = extractor.extract_audio_thumbnail_from_bytes(
                                        decrypted_bytes=collected_bytes.getvalue(),
                                        extension=file_ext,
                                    )
                                if thumb:
                                    thumbnail_data = thumb
                                    thumbnail_extracted = True
                                    collected_bytes.close()
                            except Exception:
                                pass  # Continue without thumbnail

                # Encrypt chunk for S3
                chunk_nonce = os.urandom(12)
                ciphertext_chunk = aesgcm.encrypt(chunk_nonce, decrypted_chunk, None)
                body = chunk_nonce + ciphertext_chunk

                if use_threading:
                    # Queue upload for threaded processing
                    upload_queue.put((part_number, body, len(decrypted_chunk)))
                else:
                    # Direct upload for small files (faster, no threading overhead)
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
                        percent = int((uploaded_bytes / encrypted_data_size) * 100)
                        progress_callback(min(percent, 80), f"Uploaded chunk {part_number}")
                
                part_number += 1
            
            # Yield control periodically to prevent blocking (only for large files)
            if use_threading and part_number % 5 == 0:
                threading.Event().wait(0.001)  # Tiny sleep to yield

        # Finalize decryption
        decryptor.finalize()

        # Signal upload thread to stop and wait for completion (only if threading was used)
        if use_threading:
            upload_queue.put(None)
            upload_thread.join(timeout=30)

            # Check final upload status
            if upload_error:
                raise upload_error

        # === Step 5: Complete upload ===
        # Sort parts by PartNumber to ensure correct order
        parts.sort(key=lambda x: x["PartNumber"])
        
        result = s3.complete_multipart_upload(
            Bucket=bucket,
            Key=s3_key,
            UploadId=upload_id,
            MultipartUpload={"Parts": parts},
        )

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
            collected_bytes.close()
        except Exception:
            pass
        
      