"""
Encryption/Decryption utilities for S3 images.
"""
import base64, os, re
import logging
import boto3
from rest_framework import status
from botocore.config import Config
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from django.conf import settings

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
import logging
logger = logging.getLogger(__name__)


def encrypt_and_upload_file(*, key, plaintext_bytes, content_type="application/octet-stream", 
                          file_category=None, progress_callback=None):
    """
    Encrypts and uploads file to S3 using KMS data key with progress tracking.
    """
    try:
        total_size = len(plaintext_bytes)
        processed_bytes = 0
        
        if progress_callback:
            progress_callback(0, "Starting encryption...")

        # 1) Generate KMS data key (plaintext + encrypted)
        resp = kms.generate_data_key(KeyId='843da3bb-9a57-4d9f-a8ab-879a6109f460', KeySpec="AES_256")
        data_key_plain = resp["Plaintext"]          # bytes 
        data_key_encrypted = resp["CiphertextBlob"] # bytes

        processed_bytes += total_size * 0.1  # 10% for encryption prep
        if progress_callback:
            progress_callback(int((processed_bytes / total_size) * 100), "Encrypting file...")

        # 2) Encrypt file using AES-GCM
        aesgcm = AESGCM(data_key_plain)
        nonce = os.urandom(12)  # 12-byte nonce for GCM
        ciphertext = aesgcm.encrypt(nonce, plaintext_bytes, associated_data=None)

        processed_bytes += total_size * 0.2  # 20% for encryption
        if progress_callback:
            progress_callback(int((processed_bytes / total_size) * 100), "Starting S3 upload...")

        # 3) Upload encrypted file to S3 with progress tracking
        # Configure S3 client
        config = Config(
            retries={'max_attempts': 3, 'mode': 'adaptive'},
            max_pool_connections=50
        )
        s3_client = boto3.client('s3', config=config)
        
        # Use multipart upload for files larger than 100MB
        if len(ciphertext) > 100 * 1024 * 1024:
        
            obj = _multipart_upload_with_progress(
                s3_client, ciphertext, key, content_type, 
                data_key_encrypted, nonce, file_category, progress_callback,
                processed_bytes, total_size
            )
        else:
            obj = _single_upload_with_progress(
                s3_client, ciphertext, key, content_type,
                data_key_encrypted, nonce, file_category, progress_callback,
                processed_bytes, total_size
            )

        if progress_callback:
            progress_callback(100, "Upload completed successfully!")

        return obj
        
    except Exception as e:
        if progress_callback:
            progress_callback(-1, f"Upload failed: {str(e)}")
        logger.exception("Encrypt and upload failed")
        raise e



import io
import base64

def _single_upload_with_progress(s3_client, ciphertext, key, content_type, 
                               data_key_encrypted, nonce, file_category, 
                               progress_callback, processed_bytes, total_size):
    """Handle single part upload with progress tracking"""

    class ProgressTracker:
        def __init__(self, callback, processed_bytes, total_size):
            self.callback = callback
            self.processed_bytes = processed_bytes
            self.total_size = total_size
            self.uploaded = 0

        def __call__(self, bytes_transferred):
            self.uploaded = bytes_transferred
            current_progress = self.processed_bytes + (bytes_transferred * 0.7)  # 70% for upload
            percentage = int((current_progress / self.total_size) * 100)
            if self.callback:
                self.callback(min(percentage, 99), "Uploading to S3...")

    progress_tracker = ProgressTracker(progress_callback, processed_bytes, total_size)

    # wrap ciphertext in a file-like object
    fileobj = io.BytesIO(ciphertext)

    # use upload_fileobj (supports Callback)
    s3_client.upload_fileobj(
        Fileobj=fileobj,
        Bucket='yurayi-media',
        Key=key,
        ExtraArgs={
            "ContentType": "application/octet-stream",
            "Metadata": {
                "edk": base64.b64encode(data_key_encrypted).decode(),
                "nonce": base64.b64encode(nonce).decode(),
                "orig-content-type": content_type,
                "file-category": file_category
            }
        },
        Callback=progress_tracker
    )

    return {"Key": key, "Bucket": "yurayi-media"}


def _multipart_upload_with_progress(s3_client, ciphertext, key, content_type,
                                   data_key_encrypted, nonce, file_category,
                                   progress_callback, processed_bytes, total_size):
    """Handle multipart upload with progress tracking"""
    
    # Start multipart upload
    response = s3_client.create_multipart_upload(
        Bucket='yurayi-media',
        Key=key,
        ContentType="application/octet-stream",
        Metadata={
            "edk": base64.b64encode(data_key_encrypted).decode(),
            "nonce": base64.b64encode(nonce).decode(),
            "orig-content-type": content_type,
            "file-category": file_category
        }
    )
    
    upload_id = response['UploadId']
    
    try:
        # Split into chunks (minimum 5MB for multipart)
        chunk_size = max(5 * 1024 * 1024, len(ciphertext) // 100)  # At least 5MB, max 100 parts
        chunks = []
        
        for i in range(0, len(ciphertext), chunk_size):
            chunk = ciphertext[i:i + chunk_size]
            chunks.append((i // chunk_size + 1, chunk))
        
        parts = []
        uploaded_bytes = 0
        
        for part_number, chunk in chunks:
            response = s3_client.upload_part(
                Bucket='yurayi-media',
                Key=key,
                PartNumber=part_number,
                UploadId=upload_id,
                Body=chunk
            )
            
            parts.append({
                'ETag': response['ETag'],
                'PartNumber': part_number
            })
            
            uploaded_bytes += len(chunk)
            current_progress = processed_bytes + (uploaded_bytes / len(ciphertext)) * 0.7 * total_size
            percentage = int((current_progress / total_size) * 100)
            
            if progress_callback:
                progress_callback(min(percentage, 99), f"Uploading part {part_number}/{len(chunks)}...")
        
        # Complete multipart upload
        obj = s3_client.complete_multipart_upload(
            Bucket='yurayi-media',
            Key=key,
            UploadId=upload_id,
            MultipartUpload={'Parts': parts}
        )
        
        return obj
        
    except Exception as e:
        # Abort multipart upload on error
        s3_client.abort_multipart_upload(
            Bucket='yurayi-media',
            Key=key,
            UploadId=upload_id
        )
        raise e


def get_decrypt_file_bytes(key: str):
    """
    Download, decrypt and return file bytes + content type from S3.
    Works for all file types (image, video, audio, other).
    
    Returns:
        plaintext (bytes): Decrypted file bytes
        content_type (str): Original content type from metadata
    """
    try:
        
        # 1) Fetch encrypted object
        try:
            obj = s3.get_object(Bucket=MEDIA_FILES_BUCKET, Key=key)
        except Exception as e:
            logger.error(f'Error fetching object from S3: {e}')
            return None, None
        
        ciphertext = obj["Body"].read()

        # 2) Extract encryption metadata
        metadata = obj["Metadata"]
        encrypted_data_key_b64 = metadata["edk"]
        nonce_b64 = metadata["nonce"]
        orig_content_type = metadata.get("orig-content-type", "application/octet-stream")

        encrypted_data_key = base64.b64decode(encrypted_data_key_b64)
        nonce = base64.b64decode(nonce_b64)

        # 3) Decrypt the data key with KMS
        resp = kms.decrypt(CiphertextBlob=encrypted_data_key)
        data_key = resp["Plaintext"]

        # 4) Decrypt ciphertext with AES-GCM
        aesgcm = AESGCM(data_key)
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)

        return plaintext, orig_content_type
    except Exception as e:
        logger.error(f'Exception while media decryption as {e}')


import base64
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import boto3

def decrypt_and_get_image(key: str, chunk_size: int = 10 * 1024 * 1024 + 28):
    """
    Decrypts a file uploaded via upload_file_to_s3_kms_chunked.
    """
    # s3 = boto3.client("s3")
    # kms = boto3.client("kms")

    
    try:
        obj = s3.get_object(Bucket=MEDIA_FILES_BUCKET, Key=key)
    except Exception as e:
        logger.error(f'Error fetching object from S3: {e}')
        return None, None
    
    encrypted_blob = obj["Body"].read()
    metadata = obj["Metadata"]

    # Decrypt data key from metadata
    encrypted_data_key = base64.b64decode(metadata["edk"])
    data_key = kms.decrypt(CiphertextBlob=encrypted_data_key)["Plaintext"]
    aesgcm = AESGCM(data_key)

    plaintext = bytearray()
    offset = 0

    while offset < len(encrypted_blob):
        # Each chunk = nonce (12 bytes) + ciphertext_chunk
        nonce = encrypted_blob[offset:offset + 12]
        ciphertext_chunk = encrypted_blob[offset + 12:offset + chunk_size]
        offset += len(nonce) + len(ciphertext_chunk)

        chunk_plaintext = aesgcm.decrypt(nonce, ciphertext_chunk, None)
        plaintext.extend(chunk_plaintext)

    content_type = metadata.get("orig-content-type", "application/octet-stream")
    return bytes(plaintext), content_type


def download_and_decrypt_image(*, bucket, key):
    # 1) Get ciphertext + metadata
    try:
        obj = s3.get_object(Bucket=bucket, Key=key)
    except Exception as e:
        logger.error(f'Error fetching object from S3: {e}')
        return None, None

    # obj = s3.get_object(Bucket=bucket, Key=key)
    ciphertext = obj["Body"].read()
    md = obj["Metadata"]
    edk_b64 = md["edk"]
    nonce_b64 = md["nonce"]
    content_type = md.get("orig-content-type", "application/octet-stream")

    # 2) Decrypt the encrypted data key with KMS
    edk = base64.b64decode(edk_b64)
    nonce = base64.b64decode(nonce_b64)
    data_key_plain = kms.decrypt(CiphertextBlob=edk)["Plaintext"]

    # 3) Decrypt with AES-GCM
    aesgcm = AESGCM(data_key_plain)
    plaintext = aesgcm.decrypt(nonce, ciphertext, associated_data=None)
    return plaintext, content_type


import base64
import hashlib
import hmac
import time
from urllib.parse import quote

from django.conf import settings


def generate_signed_path(s3_key: str, expiry_seconds: int = 60) -> str:
    """
    Generate a relative signed URL for a media file.
    """
    secret = settings.SECRET_KEY.encode()
    expires_at = int(time.time()) + expiry_seconds

    data = f"{s3_key}:{expires_at}".encode()
    signature = base64.urlsafe_b64encode(
        hmac.new(secret, data, hashlib.sha256).digest()
    ).decode()

    path = f"/api/media/serve/{quote(s3_key, safe='')}?exp={expires_at}&sig={signature}"
    return path


import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from django.conf import settings

def decrypt_frontend_file(uploaded_file, iv_str: str) -> bytes:
    """
    Decrypt AES-256-GCM encrypted Django TemporaryUploadedFile.
    """
    # Read the uploaded file content
    ciphertext = uploaded_file.read()  # <--- bytes

    # Now you can safely split ciphertext and auth_tag
    if len(ciphertext) < 16:
        raise ValueError("Ciphertext too short for GCM mode (missing authentication tag)")

    encrypted_data = ciphertext[:-16]
    auth_tag = ciphertext[-16:]

    # Convert IV string to bytes
    try:
        if all(c in "0123456789abcdefABCDEF" for c in iv_str.strip()):
            iv = bytes.fromhex(iv_str)
        else:
            import base64
            iv = base64.b64decode(iv_str)
    except Exception as e:
        raise ValueError(f"Invalid IV format: {e}")

    key = settings.ENCRYPTION_KEY
    if isinstance(key, str):
        import base64
        key = base64.b64decode(key)

    if len(key) != 32:
        raise ValueError(f"Key must be 32 bytes for AES-256, got {len(key)} bytes")

    cipher = Cipher(
        algorithms.AES(key),
        modes.GCM(iv, auth_tag),
        backend=default_backend()
    )
    decryptor = cipher.decryptor()

    decrypted_bytes = decryptor.update(encrypted_data) + decryptor.finalize()
    return decrypted_bytes

import io
import mimetypes

def save_and_upload_decrypted_file(filename: str, decrypted_bytes: bytes, bucket='time-capsoul-files',content_type=None, s3_key=None):
    """
    Save decrypted bytes as a file-like object and upload to S3 as a simple file.
    """
    # Create in-memory file object
    file_obj = io.BytesIO(decrypted_bytes)

    # Guess the content type (fallback to binary stream)
    if not content_type:
        content_type = "application/octet-stream"
    
    s3 = boto3.client(
        's3',
        aws_access_key_id=settings.AWS_ACCESS_KEY_ID,
        aws_secret_access_key=settings.AWS_SECRET_ACCESS_KEY,
        region_name=settings.AWS_S3_REGION_NAME
    )
    if s3_key is None:
        s3_key = f'assets/{filename}'
        
    # Upload like a normal file
    s3.upload_fileobj(
        Fileobj=file_obj,
        Bucket=bucket,
        Key=s3_key,
        ExtraArgs={
            "ContentType": content_type,
            "ACL": "public-read"   # or private if you don’t want it public
        }
    )
    return (s3_key, f"https://{bucket}.s3.amazonaws.com/{s3_key}")


import os, base64, boto3
from cryptography.hazmat.primitives.ciphers.aead import AESGCM




def encrypt_and_upload_file_no_iv(*, key, plaintext_bytes, content_type="application/octet-stream", file_category=None):
    """
    Encrypts and uploads file to S3 using KMS data key.
    Nonce is prepended to ciphertext (no separate IV storage).
    """
    try:
        # 1) Generate KMS data key (plaintext + encrypted)
        resp = kms.generate_data_key(KeyId='843da3bb-9a57-4d9f-a8ab-879a6109f460', KeySpec="AES_256")
        data_key_plain = resp["Plaintext"]          # bytes 
        data_key_encrypted = resp["CiphertextBlob"] # bytes

        # 2) Encrypt file using AES-GCM
        aesgcm = AESGCM(data_key_plain)
        nonce = os.urandom(12)  # 12-byte nonce for GCM
        ciphertext = aesgcm.encrypt(nonce, plaintext_bytes, associated_data=None)

        # 🔑 Prepend nonce so no need to store separately
        encrypted_blob = nonce + ciphertext

        # 3) Upload encrypted file to S3
        obj = s3.put_object(
            Bucket='yurayi-media',
            Key=key,
            Body=encrypted_blob,
            ContentType="application/octet-stream",  # ciphertext is binary
            Metadata={
                "edk": base64.b64encode(data_key_encrypted).decode(),
                "orig-content-type": content_type,
                "file-category": file_category or ""
            }
        )

        print(f"✅ File uploaded successfully without separate IV! S3 Key: {key}")
        return obj
    except Exception as e:
        print(f"❌ Exception: {e}")
        return None

def decrypt_and_replicat_files(key: str):
    """
    Download, decrypt and return file bytes + content type from S3.
    Works for all file types (image, video, audio, other).
    """
    # 1) Fetch encrypted object
    try:
        obj = s3.get_object(Bucket='yurayi-media', Key=key)
    except Exception as e:
        logger.error(f'Error fetching object from S3: {e}')
        return None, None

    encrypted_blob = obj["Body"].read()

    # 2) Extract metadata
    metadata = obj["Metadata"]
    encrypted_data_key_b64 = metadata["edk"]
    orig_content_type = metadata.get("orig-content-type", "application/octet-stream")

    encrypted_data_key = base64.b64decode(encrypted_data_key_b64)

    # 3) Decrypt the data key with KMS
    resp = kms.decrypt(CiphertextBlob=encrypted_data_key)
    data_key = resp["Plaintext"]

    # 4) Extract nonce and ciphertext (since nonce was prepended)
    nonce = encrypted_blob[:12]  
    ciphertext = encrypted_blob[12:]

    # 5) Decrypt ciphertext with AES-GCM
    aesgcm = AESGCM(data_key)
    plaintext = aesgcm.decrypt(nonce, ciphertext, None)

    return plaintext, orig_content_type


def generate_signature(s3_key: str, exp: str) -> str:
    raw = f"{s3_key}:{exp}"
    sig_bytes = hmac.new(settings.SECRET_KEY.encode(), raw.encode(), hashlib.sha256).digest()
    return base64.urlsafe_b64encode(sig_bytes).decode().rstrip("=")

def verify_signature(s3_key: str, exp: str, sig: str) -> bool:
    expected = generate_signature(s3_key, exp)
    return hmac.compare_digest(sig, expected)


import os
import io
import base64
import boto3
from botocore.config import Config
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Assume kms is already configured
# from your existing code: kms = boto3.client('kms')

# ------------------------ Helper Functions ------------------------

def _single_encrypt_upload(s3_client, plaintext_bytes, key, aesgcm, nonce,
                           data_key_encrypted, content_type, file_category,
                           progress_callback, processed_bytes, total_size):
    """Encrypt small files in-memory and upload in a single part with progress callback"""
    
    ciphertext = aesgcm.encrypt(nonce, plaintext_bytes, associated_data=None)
    uploaded_bytes = 0

    class ProgressTracker:
        def __init__(self, callback):
            self.callback = callback
            self.uploaded = 0

        def __call__(self, bytes_transferred):
            self.uploaded = bytes_transferred
            if self.callback:
                current = processed_bytes + (self.uploaded / total_size) * 0.7 * total_size
                self.callback(min(int((current / total_size) * 100), 99), "Uploading to S3...")

    tracker = ProgressTracker(progress_callback)
    fileobj = io.BytesIO(ciphertext)

    s3_client.upload_fileobj(
        Fileobj=fileobj,
        Bucket='yurayi-media',
        Key=key,
        ExtraArgs={
            "ContentType": content_type,
            "Metadata": {
                "edk": base64.b64encode(data_key_encrypted).decode(),
                "nonce": base64.b64encode(nonce).decode(),
                "orig-content-type": content_type,
            }
        },
        Callback=tracker
    )

    return {"Key": key, "Bucket": "yurayi-media"}


def _multipart_encrypt_upload(s3_client, plaintext_bytes, key, aesgcm, nonce,
                              data_key_encrypted, content_type, file_category,
                              progress_callback, processed_bytes, total_size):
    """Encrypt large files chunk-wise and upload using S3 multipart upload"""
    
    response = s3_client.create_multipart_upload(
        Bucket='yurayi-media',
        Key=key,
        ContentType=content_type,
        Metadata={
            "edk": base64.b64encode(data_key_encrypted).decode(),
            "nonce": base64.b64encode(nonce).decode(),
            "orig-content-type": content_type,
        }
    )
    upload_id = response['UploadId']

    try:
        chunk_size = max(5 * 1024 * 1024, total_size // 100)  # at least 5MB per part
        parts = []
        uploaded_bytes = 0

        for part_number, i in enumerate(range(0, total_size, chunk_size), start=1):
            plaintext_chunk = plaintext_bytes[i:i+chunk_size]
            ciphertext_chunk = aesgcm.encrypt(nonce, plaintext_chunk, associated_data=None)

            resp = s3_client.upload_part(
                Bucket='yurayi-media',
                Key=key,
                PartNumber=part_number,
                UploadId=upload_id,
                Body=ciphertext_chunk
            )
            parts.append({'ETag': resp['ETag'], 'PartNumber': part_number})

            uploaded_bytes += len(plaintext_chunk)
            if progress_callback:
                current_progress = processed_bytes + (uploaded_bytes / total_size) * 0.7 * total_size
                progress_callback(min(int((current_progress / total_size) * 100), 99),
                                  f"Uploading part {part_number}...")

        obj = s3_client.complete_multipart_upload(
            Bucket='yurayi-media',
            Key=key,
            UploadId=upload_id,
            MultipartUpload={'Parts': parts}
        )

        return obj

    except Exception:
        s3_client.abort_multipart_upload(Bucket='yurayi-media', Key=key, UploadId=upload_id)
        if progress_callback:
            progress_callback(-1, "Multipart upload failed")
        raise


def encrypt_and_upload_file_chunked(*, key, plaintext_bytes, content_type="application/octet-stream",
                                    file_category=None, progress_callback=None):
    """
    Encrypts and uploads a file to S3 in chunks using AES-GCM with KMS data key.
    Progress callback reports percentage and status message.
    """

    try:
        total_size = len(plaintext_bytes)
        processed_bytes = 0

        if progress_callback:
            progress_callback(0, "Starting encryption...")

        # 1) Generate KMS data key
        resp = kms.generate_data_key(KeyId='843da3bb-9a57-4d9f-a8ab-879a6109f460', KeySpec="AES_256")
        data_key_plain = resp["Plaintext"]
        data_key_encrypted = resp["CiphertextBlob"]

        processed_bytes += total_size * 0.05  # 5% for key generation
        if progress_callback:
            progress_callback(int((processed_bytes / total_size) * 100), "Encrypting file in chunks...")

        # 2) Setup AES-GCM
        aesgcm = AESGCM(data_key_plain)
        nonce = os.urandom(12)  # 12-byte nonce for GCM

        # 3) Configure S3 client
        s3_client = boto3.client('s3', config=Config(retries={'max_attempts':3, 'mode':'adaptive'}, max_pool_connections=50))

        # 4) Decide upload type
        if total_size > 100 * 1024 * 1024:  # multipart for >100MB
            obj = _multipart_encrypt_upload(s3_client, plaintext_bytes, key, aesgcm, nonce,
                                            data_key_encrypted, content_type, file_category,
                                            progress_callback, processed_bytes, total_size)
        else:
            obj = _single_encrypt_upload(s3_client, plaintext_bytes, key, aesgcm, nonce,
                                         data_key_encrypted, content_type, file_category,
                                         progress_callback, processed_bytes, total_size)

        if progress_callback:
            progress_callback(100, "Upload completed successfully!")

        return obj

    except Exception:
        if progress_callback:
            progress_callback(-1, "Upload failed")
        raise

def upload_encrypted_file_chunked(*, key, encrypted_bytes, content_type="application/octet-stream",
                                   data_key_encrypted, nonce, file_category=None,
                                   progress_callback=None):
    """
    Upload an already encrypted file to S3 in chunks with progress tracking.
    Supports both single-part and multipart upload based on size.
    """

    try:
        total_size = len(encrypted_bytes)
        uploaded_bytes = 0

        if progress_callback:
            progress_callback(0, "Starting upload...")

        s3_client = boto3.client('s3', config=Config(
            retries={'max_attempts': 3, 'mode': 'adaptive'},
            max_pool_connections=50
        ))

        # -------------------- Multipart Upload --------------------
        if total_size > 100 * 1024 * 1024:  # >100MB -> multipart
            response = s3_client.create_multipart_upload(
                Bucket='yurayi-media',
                Key=key,
                ContentType=content_type,
                Metadata={
                    "edk": base64.b64encode(data_key_encrypted).decode(),
                    "nonce": base64.b64encode(nonce).decode(),
                    "orig-content-type": content_type,
                    "file-category": file_category or ""
                }
            )
            upload_id = response['UploadId']
            try:
                chunk_size = max(5 * 1024 * 1024, total_size // 100)
                parts = []

                for part_number, i in enumerate(range(0, total_size, chunk_size), start=1):
                    chunk = encrypted_bytes[i:i + chunk_size]

                    resp = s3_client.upload_part(
                        Bucket='yurayi-media',
                        Key=key,
                        PartNumber=part_number,
                        UploadId=upload_id,
                        Body=chunk
                    )
                    parts.append({'ETag': resp['ETag'], 'PartNumber': part_number})

                    uploaded_bytes += len(chunk)
                    if progress_callback:
                        percentage = int((uploaded_bytes / total_size) * 100)
                        progress_callback(min(percentage, 99), f"Uploading part {part_number}...")

                obj = s3_client.complete_multipart_upload(
                    Bucket='yurayi-media',
                    Key=key,
                    UploadId=upload_id,
                    MultipartUpload={'Parts': parts}
                )

            except Exception:
                s3_client.abort_multipart_upload(
                    Bucket='yurayi-media',
                    Key=key,
                    UploadId=upload_id
                )
                if progress_callback:
                    progress_callback(-1, "Multipart upload failed")
                raise

        # -------------------- Single-part Upload --------------------
        else:
            class ProgressTracker:
                def __init__(self, callback):
                    self.callback = callback
                    self.uploaded = 0

                def __call__(self, bytes_transferred):
                    self.uploaded = bytes_transferred
                    if self.callback:
                        percentage = int((self.uploaded / total_size) * 100)
                        self.callback(min(percentage, 99), "Uploading to S3...")

            tracker = ProgressTracker(progress_callback)

            # Wrap file bytes in a BytesIO for chunked upload
            fileobj = io.BytesIO(encrypted_bytes)

            s3_client.upload_fileobj(
                Fileobj=fileobj,
                Bucket='yurayi-media',
                Key=key,
                ExtraArgs={
                    "ContentType": content_type,
                    "Metadata": {
                        "edk": base64.b64encode(data_key_encrypted).decode(),
                        "nonce": base64.b64encode(nonce).decode(),
                        "orig-content-type": content_type,
                        "file-category": file_category or ""
                    }
                },
                Callback=tracker
            )

            obj = {"Key": key, "Bucket": "yurayi-media"}

        if progress_callback:
            progress_callback(100, "Upload completed successfully!")

        return obj

    except Exception:
        if progress_callback:
            progress_callback(-1, "Upload failed")
        raise


from django.core.cache import cache
from rest_framework.response import Response
from rest_framework import status

def get_media_file_bytes_with_content_type(media_file, user):
    try:
        bytes_cache_key = str(media_file.s3_key)
        file_bytes = cache.get(bytes_cache_key)
        
        content_type_cache_key = f'{bytes_cache_key}_type'
        content_type = cache.get(content_type_cache_key)
        file_bytes, content_type = None, None

        
        if not file_bytes or  not content_type:
            try:
                file_bytes, content_type = get_decrypt_file_bytes(str(media_file.s3_key))
            except Exception as e:
                file_bytes, content_type = decrypt_and_get_image(str(media_file.s3_key))
            except Exception as e:
                file_bytes, content_type = decrypt_and_replicat_files(str(media_file.s3_key))
            
            except Exception as e:
                logger.error(f'Exception while serving media file to user: {user.email} room media-id: {media_file.id} as \n error message: {e}')
                return Response(status=status.HTTP_500_INTERNAL_SERVER_ERROR)
            finally:
                if file_bytes and content_type:
                    # caching here
                    print(f'file bytes cached for {media_file.s3_key} received')
                    cache.set(bytes_cache_key, file_bytes, timeout=60*60*2)  
                    cache.set(content_type_cache_key, content_type, timeout=60*60*2)
        return file_bytes, content_type
            
    except Exception as e:
        logger.error(f'Exception while fetching media file from cache or decrypting: {e} s3-key: {media_file.s3_key} for user: {user.email}')
        return None, None


def generate_capsoul_media_s3_key(filename, user_storage, time_capsoul_id):
    s3_key = f'media/time-capsoul-files/{user_storage}/capsoul-id:{time_capsoul_id}/{filename}'.replace(" ", "_")
    return s3_key


def generate_room_media_s3_key(filename, user_storage, room_id):
    s3_key = f'media/memory-room-files/{user_storage}/room-id:{room_id}/{filename}'.replace(" ", "_")
    return s3_key



def clean_filename(filename: str):
    """
    Cleans a filename by:
    - Replacing spaces with underscores
    - Removing emojis and special characters
    - Keeping only letters, numbers, and underscores
    - Preserving the original file extension
    """
    # Split into name and extension
    name, ext = os.path.splitext(filename)
    
    # Replace spaces with underscores
    name = name.replace(" ", "_")
    
    # Remove all non-alphanumeric and non-underscore characters
    name = re.sub(r'[^A-Za-z0-9_]', '', name)
    
    # Recombine cleaned name with extension
    clean_name = f"{name}{ext}"
    
    return clean_name
