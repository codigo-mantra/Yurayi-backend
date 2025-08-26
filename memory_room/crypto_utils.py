"""
Encryption/Decryption utilities for S3 images.
"""
# crypto_utils.py
import base64, os
import boto3
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from django.conf import settings


# AWS_KMS_REGION = settings.AWS_KMS_REGION
# AWS_KMS_KEY_ID = settings.AWS_KMS_KEY_ID
# MEDIA_FILES_BUCKET = settings.MEDIA_FILES_BUCKET

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

# def encrypt_and_upload_image(*, bucket, key, plaintext_bytes, kms_key_id, content_type="image/jpeg"):
#     # 1) Create a fresh data key from KMS (plaintext+encrypted)
#     resp = kms.generate_data_key(KeyId=kms_key_id, KeySpec="AES_256")
#     data_key_plain = resp["Plaintext"]          # bytes 
#     data_key_encrypted = resp["CiphertextBlob"] # bytes

#     # 2) Encrypt image with AES-GCM using the plaintext data key
#     aesgcm = AESGCM(data_key_plain)
#     nonce = os.urandom(12)  # GCM nonce
#     ciphertext = aesgcm.encrypt(nonce, plaintext_bytes, associated_data=None)

#     # 3) Upload ciphertext to S3, store EDK + nonce in metadata (base64)
#     obj = s3.put_object(
#         Bucket=bucket,
#         Key=key,
#         Body=ciphertext,
#         ContentType="application/octet-stream",  # ciphertext isn't an image
#         Metadata={
#             "edk": base64.b64encode(data_key_encrypted).decode(),
#             "nonce": base64.b64encode(nonce).decode(),
#             "orig-content-type": content_type,
#         }
#     )
#     print(f"✅ File uploaded successfully!")
#     print(f"S3 Key: {key}")
#     return obj



def encrypt_and_upload_file(*, key, plaintext_bytes,  content_type="application/octet-stream", file_category=None):
    """
    Encrypts and uploads file to S3 using KMS data key.
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

        # 3) Upload encrypted file to S3
        obj = s3.put_object(
            Bucket='yurayi-media',
            Key=key,
            Body=ciphertext,
            ContentType="application/octet-stream",  # ciphertext is binary
            Metadata={
                "edk": base64.b64encode(data_key_encrypted).decode(),
                "nonce": base64.b64encode(nonce).decode(),
                "orig-content-type": content_type,
                "file-category": file_category
            }
        )

        print(f"✅ File uploaded successfully! S3 Key: {key}")
        return obj
    except Exception as e:
        print(f'exception as ',e)






# def decrypt_and_get_image(bucket: str, key: str) -> bytes:
#     """
#     Download, decrypt and return image bytes from S3.
#     """
#     obj = s3.get_object(Bucket=bucket, Key=key)
#     ciphertext = obj["Body"].read()

#     # Metadata contains encrypted data key + nonce
#     metadata = obj["Metadata"]
#     encrypted_data_key_b64 = metadata["edk"]
#     nonce_b64 = metadata["nonce"]

#     encrypted_data_key = base64.b64decode(encrypted_data_key_b64)
#     nonce = base64.b64decode(nonce_b64)

#     # 1) Decrypt the data key with KMS
#     resp = kms.decrypt(CiphertextBlob=encrypted_data_key)
#     data_key = resp["Plaintext"]

#     # 2) Decrypt ciphertext with AESGCM
#     aesgcm = AESGCM(data_key)
#     plaintext = aesgcm.decrypt(nonce, ciphertext, None)

#     return plaintext


def decrypt_and_get_image(key: str):
    """
    Download, decrypt and return file bytes + content type from S3.
    Works for all file types (image, video, audio, other).
    
    Returns:
        plaintext (bytes): Decrypted file bytes
        content_type (str): Original content type from metadata
    """
    # 1) Fetch encrypted object
    obj = s3.get_object(Bucket=MEDIA_FILES_BUCKET, Key=key)
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



def download_and_decrypt_image(*, bucket, key):
    # 1) Get ciphertext + metadata
    obj = s3.get_object(Bucket=bucket, Key=key)
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

def save_and_upload_decrypted_file(filename: str, decrypted_bytes: bytes, bucket='time-capsoul-files',content_type=None):
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
    obj = s3.get_object(Bucket='yurayi-media', Key=key)
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
