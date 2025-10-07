import base64, os
import logging
import boto3
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


# import os
# import io
# import base64
# import boto3
# from botocore.client import Config
from botocore.exceptions import ClientError
# from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# AWS_KMS_REGION = 'ap-south-1'
# MEDIA_FILES_BUCKET = 'yurayi-media'
# AWS_KMS_KEY_ID = '843da3bb-9a57-4d9f-a8ab-879a6109f460'

# s3 = boto3.client(
#     "s3",
#     region_name=AWS_KMS_REGION,
#     config=Config(retries={"max_attempts": 5, "mode": "adaptive"}),
# )
# kms = boto3.client("kms", region_name=AWS_KMS_REGION)


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

    # Local state tracking
    parts = []
    uploaded_bytes = 0

    try:
        # Step 1: Generate KMS data key
        if progress_callback:
            progress_callback(45, "Requesting KMS data key...")

        resp = kms.generate_data_key(KeyId=AWS_KMS_KEY_ID, KeySpec="AES_256")
        data_key_plain = resp["Plaintext"]
        data_key_encrypted = resp["CiphertextBlob"]
        aesgcm = AESGCM(data_key_plain)

        # Step 2: Create multipart upload session
        multipart_resp = s3.create_multipart_upload(
            Bucket=bucket,
            Key=key,
            ContentType=content_type,
            Metadata={
                "edk": base64.b64encode(data_key_encrypted).decode(),
                "orig-content-type": content_type,
            },
        )
        upload_id = multipart_resp["UploadId"]

        # Step 3: Encrypt and upload each chunk
        for part_number, start in enumerate(range(0, total_size, chunk_size), start=1):
            chunk = plaintext_bytes[start:start + chunk_size]
            chunk_nonce = os.urandom(12)
            ciphertext_chunk = aesgcm.encrypt(chunk_nonce, chunk, associated_data=None)

            # Nonce prepended to ciphertext for later decryption
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
                s3.abort_multipart_upload(Bucket=bucket, Key=key, UploadId=upload_id)
                raise RuntimeError(f"Failed to upload part {part_number}: {e}")

            uploaded_bytes += len(chunk)
            # if progress_callback:
            #     percent = int((uploaded_bytes / total_size) * 100)
            #     progress_callback(percent, f"Uploaded chunk {part_number}")

        # Step 4: Complete the multipart upload
        result = s3.complete_multipart_upload(
            Bucket=bucket,
            Key=key,
            UploadId=upload_id,
            MultipartUpload={"Parts": parts},
        )

        if progress_callback:
            progress_callback(80, "Upload completed successfully!")

        return result

    except ClientError as e:
        # if progress_callback:
        #     progress_callback(-1, f"S3 ClientError: {str(e)}")
        pass
        raise

    except Exception as e:
        if "upload_id" in locals():
            # Cleanup if multipart initiated but failed
            try:
                s3.abort_multipart_upload(Bucket=bucket, Key=key, UploadId=upload_id)
            except Exception:
                pass
        if progress_callback:
            progress_callback(-1, f"Upload failed: {str(e)}")
        raise RuntimeError(f"Upload failed: {e}")

    finally:
        # Wipe plaintext key from memory
        try:
            del data_key_plain
        except Exception:
            pass
