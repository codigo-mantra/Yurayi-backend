from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import base64
from django.conf import settings

import math
import time
import mimetypes
from botocore.exceptions import ClientError
from botocore.config import Config

import threading
from queue import Queue, Empty

import mimetypes
from io import BytesIO
import base64, os, re 
import logging
import boto3,math
from rest_framework import status

from botocore.config import Config
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from botocore.exceptions import NoCredentialsError, ClientError
from cryptography.exceptions import InvalidTag
from timecapsoul.utils import MediaThumbnailExtractor


logger = logging.getLogger(__name__)

AWS_KMS_KEY_ID = '843da3bb-9a57-4d9f-a8ab-879a6109f460'

class S3FileHandler:
    
    def __init__(self):
        self.region = 'ap-south-1'
        self.bucket_name = 'yurayi-media'
        self.s3_client = None
        self.kms_client = None
        self.setup() # s3 setup here
    
    def setup(self):
        try:
            self.s3_client = boto3.client("s3", region_name=self.region,
                aws_access_key_id=settings.AWS_ACCESS_KEY_ID,
                aws_secret_access_key=settings.AWS_SECRET_ACCESS_KEY,
            )
            self.kms_client = boto3.client(
                "kms",
                region_name=self.region,
                aws_access_key_id=settings.AWS_ACCESS_KEY_ID,
                aws_secret_access_key=settings.AWS_SECRET_ACCESS_KEY,
            )
        except Exception as e:
            logging.error(f' S3 Setup failed in S3FileHandler error as : {e} ')
        else:
            logger.info('S3 setup successfully')
    
    def calculate_part_size(self,file_size):
        """
        Dynamically choose S3 multipart copy/upload part size.
        Keeps parts between 5MB and 5GB, under 10,000 parts.
        """
        MIN_PART_SIZE = 5 * 1024 * 1024       # 5 MB
        MAX_PART_SIZE = 5 * 1024 * 1024 * 1024  # 5 GB
        MAX_PARTS = 10000

        # Start small (100 MB), increase if file is huge
        part_size = max(MIN_PART_SIZE, file_size // MAX_PARTS)
        part_size = min(max(part_size, 100 * 1024 * 1024), MAX_PART_SIZE)

        return part_size
    
    # for testing one
    def copy_s3_object_preserve_meta_kms(
        self, 
        source_key: str, 
        destination_key: str, 
        destination_bucket=None, 
        source_bucket=None, 
        user_email=None,
        max_retries=5,
        retry_delay=2
    ):
        """
        Copy an S3 object to a new key or bucket, preserving:
        - Metadata, headers, and KMS encryption
        - Automatically uses multipart copy for files >= 100 MB
        - Handles timeouts and connection errors with retry logic
        
        Args:
            max_retries: Maximum retries per part (default: 5)
            retry_delay: Initial delay between retries in seconds (default: 2)
        """
        
        if source_bucket is None:
            source_bucket = self.bucket_name
        if destination_bucket is None:
            destination_bucket = source_bucket
        
        upload_id = None
        
        # Configure S3 client with increased timeouts for large files
        # This is critical for files over 1GB
        s3_config = Config(
            connect_timeout=300,      # 5 minutes connection timeout
            read_timeout=300,         # 5 minutes read timeout
            retries={
                'max_attempts': 10,   # Retry failed requests
                'mode': 'adaptive'    # Adaptive retry mode
            }
        )
        
        # Create a new S3 client with custom config
        import boto3
        s3_client_with_timeout = boto3.client(
            's3',
            region_name=self.region,
            aws_access_key_id=self.s3_client._request_signer._credentials.access_key,
            aws_secret_access_key=self.s3_client._request_signer._credentials.secret_key,
            config=s3_config
        )
        
        try:
            # Get the source object's metadata
            head = s3_client_with_timeout.head_object(Bucket=source_bucket, Key=source_key)
            copy_source = {"Bucket": source_bucket, "Key": source_key}
            size = head["ContentLength"]
            part_size = self.calculate_part_size(size)
            
            logger.info(
                f'S3 object copying started for user {user_email} - '
                f'Source: {source_key}, Size: {size} bytes ({size/1024/1024:.2f} MB), '
                f'Part size: {part_size/1024/1024:.2f} MB'
            )
            
            # Preserve metadata and headers
            metadata = head.get("Metadata", {})
            content_type = (
                head.get("ContentType") or 
                mimetypes.guess_type(source_key)[0] or 
                "application/octet-stream"
            )
            content_disposition = head.get("ContentDisposition")
            cache_control = head.get("CacheControl")
            content_encoding = head.get("ContentEncoding")

            # Common arguments for both copy methods
            common_args = {
                "Bucket": destination_bucket,
                "Key": destination_key,
                "Metadata": metadata,
                "ContentType": content_type,
            }
            
            if content_disposition:
                common_args["ContentDisposition"] = content_disposition
            if cache_control:
                common_args["CacheControl"] = cache_control
            if content_encoding:
                common_args["ContentEncoding"] = content_encoding

            # Preserve KMS encryption if present
            if head.get("ServerSideEncryption") == "aws:kms":
                common_args["ServerSideEncryption"] = "aws:kms"
                if head.get("SSEKMSKeyId"):
                    common_args["SSEKMSKeyId"] = head["SSEKMSKeyId"]

            # For small files (<100 MB) - use simple copy
            if size < 100 * 1024 * 1024:
                copy_args = {**common_args, "MetadataDirective": "REPLACE"}
                response = s3_client_with_timeout.copy_object(
                    CopySource=copy_source, 
                    **copy_args
                )
                logger.info(
                    f"Simple copy completed for user {user_email}: "
                    f"{source_key} → {destination_key}"
                )
                return response

            # For large files (>=100 MB) — use multipart copy with retry
            logger.info(
                f" Large file detected ({size / 1024 / 1024:.2f} MB). "
                f"Using multipart copy..."
            )

            # Create multipart upload
            mpu = s3_client_with_timeout.create_multipart_upload(**common_args)
            upload_id = mpu["UploadId"]
            
            logger.info(f" Multipart upload initiated. Upload ID: {upload_id}")

            num_parts = math.ceil(size / part_size)
            parts = []
            failed_parts = []

            # Copy each part with retry logic
            for i in range(num_parts):
                start = i * part_size
                end = min(start + part_size - 1, size - 1)
                part_num = i + 1
                part_size_mb = (end - start + 1) / 1024 / 1024

                logger.info(
                    f"Copying part {part_num}/{num_parts} "
                    f"(bytes {start:,}-{end:,}, {part_size_mb:.2f} MB)"
                )

                # Retry logic for each part
                part_uploaded = False
                for attempt in range(max_retries):
                    try:
                        part = s3_client_with_timeout.upload_part_copy(
                            Bucket=destination_bucket,
                            Key=destination_key,
                            CopySource=copy_source,
                            CopySourceRange=f"bytes={start}-{end}",
                            PartNumber=part_num,
                            UploadId=upload_id,
                        )

                        parts.append({
                            "PartNumber": part_num, 
                            "ETag": part["CopyPartResult"]["ETag"]
                        })
                        
                        logger.info(f"✓ Part {part_num}/{num_parts} copied successfully")
                        part_uploaded = True
                        break
                        
                    except (ClientError, Exception) as part_error:
                        error_msg = str(part_error)
                        
                        # Check if it's a retryable error
                        retryable_errors = [
                            'RequestTimeout', 'ConnectionError', 'ReadTimeout',
                            'ConnectTimeout', 'Connection was closed', 
                            'socket connection', 'timed out', 'Broken pipe'
                        ]
                        
                        is_retryable = any(err in error_msg for err in retryable_errors)
                        
                        if attempt < max_retries - 1 and is_retryable:
                            wait_time = retry_delay * (2 ** attempt)  # Exponential backoff
                            logger.warning(
                                f"⚠️ Part {part_num} failed (attempt {attempt + 1}/{max_retries}): "
                                f"{error_msg}. Retrying in {wait_time}s..."
                            )
                            time.sleep(wait_time)
                        else:
                            logger.error(
                                f"✗ Part {part_num} failed after {attempt + 1} attempts: {error_msg}"
                            )
                            failed_parts.append(part_num)
                            raise

            # Check if all parts were uploaded
            if failed_parts:
                raise Exception(
                    f"Failed to upload parts: {failed_parts}. "
                    f"Successfully uploaded {len(parts)}/{num_parts} parts."
                )

            # Complete the multipart upload
            logger.info(f" Completing multipart upload with {len(parts)} parts...")
            
            # Sort parts by PartNumber (critical!)
            parts.sort(key=lambda x: x["PartNumber"])
            
            s3_client_with_timeout.complete_multipart_upload(
                Bucket=destination_bucket,
                Key=destination_key,
                UploadId=upload_id,
                MultipartUpload={"Parts": parts},
            )

            logger.info(
                f'S3 object copying completed successfully for user {user_email} - '
                f'Source: {source_key} → Dest: {destination_key}, '
                f'Size: {size} bytes ({size/1024/1024:.2f} MB), '
                f'Parts: {len(parts)}'
            )
            return True

        except ClientError as e:
            error_code = e.response.get('Error', {}).get('Code', 'Unknown')
            error_msg = e.response.get('Error', {}).get('Message', str(e))
            
            logger.error(
                f'❌ S3 copy failed (ClientError) for user {user_email} - '
                f'Source: {source_key}, Size: {size if "size" in locals() else "unknown"} - '
                f'Error Code: {error_code}, Message: {error_msg}'
            )
            
            # Abort multipart upload
            if upload_id:
                try:
                    logger.info(f" Aborting incomplete multipart upload: {upload_id}")
                    s3_client_with_timeout.abort_multipart_upload(
                        Bucket=destination_bucket,
                        Key=destination_key,
                        UploadId=upload_id,
                    )
                    logger.info(f"✓ Successfully aborted upload: {upload_id}")
                except Exception as abort_error:
                    logger.error(f"Failed to abort upload {upload_id}: {abort_error}")
            
            raise
        
        except Exception as e:
            logger.error(
                f'❌ Unexpected error during S3 copy for user {user_email} - '
                f'Source: {source_key}, Error: {str(e)}',
                exc_info=True
            )
            
            # Abort multipart upload
            if upload_id:
                try:
                    s3_client_with_timeout.abort_multipart_upload(
                        Bucket=destination_bucket,
                        Key=destination_key,
                        UploadId=upload_id,
                    )
                except Exception:
                    pass
            
            raise
    
    # working one
    def copy_s3_object_preserve_meta_kms3(self, source_key: str, destination_key: str,
                                     destination_bucket=None, source_bucket=None,
                                     part_size=30 * 1024 * 512):  # 512 MB per part
        """
        Copy an S3 object to a new key or bucket, preserving:
        - Metadata, headers, and KMS encryption
        - Automatically uses multipart copy for files >= 500 MB
        """

        if source_bucket is None:
            source_bucket = self.bucket_name
        if destination_bucket is None:
            destination_bucket = source_bucket

        try:
            # Get the source object's metadata
            head = self.s3_client.head_object(Bucket=source_bucket, Key=source_key)
            copy_source = {"Bucket": source_bucket, "Key": source_key}
            size = head["ContentLength"]

            # Preserve metadata and headers
            metadata = head.get("Metadata", {})
            content_type = head.get("ContentType") or mimetypes.guess_type(source_key)[0] or "application/octet-stream"
            content_disposition = head.get("ContentDisposition")
            cache_control = head.get("CacheControl")
            content_encoding = head.get("ContentEncoding")

            # Common arguments
            common_args = {
                "Bucket": destination_bucket,
                "Key": destination_key,
                "Metadata": metadata,
                "ContentType": content_type,
                # "MetadataDirective": "REPLACE",
            }
            if content_disposition:
                common_args["ContentDisposition"] = content_disposition
            if cache_control:
                common_args["CacheControl"] = cache_control
            if content_encoding:
                common_args["ContentEncoding"] = content_encoding

            # Preserve KMS encryption if present
            if head.get("ServerSideEncryption") == "aws:kms":
                common_args["ServerSideEncryption"] = "aws:kms"
                if head.get("SSEKMSKeyId"):
                    common_args["SSEKMSKeyId"] = head["SSEKMSKeyId"]

            # For small files (<500 MB)
            if size < 100 * 1024 * 1024:
                response = self.s3_client.copy_object(CopySource=copy_source, **common_args)
                logger.info(f"Simple copy completed: {source_key} → {destination_key}")
                return response

            # For large files (>=500 MB) — use multipart copy
            logger.info(f"Large file detected ({size / 1024 / 1024:.2f} MB). Using multipart copy...")

            mpu = self.s3_client.create_multipart_upload(**common_args)
            upload_id = mpu["UploadId"]

            num_parts = math.ceil(size / part_size)
            parts = []

            for i in range(num_parts):
                start = i * part_size
                end = min(start + part_size - 1, size - 1)
                part_num = i + 1

                logger.info(f"Copying part {part_num}/{num_parts} (bytes {start}-{end})")

                part = self.s3_client.upload_part_copy(
                    Bucket=destination_bucket,
                    Key=destination_key,
                    CopySource=copy_source,
                    CopySourceRange=f"bytes={start}-{end}",
                    PartNumber=part_num,
                    UploadId=upload_id,
                )

                parts.append({"PartNumber": part_num, "ETag": part["CopyPartResult"]["ETag"]})

            self.s3_client.complete_multipart_upload(
                Bucket=destination_bucket,
                Key=destination_key,
                UploadId=upload_id,
                MultipartUpload={"Parts": parts},
            )

            logger.info(f"Multipart copy completed successfully: {source_key} → {destination_key}")
            return True

        except ClientError as e:
            logger.error(f"S3 copy failed: {e}")
            if "upload_id" in locals():
                self.s3_client.abort_multipart_upload(
                    Bucket=destination_bucket,
                    Key=destination_key,
                    UploadId=upload_id,
                )
            return None

    def copy_s3_object_preserve_meta_kms_working_test(self, source_key: str, destination_key: str, destination_bucket=None, source_bucket=None, user_email=None,):  # 512 MB per part
        """
        Copy an S3 object to a new key or bucket, preserving:
        - Metadata, headers, and KMS encryption
        - Automatically uses multipart copy for files >= 100 MB
        """
        

        if source_bucket is None:
            source_bucket = self.bucket_name
        if destination_bucket is None:
            destination_bucket = source_bucket
        

        try:
            # Get the source object's metadata
            head = self.s3_client.head_object(Bucket=source_bucket, Key=source_key)
            copy_source = {"Bucket": source_bucket, "Key": source_key}
            size = head["ContentLength"]
            part_size = self.calculate_part_size(size)
            logger.info(f'S3 object copying started for user {user_email}  where media s3-key: {source_key} file size: {size}')
            

            # Preserve metadata and headers
            metadata = head.get("Metadata", {})
            content_type = head.get("ContentType") or mimetypes.guess_type(source_key)[0] or "application/octet-stream"
            content_disposition = head.get("ContentDisposition")
            cache_control = head.get("CacheControl")
            content_encoding = head.get("ContentEncoding")

            # Common arguments (valid for both copy_object and create_multipart_upload)
            common_args = {
                "Bucket": destination_bucket,
                "Key": destination_key,
                "Metadata": metadata,
                "ContentType": content_type,
            }
            if content_disposition:
                common_args["ContentDisposition"] = content_disposition
            if cache_control:
                common_args["CacheControl"] = cache_control
            if content_encoding:
                common_args["ContentEncoding"] = content_encoding

            # Preserve KMS encryption if present
            if head.get("ServerSideEncryption") == "aws:kms":
                common_args["ServerSideEncryption"] = "aws:kms"
                if head.get("SSEKMSKeyId"):
                    common_args["SSEKMSKeyId"] = head["SSEKMSKeyId"]

            # For small files (<100 MB)
            if size < 100 * 1024 * 1024:
                # MetadataDirective is ONLY valid for copy_object, not create_multipart_upload
                copy_args = {**common_args, "MetadataDirective": "REPLACE"}
                response = self.s3_client.copy_object(CopySource=copy_source, **copy_args)
                logger.info(f"Simple copy completed: {source_key} → {destination_key}")
                return response

            # For large files (>=100 MB) — use multipart copy
            logger.info(f"Large file detected ({size / 1024 / 1024:.2f} MB). Using multipart copy...")

            # create_multipart_upload does NOT accept MetadataDirective
            mpu = self.s3_client.create_multipart_upload(**common_args)
            upload_id = mpu["UploadId"]

            num_parts = math.ceil(size / part_size)
            parts = []

            for i in range(num_parts):
                start = i * part_size
                end = min(start + part_size - 1, size - 1)
                part_num = i + 1

                logger.info(f"Copying part {part_num}/{num_parts} (bytes {start}-{end})")

                part = self.s3_client.upload_part_copy(
                    Bucket=destination_bucket,
                    Key=destination_key,
                    CopySource=copy_source,
                    CopySourceRange=f"bytes={start}-{end}",
                    PartNumber=part_num,
                    UploadId=upload_id,
                )

                parts.append({"PartNumber": part_num, "ETag": part["CopyPartResult"]["ETag"]})

            self.s3_client.complete_multipart_upload(
                Bucket=destination_bucket,
                Key=destination_key,
                UploadId=upload_id,
                MultipartUpload={"Parts": parts},
            )

            logger.info(f'S3 object copying completed successfully for user {user_email}  where media s3-key: {source_key} → {destination_key} file size: {size}')
            return True

        except ClientError as e:
            logger.info(f'S3 object copying failed  for user {user_email}  where media s3-key: {source_key}  file size: {size} as /n {e}')
            
            if "upload_id" in locals():
                self.s3_client.abort_multipart_upload(
                    Bucket=destination_bucket,
                    Key=destination_key,
                    UploadId=upload_id,
                )
            raise e
            
            return None
    
    def upload_image_file_chunked(self,key: str,file_obj,content_type: str = None, progress_callback=None, base_chunk_size: int = 10 * 1024 * 1024):
        """
        Uploads a simple Django UploadedFile (image) to S3 using multipart upload.
        - Streams file in chunks (no full read into memory)
        - Dynamically  chunk size for optimal performance
        - Supports all image formats
        - Uses AWS KMS for server-side encryption
        """

        parts = []
        uploaded_bytes = 0
        upload_error = None
        upload_id = None
        s3 = self.s3_client
        kms = self.kms_client
        bucket = self.bucket_name

        try:
            # === Determine content type if not provided ===
            if not content_type:
                content_type = file_obj.content_type or mimetypes.guess_type(file_obj.name)[0] or "application/octet-stream"

            # === Determine file size ===
            file_obj.seek(0, os.SEEK_END)
            total_size = file_obj.tell()
            file_obj.seek(0)

            if total_size == 0:
                raise ValueError("Empty file cannot be uploaded.")

            # === Dynamic chunk sizing ===
            if total_size <= 20 * 1024 * 1024:
                effective_chunk_size = base_chunk_size
                use_threading = False
            elif total_size <= 100 * 1024 * 1024:
                effective_chunk_size = 8 * 1024 * 1024
                use_threading = True
            else:
                effective_chunk_size = 5 * 1024 * 1024
                use_threading = True

            if progress_callback:
                progress_callback(5, f"Uploading {file_obj.name} ({total_size/1024/1024:.2f} MB)")

            # === Generate KMS data key ===
            resp = kms.generate_data_key(KeyId=AWS_KMS_KEY_ID, KeySpec="AES_256")
            data_key_encrypted = resp["CiphertextBlob"]

            # === Initiate multipart upload ===
            multipart = s3.create_multipart_upload(
                Bucket=bucket,
                Key=key,
                ContentType=content_type,
                Metadata={
                    "edk": base64.b64encode(data_key_encrypted).decode(),
                    "orig-content-type": content_type,
                    "chunk-size": str(effective_chunk_size),
                },
                ServerSideEncryption="aws:kms",
                SSEKMSKeyId=AWS_KMS_KEY_ID,
            )
            upload_id = multipart["UploadId"]

            upload_queue = None
            parts_lock = None

            if use_threading:
                upload_queue = Queue(maxsize=3)
                parts_lock = threading.Lock()

                def upload_worker():
                    nonlocal upload_error, uploaded_bytes
                    while True:
                        try:
                            item = upload_queue.get(timeout=1)
                            if item is None:
                                break
                            part_num, chunk = item
                            try:
                                resp = s3.upload_part(
                                    Bucket=bucket,
                                    Key=key,
                                    PartNumber=part_num,
                                    UploadId=upload_id,
                                    Body=chunk,
                                )
                                with parts_lock:
                                    parts.append({"ETag": resp["ETag"], "PartNumber": part_num})
                                    uploaded_bytes += len(chunk)
                                    if progress_callback:
                                        percent = int((uploaded_bytes / total_size) * 100)
                                        progress_callback(min(percent, 95), f"Uploaded part {part_num}")
                            except Exception as e:
                                upload_error = e
                                break
                            finally:
                                upload_queue.task_done()
                        except Empty:
                            continue

                threading.Thread(target=upload_worker, daemon=True).start()

            # === Upload file chunks ===
            part_number = 1
            total_read = 0

            while True:
                chunk = file_obj.read(effective_chunk_size)
                if not chunk:
                    break
                total_read += len(chunk)

                if use_threading:
                    upload_queue.put((part_number, chunk))
                else:
                    resp = s3.upload_part(
                        Bucket=bucket,
                        Key=key,
                        PartNumber=part_number,
                        UploadId=upload_id,
                        Body=chunk,
                    )
                    parts.append({"ETag": resp["ETag"], "PartNumber": part_number})
                    uploaded_bytes += len(chunk)
                    if progress_callback:
                        percent = int((uploaded_bytes / total_size) * 100)
                        progress_callback(min(percent, 95), f"Uploaded part {part_number}")

                part_number += 1

            if use_threading:
                upload_queue.put(None)

            # === Complete upload ===
            parts.sort(key=lambda x: x["PartNumber"])
            result = s3.complete_multipart_upload(
                Bucket=bucket,
                Key=key,
                UploadId=upload_id,
                MultipartUpload={"Parts": parts},
            )

            if progress_callback:
                progress_callback(100, f"Upload complete: {file_obj.name}")

            return {"s3_result": result, "uploaded_size": uploaded_bytes}

        except Exception as e:
            if upload_id:
                try:
                    s3.abort_multipart_upload(Bucket=bucket, Key=key, UploadId=upload_id)
                except Exception:
                    pass
            if progress_callback:
                progress_callback(0, f"Upload failed: {e}")
            logger.error(f'upload failed {content_type} error: {e}')
            raise RuntimeError(f"Upload failed: {e}")

        finally:
            file_obj.seek(0)
  
    def decrypt_s3_file_chunked_streaming(self, key: str, output_file=None, progress_callback=None, chunk_size: int = 5 * 1024 * 1024):
        """
        Download file from S3 with AWS KMS encryption in streaming chunks.
        AWS automatically decrypts data during download.
        
        Features:
        - Streams data in chunks (no full file in memory)
        - Supports extremely large files (GB+)
        - Memory efficient - only keeps one chunk in memory at a time
        - Optional progress callback
        - Can write to file or return BytesIO
        
        Args:
            key: S3 object key
            output_file: Optional file path to write to. If None, returns BytesIO
            progress_callback: Optional callback(percent, message)
            chunk_size: Size of chunks to download (default 8MB)
        
        Returns:
            (data, content_type) - data is BytesIO if output_file is None, else file path
        """
        try:
            s3 = self.s3_client
            bucket = self.bucket_name
            
            # Get object metadata first to know file size
            head = s3.head_object(Bucket=bucket, Key=key)
            total_size = head.get("ContentLength", 0)
            metadata = head.get("Metadata", {})
            content_type = metadata.get("orig-content-type") or head.get("ContentType", "application/octet-stream")
            
            logger.info(f"📥 Downloading {key} ({total_size/1024/1024:.2f} MB)")
            
            if progress_callback:
                progress_callback(5, f"Starting download ({total_size/1024/1024:.2f} MB)")
            
            # Determine output destination
            if output_file:
                # Stream directly to file
                output = open(output_file, 'wb')
            else:
                # Stream to BytesIO
                output = BytesIO()
            
            try:
                # Get object with streaming
                obj = s3.get_object(Bucket=bucket, Key=key)
                body_stream = obj["Body"]
                
                downloaded_bytes = 0
                chunk_num = 0
                
                # Stream and write in chunks
                while True:
                    # Read chunk from S3 (AWS decrypts automatically)
                    chunk = body_stream.read(chunk_size)
                    if not chunk:
                        break
                    
                    chunk_num += 1
                    downloaded_bytes += len(chunk)
                    
                    # Write chunk to output
                    output.write(chunk)
                    
                    # Progress callback
                    if progress_callback and total_size > 0:
                        percent = min(int((downloaded_bytes / total_size) * 100), 99)
                        progress_callback(percent, f"Downloaded {downloaded_bytes/1024/1024:.1f}/{total_size/1024/1024:.1f} MB")
                    
                    logger.debug(f"✓ Chunk {chunk_num}: {len(chunk)} bytes")
                
                if progress_callback:
                    progress_callback(100, f"Download complete")
                
                logger.info(f"✓ Downloaded {key}: {downloaded_bytes} bytes in {chunk_num} chunks")
                
                # Prepare return value
                if output_file:
                    output.close()
                    return output_file, content_type
                else:
                    output.seek(0)
                    return output, content_type
                    
            except Exception as e:
                if output_file and hasattr(output, 'close'):
                    output.close()
                    # Clean up partial file
                    if os.path.exists(output_file):
                        os.remove(output_file)
                raise
                
        except Exception as e:
            logger.error(f"Error downloading {key}: {e}", exc_info=True)
            if progress_callback:
                progress_callback(0, f"Download failed: {e}")
            return None, None

s3_helper =  S3FileHandler()