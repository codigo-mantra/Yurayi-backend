from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import base64
from django.conf import settings

import threading
from queue import Queue, Empty

import mimetypes
from io import BytesIO
import base64, os, re 
import logging
import boto3
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

    def copy_s3_object_preserve_meta_kms(self, source_key: str, destination_key: str, destination_bucket=None, source_bucket=None):
        """
        Copy an S3 object to a new key or bucket, preserving:
        - Metadata
        - Content-Type
        - Content-Disposition
        - Cache-Control
        - Content-Encoding
        - KMS encryption
        Automatically detects Content-Type if missing or generic.
        """

        if source_bucket is None:
            source_bucket = self.bucket_name
        if destination_bucket is None:
            destination_bucket = source_bucket

        try:
            # Get the source object's metadata
            head = self.s3_client.head_object(Bucket=source_bucket, Key=source_key)
            copy_source = {"Bucket": source_bucket, "Key": source_key}

            # Preserve custom metadata
            metadata = head.get("Metadata", {})

            # Preserve headers
            content_type = head.get("ContentType")
            if not content_type or content_type == "application/octet-stream":
                guessed_type, _ = mimetypes.guess_type(source_key)
                content_type = guessed_type or "application/octet-stream"

            content_disposition = head.get("ContentDisposition")
            cache_control = head.get("CacheControl")
            content_encoding = head.get("ContentEncoding")

            copy_args = {
                "Bucket": destination_bucket,
                "CopySource": copy_source,
                "Key": destination_key,
                "Metadata": metadata,
                "ContentType": content_type,
                "MetadataDirective": "REPLACE",  # needed when replacing metadata
            }

            # Add optional headers if they exist
            if content_disposition:
                copy_args["ContentDisposition"] = content_disposition
            if cache_control:
                copy_args["CacheControl"] = cache_control
            if content_encoding:
                copy_args["ContentEncoding"] = content_encoding

            # Preserve KMS encryption if present
            if head.get("ServerSideEncryption") == "aws:kms":
                copy_args["ServerSideEncryption"] = "aws:kms"
                copy_args["SSEKMSKeyId"] = head.get("SSEKMSKeyId")

            # Perform the copy
            response = self.s3_client.copy_object(**copy_args)
            print(f"✅ Copied (meta + KMS + headers): s3://{source_bucket}/{source_key} → s3://{destination_bucket}/{destination_key}")
            return response

        except Exception as e:
            logger.error(f"❌ Failed to copy object: s3://{source_bucket}/{source_key} → s3://{destination_bucket}/{destination_key} | {e}")
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