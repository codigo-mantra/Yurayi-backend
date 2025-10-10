import io
import boto3
import pyclamd  
import mimetypes
import string, random
from django.conf import settings
from django.utils.text import slugify

import json,io
import hmac
import base64
import hashlib
from PIL import Image, UnidentifiedImageError


from rest_framework import serializers
import logging
logger = logging.getLogger(__name__)


s3 = boto3.client(
        's3',
        aws_access_key_id=settings.AWS_ACCESS_KEY_ID,
        aws_secret_access_key=settings.AWS_SECRET_ACCESS_KEY,
        region_name=settings.AWS_S3_REGION_NAME
    )

def generate_signature(s3_key: str, exp: int) -> str:
    """
    Generate base64-encoded HMAC signature for s3_key and expiry.
    """
    raw = f"{s3_key}:{exp}"
    sig = hmac.new(settings.SECRET_KEY.encode(), raw.encode(), hashlib.sha256).digest()
    return base64.urlsafe_b64encode(sig).decode().rstrip("=")


def generate_unique_slug(instance, queryset=None):
    """
    Generate a unique slug for a model instance.
    """
    slug_base = slug = slugify(instance.name)

    slug = slug_base
    model_class = instance.__class__
    
    if queryset is None:
        queryset = model_class.objects.all()

    str_letters = string.ascii_lowercase
    while queryset.filter(slug = slug).exclude(pk=instance.pk).exists():
        slug = slugify(slug + random.choice(str_letters) + str(random.randint(1,9)))
    
    return slug



# def get_readable_file_size_from_bites(size_in_bytes):
#     calculated_size = size_in_bytes
#     try:
#         size_in_bytes = float(size_in_bytes)
#     except Exception as e:
#         print(f'\n Exception as  {e}')
#     else:
#         kb = size_in_bytes / 1024

#         if kb < 1024:
#             return f"{kb:.2f} KB"
        
#         mb = kb / 1024
#         if mb < 1024:
#             return f"{mb:.2f} MB"
        
#         gb = mb / 1024
#         return f"{gb:.2f} GB"
#     finally:
#         return calculated_size

def get_readable_file_size_from_bytes(size_in_bytes):
    """
    Convert a file size in bytes to a human-readable string (KB, MB, or GB).
    Always returns something in the finally block.
    """
    readable_size = size_in_bytes  # Default fallback
    try:
        size_in_bytes = float(size_in_bytes)
        kb = size_in_bytes / 1024

        if kb < 1024:
            readable_size = f"{kb:.2f} KB"
        else:
            mb = kb / 1024
            if mb < 1024:
                readable_size = f"{mb:.2f} MB"
            else:
                gb = mb / 1024
                readable_size = f"{gb:.2f} GB"

    except (ValueError, TypeError) as e:
        logger.warning("Invalid file size for readable conversion")

    finally:
        return readable_size



def get_file_category(file_name):
    import os

    extension = os.path.splitext(file_name)[1].lower()

    image_extensions = {'.jpg', '.jpeg', '.png', '.gif', '.bmp', '.tiff', '.webp', '.heic', '.heif', '.svg', '.ico', '.raw', '.psd'}
    video_extensions = {'.mp4', '.avi', '.mov', '.wmv', '.flv', '.mkv', '.webm', '.3gp', '.mpeg', '.mpg', '.ts', '.m4v'}
    audio_extensions = {'.mp3', '.wav', '.aac', '.flac', '.ogg', '.wma', '.alac', '.aiff', '.m4a', '.opus', '.amr'}
    
    # Grouped as "other" valid type
    other_extensions = {'.txt', '.doc', '.docx', '.pdf', '.rtf', '.odt', '.md', '.tex',
                        '.csv', '.xls', '.xlsx', '.ods', '.tsv', '.json', '.xml', '.yaml', '.yml',
                        '.zip', '.rar', '.7z', '.tar', '.gz', '.bz2', '.xz', '.iso',
                        '.exe', '.msi', '.apk', '.bat', '.sh', '.app',
                        '.html', '.htm', '.css', '.js', '.ts', '.py', '.java', '.c', '.cpp', '.cs',
                        '.php', '.rb', '.go', '.swift', '.rs', '.kt', '.sql', '.ini', '.env', '.toml'}

    if extension in image_extensions:
        return 'image'
    elif extension in video_extensions:
        return 'video'
    elif extension in audio_extensions:
        return 'audio'
    elif extension in other_extensions:
        return 'other'
    else:
        return 'invalid'

    
def upload_file_to_s3_bucket(file, folder=None):
    import io
    import boto3
    import mimetypes
    from django.conf import settings

    # Step 1: Setup file name and content type
    original_file_name = file.name
    if folder:
        file_name = f"{folder}/{original_file_name}"
    else:
        file_name = original_file_name

    file_category = get_file_category(original_file_name)
    s3_key = f"{file_category}/{file_name}"
    content_type = mimetypes.guess_type(original_file_name)[0] or 'application/octet-stream'

    # Step 2: Prepare file buffer
    file.seek(0)
    buffer = io.BytesIO(file.read())

    # Step 3: Upload to S3
    s3 = boto3.client(
        's3',
        aws_access_key_id=settings.AWS_ACCESS_KEY_ID,
        aws_secret_access_key=settings.AWS_SECRET_ACCESS_KEY,
        region_name=settings.AWS_S3_REGION_NAME
    )

    try:
        s3.upload_fileobj(
            buffer,
            settings.AWS_STORAGE_BUCKET_NAME,
            s3_key,
            ExtraArgs={
                'ContentType': content_type,
                'ACL': 'public-read'  # Change to 'private' if needed
            }
        )
    except Exception as e:
        raise Exception(f"S3 upload failed: {str(e)}")

    # Step 4: Build full S3 URL
    s3_url = f"https://{settings.AWS_STORAGE_BUCKET_NAME}.s3.{settings.AWS_S3_REGION_NAME}.amazonaws.com/{s3_key}"

    return (s3_url, file_category, s3_key)

def determine_download_chunk_size(file_size):
    """
    Dynamically determine chunk size based on file size (in bytes).
    """
    if file_size <= 10 * 1024 * 1024:      # <= 10 MB
        return 512 * 1024                 # 512 KB
    elif file_size <= 100 * 1024 * 1024:   # <= 100 MB
        return 1 * 1024 * 1024            # 1 MB
    elif file_size <= 500 * 1024 * 1024:   # <= 500 MB
        return 2 * 1024 * 1024            # 2 MB
    else:
        return 5 * 1024 * 1024            # 5 MB for large files

import threading
import sys

class S3FileHandler:
    def __init__(self):
        self.s3 = boto3.client(
            's3',
            aws_access_key_id=settings.AWS_ACCESS_KEY_ID,
            aws_secret_access_key=settings.AWS_SECRET_ACCESS_KEY,
            region_name=settings.AWS_S3_REGION_NAME
        )
        self.bucket_name = settings.AWS_STORAGE_BUCKET_NAME
        self.region = settings.AWS_S3_REGION_NAME
        self.clam = None  # Lazy load

    def _get_virus_scanner(self):
        import pyclamd

        # Try Unix socket first
        try:
            clam = pyclamd.ClamdUnixSocket()
            clam.ping()
            return clam
        except:
            pass

        # Fallback to TCP socket
        try:
            clam = pyclamd.ClamdNetworkSocket(host='127.0.0.1', port=3310)
            clam.ping()
            return clam
        except:
            raise Exception("Could not connect to ClamAV daemon")

    def _ensure_clam(self):
        if not self.clam:
            self.clam = self._get_virus_scanner()

    def scan_file_for_viruses(self, file_buffer: io.BytesIO):
        self._ensure_clam()
        file_buffer.seek(0)
        result = self.clam.scan_stream(file_buffer.read())
        if result:
            raise Exception(f"Virus detected in file: {result}")
        file_buffer.seek(0)

    # def upload_file_to_s3_bucket(self, file, folder=None, file_category=None):
    #     original_file_name = file.name
    #     # file_category = get_file_category(original_file_name)
    #     # if file_category == 'invalid':
    #     #     raise serializers.ValidationError({'file_type': 'File type is invalid.'})

    #     file_name = f"{folder}/{original_file_name}" if folder else original_file_name
    #     if file_category: 
    #         s3_key = f"{file_category}/{file_name}"
    #     else:
    #         s3_key = f"{file_name}"



    #     content_type = mimetypes.guess_type(original_file_name)[0] or 'application/octet-stream'

    #     file.seek(0)
    #     buffer = io.BytesIO(file.read())

    #     # Scan before upload
    #     # self.scan_file_for_viruses(buffer)

    #     try:
    #         self.s3.upload_fileobj(
    #             buffer,
    #             self.bucket_name,
    #             s3_key,
    #             ExtraArgs={
    #                 'ContentType': content_type,
    #                 'ACL': 'public-read'
    #             }
    #         )
    #     except Exception as e:
    #         raise Exception(f"S3 upload failed: {str(e)}")

    #     s3_url = f"https://{self.bucket_name}.s3.{self.region}.amazonaws.com/{s3_key}"
    #     return s3_url, file_category, s3_key
    
    def upload_file_to_s3_bucket(self, file, folder=None, file_category=None, progress_callback=None):
        original_file_name = file.name
        file_name = f"{folder}/{original_file_name}" if folder else original_file_name
        s3_key = f"{file_category}/{file_name}" if file_category else file_name
        content_type = mimetypes.guess_type(original_file_name)[0] or 'application/octet-stream'

        file.seek(0)
        buffer = io.BytesIO(file.read())

        # Wrap buffer to track progress
        if progress_callback:
            total_size = len(buffer.getvalue())

            class ProgressWrapper(io.BytesIO):
                def __init__(self, data):
                    super().__init__(data)
                    self.bytes_uploaded = 0

                def read(self, amt=-1):
                    chunk = super().read(amt)
                    self.bytes_uploaded += len(chunk)
                    percent = int((self.bytes_uploaded / total_size) * 100)
                    progress_callback(percent)
                    return chunk

            buffer = ProgressWrapper(buffer.getvalue())

        try:
            self.s3.upload_fileobj(
                buffer,
                self.bucket_name,
                s3_key,
                ExtraArgs={'ContentType': content_type, 'ACL': 'public-read'}
            )
        except Exception as e:
            raise Exception(f"S3 upload failed: {str(e)}")

        s3_url = f"https://{self.bucket_name}.s3.{self.region}.amazonaws.com/{s3_key}"
        return s3_url, file_category, s3_key


    def delete_file_from_s3_bucket(self, s3_key):
        is_deleted = False
        try:
            self.s3.delete_object(Bucket=self.bucket_name, Key=s3_key)
        except Exception as e:
            raise Exception(f"S3 delete failed: {str(e)}")
        else:
            is_deleted = True
            logger.info('File deleted from s3')
        finally:
            return is_deleted


import re

# def parse_storage_size(size_str, default_unit="MB"):
#     """
#     Parse a size string like '1.53 MB', '200 kb', '3.4 Gb', '0.75 tb'
#     into (float_value, unit in uppercase).
#     If size_str is empty or invalid, return (0, default_unit)
#     """
#     if not size_str or not size_str.strip():
#         return 0, default_unit.upper()
    
#     match = re.match(r"(\d+(?:\.\d+)?)\s*(KB|MB|GB|TB)", size_str.strip(), re.IGNORECASE)
#     if not match:
#         return 0, default_unit.upper()
    
#     value, unit = match.groups()
#     return float(value), unit.upper()

import re

def parse_storage_size(size_str):
    """
    Parse a size string like '1.53 MB', '200 kb', '3.4 Gb', '0.75 tb'
    and always return the value in GB.
    If size_str is empty or invalid, return (0, 'GB')
    """
    if not size_str or not size_str.strip():
        return 0, "GB"
    
    match = re.match(r"(\d+(?:\.\d+)?)\s*(KB|MB|GB|TB)", size_str.strip(), re.IGNORECASE)
    if not match:
        return 0, "GB"
    
    value, unit = match.groups()
    value = float(value)
    unit = unit.upper()

    # Convert everything to GB
    if unit == "KB":
        value = value / (1024 * 1024)
    elif unit == "MB":
        value = value / 1024
    elif unit == "GB":
        value = value
    elif unit == "TB":
        value = value * 1024

    return value, "GB"



def to_mb(value, unit):
    """
    Convert any size to MB.
    """
    unit = unit.upper()
    if unit == "KB":
        return value / 1024
    elif unit == "MB":
        return value
    elif unit == "GB":
        return value * 1024
    elif unit == "TB":
        return value * 1024 * 1024
    else:
        raise ValueError(f"Unknown unit: {unit}")
    

def to_gb(value, unit):
    """
    Convert any size to GB.
    """
    unit = unit.upper()
    if unit == "KB":
        return value / (1024 * 1024)
    elif unit == "MB":
        return value / 1024
    elif unit == "GB":
        return value
    elif unit == "TB":
        return value * 1024
    else:
        raise ValueError(f"Unknown unit: {unit}")



import os
import subprocess
import tempfile

def convert_doc_to_docx_bytes(doc_bytes: bytes, media_file_id=None, email=None) -> bytes:
    """
    Convert a .doc file (binary bytes) to .docx using LibreOffice.
    Returns the .docx file bytes.
    """
    try:
        print(f'\n---doc conversion called---')
        logger.info(f'Doc to docx conversion started for {media_file_id} for user : {email}')
        # Save .doc temporarily
        with tempfile.NamedTemporaryFile(suffix=".doc", delete=False) as tmp_doc:
            tmp_doc.write(doc_bytes)
            tmp_doc.flush()
            doc_path = tmp_doc.name

        # Temporary output folder
        output_dir = tempfile.mkdtemp()

        # Convert to .docx using LibreOffice headless
        subprocess.run([
            "soffice", "--headless", "--convert-to", "docx",
            "--outdir", output_dir, doc_path
        ], check=True)

        # Read converted file
        docx_path = os.path.join(output_dir, os.path.basename(doc_path).replace(".doc", ".docx"))
        with open(docx_path, "rb") as f:
            docx_bytes = f.read()

        # Cleanup
        os.remove(doc_path)
        os.remove(docx_path)
        os.rmdir(output_dir)
        print(f'\n---doc conversion completed---')
        logger.info(f'Doc to docx conversion completed for {media_file_id} for user : {email}')
        

        return docx_bytes
    except Exception as e:
        logger.error(f'Exception while converting doc file docx as {e}')


from pillow_heif import register_heif_opener
from PIL import Image
import io

register_heif_opener()

# def convert_heic_to_jpeg_bytes(file_bytes):
#     image = Image.open(io.BytesIO(file_bytes))
#     output = io.BytesIO()
#     image.convert("RGB").save(output, format="JPEG", quality=90)
#     return output.getvalue(), "image/jpeg"



def convert_heic_to_jpeg_bytes(file_bytes, quality: int = 95):
    """
    Convert HEIC/HEIF image bytes to high-quality JPEG bytes.

    Args:
        file_bytes (bytes): The HEIC/HEIF file content.
        quality (int): JPEG output quality (default=95, max=100).

    Returns:
        tuple: (jpeg_bytes, "image/jpeg")

    Raises:
        ValueError: If conversion fails or input is invalid.
    """
    input_buffer = None
    output_buffer = None

    try:
        # Wrap input in memory buffer
        input_buffer = io.BytesIO(file_bytes)

        try:
            image = Image.open(input_buffer)
        except UnidentifiedImageError as e:
            logger.error(f"[HEIC->JPEG] Unsupported image format: {e}")
            raise ValueError("Invalid HEIC/HEIF image data") from e

        # Ensure RGB (JPEG doesn’t support alpha/other modes)
        if image.mode == "RGBA":
            background = Image.new("RGB", image.size, (255, 255, 255))
            background.paste(image, mask=image.split()[3])  # handle alpha
            image = background
        elif image.mode != "RGB":
            image = image.convert("RGB")

        # Save as JPEG
        output_buffer = io.BytesIO()
        image.save(output_buffer, format="JPEG", quality=quality, optimize=True)
        jpeg_bytes = output_buffer.getvalue()

        return jpeg_bytes, "image/jpeg"

    except Exception as e:
        logger.exception(f"[HEIC->JPEG] Conversion failed: {e}")
        raise ValueError("HEIC to JPEG conversion failed") from e

    finally:
        # Cleanup buffers to free memory
        if input_buffer:
            input_buffer.close()
        if output_buffer:
            output_buffer.close()


import subprocess
import io

import subprocess
import io
import tempfile
import os
import logging

logger = logging.getLogger(__name__)

def convert_mkv_to_mp4_bytes(file_bytes):
    """
    Convert MKV video bytes to MP4 (container rewrap) using ffmpeg.
    Returns (mp4_bytes, content_type) or raises Exception if conversion fails.
    """
    input_path = None
    output_path = None

    try:
        # Create temporary files
        with tempfile.NamedTemporaryFile(suffix=".mkv", delete=False) as tmp_in:
            tmp_in.write(file_bytes)
            input_path = tmp_in.name

        output_path = input_path.replace(".mkv", ".mp4")

        # Run ffmpeg to rewrap MKV -> MP4 without re-encoding
        subprocess.run(
            ["ffmpeg", "-y", "-i", input_path, "-c", "copy", output_path],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=True
        )

        # Read back converted file
        with open(output_path, "rb") as f:
            converted_bytes = f.read()

        logger.info(f"MKV to MP4 conversion successful: {len(converted_bytes)} bytes")
        return converted_bytes, "video/mp4"

    except subprocess.CalledProcessError as e:
        logger.error(f"ffmpeg conversion failed: {e.stderr.decode(errors='ignore')}")
        raise
    except Exception as e:
        logger.error(f"Unexpected error in MKV conversion: {e}")
        raise
    finally:
        # Cleanup temp files
        try:
            if input_path and os.path.exists(input_path):
                os.remove(input_path)
            if output_path and os.path.exists(output_path):
                os.remove(output_path)
        except Exception as cleanup_err:
            logger.warning(f"Failed to clean up temp files: {cleanup_err}")


import re

def convert_file_size(size_str, target_unit="MB"):
    """
    Convert a file size string (e.g. '28.42 MB') into the given target format.
    
    Args:
        size_str (str): The input size, e.g. '28.42 MB'
        target_unit (str): One of 'KB', 'MB', 'GB', 'TB'
    
    Returns:
        str: Converted size string in requested format, rounded to 2 decimals.
    """
    try:
        if not size_str or not str(size_str).strip():
            return 0,f"{target_unit.upper()}"
        
        match = re.match(r"(\d+(?:\.\d+)?)\s*(KB|MB|GB|TB)", str(size_str).strip(), re.IGNORECASE)
        if not match:
            return f"0 {target_unit.upper()}"
        
        value, unit = match.groups()
        value = float(value)
        unit = unit.upper()
        target_unit = target_unit.upper()

        # Step 1: Convert everything to GB
        if unit == "KB":
            value_gb = value / (1024 * 1024)
        elif unit == "MB":
            value_gb = value / 1024
        elif unit == "GB":
            value_gb = value
        elif unit == "TB":
            value_gb = value * 1024
        else:
            return 0, target_unit

        # Step 2: Convert GB → target unit
        if target_unit == "KB":
            final_value = value_gb * 1024 * 1024
        elif target_unit == "MB":
            final_value = value_gb * 1024
        elif target_unit == "GB":
            final_value = value_gb
        elif target_unit == "TB":
            final_value = value_gb / 1024
        else:
            return 0, target_unit

        # Format: avoid trailing ".0"
        final_value = round(final_value, 2)
        if final_value.is_integer():
            final_value = int(final_value)

        return final_value,target_unit

    except Exception:
            return 0, target_unit

import boto3
from botocore.exceptions import ClientError

def delete_s3_file(s3_key: str, bucket_name: str = 'yurayi-media') -> bool:
    """
    Delete a file from S3 using its key.
    
    Args:
        s3_key (str): The S3 object key (e.g., 'media/uploads/file.jpg')
        bucket_name (str, optional): S3 bucket name. 
            Defaults to settings.AWS_STORAGE_BUCKET_NAME.
    
    Returns:
        bool: True if deleted successfully, False otherwise.
    """
    bucket = bucket_name or getattr(settings, "AWS_STORAGE_BUCKET_NAME", None)
    if not bucket:
        print("Error: S3 bucket name not configured.")
        return False

    try:
        s3.delete_object(Bucket=bucket, Key=s3_key)
        print(f"Deleted {s3_key} from {bucket}")
        return True
    except ClientError as e:
        error_code = e.response.get("Error", {}).get("Code", "")
        if error_code == "NoSuchKey":
            print(f"File not found in S3: {s3_key}")
        else:
            print(f"Failed to delete {s3_key}: {e}")
        return False
    except Exception as e:
        print(f"Unexpected error deleting {s3_key}: {e}")
        return False


def auto_format_size(size_kb: float, round_digit=5):
    """
    Automatically format a file size in KB to the most appropriate unit (KB, MB, or GB).
    
    Args:
        size_kb (float): Size in kilobytes.
    
    Returns:
        tuple: (value, unit) — e.g. (512.35, 'KB'), (42.3, 'MB'), (1.2, 'GB')
    """
    try:
        if size_kb < 0:
            return 0, "KB"

        KB_IN_MB = 1024
        KB_IN_GB = 1024 * 1024

        if size_kb < KB_IN_MB:  # < 1 MB
            value = round(size_kb, round_digit)
            unit = "KB"
        elif size_kb < KB_IN_GB:  # < 1 GB
            value = round(size_kb / KB_IN_MB, round_digit)
            unit = "MB"
        else:
            value = round(size_kb / KB_IN_GB, round_digit)
            unit = "GB"

        return value, unit
    except Exception:
        return 0, "KB"
