import io
import boto3
import pyclamd  
import mimetypes
import string, random
from django.conf import settings
from django.utils.text import slugify

from rest_framework import serializers

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
        print(f"\nException: {e}")

    finally:
        return readable_size



def get_file_category(file_name):
    import os

    extension = os.path.splitext(file_name)[1].lower()

    image_extensions = {'.jpg', '.jpeg', '.png', '.gif', '.bmp', '.tiff', '.webp', '.heic', '.svg', '.ico', '.raw', '.psd'}
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

class ProgressPercentage:
    def __init__(self, filename, filesize, callback=None):
        self._filename = filename
        self._filesize = filesize
        self._seen_so_far = 0
        self._lock = threading.Lock()
        self._callback = callback  # Optional callback to send progress updates

    def __call__(self, bytes_amount):
        # Thread-safe progress update
        with self._lock:
            self._seen_so_far += bytes_amount
            percentage = (self._seen_so_far / self._filesize) * 100

            # If no callback, just print to stdout
            if self._callback:
                self._callback(self._filename, round(percentage, 2))
            else:
                sys.stdout.write(
                    f"\r{self._filename}  {self._seen_so_far} / {self._filesize}  ({percentage:.2f}%)"
                )
                sys.stdout.flush()


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
            print(f'File deleted successfully from s3 s3: {s3_key} status: {is_deleted}')
        finally:
            return is_deleted



import jwt
from cryptography.fernet import Fernet
from django.conf import settings


class JWTEncryptionManager:
    def __init__(self, jwt_secret=None, fernet_key='vYkhUkBpskFnpYZphr05aIBgubkFfPmk_vm16J-XjV4='):
        # Load from Django settings or pass directly
        self.jwt_secret = jwt_secret or settings.SECRET_KEY
        self.fernet_key = fernet_key or getattr(settings, "FERNET_KEY", None)

        if not self.fernet_key:
            raise ValueError("FERNET_KEY must be defined in Django settings.")

        self.fernet = Fernet(self.fernet_key)

    def create_token(self, payload: dict, algorithm: str = "HS256") -> str:
        """
        Create a signed JWT and then encrypt it.
        """
        token = jwt.encode(payload, self.jwt_secret, algorithm=algorithm)
        encrypted = self.fernet.encrypt(token.encode())
        return encrypted.decode()

    def decode_token(self, encrypted_token: str, algorithm: str = "HS256") -> dict:
        """
        Decrypt token and then verify + decode JWT.
        """
        decrypted = self.fernet.decrypt(encrypted_token.encode()).decode()
        payload = jwt.decode(decrypted, self.jwt_secret, algorithms=[algorithm])
        return payload
