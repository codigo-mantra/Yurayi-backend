import os
from storages.backends.s3boto3 import S3Boto3Storage
import boto3
import mimetypes
import boto3
from email.mime.image import MIMEImage

from django.conf import settings

from mutagen.mp3 import MP3
from mutagen.id3 import ID3, APIC
from mutagen.mp4 import MP4
from mutagen.flac import FLAC
from io import BytesIO



from mutagen.mp3 import MP3
from mutagen.id3 import ID3, APIC
from mutagen.mp4 import MP4
from mutagen.flac import FLAC
from io import BytesIO

class MediaThumbnailExtractor:
    def __init__(self, file, file_ext):
        """
        :param file: Django InMemoryUploadedFile or TemporaryUploadedFile
        :param file_ext: File extension like '.mp3', '.m4a', '.mp4', '.flac'
        """
        self.file = file
        self.extension = file_ext.lower()

    def extract(self):
        if self.extension in ['.mp3', '.m4a', '.mp4', '.flac']:
            return self._extract_audio_thumbnail()
        return None

    def _extract_audio_thumbnail(self):
        try:
            # Reset pointer just in case
            self.file.seek(0)
            data = BytesIO(self.file.read())
            data.seek(0)

            if self.extension == ".mp3":
                try:
                    audio = MP3(data, ID3=ID3)
                except Exception as e:
                    print("🔴 MP3 header sync issue, trying raw ID3")
                    try:
                        audio = ID3(data)
                    except Exception as e2:
                        print(f"❌ Failed to read ID3 tags: {e2}")
                        return None

                tags = getattr(audio, 'tags', audio)
                for tag in tags.values():
                    if isinstance(tag, APIC):
                        return tag.data

            elif self.extension in [".m4a", ".mp4"]:
                audio = MP4(data)
                if 'covr' in audio:
                    return audio['covr'][0]

            elif self.extension == ".flac":
                audio = FLAC(data)
                if audio.pictures:
                    return audio.pictures[0].data

        except Exception as e:
            print(f"❌ Thumbnail extraction failed: {e}")
        return None


from django.core.mail import EmailMultiAlternatives
from django.template.loader import render_to_string
from django.conf import settings


# def send_html_email(subject, to_email, template_name, context=None):
#     """
#     Send an HTML email using a template and context.

#     :param subject: Subject of the email
#     :param to_email: Recipient's email address (string or list)
#     :param template_name: Path to HTML template (e.g. 'emails/welcome_email.html')
#     :param context: Context dictionary for the template
#     :param from_email: Sender's email address (defaults to settings.DEFAULT_FROM_EMAIL)
#     """
    
#     from_email = settings.DEFAULT_FROM_EMAIL
#     if isinstance(to_email, str):
#         to_email = [to_email]
#     if context is None:
#         context = {}

#     html_content = render_to_string(template_name, context)

#     email = EmailMultiAlternatives(subject, "", from_email, to_email)
#     email.attach_alternative(html_content, "text/html")
#     email.send()


def send_html_email(subject, to_email, template_name, context=None, inline_images=None):
    """
    Send an HTML email using a template and context.

    :param subject: Subject of the email
    :param to_email: Recipient's email address (string or list)
    :param template_name: Path to HTML template (e.g. 'emails/welcome_email.html')
    :param context: Context dictionary for the template
    :param inline_images: Optional dict for CID images: {'cid_name': '/absolute/path/to/image.png'}
    """
    
    from_email = settings.DEFAULT_FROM_EMAIL
    if isinstance(to_email, str):
        to_email = [to_email]
    if context is None:
        context = {}

    html_content = render_to_string(template_name, context)

    email = EmailMultiAlternatives(subject, "", from_email, to_email)
    email.attach_alternative(html_content, "text/html")

    # Attach inline CID images if provided
    if inline_images:
        for cid, image_path in inline_images.items():
            if os.path.exists(image_path):
                with open(image_path, 'rb') as img:
                    mime_image = MIMEImage(img.read())
                    mime_image.add_header('Content-ID', f'<{cid}>')
                    mime_image.add_header('Content-Disposition', 'inline', filename=os.path.basename(image_path))
                    email.attach(mime_image)

    email.send()


# class MediaThumbnailExtractor:
#     def __init__(self, file_obj, file_ext):
#         """
#         :param file_obj: Django InMemoryUploadedFile or TemporaryUploadedFile
#         :param file_ext: File extension like '.mp3', '.mp4', etc.
#         """
#         self.file = file_obj
#         self.extension = file_ext.lower()

#     def extract(self):
#         if self.extension in ['.mp3', '.m4a', '.mp4', '.flac']:
#             return self._extract_audio_thumbnail()
#         return None

#     def _extract_audio_thumbnail(self):
#         try:
#             data = BytesIO(self.file.read())  # Reset later
#             self.file.seek(0)

#             if self.extension == ".mp3":
#                 audio = MP3(data, ID3=ID3)
#                 for tag in audio.tags.values():
#                     if isinstance(tag, APIC):
#                         return tag.data

#             elif self.extension in [".m4a", ".mp4"]:
#                 audio = MP4(data)
#                 if 'covr' in audio:
#                     return audio['covr'][0]

#             elif self.extension == ".flac":
#                 audio = FLAC(data)
#                 if audio.pictures:
#                     return audio.pictures[0].data

#         except Exception as e:
#             print(f"Thumbnail extraction failed: {e}")
#         return None


# class MediaThumbnailExtractor:
#     def __init__(self, media_path):
#         self.media_path = media_path
#         self.extension = os.path.splitext(media_path)[1].lower()

#     def extract(self, output_path="media/"):
#         if self.extension in ['.mp3', '.m4a', '.flac', '.mp4']:
#             return self._extract_audio_thumbnail(output_path)
#         # elif self.extension in ['.avi', '.mkv', '.mp4', '.mov', '.webm']:
#         #     return self._extract_video_thumbnail(output_path)
#         else:
#             raise ValueError(f"Unsupported media type: {self.extension}")

#     def _extract_audio_thumbnail(self, output_path):
#         try:
#             if self.extension == ".mp3":
#                 audio = MP3(self.media_path, ID3=ID3)
#                 for tag in audio.tags.values():
#                     if isinstance(tag, APIC):
#                         with open(output_path, 'wb') as img:
#                             img.write(tag.data)
#                         print(f"✅ MP3 album art saved to: {output_path}")
#                         return True

#             elif self.extension in [".m4a", ".mp4"]:
#                 audio = MP4(self.media_path)
#                 if 'covr' in audio:
#                     with open(output_path, 'wb') as img:
#                         img.write(audio['covr'][0])
#                     print(f"✅ M4A/MP4 album art saved to: {output_path}")
#                     return True

#             elif self.extension == ".flac":
#                 audio = FLAC(self.media_path)
#                 if audio.pictures:
#                     with open(output_path, 'wb') as img:
#                         img.write(audio.pictures[0].data)
#                     print(f"✅ FLAC album art saved to: {output_path}")
#                     return True

#             print("⚠️ No album art found.")
#             return False

#         except Exception as e:
#             print(f"❌ Error extracting audio thumbnail: {e}")
#             return False

    # def _extract_video_thumbnail(self, output_path):
    #     try:
    #         clip = VideoFileClip(self.media_path)
    #         frame = clip.get_frame(1)  # 1 second into the video
    #         clip.save_frame(output_path, t=1)
    #         print(f"✅ Video thumbnail saved to: {output_path}")
    #         clip.close()
    #         return True
    #     except Exception as e:
    #         print(f"❌ Error extracting video thumbnail: {e}")
    #         return False


class MediaRootS3Boto3Storage(S3Boto3Storage):
    location = 'media'  
    file_overwrite = False
    default_acl = 'private'


def upload_to_s3(file_path, s3_key=None):
    s3 = boto3.client(
        's3',
        aws_access_key_id=settings.AWS_ACCESS_KEY_ID,
        aws_secret_access_key=settings.AWS_SECRET_ACCESS_KEY,
        region_name=settings.AWS_S3_REGION_NAME
    )

    if not s3_key:
        s3_key = f'media/{os.path.basename(file_path)}'

    content_type, _ = mimetypes.guess_type(file_path)
    content_type = content_type or 'application/octet-stream'  # fallback

    with open(file_path, 'rb') as file_data:
        s3.upload_fileobj(
            file_data,
            settings.AWS_STORAGE_BUCKET_NAME,
            s3_key,
            ExtraArgs={
                'ContentType': content_type,
                'ACL': 'public-read'
            }
        )
    return f"https://{settings.AWS_STORAGE_BUCKET_NAME}.s3.{settings.AWS_S3_REGION_NAME}.amazonaws.com/{s3_key}"

def load_env(path='.env'):
    if os.path.exists(path):
        with open(path) as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    if '=' in line:
                        key, val = line.split('=', 1)
                        os.environ[key] = val
                    else:
                        print(f"Warning: Skipping invalid .env line: {line}")



def upload_to_s3(file_path):
    """Upload file to S3 and return the S3 URL"""
    try:
        s3_client = boto3.client(
            's3',
            aws_access_key_id=settings.AWS_ACCESS_KEY_ID,
            aws_secret_access_key=settings.AWS_SECRET_ACCESS_KEY,
            region_name=settings.AWS_S3_REGION_NAME
        )
        bucket_name = settings.AWS_STORAGE_BUCKET_NAME
        file_name = os.path.basename(file_path)
        with open(file_path, "rb") as file_obj:
            s3_client.upload_fileobj(file_obj, bucket_name, file_name)
        s3_url = f"https://{bucket_name}.s3.{settings.AWS_S3_REGION_NAME}.amazonaws.com/{file_name}"
        print(f"File uploaded to S3: {s3_url}")
        return s3_url
    except Exception as e:
        print(f"Error uploading to S3: {e}")
        return None

def upload_to_file_s3_bucket():
    try:
        s3_client = boto3.client(
            's3',
            aws_access_key_id=settings.AWS_ACCESS_KEY_ID,
            aws_secret_access_key=settings.AWS_SECRET_ACCESS_KEY,
            region_name=settings.AWS_S3_REGION_NAME
        )
        bucket_name = settings.AWS_STORAGE_BUCKET_NAME
    except:
        pass


import boto3
import json
import os

def get_aws_secret(secret_name: str, ):
    session = boto3.session.Session()
    client = session.client(
        service_name='secretsmanager',
        region_name='ap-south-1'
    )

    try:
        get_secret_value_response = client.get_secret_value(SecretId=secret_name)
    except Exception as e:
        raise Exception(f"Error retrieving secret {secret_name}: {e}")

    secret = get_secret_value_response.get('SecretString')
    if secret:
        return json.loads(secret)
    raise Exception("Secret not found")
