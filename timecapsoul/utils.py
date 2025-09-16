import os
from storages.backends.s3boto3 import S3Boto3Storage
import boto3
import mimetypes
import json
from email.mime.image import MIMEImage

from django.conf import settings
import logging
logger = logging.getLogger(__name__)

from mutagen.mp3 import MP3
from mutagen.mp4 import MP4
from mutagen.flac import FLAC
from io import BytesIO
from mutagen.id3 import ID3, APIC

from django.core.mail import EmailMultiAlternatives
from django.template.loader import render_to_string
from django.conf import settings

class MediaThumbnailExtractor:
    def __init__(self, file=None, file_ext=None):
        """
        :param file: Django InMemoryUploadedFile or TemporaryUploadedFile
        :param file_ext: File extension like '.mp3', '.m4a', '.mp4', '.flac'
        """
        self.file = file
        self.extension = file_ext.lower()
        pass

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
                    logger.warning("MP3 header sync issue, trying raw ID3")
                    try:
                        audio = ID3(data)
                    except Exception as e2:
                        logger.error("Failed to read ID3 tags", extra={"error": str(e2)})
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
            logger.error("Thumbnail extraction failed", extra={"error": str(e)})
        return None
    
    def extract_audio_thumbnail_from_bytes(self, extension, decrypted_bytes):
        if extension  not in ['.mp3', '.m4a', '.mp4', '.flac']:
            return None
        try:
            data = BytesIO(decrypted_bytes)
            data.seek(0)

            if extension == ".mp3":
                try:
                    audio = MP3(data, ID3=ID3)
                except Exception as e:
                    logger.warning("MP3 header sync issue, trying raw ID3")
                    try:
                        audio = ID3(data)
                    except Exception as e2:
                        logger.error("Failed to read ID3 tags", extra={"error": str(e2)})
                        return None

                tags = getattr(audio, 'tags', audio)
                for tag in tags.values():
                    if isinstance(tag, APIC):
                        return tag.data

            elif extension in [".m4a", ".mp4"]:
                audio = MP4(data)
                if 'covr' in audio:
                    return audio['covr'][0]

            elif extension == ".flac":
                audio = FLAC(data)
                if audio.pictures:
                    return audio.pictures[0].data

        except Exception as e:
            logger.error("Thumbnail extraction failed", extra={"error": str(e)})
        return None

def send_html_email(subject, to_email, template_name, context=None, inline_images=None, email_list = None):
    """
    Send an HTML email using a template and context.

    :param subject: Subject of the email
    :param to_email: Recipient's email address (string or list)
    :param template_name: Path to HTML template (e.g. 'emails/welcome_email.html')
    :param context: Context dictionary for the template
    :param inline_images: Optional dict for CID images: {'cid_name': '/absolute/path/to/image.png'}
    """
    try:
        from_email = settings.DEFAULT_FROM_EMAIL
        if email_list is None:
            if isinstance(to_email, str):
                to_email = [to_email]
        else:
            to_email = email_list
            
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
                        img_data = img.read()
                        content_type, encoding = mimetypes.guess_type(image_path)
                        maintype, subtype = content_type.split('/') if content_type else ('image', 'png')
                        mime_image = MIMEImage(img_data, _subtype=subtype)
                        mime_image.add_header('Content-ID', f'<{cid}>')
                        mime_image.add_header('Content-Disposition', 'inline', filename=os.path.basename(image_path))
                        email.attach(mime_image)

        email.send()
    except Exception as e:
        pass

class MediaRootS3Boto3Storage(S3Boto3Storage):
    location = 'media'  
    file_overwrite = False
    default_acl = 'private'


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
                        logger.warning("Skipping invalid .env line", extra={"line": line})


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
    raise Exception(f"\n -------- Exception: AWS Secret not found --------")


def process_sqs_messages(sqs, queue_url):
    response = sqs.receive_message(
        QueueUrl=queue_url,
        MaxNumberOfMessages=10,
        WaitTimeSeconds=5
    )

    if "Messages" in response:
        for message in response["Messages"]:
            body = json.loads(message["Body"]) 
            logger.info("S3 Event received", extra={"body": body})

            # Delete message from queue after processing
            sqs.delete_message(
                QueueUrl=queue_url,
                ReceiptHandle=message["ReceiptHandle"]
            )
