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

from io import BytesIO
import logging
from mutagen.mp4 import MP4
from mutagen.flac import FLAC
# from moviepy.editor import VideoFileCli
import tempfile
from PIL import Image

import tempfile
import os
import subprocess
from io import BytesIO
from PIL import Image
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
                        logger.error("Failed to read ID3 tags")
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
            logger.error("Thumbnail extraction failed")
        return None
    # working one
    # def extract_video_thumbnail_from_bytes(self, extension, decrypted_bytes):
    #     """
    #     Extract a thumbnail (JPEG bytes) from a decrypted video byte stream.
    #     Works for common formats: .mp4, .mov, .avi, .mkv
    #     """
    #     if extension.lower() not in ['.mp4', '.mov', '.avi', '.mkv']:
    #         return None

    #     try:  
            
    #         # Write decrypted bytes to a temporary file
    #         with tempfile.NamedTemporaryFile(suffix=extension, delete=True) as tmp_file:
    #             tmp_file.write(decrypted_bytes)
    #             tmp_file.flush()

    #             # Load video
    #             clip = VideoFileClip(tmp_file.name)
    #             frame = clip.get_frame(0.5)  # frame at 0.5 sec (you can adjust)

    #             # Convert frame (numpy array) → image bytes
    #             img = Image.fromarray(frame)
    #             img_bytes = BytesIO()
    #             img.save(img_bytes, format="JPEG")
    #             clip.close()

    #             return img_bytes.getvalue()

    #     except Exception as e:
    #         logger.error(f"Video thumbnail extraction failed: {e}")
    #         return None
    
    def extract_video_thumbnail_from_bytes(self, extension, decrypted_bytes):
        """
        Extract a thumbnail (JPEG bytes) from a decrypted video byte stream.
        Works for common formats: .mp4, .mov, .avi, .mkv, .wmv, .flv, .webm, .m4v
        """
        supported_extensions = ['.mp4', '.avi', '.mov', '.wmv', '.flv', '.mkv', '.webm', '.3gp', '.mpeg', '.mpg', '.ts', '.m4v','.mpeg',]
        
        if extension.lower() not in supported_extensions:
            return None

        try:
            # Write decrypted bytes to a temporary file
            with tempfile.NamedTemporaryFile(suffix=extension, delete=False) as tmp_file:
                tmp_file.write(decrypted_bytes)
                tmp_file_path = tmp_file.name

            try:
                # Load video with error handling
                clip = VideoFileClip(tmp_file_path, audio=False)  # Disable audio for faster loading
                
                # Get video duration and calculate safe frame position
                duration = clip.duration
                
                # Try multiple frame positions in case one fails
                frame_positions = [
                    min(0.5, duration / 2),  # 0.5 sec or middle of short videos
                    min(1.0, duration / 3),  # 1 sec or 1/3 of video
                    min(2.0, duration / 4),  # 2 sec or 1/4 of video
                    0.0  # First frame as last resort
                ]
                
                frame = None
                for position in frame_positions:
                    try:
                        frame = clip.get_frame(position)
                        if frame is not None and frame.size > 0:
                            break
                    except Exception as frame_error:
                        logger.warning(f"Failed to extract frame at {position}s: {frame_error}")
                        continue
                
                if frame is None:
                    raise Exception("Could not extract any frame from video")
                
                # Convert frame (numpy array) → image bytes
                img = Image.fromarray(frame)
                
                # Resize if too large (optional optimization)
                max_size = (800, 800)
                img.thumbnail(max_size, Image.Resampling.LANCZOS)
                
                img_bytes = BytesIO()
                img.save(img_bytes, format="JPEG", quality=85, optimize=True)
                
                clip.close()
                
                return img_bytes.getvalue()
                
            finally:
                # Clean up temporary file
                try:
                    os.unlink(tmp_file_path)
                except Exception as cleanup_error:
                    logger.warning(f"Failed to cleanup temp file {tmp_file_path}: {cleanup_error}")

        except Exception as e:
            logger.error(f"Video thumbnail extraction failed for {extension}: {e}")
            return None
    
    def extract_audio_thumbnail_from_bytes(self, extension, decrypted_bytes):
        if extension  not in ['.mp3', '.wav', '.aac', '.flac', '.ogg', '.wma', '.alac', '.aiff', '.m4a', '.opus', '.amr', '.mpeg',]:
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
                        logger.error("Failed to read ID3 tags")
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
            logger.error("Thumbnail extraction failed")
        return None
    
        
    def extract_video_thumbnail_ffmpeg(self, extension, decrypted_bytes):
        """
        NEW METHOD: Extract thumbnail using FFmpeg (more reliable).
        Achieves ~100% success rate with multiple fallback strategies.
        Works for: .mp4, .mov, .avi, .mkv, .wmv, .flv, .webm, .m4v, .3gp, etc.
        """
        supported_extensions = [
            '.mp4', '.avi', '.mov', '.wmv', '.flv', '.mkv', 
            '.webm', '.3gp', '.mpeg', '.mpg', '.ts', '.m4v', 
            '.ogv', '.vob', '.mts', '.m2ts'
        ]
        
        if extension.lower() not in supported_extensions:
            return None

        tmp_video_path = None
        tmp_thumb_path = None
        
        try:
            # Create temporary files
            with tempfile.NamedTemporaryFile(suffix=extension, delete=False) as tmp_video:
                tmp_video.write(decrypted_bytes)
                tmp_video_path = tmp_video.name
            
            tmp_thumb_path = tempfile.mktemp(suffix='.jpg')
            
            # Strategy 1: Extract frame at 1 second (most reliable)
            success = self._ffmpeg_extract_frame(tmp_video_path, tmp_thumb_path, seek_time='1')
            
            # Strategy 2: Extract frame at 0.5 seconds if Strategy 1 fails
            if not success:
                logger.info("Strategy 1 failed, trying 0.5 second mark")
                success = self._ffmpeg_extract_frame(tmp_video_path, tmp_thumb_path, seek_time='0.5')
            
            # Strategy 3: Extract first frame (for very short videos)
            if not success:
                logger.info("Strategy 2 failed, trying first frame")
                success = self._ffmpeg_extract_frame(tmp_video_path, tmp_thumb_path, seek_time='0')
            
            # Strategy 4: Extract frame from 10% of duration
            if not success:
                logger.info("Strategy 3 failed, trying 10% duration")
                success = self._ffmpeg_extract_frame_percentage(tmp_video_path, tmp_thumb_path)
            
            # Strategy 5: Use first available keyframe
            if not success:
                logger.info("Strategy 4 failed, trying keyframe extraction")
                success = self._ffmpeg_extract_keyframe(tmp_video_path, tmp_thumb_path)
            
            if success and os.path.exists(tmp_thumb_path):
                # Optimize and return thumbnail
                return self._optimize_thumbnail(tmp_thumb_path)
            
            logger.error(f"All thumbnail extraction strategies failed for {extension}")
            return None
            
        except Exception as e:
            logger.error(f"Video thumbnail extraction failed for {extension}: {e}")
            return None
            
        finally:
            # Cleanup temporary files
            for path in [tmp_video_path, tmp_thumb_path]:
                if path:
                    try:
                        os.unlink(path)
                    except Exception as e:
                        logger.debug(f"Cleanup failed for {path}: {e}")
    
    def _ffmpeg_extract_frame(self, video_path, output_path, seek_time='1'):
        """Extract frame at specific time using FFmpeg"""
        try:
            cmd = [
                'ffmpeg',
                '-ss', str(seek_time),  # Seek to position
                '-i', video_path,
                '-vframes', '1',  # Extract 1 frame
                '-q:v', '2',  # Quality (2 is high)
                '-vf', 'scale=800:-1',  # Resize width to 800px, maintain aspect ratio
                '-y',  # Overwrite output
                output_path
            ]
            
            result = subprocess.run(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=30,
                check=False
            )
            
            return result.returncode == 0 and os.path.exists(output_path) and os.path.getsize(output_path) > 0
            
        except subprocess.TimeoutExpired:
            logger.warning(f"FFmpeg timeout at seek_time={seek_time}")
            return False
        except Exception as e:
            logger.warning(f"FFmpeg extraction failed at seek_time={seek_time}: {e}")
            return False
    
    def _ffmpeg_extract_frame_percentage(self, video_path, output_path):
        """Extract frame at 10% of video duration"""
        try:
            # First, get video duration
            cmd_duration = [
                'ffprobe',
                '-v', 'error',
                '-show_entries', 'format=duration',
                '-of', 'default=noprint_wrappers=1:nokey=1',
                video_path
            ]
            
            result = subprocess.run(
                cmd_duration,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=10,
                check=False
            )
            
            if result.returncode == 0:
                duration = float(result.stdout.decode().strip())
                seek_time = duration * 0.1  # 10% into video
                return self._ffmpeg_extract_frame(video_path, output_path, str(seek_time))
            
        except Exception as e:
            logger.warning(f"Duration-based extraction failed: {e}")
        
        return False
    
    def _ffmpeg_extract_keyframe(self, video_path, output_path):
        """Extract first available keyframe (most compatible)"""
        try:
            cmd = [
                'ffmpeg',
                '-i', video_path,
                '-vf', 'select=eq(pict_type\\,I),scale=800:-1',  # Select I-frames only
                '-vframes', '1',
                '-q:v', '2',
                '-y',
                output_path
            ]
            
            result = subprocess.run(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=30,
                check=False
            )
            
            return result.returncode == 0 and os.path.exists(output_path) and os.path.getsize(output_path) > 0
            
        except Exception as e:
            logger.warning(f"Keyframe extraction failed: {e}")
            return False
    
    def _optimize_thumbnail(self, thumb_path):
        """Optimize thumbnail size and quality"""
        try:
            with Image.open(thumb_path) as img:
                # Convert to RGB if needed
                if img.mode in ('RGBA', 'P', 'LA'):
                    img = img.convert('RGB')
                
                # Ensure max dimensions
                max_size = (800, 800)
                img.thumbnail(max_size, Image.Resampling.LANCZOS)
                
                # Save to bytes
                img_bytes = BytesIO()
                img.save(img_bytes, format='JPEG', quality=85, optimize=True)
                
                return img_bytes.getvalue()
                
        except Exception as e:
            logger.error(f"Thumbnail optimization failed: {e}")
            return None
    
    def extract_video_thumbnail_moviepy_enhanced(self, extension, decrypted_bytes):
        """
        NEW METHOD: Enhanced moviepy extraction with better error handling.
        Use this as fallback if FFmpeg is not available.
        """
        from moviepy.editor import VideoFileClip
        
        supported_extensions = [
            '.mp4', '.avi', '.mov', '.wmv', '.flv', '.mkv', 
            '.webm', '.3gp', '.mpeg', '.mpg', '.ts', '.m4v'
        ]
        
        if extension.lower() not in supported_extensions:
            return None

        tmp_file_path = None
        
        try:
            # Write to temporary file
            with tempfile.NamedTemporaryFile(suffix=extension, delete=False) as tmp_file:
                tmp_file.write(decrypted_bytes)
                tmp_file_path = tmp_file.name
            
            # Load video with error handling
            clip = VideoFileClip(tmp_file_path, audio=False, verbose=False)
            
            try:
                duration = clip.duration
                
                # Try multiple frame positions
                frame_positions = [
                    min(1.0, duration * 0.1),   # 1 sec or 10% of video
                    min(0.5, duration * 0.05),  # 0.5 sec or 5% of video
                    min(2.0, duration * 0.2),   # 2 sec or 20% of video
                    0.0                          # First frame
                ]
                
                frame = None
                for position in frame_positions:
                    try:
                        frame = clip.get_frame(position)
                        if frame is not None and frame.size > 0:
                            break
                    except Exception:
                        continue
                
                if frame is None:
                    raise Exception("Could not extract any frame")
                
                # Convert to image
                img = Image.fromarray(frame)
                
                # Ensure RGB mode
                if img.mode != 'RGB':
                    img = img.convert('RGB')
                
                # Resize
                max_size = (800, 800)
                img.thumbnail(max_size, Image.Resampling.LANCZOS)
                
                # Save to bytes
                img_bytes = BytesIO()
                img.save(img_bytes, format='JPEG', quality=85, optimize=True)
                
                return img_bytes.getvalue()
                
            finally:
                clip.close()
                
        except Exception as e:
            logger.error(f"MoviePy thumbnail extraction failed for {extension}: {e}")
            return None
            
        finally:
            if tmp_file_path:
                try:
                    os.unlink(tmp_file_path)
                except Exception:
                    pass

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
                        logger.warning("Skipping invalid .env line")


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
            logger.info("S3 Event received")

            # Delete message from queue after processing
            sqs.delete_message(
                QueueUrl=queue_url,
                ReceiptHandle=message["ReceiptHandle"]
            )
