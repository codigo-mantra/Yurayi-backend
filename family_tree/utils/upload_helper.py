import threading
import time
import os
import tempfile
from timecapsoul.utils import MediaThumbnailExtractor


class ChunkedUploadSession:
    def __init__(
        self,
        upload_id,
        user_id,
        gallery_media_id,
        file_name,
        file_size,
        file_type,
        total_chunks,
        chunk_size,
    ):
        self.upload_id = str(upload_id)
        self.user_id = str(user_id)
        self.gallery_media_id = str(gallery_media_id)
        self.file_name = file_name
        self.file_size = file_size
        self.file_type = file_type
        self.total_chunks = total_chunks
        self.chunk_size = chunk_size
        self.received_bytes = 0
        self.uploaded_chunks = set()
        self.created_at = time.time()
        self.last_activity = time.time()

        self.local_path = None
        self.temp_file_path = None
        self.is_small_file = False

        self.lock = threading.Lock()

    def to_dict(self):
        return {
            "upload_id": self.upload_id,
            "user_id": self.user_id,
            "gallery_media_id": self.gallery_media_id,
            "file_name": self.file_name,
            "file_size": self.file_size,
            "file_type": self.file_type,
            "total_chunks": self.total_chunks,
            "chunk_size": self.chunk_size,
            "local_path": self.local_path,
            "temp_file_path": self.temp_file_path,
            "uploaded_chunks": list(self.uploaded_chunks),
            "created_at": self.created_at,
            "last_activity": self.last_activity,
            "is_small_file": self.is_small_file,
            "received_bytes ": self.received_bytes,
        }

    @classmethod
    def from_dict(cls, data):
        session = cls(
            data["upload_id"],
            data["user_id"],
            data["gallery_media_id"],
            data["file_name"],
            data["file_size"],
            data["file_type"],
            data["total_chunks"],
            data["chunk_size"],
        )

        session.local_path = data.get("local_path")
        session.temp_file_path = data.get("temp_file_path")
        session.uploaded_chunks = set(data.get("uploaded_chunks", []))
        session.created_at = data.get("created_at")
        session.last_activity = data.get("last_activity")
        session.is_small_file = data.get("is_small_file", False)

        return session

    def is_expired(self, timeout=3600):
        """Check if session has expired"""
        return (time.time() - self.last_activity) > timeout

    def get_progress(self):
        """Get upload progress as percentage"""
        if self.total_chunks == 0:
            return 0.0
        
        if self.is_jpg:
            return (len(self.uploaded_chunks) / self.total_chunks) * 50
        else:
            return (len(self.uploaded_chunks) / self.total_chunks) * 100

    def is_complete(self):
        """Check if all chunks have been uploaded"""
        return len(self.uploaded_chunks) == self.total_chunks

    def get_missing_chunks(self):
        """Get list of chunks that haven't been uploaded yet"""
        all_chunks = set(range(self.total_chunks))
        return sorted(list(all_chunks - self.uploaded_chunks))

    def mark_chunk_uploaded(self, chunk_index):
        """Mark a chunk as successfully uploaded"""
        with self.lock:
            self.uploaded_chunks.add(chunk_index)
            self.last_activity = time.time()

    def needs_processing(self):
        """Check if file needs special processing (only JPG)"""
        return self.is_jpg

    def __repr__(self):
        return (
            f"ChunkedUploadSession(upload_id={self.upload_id}, "
            f"file_name={self.file_name}, "
            f"progress={self.get_progress():.1f}%, "
            f"is_jpg={self.is_jpg}, "
            f"is_small_file={self.is_small_file})"
        )



def detect_mime_type(file_path: str) -> str:
    import magic
    try:
        mime = magic.from_file(file_path, mime=True)
        return mime or "application/octet-stream"
    except Exception:
        return "application/octet-stream"



class UniversalThumbnailService:

    @staticmethod
    def generate(encrypted_file_path, decrypt_func, extension):
        decrypted_bytes = decrypt_func(encrypted_file_path)

        with tempfile.NamedTemporaryFile(delete=False, suffix=extension) as tmp:
            tmp.write(b"".join(decrypted_bytes))
            temp_path = tmp.name

        try:

            mime = detect_mime_type(temp_path)

            extractor = MediaThumbnailExtractor(tmp, extension)
            if mime.startswith("image/"):
                with open(temp_path, "rb") as img:
                    return img.read()

            if mime.startswith("video/"):
                with open(temp_path, "rb") as f:
                    video_bytes = f.read()
                thumb = extractor.extract_video_thumbnail_ffmpeg(
                    extension,
                    video_bytes
                )
                if thumb:
                    return thumb

            if mime.startswith("audio/"):
                with open(temp_path, "rb") as f:
                    audio_bytes = f.read()
                thumb = extractor.extract_audio_thumbnail_from_bytes(
                    extension,
                    audio_bytes
                )
                if thumb:
                    return thumb
            return None

        finally:
            os.remove(temp_path)

    @staticmethod
    def generate_from_bytes(decrypted_bytes, extension):

        extractor = MediaThumbnailExtractor(
            file=None,
            file_ext=extension
        )
        

        thumb = extractor.extract_video_thumbnail_ffmpeg(extension, decrypted_bytes)

        if thumb:
            return thumb

        thumb = extractor.extract_audio_thumbnail_from_bytes(extension, decrypted_bytes)

        if thumb:
            return thumb

        return None


    @staticmethod
    def generic_icon():
        with open("static/icons/file.jpg", "rb") as f:
            return f.read()

    # @staticmethod
    # def pdf_thumbnail(path):
    #     try:
    #         import fitz
    #         doc = fitz.open(path)
    #         page = doc.load_page(0)
    #         pix = page.get_pixmap()

    #         return pix.tobytes("jpeg")

    #     except:
    #         return UniversalThumbnailService.generic_icon()
