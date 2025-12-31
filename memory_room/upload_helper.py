import os
import base64
import tempfile
from typing import Optional, Callable
import gc
import logging

import boto3
from django.conf import settings
from timecapsoul.utils import MediaThumbnailExtractor

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend
from botocore.config import Config
from memory_room.media_helper import ChunkedDecryptor
from contextlib import nullcontext
import threading
from queue import Queue, Empty
from io import BytesIO
import time
import subprocess
from PIL import Image
import io
import numpy as np
from PIL import Image, ImageDraw
from mutagen import File as MutagenFile

logger = logging.getLogger(__name__)

AWS_KMS_REGION = 'ap-south-1'
AWS_KMS_KEY_ID = '843da3bb-9a57-4d9f-a8ab-879a6109f460'
MEDIA_FILES_BUCKET = 'yurayi-media'


boto_config = Config(
    retries={
        'max_attempts': 5,
        'mode': 'adaptive'  # Uses exponential backoff
    },
    max_pool_connections=50,
)

s3 = boto3.client(
    's3',
    region_name=AWS_KMS_REGION,
    aws_access_key_id=settings.AWS_ACCESS_KEY_ID,
    aws_secret_access_key=settings.AWS_SECRET_ACCESS_KEY,
    config=boto_config
)

kms = boto3.client(
    "kms",
    region_name=AWS_KMS_REGION,
    aws_access_key_id=settings.AWS_ACCESS_KEY_ID,
    aws_secret_access_key=settings.AWS_SECRET_ACCESS_KEY,
)




def try_ffmpeg_direct(segment_bytes: bytes, file_ext: str) -> bytes | None:
    """
    Try direct FFmpeg extraction without rebuilding.
    Sometimes works even without moov atom.
    """
    tmp_in = None
    tmp_out = None
    
    try:
        # Write segment
        with tempfile.NamedTemporaryFile(delete=False, suffix=file_ext) as f:
            f.write(segment_bytes)
            tmp_in = f.name
        
        tmp_out = tempfile.mktemp(suffix='.jpg')
        
        # Try extraction with error recovery flags
        cmd = [
            "ffmpeg",
            "-y",
            "-hide_banner",
            "-loglevel", "warning",
            "-err_detect", "ignore_err",  # Ignore errors
            "-fflags", "+genpts+igndts",  # Generate timestamps
            "-i", tmp_in,
            "-frames:v", "1",
            "-q:v", "2",
            "-vf", "scale=800:-1",
            tmp_out
        ]
        
        result = subprocess.run(cmd, capture_output=True, timeout=10)
        
        if os.path.exists(tmp_out) and os.path.getsize(tmp_out) > 1000:
            with open(tmp_out, 'rb') as f:
                return f.read()
        
        # Try seeking to different positions
        for seek_pos in ["0", "0.5", "1", "2"]:
            cmd = [
                "ffmpeg", "-y", "-hide_banner", "-loglevel", "warning",
                "-ss", seek_pos,
                "-err_detect", "ignore_err",
                "-i", tmp_in,
                "-frames:v", "1", "-q:v", "2",
                tmp_out
            ]
            
            result = subprocess.run(cmd, capture_output=True, timeout=10)
            
            if os.path.exists(tmp_out) and os.path.getsize(tmp_out) > 1000:
                with open(tmp_out, 'rb') as f:
                    return f.read()
        
        return None
        
    except Exception as e:
        print(f"Direct FFmpeg failed: {e}")
        return None
        
    finally:
        for path in [tmp_in, tmp_out]:
            if path and os.path.exists(path):
                try:
                    os.remove(path)
                except:
                    pass



def locate_moov_atom(data: bytes) -> tuple[int, int] | None:
    """
    Scan for moov atom location in partial MP4 data.
    Returns (start_offset, size) or None
    """
    try:
        pos = 0
        max_scan = min(len(data), 50 * 1024 * 1024)  # Scan up to 50MB
        
        while pos < max_scan - 8:
            # Read atom size and type
            if pos + 8 > len(data):
                break
                
            atom_size = int.from_bytes(data[pos:pos+4], 'big')
            atom_type = data[pos+4:pos+8]
            
            if atom_type == b'moov':
                print(f"✓ Found moov atom at offset {pos}, size {atom_size}")
                return (pos, atom_size)
            
            # Skip to next atom
            if atom_size < 8 or atom_size > len(data) - pos:
                # Try scanning byte by byte for moov signature
                pos += 1
            else:
                pos += atom_size
            
    except Exception as e:
        print(f"✗ Error scanning for moov: {e}")
    
    return None


def scan_for_atoms(data: bytes, max_scan: int = 1024 * 1024) -> list:
    """
    Scan and list all MP4 atoms found in data.
    Useful for debugging.
    """
    atoms = []
    pos = 0
    scan_limit = min(len(data), max_scan)
    
    while pos < scan_limit - 8:
        try:
            atom_size = int.from_bytes(data[pos:pos+4], 'big')
            atom_type = data[pos+4:pos+8]
            
            if atom_type.isalpha() or atom_type in [b'ftyp', b'moov', b'mdat', b'free', b'wide']:
                atoms.append({
                    'type': atom_type.decode('ascii', errors='ignore'),
                    'offset': pos,
                    'size': atom_size
                })
                
            if atom_size < 8 or atom_size > len(data) - pos:
                pos += 1
            else:
                pos += atom_size
        except:
            pos += 1
    
    return atoms


def decrypt_range(s3_key, start_byte, end_byte):
    """
    Decrypt only a specific byte range of the encrypted file.
    Optimized: reads chunks sequentially, extracts only required portion.
    """
    # Ensure integers
    start_byte = int(start_byte)
    end_byte = int(end_byte)
    
    buffer = bytearray()
    current_pos = 0

    with ChunkedDecryptor(s3_key) as decryptor:
        for chunk in decryptor.decrypt_chunks():
            chunk_len = len(chunk)
            chunk_start = current_pos
            chunk_end = current_pos + chunk_len

            # If chunk overlaps requested range
            if chunk_end >= start_byte and chunk_start <= end_byte:
                rs = max(0, start_byte - chunk_start)
                re = min(chunk_len, end_byte - chunk_start)
                buffer.extend(chunk[rs:re])

            current_pos += chunk_len

            if current_pos > end_byte:
                break

    return bytes(buffer)

def smart_decrypt_for_mp4(s3_key, file_size):
    """
    Enhanced MP4 decryption with larger segments and better coverage.
    """
    mb = 1024 * 1024
    file_size = int(file_size)
    segments = []
    
    print(f"File size: {file_size / mb:.2f} MB")
    
    # Strategy 1: Large HEAD segment (up to 20 MB)
    head_size = int(min(20 * mb, file_size // 3))
    print(f"Decrypting HEAD: 0 to {head_size / mb:.2f} MB")
    head = decrypt_range(s3_key, 0, head_size)
    
    # Scan for atoms in head
    atoms = scan_for_atoms(head)
    print(f"HEAD atoms found: {[a['type'] for a in atoms]}")
    
    segments.append(('head', head))
    
    # Strategy 2: Large TAIL segment (up to 25 MB - moov often here)
    tail_size = int(min(25 * mb, file_size // 3))
    tail_start = int(max(0, file_size - tail_size))
    print(f"Decrypting TAIL: {tail_start / mb:.2f} MB to {file_size / mb:.2f} MB")
    tail = decrypt_range(s3_key, tail_start, file_size)
    
    # Scan for atoms in tail
    atoms = scan_for_atoms(tail)
    print(f"TAIL atoms found: {[a['type'] for a in atoms]}")
    
    segments.append(('tail', tail))
    
    # Strategy 3: Check if we need MID
    moov_found = False
    for name, seg in segments:
        if locate_moov_atom(seg):
            moov_found = True
            print(f"✓ moov found in {name}")
            break
    
    if not moov_found:
        print("⚠ moov not found in HEAD or TAIL, trying MID")
        if file_size > 50 * mb:
            mid_size = int(min(15 * mb, file_size // 5))
            mid_start = int((file_size // 2) - (mid_size // 2))
            print(f"Decrypting MID: {mid_start / mb:.2f} MB to {(mid_start + mid_size) / mb:.2f} MB")
            mid = decrypt_range(s3_key, mid_start, mid_start + mid_size)
            
            atoms = scan_for_atoms(mid)
            print(f"MID atoms found: {[a['type'] for a in atoms]}")
            
            segments.append(('mid', mid))
    
    return segments


def try_ffmpeg_direct(segment_bytes: bytes, file_ext: str) -> bytes | None:
    """
    Try direct FFmpeg extraction without rebuilding.
    Sometimes works even without moov atom.
    """
    tmp_in = None
    tmp_out = None
    
    try:
        # Write segment
        with tempfile.NamedTemporaryFile(delete=False, suffix=file_ext) as f:
            f.write(segment_bytes)
            tmp_in = f.name
        
        tmp_out = tempfile.mktemp(suffix='.jpg')
        
        # Try extraction with error recovery flags
        cmd = [
            "ffmpeg",
            "-y",
            "-hide_banner",
            "-loglevel", "warning",
            "-err_detect", "ignore_err",  # Ignore errors
            "-fflags", "+genpts+igndts",  # Generate timestamps
            "-i", tmp_in,
            "-frames:v", "1",
            "-q:v", "2",
            "-vf", "scale=800:-1",
            tmp_out
        ]
        
        result = subprocess.run(cmd, capture_output=True, timeout=10)
        
        if os.path.exists(tmp_out) and os.path.getsize(tmp_out) > 1000:
            with open(tmp_out, 'rb') as f:
                return f.read()
        
        # Try seeking to different positions
        for seek_pos in ["0", "0.5", "1", "2"]:
            cmd = [
                "ffmpeg", "-y", "-hide_banner", "-loglevel", "warning",
                "-ss", seek_pos,
                "-err_detect", "ignore_err",
                "-i", tmp_in,
                "-frames:v", "1", "-q:v", "2",
                tmp_out
            ]
            
            result = subprocess.run(cmd, capture_output=True, timeout=10)
            
            if os.path.exists(tmp_out) and os.path.getsize(tmp_out) > 1000:
                with open(tmp_out, 'rb') as f:
                    return f.read()
        
        return None
        
    except Exception as e:
        print(f"Direct FFmpeg failed: {e}")
        return None
        
    finally:
        for path in [tmp_in, tmp_out]:
            if path and os.path.exists(path):
                try:
                    os.remove(path)
                except:
                    pass


def rebuild_mp4_with_unsparsing(segment_bytes: bytes, file_ext: str) -> str | None:
    """
    Advanced MP4 rebuild with multiple strategies.
    """
    tmp_in = None
    tmp_out = None
    
    try:
        with tempfile.NamedTemporaryFile(delete=False, suffix=file_ext) as f:
            f.write(segment_bytes)
            tmp_in = f.name
        
        tmp_out = tempfile.mktemp(suffix=".mp4")
        
        # Strategy 1: Copy with faststart
        cmd1 = [
            "ffmpeg", "-y", "-hide_banner", "-loglevel", "error",
            "-i", tmp_in,
            "-c", "copy",
            "-movflags", "+faststart",
            "-f", "mp4",
            tmp_out
        ]
        
        result = subprocess.run(cmd1, capture_output=True, timeout=15)
        if os.path.exists(tmp_out) and os.path.getsize(tmp_out) > 5000:
            return tmp_out
        
        # Strategy 2: Re-encode first few seconds (more reliable but slower)
        cmd2 = [
            "ffmpeg", "-y", "-hide_banner", "-loglevel", "error",
            "-err_detect", "ignore_err",
            "-i", tmp_in,
            "-t", "3",  # Only 3 seconds
            "-c:v", "libx264",
            "-preset", "ultrafast",
            "-crf", "28",
            "-an",  # No audio
            "-movflags", "+faststart",
            tmp_out
        ]
        
        result = subprocess.run(cmd2, capture_output=True, timeout=30)
        if os.path.exists(tmp_out) and os.path.getsize(tmp_out) > 5000:
            return tmp_out
        
        return None
        
    except Exception as e:
        print(f"MP4 rebuild failed: {e}")
        return None
        
    finally:
        if tmp_in and os.path.exists(tmp_in):
            try:
                os.remove(tmp_in)
            except:
                pass


def extract_thumbnail_from_segment(segment_bytes: bytes, file_ext: str, segment_name: str) -> bytes | None:
    """
    Extract thumbnail with multiple fallback strategies.
    """
    print(f"\n--- Processing {segment_name} ({len(segment_bytes) / (1024*1024):.2f} MB) ---")
    
    # Check for moov atom
    moov_location = locate_moov_atom(segment_bytes)
    
    # Strategy 1: Direct FFmpeg (fastest, works even without complete moov)
    # print("Strategy 1: Direct FFmpeg extraction")
    thumb = try_ffmpeg_direct(segment_bytes, file_ext)
    if thumb:
        print("✓ Success with direct FFmpeg")
        return thumb
    
    # Strategy 2: Rebuild MP4 if needed
    if not moov_location:
        # print("Strategy 2: Rebuilding MP4 structure")
        rebuilt_path = rebuild_mp4_with_unsparsing(segment_bytes, file_ext)
        
        if rebuilt_path:
            try:
                thumb = try_ffmpeg_direct(open(rebuilt_path, 'rb').read(), '.mp4')
                if thumb:
                    print("✓ Success with rebuilt MP4")
                    os.remove(rebuilt_path)
                    return thumb
                os.remove(rebuilt_path)
            except:
                pass
    
    # Strategy 3: Try with moviepy (if available)
    # print("Strategy 3: Trying MoviePy")
    try:
        from moviepy.editor import VideoFileClip
        
        tmp_path = None
        try:
            with tempfile.NamedTemporaryFile(delete=False, suffix=file_ext) as f:
                f.write(segment_bytes)
                tmp_path = f.name
            
            clip = VideoFileClip(tmp_path, audio=False)
            frame = clip.get_frame(min(0.5, clip.duration / 2))
            
            img = Image.fromarray(frame)
            if img.mode != 'RGB':
                img = img.convert('RGB')
            img.thumbnail((800, 800), Image.Resampling.LANCZOS)
            
            img_bytes = BytesIO()
            img.save(img_bytes, format='JPEG', quality=85)
            
            clip.close()
            print("✓ Success with MoviePy")
            return img_bytes.getvalue()
            
        finally:
            if tmp_path and os.path.exists(tmp_path):
                os.remove(tmp_path)
                
    except Exception as e:
        print(f"✗ MoviePy failed: {e}")
    
    print(f"✗ All strategies failed for {segment_name}")
    return None


def fallback_thumbnail_multi_segment_fixed(s3_key, file_type, file_ext, file_size):
    """
    Enhanced multi-segment thumbnail extraction with diagnostics.
    """
    if file_type != "video":
        print("Not a video file, using audio extraction")
        # Use your existing audio extraction
        return None
    
   
    
    # Get segments
    segments = smart_decrypt_for_mp4(s3_key, file_size)
    
    # Try each segment
    for segment_name, segment_bytes in segments:
        if not segment_bytes or len(segment_bytes) < 10000:
            print(f"⚠ Skipping {segment_name}: too small")
            continue
        
        thumb = extract_thumbnail_from_segment(segment_bytes, file_ext, segment_name)
        
        if thumb:
            return thumb
        
        # Cleanup
        del segment_bytes
    
    print("✗✗✗ FAILED: All segments exhausted ✗✗✗")
    return None

def extract_thumbnail_full_decrypt(s3_key, file_ext):
    """
    Last resort: decrypt entire file.
    Only use for files < 100 MB.
    """
    print("Using full file decryption...")
    
    with ChunkedDecryptor(s3_key) as decryptor:
        full_data = b''.join(decryptor.decrypt_chunks())
    
    print(f"Decrypted {len(full_data) / (1024*1024):.2f} MB")
    
    return extract_thumbnail_from_segment(full_data, file_ext, "full_file")


# def decrypt_upload_and_extract_audio_thumbnail_chunked(
#         key: str,
#         encrypted_file,
#         iv_str: str,
#         content_type: str = "application/octet-stream",
#         file_ext: str = "",
#         progress_callback=None,
#         chunk_size: int = 10 * 1024 * 1024,  # 10 MB default
#         file_type=None,
#         thumbnail_buffer_size: int = 512 * 1024,  # 512 KB buffer for thumbnail
#         max_retries: int = 3,  # Retry failed uploads
#     ):
#     """
#     Decrypt AES-256-GCM encrypted file chunk-by-chunk, upload decrypted chunks to S3, 
#     and extract embedded audio/video thumbnail while streaming.
#     Optimized for minimal RAM usage with retry logic.
    
#     IMPROVEMENTS:
#     - Fixed race conditions with proper thread synchronization
#     - Ultra-low RAM usage with streaming and aggressive cleanup
#     - Max 4 workers for optimal performance/resource balance
#     - Exponential backoff retry logic for failed uploads
#     - Strategic thumbnail extraction at start, middle, and end (7 attempts)
#     - Progress updates from 15-85% during processing
#     """

#     bucket = MEDIA_FILES_BUCKET
#     parts = []
#     uploaded_bytes = 0
#     thumbnail_data = None
#     upload_error = None
#     buffer_for_thumbnail = None
    
#     # Thread-safe thumbnail extraction
#     thumbnail_extracted = False
#     thumbnail_lock = threading.Lock()
#     MAX_THUMBNAIL_ATTEMPTS = 3
#     MIN_BUFFER_FOR_ATTEMPT = 256 * 1024
    
#     # Strategic extraction points
#     thumbnail_extraction_points = []
    
#     # Retry configuration
#     MAX_RETRIES = max_retries
#     RETRY_DELAY_BASE = 1  # seconds
    
#     try:
#         s3_key = key
#         if progress_callback:
#             progress_callback(15, "Initializing decryption...")

#         # Parse IV
#         try:
#             if all(c in "0123456789abcdefABCDEF" for c in iv_str.strip()):
#                 iv = bytes.fromhex(iv_str)
#             else:
#                 iv = base64.b64decode(iv_str)
#         except Exception as e:
#             raise ValueError(f"Invalid IV format: {e}")

#         # Decode AES key
#         key_bytes = settings.ENCRYPTION_KEY
#         if isinstance(key_bytes, str):
#             key_bytes = base64.b64decode(key_bytes)
#         if len(key_bytes) != 32:
#             raise ValueError(f"Key must be 32 bytes for AES-256, got {len(key_bytes)} bytes")

#         # Determine file size and auth tag
#         encrypted_file.seek(0, 2)
#         total_size = encrypted_file.tell()
#         if total_size < 16:
#             raise ValueError("Encrypted file too short (missing GCM tag).")
#         encrypted_data_size = total_size - 16
#         encrypted_file.seek(encrypted_data_size)
#         auth_tag = encrypted_file.read(16)
#         encrypted_file.seek(0)

#         # RAM-OPTIMIZED: Conservative adaptive strategy (max 4 workers)
#         if encrypted_data_size <= 5 * 1024 * 1024:  # < 5MB
#             effective_chunk_size = max(encrypted_data_size, 2 * 1024 * 1024)
#             use_threading = False
#             max_workers = 1
#         elif encrypted_data_size <= 50 * 1024 * 1024:  # 5-50MB
#             effective_chunk_size = 5 * 1024 * 1024
#             use_threading = True
#             max_workers = 2
#         elif encrypted_data_size <= 200 * 1024 * 1024:  # 50-200MB
#             effective_chunk_size = 8 * 1024 * 1024
#             use_threading = True
#             max_workers = 3
#         else:  # > 200MB - CAPPED at 4 workers for RAM efficiency
#             effective_chunk_size = 12 * 1024 * 1024  # Balanced chunk size
#             use_threading = True
#             max_workers = 4  # HARD CAP

#         # Calculate strategic thumbnail extraction points
#         # if file_type in ['video', 'audio']:
#         #     buffer_for_thumbnail = BytesIO()
#         #     total_chunks = (encrypted_data_size + effective_chunk_size - 1) // effective_chunk_size
            
#         #     # 7 attempts: 2 start, 3 middle, 2 end
#         #     thumbnail_extraction_points = [
#         #         1,  # Start - chunk 1
#         #         2,  # Start - chunk 2
#         #         total_chunks // 3,  # Early middle
#         #         total_chunks // 2,  # Middle
#         #         (total_chunks * 2) // 3,  # Late middle
#         #         max(total_chunks - 1, 3),  # Near end
#         #         total_chunks  # End
#         #     ]
#         #     thumbnail_extraction_points = sorted(set(thumbnail_extraction_points))[:MAX_THUMBNAIL_ATTEMPTS]
        
#         if file_type in ('video', 'audio'):
#             buffer_for_thumbnail = BytesIO()
#             total_chunks = max(1, (encrypted_data_size + effective_chunk_size - 1) // effective_chunk_size)
#             # Build candidate points, then pick at most MAX_THUMBNAIL_ATTEMPTS
#             candidate_points = [
#                 1, 2,
#                 max(1, total_chunks // 6),
#                 max(1, total_chunks // 3),
#                 max(1, total_chunks // 2),
#                 max(1, (total_chunks * 2) // 3),
#                 total_chunks - 1 if total_chunks > 2 else total_chunks
#             ]
#             # unique, sorted, cap
#             thumbnail_extraction_points = sorted({p for p in candidate_points if 1 <= p <= total_chunks})[:MAX_THUMBNAIL_ATTEMPTS]
#             logger.info(f"Thumbnail extraction planned at chunks: {thumbnail_extraction_points}")

#         # Initialize decryptor
#         cipher = Cipher(algorithms.AES(key_bytes), modes.GCM(iv, auth_tag), backend=default_backend())
#         decryptor = cipher.decryptor()

#         if progress_callback:
#             progress_callback(17, "Starting chunked decrypt & upload...")

#         # Generate KMS data key & AESGCM encryptor for S3
#         resp = kms.generate_data_key(KeyId=AWS_KMS_KEY_ID, KeySpec="AES_256")
#         data_key_plain = resp["Plaintext"]
#         data_key_encrypted = resp["CiphertextBlob"]
#         aesgcm = AESGCM(data_key_plain)

#         # Prepare S3 multipart upload
#         multipart_resp = s3.create_multipart_upload(
#             Bucket=bucket,
#             Key=s3_key,
#             ContentType=content_type,
#             Metadata={
#                 "edk": base64.b64encode(data_key_encrypted).decode(),
#                 "orig-content-type": content_type,
#                 "chunk-size": str(effective_chunk_size),
#             },
#         )
#         upload_id = multipart_resp["UploadId"]

#         upload_queue = None
#         upload_threads = []
        
#         # Single lock for all shared state (prevents race conditions)
#         state_lock = threading.Lock() if use_threading else None

#         # RAM-OPTIMIZED: Retry logic with exponential backoff
#         def upload_part_with_retry(bucket, key, part_num, upload_id, body, max_retries=MAX_RETRIES):
#             """Upload a part with exponential backoff retry logic"""
#             for attempt in range(max_retries):
#                 try:
#                     resp = s3.upload_part(
#                         Bucket=bucket,
#                         Key=key,
#                         PartNumber=part_num,
#                         UploadId=upload_id,
#                         Body=body,
#                     )
#                     return resp
#                 except Exception as e:
#                     if attempt == max_retries - 1:
#                         raise  # Last attempt failed
                    
#                     # Exponential backoff: 1s, 2s, 4s, 8s...
#                     delay = RETRY_DELAY_BASE * (2 ** attempt)
#                     logger.warning(f"Upload part {part_num} failed (attempt {attempt + 1}/{max_retries}), retrying in {delay}s: {str(e)}")
#                     time.sleep(delay)
            
#             raise RuntimeError(f"Failed to upload part {part_num} after {max_retries} attempts")

#         if use_threading:
#             # RAM-OPTIMIZED: Minimal queue size (only 1 slot per worker)
#             upload_queue = Queue(maxsize=max_workers)

#             def upload_worker():
#                 nonlocal upload_error, uploaded_bytes
#                 while True:
#                     item = None
#                     try:
#                         item = upload_queue.get(timeout=2)
#                         if item is None:
#                             break
                        
#                         part_num, encrypted_body, decrypted_len = item
                        
#                         try:
#                             # Upload with retry logic
#                             resp = upload_part_with_retry(
#                                 bucket, s3_key, part_num, upload_id, encrypted_body
#                             )
                            
#                             # Thread-safe state update
#                             with state_lock:
#                                 if upload_error:  # Stop if another thread failed
#                                     break
                                    
#                                 parts.append({"ETag": resp["ETag"], "PartNumber": part_num})
#                                 uploaded_bytes += decrypted_len
                                
#                                 # Progress from 20-85
#                                 percent = 20 + int((uploaded_bytes / encrypted_data_size) * 65)
#                                 if progress_callback:
#                                     progress_callback(min(percent, 85), None)
                                    
#                         except Exception as e:
#                             with state_lock:
#                                 if not upload_error:
#                                     upload_error = e
#                                     logger.error(f"Part {part_num} upload failed after retries: {str(e)}")
#                             break
                            
#                     except Empty:
#                         continue
#                     finally:
#                         if item:
#                             upload_queue.task_done()
#                             # RAM-OPTIMIZED: Immediately free memory
#                             del item
#                             if 'encrypted_body' in locals():
#                                 del encrypted_body

#             # Start worker threads (max 4)
#             for _ in range(max_workers):
#                 thread = threading.Thread(target=upload_worker, daemon=True)
#                 thread.start()
#                 upload_threads.append(thread)

#         # Process chunks
#         part_number = 1
#         total_read = 0
#         current_chunk_number = 0

#         while total_read < encrypted_data_size:
#             # Check for errors before processing more
#             if use_threading:
#                 with state_lock if state_lock else nullcontext():
#                     if upload_error:
#                         raise upload_error

#             to_read = min(effective_chunk_size, encrypted_data_size - total_read)
#             chunk = encrypted_file.read(to_read)
#             total_read += len(chunk)
#             current_chunk_number += 1

#             # Decrypt chunk
#             decrypted_chunk = decryptor.update(chunk)
            
#             # RAM-OPTIMIZED: Free encrypted chunk immediately
#             del chunk

#             # Strategic thumbnail extraction
#             if (not thumbnail_extracted and 
#                 file_type in ['video', 'audio'] and 
#                 buffer_for_thumbnail is not None and
#                 current_chunk_number in thumbnail_extraction_points):
                
#                 with thumbnail_lock:
#                     if not thumbnail_extracted:
#                         buffer_for_thumbnail.write(decrypted_chunk)
#                         current_buffer_size = buffer_for_thumbnail.tell()
                        
#                         if current_buffer_size >= MIN_BUFFER_FOR_ATTEMPT:
#                             attempt_num = thumbnail_extraction_points.index(current_chunk_number) + 1
                            
#                             try:
#                                 logger.info(f"Thumbnail extraction attempt {attempt_num} at chunk {current_chunk_number} (buffer: {current_buffer_size} bytes)")
                                
#                                 extractor = MediaThumbnailExtractor(file='', file_ext=file_ext)
#                                 buffer_data = buffer_for_thumbnail.getvalue()
                                
#                                 if file_type == 'video':
#                                     thumb = extractor.extract_video_thumbnail_from_bytes(
#                                         extension=file_ext,
#                                         decrypted_bytes=buffer_data,
#                                     )
#                                 else:
#                                     thumb = extractor.extract_audio_thumbnail_from_bytes(
#                                         extension=file_ext,
#                                         decrypted_bytes=buffer_data,
#                                     )
                                
#                                 if thumb:
#                                     thumbnail_data = thumb
#                                     thumbnail_extracted = True
#                                     # RAM-OPTIMIZED: Free buffer immediately
#                                     buffer_for_thumbnail.close()
#                                     buffer_for_thumbnail = None
#                                     del buffer_data
#                                     logger.info(f"Thumbnail extracted successfully on attempt {attempt_num}")
#                                 else:
#                                     del buffer_data
#                                     logger.info(f"Attempt {attempt_num} returned None")
                                    
#                             except Exception as e:
#                                 logger.warning(f"Attempt {attempt_num} failed: {str(e)}")
                        
#                         if buffer_for_thumbnail:
#                             should_clear = (
#                                 current_buffer_size > thumbnail_buffer_size * 2 or
#                                 attempt_num > MAX_THUMBNAIL_ATTEMPTS // 2
#                             )
#                             if should_clear:
#                                 buffer_for_thumbnail.seek(0)
#                                 buffer_for_thumbnail.truncate()
#                                 logger.info(f"Buffer cleared at {current_buffer_size} bytes (attempt {attempt_num})")

#             # Encrypt chunk for S3 upload
#             nonce = os.urandom(12)
#             ciphertext_chunk = aesgcm.encrypt(nonce, decrypted_chunk, None)
#             body = nonce + ciphertext_chunk
            
#             # RAM-OPTIMIZED: Delete intermediate data
#             del ciphertext_chunk, nonce

#             if use_threading:
#                 # Block if queue full (natural backpressure)
#                 upload_queue.put((part_number, body, len(decrypted_chunk)))
#                 # Don't delete body - needed by worker thread
#             else:
#                 # Direct upload with retry for single-threaded mode
#                 try:
#                     resp = upload_part_with_retry(
#                         bucket, s3_key, part_number, upload_id, body
#                     )
#                     parts.append({"ETag": resp["ETag"], "PartNumber": part_number})
#                     uploaded_bytes += len(decrypted_chunk)
                    
#                     # Progress from 20-85
#                     percent = 20 + int((uploaded_bytes / encrypted_data_size) * 65)
#                     if progress_callback:
#                         progress_callback(min(percent, 83), None)
#                 except Exception as e:
#                     raise RuntimeError(f"Failed to upload part {part_number}: {str(e)}")
#                 finally:
#                     del body

#             # RAM-OPTIMIZED: Free decrypted chunk
#             del decrypted_chunk
#             part_number += 1

#         # Finalize decryption
#         decryptor.finalize()

#         if use_threading:
#             # Signal all workers to stop
#             for _ in range(max_workers):
#                 upload_queue.put(None)
            
#             # Wait for all workers
#             timeout = 60 if encrypted_data_size > 1024 * 1024 * 1024 else 30
#             for thread in upload_threads:
#                 thread.join(timeout=timeout)
            
#             # Check final error state
#             with state_lock if state_lock else nullcontext():
#                 if upload_error:
#                     raise upload_error

#         # Complete S3 upload
#         parts.sort(key=lambda x: x["PartNumber"])
#         result = s3.complete_multipart_upload(
#             Bucket=bucket,
#             Key=s3_key,
#             UploadId=upload_id,
#             MultipartUpload={"Parts": parts},
#         )
        
#         if  not thumbnail_data and file_type in ['video', 'audio']:
            
#             if file_type  == 'video':
#                 thumbnail_data  = extract_thumbnail_full_decrypt(
#                     s3_key=s3_key,
#                     file_ext = file_ext,
#                 )
#             else:
#                 try:
#                     with ChunkedDecryptor(s3_key) as decryptor:
#                         full_data = b''.join(decryptor.decrypt_chunks())
#                     thumbnail_data  = extractor.extract_audio_thumbnail_from_bytes(
#                         extension=file_ext,
#                         decrypted_bytes=full_data
#                     )
#                     try:
#                         del full_data
#                     except Exception as e:
#                         pass
#                 except Exception as e:
#                     logger.error(f'Exception while audio thumbnail extraction  for s3-key: {s3_key}  as {e}')
                
#             if not thumbnail_data:
#                 logger.error(f'Thumbnail extraction failed for s3-key: {s3_key}')
                

#         if progress_callback:
#             progress_callback(85, None)

#         return {
#             "s3_result": result,
#             "uploaded_size": uploaded_bytes,
#             "thumbnail_data": thumbnail_data,
#         }

#     except Exception as e:
#         if "upload_id" in locals():
#             try:
#                 s3.abort_multipart_upload(Bucket=bucket, Key=s3_key, UploadId=upload_id)
#             except Exception:
#                 pass
#         if progress_callback:
#             progress_callback(0, f"Decrypt/upload failed: {e}")
#         raise RuntimeError(f"Decrypt/upload failed: {e}")

#     finally:
#         # RAM-OPTIMIZED: Aggressive cleanup
#         try:
#             del data_key_plain
#         except Exception:
#             pass
#         try:
#             if buffer_for_thumbnail:
#                 buffer_for_thumbnail.close()
#         except Exception:
#             pass
#         try:
#             del decryptor, aesgcm
#         except Exception:
#             pass
#         try:
#             if 'cipher' in locals():
#                 del cipher
#         except Exception:
#             pass


def generate_waveform_thumbnail(size=(512, 512)) -> bytes:
    """
    Generate a clean waveform placeholder image.
    """

    width, height = size
    img = Image.new("RGB", size, "#0f172a")
    draw = ImageDraw.Draw(img)

    samples = np.random.randint(20, height // 2, width // 4)

    center = height // 2
    x = 0

    for s in samples:
        draw.line((x, center - s, x, center + s), fill="#38bdf8", width=2)
        x += 4

    output = io.BytesIO()
    img.save(output, format="JPEG", quality=85)
    return output.getvalue()



def extract_audio_thumbnail_from_bytes(
    audio_bytes: bytes,
    extension: str,
    fallback_waveform: bool = True,
    thumb_size=(512, 512),
) -> bytes | None:
    """
    Extract embedded audio cover art from audio bytes.
    Returns JPEG bytes or None.
    """

    if not audio_bytes or not isinstance(audio_bytes, (bytes, bytearray)):
        logger.warning("Empty or invalid audio bytes")
        return None

    try:
        audio = MutagenFile(BytesIO(audio_bytes), easy=False)
    except Exception as e:
        logger.error(f"Mutagen failed to parse audio: {e}")
        audio = None

    image_bytes = None

    # 🎵 MP3 / ID3
    try:
        if audio and hasattr(audio, "tags"):
            for tag in audio.tags.values():
                if hasattr(tag, "data"):
                    image_bytes = tag.data
                    break
    except Exception:
        pass

    # 🎵 MP4 / M4A
    try:
        if not image_bytes and audio and hasattr(audio, "tags"):
            covr = audio.tags.get("covr")
            if covr:
                image_bytes = covr[0]
    except Exception:
        pass

    # 🎵 FLAC / OGG
    try:
        if not image_bytes and audio and hasattr(audio, "pictures"):
            if audio.pictures:
                image_bytes = audio.pictures[0].data
    except Exception:
        pass

    # 🎨 Convert image → JPEG
    if image_bytes:
        try:
            img = Image.open(BytesIO(image_bytes)).convert("RGB")
            img.thumbnail(thumb_size)

            output = BytesIO()
            img.save(output, format="JPEG", quality=90)
            return output.getvalue()
        except Exception as e:
            logger.error(f"Image conversion failed: {e}")

    # 🔊 Fallback waveform thumbnail
    if fallback_waveform:
        try:
            return generate_waveform_thumbnail(thumb_size)
        except Exception as e:
            logger.error(f"Waveform fallback failed: {e}")

    return None



def decrypt_upload_and_extract_audio_thumbnail_chunked(
        key: str,
        encrypted_file,
        iv_str: str,
        content_type: str = "application/octet-stream",
        file_ext: str = "",
        progress_callback=None,
        chunk_size: int = 10 * 1024 * 1024,  # 10 MB default
        file_type=None,
        thumbnail_buffer_size: int = 512 * 1024,  # 512 KB buffer for thumbnail
        max_retries: int = 3,  # Retry failed uploads
        fallback_thumbnail_max_size: int = 1024 * 1024 * 1024,  # 1 GB limit for fallback
    ):
    """
    Decrypt AES-256-GCM encrypted file chunk-by-chunk, upload decrypted chunks to S3, 
    and extract embedded audio/video thumbnail while streaming.
    Optimized for minimal RAM and CPU usage - single-threaded for simplicity.
    
    Args:
        fallback_thumbnail_max_size: Max file size (bytes) for fallback thumbnail extraction.
                                     Prevents OOM on large files. Default: 100MB
    """
    
    # Input validation
    if chunk_size <= 0:
        raise ValueError(f"chunk_size must be positive, got {chunk_size}")
    if max_retries < 1:
        raise ValueError(f"max_retries must be at least 1, got {max_retries}")
    if not hasattr(encrypted_file, 'seek') or not hasattr(encrypted_file, 'read'):
        raise ValueError("encrypted_file must be a seekable file-like object")

    bucket = MEDIA_FILES_BUCKET
    parts = []
    uploaded_bytes = 0
    thumbnail_data = None
    buffer_for_thumbnail = None
    upload_id = None
    cipher = None
    decryptor = None
    aesgcm = None
    data_key_plain = None
    
    # Thumbnail extraction config
    thumbnail_extracted = False
    MAX_THUMBNAIL_ATTEMPTS = 3
    MIN_BUFFER_FOR_ATTEMPT = 256 * 1024  # Minimum buffer before attempting extraction
    thumbnail_extraction_points = []
    
    # Retry configuration
    RETRY_DELAY_BASE = 1  # seconds
    
    # Timing metrics
    start_time = time.time()
    
    try:
        s3_key = key
        if progress_callback:
            progress_callback(15, "Initializing decryption...")

        # Parse IV
        try:
            if all(c in "0123456789abcdefABCDEF" for c in iv_str.strip()):
                iv = bytes.fromhex(iv_str)
            else:
                iv = base64.b64decode(iv_str)
        except Exception as e:
            raise ValueError(f"Invalid IV format: {e}")

        # Decode AES key
        key_bytes = settings.ENCRYPTION_KEY
        if isinstance(key_bytes, str):
            key_bytes = base64.b64decode(key_bytes)
        if len(key_bytes) != 32:
            raise ValueError(f"Key must be 32 bytes for AES-256, got {len(key_bytes)} bytes")

        # Determine file size and auth tag
        encrypted_file.seek(0, 2)
        total_size = encrypted_file.tell()
        if total_size < 16:
            raise ValueError("Encrypted file too short (missing GCM tag).")
        encrypted_data_size = total_size - 16
        encrypted_file.seek(encrypted_data_size)
        auth_tag = encrypted_file.read(16)
        encrypted_file.seek(0)

        # Adaptive chunk sizing (simplified)
        if encrypted_data_size <= 5 * 1024 * 1024:  # < 5MB
            effective_chunk_size = max(encrypted_data_size, 2 * 1024 * 1024)
        elif encrypted_data_size <= 50 * 1024 * 1024:  # 5-50MB
            effective_chunk_size = 8 * 1024 * 1024
        elif encrypted_data_size <= 200 * 1024 * 1024:  # 50-200MB
            effective_chunk_size = 12 * 1024 * 1024
        else:  # > 200MB
            effective_chunk_size = 18 * 1024 * 1024
            
        
        # print(f'\n ----- effective_chunk_size : {effective_chunk_size} ----')

        # Calculate strategic thumbnail extraction points
        if file_type in ('video', 'audio'):
            buffer_for_thumbnail = BytesIO()
            total_chunks = max(1, (encrypted_data_size + effective_chunk_size - 1) // effective_chunk_size)
            
            # Build candidate points for thumbnail extraction
            candidate_points = [
                1, 2,
                max(1, total_chunks // 6),
                max(1, total_chunks // 3),
                max(1, total_chunks // 2),
                max(1, (total_chunks * 2) // 3),
                total_chunks - 1 if total_chunks > 2 else total_chunks
            ]
            # Unique, sorted, cap at MAX_THUMBNAIL_ATTEMPTS
            thumbnail_extraction_points = sorted({p for p in candidate_points if 1 <= p <= total_chunks})[:MAX_THUMBNAIL_ATTEMPTS]
            logger.info(f"Thumbnail extraction planned at chunks: {thumbnail_extraction_points} for file size: {encrypted_data_size} bytes")

        # Initialize decryptor
        cipher = Cipher(algorithms.AES(key_bytes), modes.GCM(iv, auth_tag), backend=default_backend())
        decryptor = cipher.decryptor()

        if progress_callback:
            progress_callback(17, "Starting chunked decrypt & upload...")

        # Generate KMS data key & AESGCM encryptor for S3
        resp = kms.generate_data_key(KeyId=AWS_KMS_KEY_ID, KeySpec="AES_256")
        data_key_plain = resp["Plaintext"]
        data_key_encrypted = resp["CiphertextBlob"]
        aesgcm = AESGCM(data_key_plain)

        # Prepare S3 multipart upload
        multipart_resp = s3.create_multipart_upload(
            Bucket=bucket,
            Key=s3_key,
            ContentType=content_type,
            Metadata={
                "edk": base64.b64encode(data_key_encrypted).decode(),
                "orig-content-type": content_type,
                "chunk-size": str(effective_chunk_size),
            },
        )
        upload_id = multipart_resp["UploadId"]

        # Upload with retry logic
        def upload_part_with_retry(bucket, key, part_num, upload_id, body):
            """Upload a part with exponential backoff retry logic"""
            for attempt in range(max_retries):
                try:
                    resp = s3.upload_part(
                        Bucket=bucket,
                        Key=key,
                        PartNumber=part_num,
                        UploadId=upload_id,
                        Body=body,
                    )
                    return resp
                except Exception as e:
                    if attempt == max_retries - 1:
                        raise  # Last attempt failed
                    
                    # Exponential backoff: 1s, 2s, 4s, 8s...
                    delay = RETRY_DELAY_BASE * (2 ** attempt)
                    logger.warning(f"Upload part {part_num} failed (attempt {attempt + 1}/{max_retries}), retrying in {delay}s: {str(e)}")
                    time.sleep(delay)
            
            raise RuntimeError(f"Failed to upload part {part_num} after {max_retries} attempts")

        # Process chunks
        part_number = 1
        total_read = 0
        current_chunk_number = 0
        thumbnail_attempts = 0

        while total_read < encrypted_data_size:
            to_read = min(effective_chunk_size, encrypted_data_size - total_read)
            chunk = encrypted_file.read(to_read)
            if not chunk:
                raise RuntimeError(f"Unexpected EOF: read {total_read}/{encrypted_data_size} bytes")
            total_read += len(chunk)
            current_chunk_number += 1

            # Decrypt chunk
            decrypted_chunk = decryptor.update(chunk)

            # Strategic thumbnail extraction
            if (not thumbnail_extracted and 
                file_type in ['video', 'audio'] and 
                buffer_for_thumbnail is not None and
                current_chunk_number in thumbnail_extraction_points):
                
                buffer_for_thumbnail.write(decrypted_chunk)
                current_buffer_size = buffer_for_thumbnail.tell()
                
                if current_buffer_size >= MIN_BUFFER_FOR_ATTEMPT:
                    thumbnail_attempts += 1
                    attempt_num = thumbnail_extraction_points.index(current_chunk_number) + 1
                    
                    try:
                        if logger.isEnabledFor(logging.INFO):
                            logger.info(f"Thumbnail extraction attempt {attempt_num}/{MAX_THUMBNAIL_ATTEMPTS} at chunk {current_chunk_number} (buffer: {current_buffer_size} bytes)")
                        
                        extractor = MediaThumbnailExtractor(file='', file_ext=file_ext)
                        buffer_data = buffer_for_thumbnail.getvalue()
                        
                        if file_type == 'video':
                            thumb = extractor.extract_video_thumbnail_from_bytes(
                                extension=file_ext,
                                decrypted_bytes=buffer_data,
                            )
                        else:
                            thumb = extractor.extract_audio_thumbnail_from_bytes(
                                extension=file_ext,
                                decrypted_bytes=buffer_data,
                            )
                        
                        if thumb:
                            thumbnail_data = thumb
                            thumbnail_extracted = True
                            # Free buffer immediately
                            buffer_for_thumbnail.close()
                            buffer_for_thumbnail = None
                            logger.info(f"Thumbnail extracted successfully on attempt {attempt_num}/{MAX_THUMBNAIL_ATTEMPTS}")
                            if progress_callback:
                                progress_callback(None, "Thumbnail extracted")
                        else:
                            if logger.isEnabledFor(logging.INFO):
                                logger.info(f"Attempt {attempt_num} returned None")
                            
                    except Exception as e:
                        logger.warning(f"Thumbnail extraction attempt {attempt_num} failed: {str(e)}")
                
                # Buffer management
                if buffer_for_thumbnail:
                    should_clear = (
                        current_buffer_size > thumbnail_buffer_size * 2 or
                        attempt_num > MAX_THUMBNAIL_ATTEMPTS // 2
                    )
                    if should_clear:
                        buffer_for_thumbnail.seek(0)
                        buffer_for_thumbnail.truncate()
                        if logger.isEnabledFor(logging.DEBUG):
                            logger.debug(f"Buffer cleared at {current_buffer_size} bytes (attempt {attempt_num})")

            # Encrypt chunk for S3 upload
            nonce = os.urandom(12)
            ciphertext_chunk = aesgcm.encrypt(nonce, decrypted_chunk, None)
            body = nonce + ciphertext_chunk

            # Direct upload with retry
            try:
                resp = upload_part_with_retry(bucket, s3_key, part_number, upload_id, body)
                parts.append({"ETag": resp["ETag"], "PartNumber": part_number})
                uploaded_bytes += len(decrypted_chunk)
                
                # Progress from 20-83
                percent = 20 + int((uploaded_bytes / encrypted_data_size) * 63)
                if progress_callback:
                    progress_callback(min(percent, 83), None)
            except Exception as e:
                raise RuntimeError(f"Failed to upload part {part_number}: {str(e)}")

            part_number += 1

        # Finalize decryption
        decryptor.finalize()

       

        # Complete S3 upload
        parts.sort(key=lambda x: x["PartNumber"])
        result = s3.complete_multipart_upload(
            Bucket=bucket,
            Key=s3_key,
            UploadId=upload_id,
            MultipartUpload={"Parts": parts},
        )
        upload_id = None  # Successfully completed, don't abort in finally
        
        # Fallback thumbnail extraction with size check
        if not thumbnail_data and file_type in ['video', 'audio']:
            
            try:
                if file_type == 'video':
                    thumbnail_data = extract_thumbnail_full_decrypt(
                        s3_key=s3_key,
                        file_ext=file_ext,
                    )
                else:
                    with ChunkedDecryptor(s3_key) as decryptor_obj:
                        full_data = b''.join(decryptor_obj.decrypt_chunks())
                    
                    extractor = MediaThumbnailExtractor(file='', file_ext=file_ext)
                    thumbnail_data = extractor.extract_audio_thumbnail_from_bytes(
                        extension=file_ext,
                        decrypted_bytes=full_data
                    )
                    if not thumbnail_data:
                        thumbnail_data = extract_audio_thumbnail_from_bytes(
                            extension=file_ext,
                            audio_bytes=full_data,
                        )

            except Exception as e:
                logger.error(f'Fallback thumbnail extraction failed for s3-key: {s3_key}, error: {str(e)}')
            
        if not thumbnail_data and file_type in ['video', 'audio']:
            logger.warning(f'All thumbnail extraction attempts failed for s3-key: {s3_key} ')

        # Log metrics
        elapsed_time = time.time() - start_time
        throughput_mbps = (uploaded_bytes / (1024 * 1024)) / elapsed_time if elapsed_time > 0 else 0
        logger.info(f"Upload completed: {uploaded_bytes} bytes in {elapsed_time:.2f}s ({throughput_mbps:.2f} MB/s)")

        if progress_callback:
            progress_callback(85, "Completing upload...")

        return {
            "s3_result": result,
            "uploaded_size": uploaded_bytes,
            "thumbnail_data": thumbnail_data,
        }

    except Exception as e:
        logger.error(f"Decrypt/upload failed for key {s3_key}: {str(e)}", exc_info=True)
        raise RuntimeError(f"Decrypt/upload failed: {e}") from e

    finally:
        # Cleanup in proper order
        
        # 1. Abort failed S3 upload
        if upload_id is not None:
            try:
                s3.abort_multipart_upload(Bucket=bucket, Key=s3_key, UploadId=upload_id)
                logger.info(f"Aborted multipart upload {upload_id} for {s3_key}")
            except Exception as e:
                logger.error(f"Failed to abort multipart upload {upload_id}: {str(e)}")
        
        # 2. Close file buffers
        if buffer_for_thumbnail is not None:
            try:
                buffer_for_thumbnail.close()
            except Exception as e:
                logger.error(f"Failed to close thumbnail buffer: {str(e)}")
        
        # 3. Clear sensitive data
        if data_key_plain is not None:
            try:
                # Overwrite sensitive key data before clearing reference
                if isinstance(data_key_plain, bytes):
                    data_key_plain = b'\x00' * len(data_key_plain)
            except Exception as e:
                logger.error(f"Failed to clear data key: {str(e)}")

def truncate_filename(filename, max_length=100):
    name, ext = os.path.splitext(filename)
    return f"{name[:max_length - len(ext)]}{ext}"

def media_cache_key(prefix: str, s3_key: str) -> str:
    import hashlib
    digest = hashlib.sha256(s3_key.encode("utf-8")).hexdigest()
    return f"{prefix}:{digest}"


class ChunkedUploadSession:
    def __init__(
        self,
        upload_id,
        user_id,
        time_capsoul_id,
        file_name,
        file_size,
        file_type,
        total_chunks,
        chunk_size,
        s3_key,
    ):
        self.upload_id = upload_id
        self.user_id = user_id
        self.time_capsoul_id = time_capsoul_id
        self.file_name = file_name
        self.file_size = file_size
        self.file_type = file_type
        self.total_chunks = total_chunks
        self.chunk_size = chunk_size
        self.s3_key = s3_key

        self.s3_upload_id = None
        self.s3_parts = {}
        self.uploaded_chunks = set()
        
        self.created_at = time.time()
        self.last_activity = time.time()

        self.data_key_plain = None
        self.data_key_encrypted = None
        self.aesgcm = None
        
        # JPG and small file specific fields
        self.is_jpg = False
        self.is_small_file = False
        self.file_ext = None
        self.temp_chunks_key = None  # Unified key for both JPG and small files
        
        # Completion result storage
        self.completion_result = None
        
        # Thread safety
        self.lock = threading.Lock()

    def to_dict(self):
        """Serialize session to dictionary for cache storage"""
        with self.lock:
            return {
                "upload_id": self.upload_id,
                "user_id": self.user_id,
                "time_capsoul_id": self.time_capsoul_id,
                "file_name": self.file_name,
                "file_size": self.file_size,
                "file_type": self.file_type,
                "total_chunks": self.total_chunks,
                "chunk_size": self.chunk_size,
                "s3_key": self.s3_key,
                "s3_upload_id": self.s3_upload_id,
                "s3_parts": self.s3_parts,
                "uploaded_chunks": list(self.uploaded_chunks),
                "created_at": self.created_at,
                "last_activity": self.last_activity,
                "data_key_encrypted": (
                    base64.b64encode(self.data_key_encrypted).decode()
                    if self.data_key_encrypted else None
                ),
                # JPG and small file specific fields
                "is_jpg": self.is_jpg,
                "is_small_file": self.is_small_file,
                "file_ext": self.file_ext,
                "temp_chunks_key": self.temp_chunks_key,
                "completion_result": self.completion_result,
            }

    @classmethod
    def from_dict(cls, data):
        """Deserialize session from dictionary"""
        session = cls(
            data["upload_id"],
            data["user_id"],
            data["time_capsoul_id"],
            data["file_name"],
            data["file_size"],
            data["file_type"],
            data["total_chunks"],
            data["chunk_size"],
            data["s3_key"],
        )

        session.s3_upload_id = data["s3_upload_id"]
        session.s3_parts = data["s3_parts"]
        session.uploaded_chunks = set(data["uploaded_chunks"])
        session.created_at = data["created_at"]
        session.last_activity = data["last_activity"]

        # Restore encryption key
        if data.get("data_key_encrypted"):
            encrypted = base64.b64decode(data["data_key_encrypted"])
            resp = kms.decrypt(CiphertextBlob=encrypted)
            session.data_key_plain = resp["Plaintext"]
            session.data_key_encrypted = encrypted
            session.aesgcm = AESGCM(session.data_key_plain)

        # Restore JPG and small file specific fields
        session.is_jpg = data.get("is_jpg", False)
        session.is_small_file = data.get("is_small_file", False)
        session.file_ext = data.get("file_ext")
        session.temp_chunks_key = data.get("temp_chunks_key")
        session.completion_result = data.get("completion_result")

        return session

    def is_expired(self, timeout=3600):
        """Check if session has expired"""
        return (time.time() - self.last_activity) > timeout

    def get_progress(self):
        """Get upload progress as percentage"""
        if self.total_chunks == 0:
            return 0.0
        
        # For JPG files, chunk upload is only 50% of progress
        if self.is_jpg:
            return (len(self.uploaded_chunks) / self.total_chunks) * 50
        else:
            # For small and large files, normal progress
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

    def add_s3_part(self, part_number, etag):
        """Add an S3 part (for non-JPG, non-small files)"""
        with self.lock:
            self.s3_parts[str(part_number)] = etag
            self.last_activity = time.time()

    def get_s3_parts_list(self):
        """Get sorted list of S3 parts for completion"""
        parts = [
            {"PartNumber": int(p), "ETag": et}
            for p, et in self.s3_parts.items()
        ]
        return sorted(parts, key=lambda x: x["PartNumber"])

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