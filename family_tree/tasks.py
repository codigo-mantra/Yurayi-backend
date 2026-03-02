import os
import uuid
import time
import struct
import logging

from celery import shared_task
from django.conf import settings
from django.core.files import File
from django.core.files.base import ContentFile
from django.core.cache import cache

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

from family_tree.models import FamilyTreeGallery
from family_tree.utils.upload_helper import UniversalThumbnailService
from family_tree.apis.views.gallery_media import (
    ChunkedUploadSession,
    get_local_upload_path,
    get_file_category,
)
from .models import UploadSession

logger = logging.getLogger(__name__)

CHUNK_SIZE          = 5 * 1024 * 1024
PROGRESS_TTL        = 60 * 60
PROGRESS_KEY_PREFIX = "upload_progress"


# ---------------------------------------------------------------------------
# Redis helpers — progress lives here only, never in DB
# ---------------------------------------------------------------------------

def _progress_key(uid: str) -> str:
    return f"{PROGRESS_KEY_PREFIX}:{uid}"

def set_progress(uid: str, progress: int):
    cache.set(_progress_key(uid), progress, PROGRESS_TTL)

def get_progress(uid: str) -> int:
    return cache.get(_progress_key(uid), 0)

def clear_progress(uid: str):
    cache.delete(_progress_key(uid))


# ---------------------------------------------------------------------------
# DB status helper — queryset .update() only, no progress field
# ---------------------------------------------------------------------------

def _set_db_status(upload_session_id: str, status: str):
    updated = UploadSession.objects.filter(id=upload_session_id).update(status=status)
    if updated == 0:
        logger.warning(f"[{upload_session_id}] _set_db_status: no rows updated (status={status})")
    else:
        logger.info(f"[{upload_session_id}] DB status → {status}")


# ---------------------------------------------------------------------------
# Path helpers
# ---------------------------------------------------------------------------

def get_temp_dir(family_tree_id, upload_session_id: str) -> str:
    return os.path.join(
        settings.MEDIA_ROOT,
        str(family_tree_id),
        "temp_uploads",
        str(upload_session_id),
    )

def discover_source_file(temp_dir: str) -> str:
    if not os.path.isdir(temp_dir):
        raise FileNotFoundError(f"Temp directory not found: {temp_dir}")

    files = [
        os.path.join(temp_dir, f)
        for f in os.listdir(temp_dir)
        if os.path.isfile(os.path.join(temp_dir, f))
    ]

    if not files:
        raise FileNotFoundError(f"No files found in: {temp_dir}")
    if len(files) > 1:
        raise ValueError(f"Expected 1 file per session, found {len(files)}")

    return files[0]


# ---------------------------------------------------------------------------
# Encryption
# [12 bytes IV][4 bytes big-endian length][ciphertext + 16-byte tag]
# ---------------------------------------------------------------------------

def _write_encrypted_chunk(f, plaintext: bytes, key: bytes):
    iv = os.urandom(12)
    encryptor = Cipher(
        algorithms.AES(key),
        modes.GCM(iv),
        backend=default_backend(),
    ).encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    encrypted  = ciphertext + encryptor.tag

    f.write(iv)
    f.write(struct.pack(">I", len(encrypted)))
    f.write(encrypted)


# ---------------------------------------------------------------------------
# Step 1 — Build internal session
# ---------------------------------------------------------------------------

def _build_session(source_path: str, family_tree_id, user_id) -> ChunkedUploadSession:
    from django.utils.text import get_valid_filename

    clean_name     = get_valid_filename(os.path.basename(source_path))
    file_size      = os.path.getsize(source_path)
    total_chunks   = max(1, (file_size + CHUNK_SIZE - 1) // CHUNK_SIZE)
    upload_id      = str(uuid.uuid4())
    local_path     = get_local_upload_path(family_tree_id, upload_id, clean_name)
    temp_file_path = f"{local_path}.part"

    # Ensure directory exists for both .part and final file
    os.makedirs(os.path.dirname(temp_file_path), exist_ok=True)

    session = ChunkedUploadSession(
        upload_id=upload_id,
        user_id=user_id,
        gallery_media_id=family_tree_id,
        file_name=clean_name,
        file_size=file_size,
        file_type=get_file_category(clean_name),
        total_chunks=total_chunks,
        chunk_size=CHUNK_SIZE,
    )
    session.local_path     = local_path
    session.temp_file_path = temp_file_path
    session.last_activity  = time.time()

    logger.info(
        f"[{upload_id}] Session built — "
        f"file={clean_name}, size={file_size}B, chunks={total_chunks}"
    )
    return session


# ---------------------------------------------------------------------------
# Step 2 — Encrypt chunks, update Redis progress per chunk
# ---------------------------------------------------------------------------

def _process_chunks(
    source_path: str,
    session: ChunkedUploadSession,
    upload_session_id: str,
):
    key          = settings.ENCRYPTION_KEY
    total_chunks = session.total_chunks

    chunk_index = 0
    with open(source_path, "rb") as src, open(session.temp_file_path, "ab") as dst:
        while True:
            plaintext = src.read(CHUNK_SIZE)
            if not plaintext:
                break
            
            _write_encrypted_chunk(dst, plaintext, key)
            time.sleep(0.5)
            session.received_bytes += len(plaintext)
            session.uploaded_chunks.add(chunk_index)
            chunk_index += 1

            # 10%–90% band, updated every chunk — Redis only, zero DB hits
            set_progress(upload_session_id, 10 + int((chunk_index / total_chunks) * 80))

    logger.info(f"[{session.upload_id}] Encrypted {chunk_index}/{total_chunks} chunks")


# ---------------------------------------------------------------------------
# Step 3 — Finalise
# ---------------------------------------------------------------------------

def _finalise(
    session: ChunkedUploadSession,
    user,
    family_tree,
    member,
    upload_session_id: str,
) -> FamilyTreeGallery:
    if len(session.uploaded_chunks) != session.total_chunks:
        raise ValueError(
            f"Chunk mismatch: expected {session.total_chunks}, "
            f"got {len(session.uploaded_chunks)}"
        )

    if not os.path.exists(session.temp_file_path):
        raise FileNotFoundError(f".part file missing: {session.temp_file_path}")

    os.replace(session.temp_file_path, session.local_path)
    logger.info(f"[{session.upload_id}] Moved to final: {session.local_path}")
    set_progress(upload_session_id, 90)

    media = FamilyTreeGallery.objects.create(
        author=user,
        family_tree=family_tree,
        # member=member,
        title=session.file_name,
        file_size=session.file_size,
        file_type=session.file_type,
    )

    with open(session.local_path, "rb") as f:
        media.file.save(os.path.basename(session.local_path), File(f), save=True)

    set_progress(upload_session_id, 95)

    from family_tree.apis.views.gallery_media import ChunkedMediaFileUploadView
    decrypt_fn = ChunkedMediaFileUploadView().decrypt_full_file
    extension  = os.path.splitext(session.local_path)[1].lower()

    try:
        thumbnail_bytes = UniversalThumbnailService.generate(
            session.local_path, decrypt_fn, extension=extension,
        )
    except Exception:
        logger.exception(f"[{session.upload_id}] Thumbnail failed — rolling back")
        if os.path.exists(session.local_path):
            os.remove(session.local_path)
        media.delete()
        raise

    if thumbnail_bytes:
        media.thumbnail_preview.save(
            f"{session.upload_id}_thumb.jpg",
            ContentFile(thumbnail_bytes),
            save=True,
        )

    return media


# ---------------------------------------------------------------------------
# Celery task
# ---------------------------------------------------------------------------

@shared_task(bind=True, max_retries=3, default_retry_delay=30)
def process_encrypted_upload(self, upload_session_id: str):
    """
    Server-side chunked encrypted upload.

    DB writes (status only, no progress field):
        → Initialized   task started
        → Pending       raw file confirmed
        → Uploading     encryption started
        → Aborted       on any unrecoverable error
        → (deleted)     on Completed — UploadSession row is removed

    Progress (Redis only, never DB):
        0%   Initialized
        5%   Pending
        10–90%  per-chunk during Uploading
        90%  file moved to final path
        95%  thumbnail generated
        100% done — Redis key cleared after SSE reads it
    """
    logger.info(f"[TASK] Started — session={upload_session_id}")

    # ── Load DB session ────────────────────────────────────────────────
    try:
        db_session = UploadSession.objects.select_related(
            "family_tree", "user", "member"
        ).get(id=upload_session_id)
    except UploadSession.DoesNotExist:
        logger.error(f"[TASK] UploadSession not found: {upload_session_id}")
        return {"status": "failed", "reason": "UploadSession not found"}

    if db_session.status in ("Uploading", "Completed"):
        logger.warning(f"[TASK] Already {db_session.status} — skipping")
        return {"status": "ignored"}

    _set_db_status(upload_session_id, "Initialized")
    set_progress(upload_session_id, 0)

    # ── Find raw file ──────────────────────────────────────────────────
    temp_dir = get_temp_dir(db_session.family_tree_id, upload_session_id)

    try:
        source_path = discover_source_file(temp_dir)
    except (FileNotFoundError, ValueError) as exc:
        logger.error(f"[TASK] {exc}")
        _set_db_status(upload_session_id, "Aborted")
        clear_progress(upload_session_id)
        return {"status": "Aborted", "reason": str(exc)}

    _set_db_status(upload_session_id, "Pending")
    set_progress(upload_session_id, 5)

    # ── Build internal session ─────────────────────────────────────────
    try:
        session = _build_session(
            source_path=source_path,
            family_tree_id=db_session.family_tree_id,
            user_id=db_session.user_id,
        )
    except Exception as exc:
        logger.exception("[TASK] Session build failed")
        _set_db_status(upload_session_id, "Aborted")
        clear_progress(upload_session_id)
        raise self.retry(exc=exc)

    # ── Encrypt + write chunks ─────────────────────────────────────────
    _set_db_status(upload_session_id, "Uploading")
    set_progress(upload_session_id, 10)

    try:
        _process_chunks(source_path, session, upload_session_id)
    except Exception as exc:
        logger.exception("[TASK] Chunk encryption failed")
        if os.path.exists(session.temp_file_path):
            os.remove(session.temp_file_path)
        _set_db_status(upload_session_id, "Aborted")
        clear_progress(upload_session_id)
        raise self.retry(exc=exc)

    # ── Finalise ───────────────────────────────────────────────────────
    try:
        media = _finalise(
            session,
            db_session.user,
            db_session.family_tree,
            db_session.member,
            upload_session_id,
        )
    except Exception as exc:
        logger.exception("[TASK] Finalisation failed")
        _set_db_status(upload_session_id, "Aborted")
        clear_progress(upload_session_id)
        raise self.retry(exc=exc)

    # ── Cleanup raw file ───────────────────────────────────────────────
    try:
        os.remove(source_path)
        if os.path.isdir(temp_dir) and not os.listdir(temp_dir):
            os.rmdir(temp_dir)
    except Exception:
        logger.warning(f"[TASK] Cleanup failed: {temp_dir}", exc_info=True)

    # ── Delete UploadSession — no longer needed ────────────────────────
    # Set progress to 100 in Redis first so SSE can emit one final event,
    # then the SSE view will drop it from active_ids on the next poll.
    set_progress(upload_session_id, 100)
    UploadSession.objects.filter(id=upload_session_id).delete()
    logger.info(f"[TASK] UploadSession {upload_session_id} deleted")

    logger.info(f"[TASK] Done — media_id={media.id}")
    return {"status": "Completed", "media_id": str(media.id)}