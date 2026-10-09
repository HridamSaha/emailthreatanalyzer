from __future__ import annotations

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.database import get_db
from app.schemas.api import RawEmailRequest, UrlAnalyzeRequest
from app.services.orchestrator import (
    analyze_attachment_only,
    analyze_email_file,
    analyze_raw_email,
    analyze_url_only,
)

router = APIRouter(prefix="/api/v1/analyze", tags=["analyze"])
settings = get_settings()

EMAIL_MAGIC_HINTS = (b"From:", b"from:", b"Received:", b"MIME-Version:", b"Subject:", b"Return-Path:")


def _read_upload(upload: UploadFile, allowed_suffixes: tuple[str, ...]) -> tuple[bytes, str]:
    filename = upload.filename or "upload.bin"
    suffix = "." + filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
    if allowed_suffixes and suffix not in allowed_suffixes:
        raise HTTPException(status_code=400, detail=f"Unsupported file type. Allowed: {', '.join(allowed_suffixes)}")
    data = upload.file.read(settings.max_upload_bytes + 1)
    if len(data) > settings.max_upload_bytes:
        raise HTTPException(status_code=413, detail="File exceeds the configured upload size limit.")
    if not data:
        raise HTTPException(status_code=400, detail="Uploaded file is empty.")
    return data, filename


@router.post("/email")
def analyze_email(file: UploadFile = File(...), db: Session = Depends(get_db)):
    data, filename = _read_upload(file, (".eml",))
    head = data.lstrip()[:400]
    if not any(hint in head for hint in EMAIL_MAGIC_HINTS) and b"Content-Type:" not in head:
        raise HTTPException(status_code=400, detail="File does not look like an RFC email message.")
    return analyze_email_file(db, data, filename)


@router.post("/raw")
def analyze_raw(payload: RawEmailRequest, db: Session = Depends(get_db)):
    text = payload.raw.strip()
    if ":" not in text.splitlines()[0] and "From:" not in text and "Subject:" not in text:
        raise HTTPException(status_code=400, detail="Pasted content does not appear to include email headers.")
    return analyze_raw_email(db, payload.raw)


@router.post("/url")
def analyze_url(payload: UrlAnalyzeRequest, db: Session = Depends(get_db)):
    url = payload.url.strip()
    if not url.lower().startswith(("http://", "https://", "ftp://")):
        raise HTTPException(status_code=400, detail="Provide an absolute URL including a scheme. Destinations are not visited.")
    return analyze_url_only(db, url)


@router.post("/attachment")
def analyze_attachment(file: UploadFile = File(...), db: Session = Depends(get_db)):
    data, filename = _read_upload(file, ())
    content_type = file.content_type or "application/octet-stream"
    return analyze_attachment_only(db, filename, content_type, data)
