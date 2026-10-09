from __future__ import annotations

import io
import zipfile
from pathlib import Path

from app.core.config import get_settings
from app.services.hash_service import sha256_bytes

DANGEROUS_EXTENSIONS = {
    ".exe",
    ".bat",
    ".cmd",
    ".scr",
    ".js",
    ".jse",
    ".vbs",
    ".vbe",
    ".ps1",
    ".dll",
    ".hta",
    ".iso",
    ".img",
    ".jar",
    ".msi",
    ".com",
    ".pif",
    ".cpl",
    ".wsf",
    ".lnk",
    ".docm",
    ".xlsm",
    ".pptm",
    ".dotm",
    ".xltm",
}

ARCHIVE_EXTENSIONS = {".zip", ".docx", ".xlsx", ".pptx", ".odt", ".ods", ".odp"}

SIGNATURES = [
    (b"MZ", "exe/dll"),
    (b"%PDF", "pdf"),
    (b"PK\x03\x04", "zip"),
    (b"\x89PNG\r\n\x1a\n", "png"),
    (b"\xff\xd8\xff", "jpeg"),
    (b"GIF87a", "gif"),
    (b"GIF89a", "gif"),
    (b"Rar!\x1a\x07", "rar"),
    (b"7z\xbc\xaf'\x1c", "7z"),
    (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "ole"),
]


def detect_signature(data: bytes) -> str | None:
    for magic, label in SIGNATURES:
        if data.startswith(magic):
            return label
    return None


def extension_of(filename: str) -> str:
    return Path(filename).suffix.lower()


def _zip_inspect(data: bytes) -> dict:
    settings = get_settings()
    result = {
        "is_archive": True,
        "entries": [],
        "encrypted": False,
        "path_traversal_rejected": False,
        "truncated": False,
        "macro_enabled": False,
        "contains_executable": False,
        "error": None,
    }
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            infolist = archive.infolist()
            if len(infolist) > settings.max_archive_entries:
                result["truncated"] = True
                infolist = infolist[: settings.max_archive_entries]
            for info in infolist:
                name = info.filename
                if name.startswith("/") or ".." in Path(name).parts:
                    result["path_traversal_rejected"] = True
                    continue
                if info.flag_bits & 0x1:
                    result["encrypted"] = True
                lower = name.lower()
                entry = {
                    "name": name[:240],
                    "size": info.file_size,
                    "compressed_size": info.compress_size,
                }
                result["entries"].append(entry)
                if lower.endswith("vbaproject.bin") or lower.endswith(".docm") or "/macros/" in lower:
                    result["macro_enabled"] = True
                if Path(lower).suffix in {".exe", ".dll", ".scr", ".js", ".vbs", ".ps1", ".bat"}:
                    result["contains_executable"] = True
    except zipfile.BadZipFile:
        result["error"] = "Not a readable ZIP archive."
        result["is_archive"] = False
    except Exception as exc:
        result["error"] = f"Archive inspection stopped: {exc.__class__.__name__}"
    return result


def _pdf_inspect(data: bytes) -> dict:
    meta: dict = {"is_pdf": True, "encrypted": False, "javascript_hint": False, "metadata": {}, "error": None}
    try:
        from pypdf import PdfReader

        reader = PdfReader(io.BytesIO(data), strict=False)
        meta["encrypted"] = bool(reader.is_encrypted)
        if reader.is_encrypted:
            meta["note"] = "PDF appears encrypted; contents were not decrypted."
            return meta
        info = reader.metadata or {}
        meta["metadata"] = {
            "title": str(getattr(info, "title", "") or ""),
            "author": str(getattr(info, "author", "") or ""),
            "creator": str(getattr(info, "creator", "") or ""),
            "producer": str(getattr(info, "producer", "") or ""),
        }
        raw = data[: min(len(data), 512_000)].lower()
        if b"/js" in raw or b"/javascript" in raw:
            meta["javascript_hint"] = True
        meta["page_count_reported"] = len(reader.pages)
    except Exception as exc:
        meta["error"] = f"PDF metadata inspection limited: {exc.__class__.__name__}"
    return meta


def analyze_attachment(
    filename: str,
    content_type: str,
    payload: bytes,
    known_malicious_hashes: dict[str, str] | None = None,
) -> dict:
    digest = sha256_bytes(payload)
    ext = extension_of(filename)
    signature = detect_signature(payload)
    findings: list[str] = []
    triggered: list[str] = []
    score = 0

    mime = (content_type or "application/octet-stream").lower()
    risky_ext = ext in DANGEROUS_EXTENSIONS
    if risky_ext:
        findings.append(f"Attachment uses a potentially dangerous extension ({ext}).")
        triggered.append("ATTACH-001")
        score += 20

    mismatch = False
    if signature == "exe/dll" and ext not in {".exe", ".dll", ".scr", ".com", ".sys"}:
        mismatch = True
    if signature == "zip" and ext not in ARCHIVE_EXTENSIONS | {".zip"}:
        mismatch = True
    if signature == "pdf" and ext not in {".pdf"}:
        mismatch = True
    if signature and mime.startswith("text/") and signature in {"exe/dll", "zip", "pdf"}:
        mismatch = True
    if mismatch:
        findings.append("File signature, extension, and/or MIME type disagree.")
        triggered.append("ATTACH-002")
        score += 18

    archive_info = None
    pdf_info = None
    if signature == "zip" or ext in ARCHIVE_EXTENSIONS:
        archive_info = _zip_inspect(payload)
        if archive_info.get("path_traversal_rejected"):
            findings.append("Archive contained path-traversal entries that were rejected.")
            triggered.append("ATTACH-001")
            score += 8
        if archive_info.get("contains_executable") or archive_info.get("macro_enabled"):
            findings.append("Archive listing includes executable content or macro-related parts.")
            triggered.append("ATTACH-001")
            score += 12
        if archive_info.get("encrypted"):
            findings.append("Archive members appear password-protected or encrypted.")
            score += 6
    if signature == "pdf" or ext == ".pdf":
        pdf_info = _pdf_inspect(payload)
        if pdf_info.get("javascript_hint"):
            findings.append("PDF bytes contain JavaScript-related markers.")
            triggered.append("ATTACH-001")
            score += 8

    intel_match = None
    known = known_malicious_hashes or {}
    if digest.lower() in {item.lower() for item in known}:
        source = known.get(digest) or known.get(digest.lower()) or "configured-test-source"
        intel_match = {"source": source, "hash": digest}
        findings.append(f"SHA-256 matched a documented indicator from {source}.")
        triggered.append("ATTACH-003")
        score += 50

    return {
        "filename": filename,
        "extension": ext or "(none)",
        "reported_mime": mime,
        "detected_type": signature or "unknown",
        "size_bytes": len(payload),
        "sha256": digest,
        "signature_mismatch": mismatch,
        "risky_type": risky_ext,
        "archive": archive_info,
        "pdf": pdf_info,
        "findings": findings,
        "triggered_rules": sorted(set(triggered)),
        "risk_contribution": min(score, 70),
        "intel_match": intel_match,
        "notes": "Static inspection is not proof that a file is malware-free. The file was not executed.",
    }
