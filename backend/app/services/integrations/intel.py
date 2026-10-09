from __future__ import annotations

import json
from pathlib import Path

from app.core.config import BACKEND_ROOT, get_settings
from app.services.hash_service import sha256_bytes

# Test-only documented indicator. This is NOT a real-world malware hash.
# It is the SHA-256 of the inert ASCII fixture "ETAS-TEST-MALICIOUS-HASH-FIXTURE".
TEST_FIXTURE_BYTES = b"ETAS-TEST-MALICIOUS-HASH-FIXTURE"
TEST_FIXTURE_SHA256 = sha256_bytes(TEST_FIXTURE_BYTES)
LOCAL_HASH_SOURCE = "local-test-indicator-list"


def local_malicious_hashes() -> dict[str, str]:
    mapping = {TEST_FIXTURE_SHA256: LOCAL_HASH_SOURCE}
    extra = BACKEND_ROOT / "data" / "local_malicious_hashes.json"
    if extra.exists():
        try:
            payload = json.loads(extra.read_text(encoding="utf-8"))
            for item in payload:
                digest = str(item.get("sha256", "")).lower()
                source = str(item.get("source", "local-indicator-list"))
                if len(digest) == 64:
                    mapping[digest] = source
        except Exception:
            pass
    return mapping


def lookup_virustotal_hash(digest: str) -> dict:
    settings = get_settings()
    if not settings.virustotal_api_key:
        return {
            "provider": "virustotal",
            "status": "unavailable",
            "reason": "VIRUSTOTAL_API_KEY is not configured.",
            "malicious": False,
        }
    try:
        import httpx

        url = f"{settings.virustotal_base_url.rstrip('/')}/files/{digest}"
        response = httpx.get(
            url,
            headers={"x-apikey": settings.virustotal_api_key},
            timeout=8.0,
        )
        if response.status_code == 404:
            return {
                "provider": "virustotal",
                "status": "no_record",
                "malicious": False,
                "note": "No record is not a clean result.",
            }
        if response.status_code == 429:
            return {"provider": "virustotal", "status": "rate_limited", "malicious": False}
        if response.status_code >= 400:
            return {
                "provider": "virustotal",
                "status": "error",
                "malicious": False,
                "reason": f"HTTP {response.status_code}",
            }
        stats = response.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        malicious_count = int(stats.get("malicious", 0) or 0)
        return {
            "provider": "virustotal",
            "status": "ok",
            "malicious": malicious_count > 0,
            "stats": stats,
            "provenance": "virustotal_hash_lookup",
        }
    except Exception as exc:
        return {
            "provider": "virustotal",
            "status": "error",
            "malicious": False,
            "reason": exc.__class__.__name__,
        }


def lookup_virustotal_url(url: str) -> dict:
    settings = get_settings()
    if not settings.virustotal_api_key:
        return {
            "provider": "virustotal",
            "status": "unavailable",
            "reason": "VIRUSTOTAL_API_KEY is not configured.",
            "malicious": False,
        }
    return {
        "provider": "virustotal",
        "status": "skipped",
        "malicious": False,
        "reason": "URL reputation lookups require explicit authorization; hash-only lookups are preferred.",
        "url_hash_hint": url[:80],
    }


def clamav_scan(data: bytes, filename: str) -> dict:
    settings = get_settings()
    if not settings.clamav_enabled:
        return {"provider": "clamav", "status": "unavailable", "reason": "ClamAV is not enabled."}
    try:
        import socket

        with socket.create_connection((settings.clamav_host, settings.clamav_port), timeout=settings.clamav_timeout_seconds) as sock:
            sock.sendall(b"nPING\n")
            ping = sock.recv(32)
            if b"PONG" not in ping:
                return {"provider": "clamav", "status": "error", "reason": "Unexpected PING response."}
        return {
            "provider": "clamav",
            "status": "unavailable",
            "reason": "INSTREAM scanning is documented but not invoked from the web request path in this build.",
            "note": "A clean scan would not prove safety.",
        }
    except OSError as exc:
        return {"provider": "clamav", "status": "unavailable", "reason": exc.__class__.__name__}
    except TimeoutError:
        return {"provider": "clamav", "status": "timeout"}


def yara_scan(data: bytes, filename: str) -> dict:
    settings = get_settings()
    rules_dir = Path(settings.yara_rules_path)
    if not rules_dir.is_absolute():
        rules_dir = BACKEND_ROOT / rules_dir
    if not rules_dir.exists():
        return {"provider": "yara", "status": "unavailable", "reason": "No YARA rules directory configured."}
    try:
        import yara  # type: ignore
    except Exception:
        return {"provider": "yara", "status": "unavailable", "reason": "yara-python is not installed."}
    try:
        sources = {}
        for path in rules_dir.glob("*.yar"):
            sources[path.stem] = path.read_text(encoding="utf-8")
        if not sources:
            return {"provider": "yara", "status": "unavailable", "reason": "No .yar files found."}
        rules = yara.compile(sources=sources)
        matches = rules.match(data=data)
        return {
            "provider": "yara",
            "status": "ok",
            "matches": [match.rule for match in matches],
            "note": "Sample rules are for synthetic fixtures and do not detect real malware families.",
        }
    except Exception as exc:
        return {"provider": "yara", "status": "error", "reason": exc.__class__.__name__}
