from __future__ import annotations

import io
import zipfile

from app.services.attachment_analyzer import analyze_attachment, detect_signature
from app.services.hash_service import sha256_bytes
from app.services.integrations.intel import TEST_FIXTURE_BYTES, TEST_FIXTURE_SHA256, local_malicious_hashes


def test_sha256_correctness():
    assert sha256_bytes(b"abc") == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    assert sha256_bytes(TEST_FIXTURE_BYTES) == TEST_FIXTURE_SHA256


def test_file_signature_mismatch():
    result = analyze_attachment("notes.txt", "text/plain", b"MZFAKE")
    assert result["signature_mismatch"] is True
    assert "ATTACH-002" in result["triggered_rules"]


def test_risky_file_type():
    result = analyze_attachment("dropper.bat", "text/plain", b"echo inert")
    assert "ATTACH-001" in result["triggered_rules"]


def test_known_malicious_hash_test_source_only():
    known = local_malicious_hashes()
    result = analyze_attachment("fixture.bin", "application/octet-stream", TEST_FIXTURE_BYTES, known)
    assert "ATTACH-003" in result["triggered_rules"]
    assert result["intel_match"]["source"] == "local-test-indicator-list"


def test_archive_path_traversal_rejected():
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("../escape.txt", "nope")
        archive.writestr("ok.txt", "ok")
    result = analyze_attachment("bundle.zip", "application/zip", buffer.getvalue())
    assert result["archive"]["path_traversal_rejected"] is True
    names = [item["name"] for item in result["archive"]["entries"]]
    assert "../escape.txt" not in names
