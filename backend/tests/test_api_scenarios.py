from __future__ import annotations

from pathlib import Path

from app.services.integrations.intel import TEST_FIXTURE_BYTES

SAMPLES = Path(__file__).resolve().parents[2] / "samples"


def _upload(client, path: Path):
    return client.post(
        "/api/v1/analyze/email",
        files={"file": (path.name, path.read_bytes(), "message/rfc822")},
    )


def test_tc01_benign_email(client):
    response = _upload(client, SAMPLES / "benign.eml")
    assert response.status_code == 200
    body = response.json()
    assert body["classification"] == "safe"
    assert body["risk_score"] < 30
    assert body["id"]
    listed = client.get("/api/v1/analyses")
    assert listed.json()["total"] >= 1


def test_tc02_suspicious_url(client):
    response = _upload(client, SAMPLES / "suspicious-url.eml")
    body = response.json()
    assert body["classification"] in {"suspicious", "malicious"}
    assert any(item["rule_id"] in {"URL-001", "URL-003"} for item in body["findings"])


def test_tc03_sender_mismatch(client):
    response = _upload(client, SAMPLES / "sender-mismatch.eml")
    body = response.json()
    assert body["classification"] in {"suspicious", "malicious"}
    assert any(item["rule_id"] == "EMAIL-001" for item in body["findings"])


def test_tc04_risky_attachment(client):
    response = _upload(client, SAMPLES / "risky-attachment.eml")
    body = response.json()
    assert body["classification"] in {"suspicious", "malicious"}
    assert body["attachment_analysis"]
    assert len(body["attachment_analysis"][0]["sha256"]) == 64
    assert any(item["rule_id"] in {"ATTACH-001", "ATTACH-002"} for item in body["findings"])


def test_tc05_known_malicious_hash(client):
    response = client.post(
        "/api/v1/analyze/attachment",
        files={"file": ("fixture.bin", TEST_FIXTURE_BYTES, "application/octet-stream")},
    )
    body = response.json()
    assert any(item["rule_id"] == "ATTACH-003" for item in body["findings"])
    assert body["classification"] == "malicious"
    assert "local-test-indicator-list" in str(body)


def test_tc06_multiple_phishing_indicators(client):
    response = _upload(client, SAMPLES / "phishing-multi.eml")
    body = response.json()
    ids = {item["rule_id"] for item in body["findings"]}
    assert "EMAIL-001" in ids
    assert "EMAIL-003" in ids
    assert "CORR-001" in ids
    assert body["risk_score"] >= 30


def test_tc07_malformed_email(client):
    # Direct parse path via raw that has a header-like first line so API accepts it,
    # but still missing critical fields.
    raw = "X-Broken: yes\n\n"
    response = client.post("/api/v1/analyze/raw", json={"raw": raw})
    body = response.json()
    assert body["classification"] == "manual_review"
    assert any(item["rule_id"] == "PARSER-001" for item in body["findings"])


def test_file_size_validation(client):
    huge = b"From: a@b.example\nSubject: x\n\n" + (b"A" * (11 * 1024 * 1024))
    response = client.post("/api/v1/analyze/email", files={"file": ("big.eml", huge, "message/rfc822")})
    assert response.status_code == 413


def test_file_type_validation(client):
    response = client.post("/api/v1/analyze/email", files={"file": ("note.txt", b"hello", "text/plain")})
    assert response.status_code == 400


def test_url_analyze_does_not_require_network(client):
    response = client.post("/api/v1/analyze/url", json={"url": "http://192.0.2.10/login"})
    assert response.status_code == 200
    assert response.json()["url_analysis"][0]["ip_host"] is True


def test_report_generation(client):
    created = _upload(client, SAMPLES / "benign.eml").json()
    pdf = client.get(f"/api/v1/analyses/{created['id']}/report")
    assert pdf.status_code == 200
    assert pdf.content[:4] == b"%PDF"
    exported = client.get(f"/api/v1/analyses/{created['id']}/export?format=json")
    assert exported.status_code == 200
    csv_resp = client.get(f"/api/v1/analyses/{created['id']}/export?format=csv")
    assert csv_resp.status_code == 200
    assert b"classification" in csv_resp.content


def test_api_error_handling(client):
    missing = client.get("/api/v1/analyses/does-not-exist")
    assert missing.status_code == 404
    assert "detail" in missing.json()
    assert "Traceback" not in missing.text


def test_stats_and_rules(client):
    _upload(client, SAMPLES / "benign.eml")
    stats = client.get("/api/v1/stats").json()
    assert stats["total"] >= 1
    rules = client.get("/api/v1/rules").json()
    assert any(item["rule_id"] == "EMAIL-001" for item in rules)


def test_delete_analysis(client):
    created = _upload(client, SAMPLES / "benign.eml").json()
    deleted = client.delete(f"/api/v1/analyses/{created['id']}")
    assert deleted.status_code == 200
    assert client.get(f"/api/v1/analyses/{created['id']}").status_code == 404


def test_scanner_unavailable(client):
    response = client.post(
        "/api/v1/analyze/attachment",
        files={"file": ("readme.txt", b"hello inert", "text/plain")},
    )
    scanners = response.json()["attachment_analysis"][0]["scanners"]
    assert scanners["clamav"]["status"] in {"unavailable", "error", "timeout"}
    assert scanners["virustotal"]["status"] in {"unavailable", "error", "skipped", "no_record"}
