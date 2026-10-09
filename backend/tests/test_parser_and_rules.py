from __future__ import annotations

from pathlib import Path

from app.services.detection_engine import evaluate_body, evaluate_sender, evaluate_urls
from app.services.email_parser import parse_email_bytes, parse_email_text
from app.services.risk_scorer import score_and_classify
from app.services.url_analyzer import analyze_url, analyze_urls

SAMPLES = Path(__file__).resolve().parents[2] / "samples"
ENABLED = {f"EMAIL-00{i}": True for i in range(1, 5)} | {
    "URL-001": True,
    "URL-002": True,
    "URL-003": True,
    "PARSER-001": True,
    "CORR-001": True,
}


def test_valid_eml_parsing():
    parsed = parse_email_bytes((SAMPLES / "benign.eml").read_bytes())
    assert parsed.parse_ok
    assert parsed.from_address == "ops@contoso.example"
    assert "staff meeting" in parsed.body_text.lower()


def test_missing_headers():
    parsed = parse_email_text("Subject: only a subject\n\nHello")
    assert "From" in parsed.missing_fields


def test_malformed_message():
    parsed = parse_email_bytes((SAMPLES / "malformed.eml").read_bytes())
    assert parsed.warnings


def test_multiple_urls():
    parsed = parse_email_text(
        "From: a@b.example\nSubject: links\n\nSee http://one.example/a and https://two.example/b"
    )
    assert len(parsed.urls) >= 2


def test_sender_reply_to_mismatch():
    parsed = parse_email_bytes((SAMPLES / "sender-mismatch.eml").read_bytes())
    findings = evaluate_sender(parsed, ENABLED)
    assert any(item["rule_id"] == "EMAIL-001" for item in findings)


def test_suspicious_url_characteristics():
    result = analyze_url("http://user@185.1.1.1:8443/login-secure/%2e%2e")
    assert "URL-003" in result["triggered_rules"]
    assert "URL-001" in result["triggered_rules"]
    assert result["ip_host"] is True


def test_benign_and_suspicious_text():
    benign = parse_email_bytes((SAMPLES / "benign.eml").read_bytes())
    assert evaluate_body(benign, ENABLED) == []
    phish = parse_email_bytes((SAMPLES / "phishing-multi.eml").read_bytes())
    body_findings = evaluate_body(phish, ENABLED)
    assert any(item["rule_id"] == "EMAIL-003" for item in body_findings)
    assert any(item["rule_id"] == "EMAIL-004" for item in body_findings)


def test_link_mismatch_rule():
    results = analyze_urls(
        ["http://185.199.108.153/login-secure"],
        [{"text": "https://login.microsoft.com", "href": "http://185.199.108.153/login-secure"}],
    )
    findings = evaluate_urls(results, ENABLED)
    assert any(item["rule_id"] == "URL-002" for item in findings)


def test_risk_score_and_thresholds():
    scored = score_and_classify(
        [
            {
                "rule_id": "EMAIL-001",
                "category": "email",
                "score_contribution": 15,
                "evidence_kind": "observed",
            }
        ],
        parser_unreliable=False,
    )
    assert scored["risk_score"] == 15
    assert scored["classification"] == "suspicious"

    malicious = score_and_classify(
        [
            {"rule_id": "ATTACH-003", "category": "attachment", "score_contribution": 50, "evidence_kind": "intelligence"},
            {"rule_id": "EMAIL-003", "category": "content", "score_contribution": 15, "evidence_kind": "observed"},
        ],
        parser_unreliable=False,
    )
    assert malicious["classification"] == "malicious"
    assert malicious["risk_score"] == 65


def test_single_weak_anomaly_not_malicious():
    scored = score_and_classify(
        [{"rule_id": "URL-001", "category": "url", "score_contribution": 70, "evidence_kind": "heuristic"}],
        parser_unreliable=False,
    )
    assert scored["classification"] != "malicious"


def test_manual_review_when_unreliable():
    scored = score_and_classify([], parser_unreliable=True)
    assert scored["classification"] == "manual_review"
