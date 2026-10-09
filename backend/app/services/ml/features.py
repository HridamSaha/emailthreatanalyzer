from __future__ import annotations

from app.services.email_parser import ParsedEmail


def extract_features(parsed: ParsedEmail | None, url_results: list[dict], attachment_results: list[dict], findings: list[dict]) -> dict:
    body = (parsed.body_text if parsed else "") or ""
    return {
        "url_count": len(url_results),
        "suspicious_url_count": sum(1 for item in url_results if item.get("triggered_rules")),
        "sender_mismatch": int(any(item.get("rule_id") == "EMAIL-001" for item in findings)),
        "credential_request": int(any(item.get("rule_id") == "EMAIL-003" for item in findings)),
        "attachment_count": len(attachment_results),
        "risky_attachment_count": sum(1 for item in attachment_results if item.get("risky_type") or item.get("signature_mismatch")),
        "body_length": min(len(body), 20000),
        "exclamation_count": body.count("!"),
        "finding_count": len(findings),
    }


def feature_vector(features: dict) -> list[float]:
    order = [
        "url_count",
        "suspicious_url_count",
        "sender_mismatch",
        "credential_request",
        "attachment_count",
        "risky_attachment_count",
        "body_length",
        "exclamation_count",
        "finding_count",
    ]
    return [float(features.get(key, 0)) for key in order]
