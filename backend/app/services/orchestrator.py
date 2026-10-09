from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.rules_catalog import RULE_CATALOG
from app.models.orm import Analysis, AuditEvent, DetectionFinding, DetectionRule, Indicator
from app.services.attachment_analyzer import analyze_attachment
from app.services.detection_engine import (
    evaluate_attachments,
    evaluate_body,
    evaluate_correlation,
    evaluate_intel,
    evaluate_parser,
    evaluate_sender,
    evaluate_urls,
)
from app.services.email_parser import ParsedEmail, parse_email_bytes, parse_email_text
from app.services.hash_service import sha256_bytes, sha256_text
from app.services.integrations.intel import (
    clamav_scan,
    local_malicious_hashes,
    lookup_virustotal_hash,
    yara_scan,
)
from app.services.ioc_extractor import extract_iocs
from app.services.ml.classifier import predict_optional
from app.services.risk_scorer import score_and_classify
from app.services.url_analyzer import analyze_url, analyze_urls


def _enabled_map(db: Session) -> dict[str, bool]:
    rows = db.query(DetectionRule).all()
    if not rows:
        return {item["rule_id"]: True for item in RULE_CATALOG}
    return {row.rule_id: bool(row.enabled) for row in rows}


def _public_result(analysis: Analysis) -> dict[str, Any]:
    payload = dict(analysis.result_payload or {})
    payload.update(
        {
            "id": analysis.id,
            "analysis_type": analysis.analysis_type,
            "original_filename": analysis.original_filename,
            "input_hash": analysis.input_hash,
            "created_at": analysis.created_at.isoformat() if analysis.created_at else None,
            "classification": analysis.classification,
            "risk_score": analysis.risk_score,
            "severity": analysis.severity,
            "status": analysis.status,
            "summary": analysis.summary,
            "evidence_strength": analysis.evidence_strength,
            "recommended_action": analysis.recommended_action,
            "limitations": payload.get("limitations") or [analysis.limitations],
            "parser_warnings": analysis.parser_warnings or [],
        }
    )
    return payload


def persist_analysis(db: Session, record: dict[str, Any]) -> Analysis:
    analysis = Analysis(
        id=record["id"],
        analysis_type=record["analysis_type"],
        original_filename=record.get("original_filename"),
        input_hash=record.get("input_hash"),
        created_at=datetime.now(timezone.utc),
        classification=record["classification"],
        risk_score=record["risk_score"],
        severity=record["severity"],
        status="completed",
        summary=record.get("summary") or "",
        subject=(record.get("header_analysis") or {}).get("subject"),
        sender_domain=(record.get("header_analysis") or {}).get("sender_domain"),
        evidence_strength=record.get("evidence_strength") or "limited",
        recommended_action=record.get("recommended_action") or "",
        limitations=" ".join(record.get("limitations") or []),
        parser_warnings=record.get("parser_warnings") or [],
        result_payload=record,
        persist_raw=False,
        raw_content=None,
    )
    db.add(analysis)
    for finding in record.get("findings") or []:
        db.add(
            DetectionFinding(
                analysis_id=analysis.id,
                rule_id=finding["rule_id"],
                rule_name=finding["rule_name"],
                severity=finding["severity"],
                evidence=finding.get("evidence") or "",
                explanation=finding.get("explanation") or "",
                score_contribution=int(finding.get("score_contribution") or 0),
                suggested_response=finding.get("suggested_response") or "",
                evidence_kind=finding.get("evidence_kind") or "heuristic",
            )
        )
    for ioc in record.get("indicators") or []:
        db.add(
            Indicator(
                analysis_id=analysis.id,
                indicator_type=ioc["indicator_type"],
                value=str(ioc["value"])[:1024],
                provenance=ioc.get("provenance") or "extracted",
                verification_status=ioc.get("verification_status") or "unverified",
                notes=ioc.get("notes") or "",
            )
        )
    db.add(
        AuditEvent(
            event_type="analysis_created",
            subject_id=analysis.id,
            outcome="success",
            details=f"{analysis.analysis_type}:{analysis.classification}:{analysis.risk_score}",
        )
    )
    db.commit()
    db.refresh(analysis)
    return analysis


def _header_block(parsed: ParsedEmail) -> dict[str, Any]:
    auth = parsed.auth_claims or {}
    return {
        "from": parsed.from_raw or None,
        "from_address": parsed.from_address or None,
        "reply_to": parsed.reply_to_raw or None,
        "return_path": parsed.return_path_raw or None,
        "sender": parsed.sender_raw or None,
        "sender_domain": parsed.from_domain or None,
        "subject": parsed.subject or None,
        "date": parsed.date or None,
        "message_id": parsed.message_id or None,
        "auth_claims": auth,
        "spf": auth.get("spf"),
        "dkim": auth.get("dkim"),
        "dmarc": auth.get("dmarc"),
        "auth_note": (
            "SPF/DKIM/DMARC values are copied from supplied authentication headers when present. "
            "They are not independently verified by this application."
            if auth
            else "No SPF, DKIM, or DMARC authentication-result headers were present. No pass/fail is claimed."
        ),
        "header_inconsistencies": [
            warning for warning in parsed.warnings if "From" in warning or "identit" in warning.lower()
        ],
    }


def _scan_attachments(attachment_results: list[dict], payloads: list[bytes]) -> list[dict]:
    integrations = []
    known = local_malicious_hashes()
    for item, payload in zip(attachment_results, payloads):
        clam = clamav_scan(payload, item["filename"])
        yara = yara_scan(payload, item["filename"])
        vt = lookup_virustotal_hash(item["sha256"]) if item.get("sha256") else {"status": "skipped"}
        item["scanners"] = {"clamav": clam, "yara": yara, "virustotal": vt}
        integrations.append(item["scanners"])
        if vt.get("malicious") and vt.get("status") == "ok":
            item.setdefault("triggered_rules", []).append("INTEL-001")
        # re-run local hash if analyzer did not receive the map
        if item["sha256"] in known and "ATTACH-003" not in (item.get("triggered_rules") or []):
            item["intel_match"] = {"source": known[item["sha256"]], "hash": item["sha256"]}
            item.setdefault("triggered_rules", []).append("ATTACH-003")
            item.setdefault("findings", []).append("SHA-256 matched a documented local test indicator.")
    return integrations


def analyze_parsed_email(
    db: Session,
    parsed: ParsedEmail,
    analysis_type: str,
    original_filename: str | None,
) -> dict[str, Any]:
    settings = get_settings()
    enabled = _enabled_map(db)
    known = local_malicious_hashes()
    url_results = analyze_urls(parsed.urls, parsed.html_links)
    attachment_payloads = [item.payload for item in parsed.attachments]
    attachment_results = [
        analyze_attachment(item.filename, item.content_type, item.payload, known)
        for item in parsed.attachments
    ]
    _scan_attachments(attachment_results, attachment_payloads)

    findings: list[dict] = []
    findings += evaluate_sender(parsed, enabled)
    findings += evaluate_body(parsed, enabled)
    findings += evaluate_urls(url_results, enabled)
    findings += evaluate_attachments(attachment_results, enabled)
    findings += evaluate_parser(parsed, enabled)
    intel_hits = []
    for att in attachment_results:
        vt = (att.get("scanners") or {}).get("virustotal") or {}
        if vt.get("malicious") and vt.get("status") == "ok":
            intel_hits.append({**vt, "target": att.get("sha256")})
    findings += evaluate_intel(intel_hits, enabled)
    findings += evaluate_correlation(findings, enabled)

    parser_unreliable = (not parsed.parse_ok) or (len(parsed.missing_fields) >= 2 and not attachment_results and not url_results)
    scored = score_and_classify(findings, parser_unreliable)
    findings = scored["deduped_findings"]
    iocs = extract_iocs(parsed, url_results, attachment_results, findings)
    body_excerpt = (parsed.body_text or "")[: settings.max_body_chars]
    ml = predict_optional(parsed, url_results, attachment_results, findings)

    summary = (
        f"Classified as {scored['classification']} with risk score {scored['risk_score']}. "
        f"{scored['explanation']}"
    )
    record = {
        "id": str(uuid.uuid4()),
        "analysis_type": analysis_type,
        "original_filename": original_filename,
        "input_hash": parsed.raw_hash,
        "classification": scored["classification"],
        "risk_score": scored["risk_score"],
        "severity": scored["severity"],
        "evidence_strength": scored["evidence_strength"],
        "explanation": scored["explanation"],
        "recommended_action": scored["recommended_action"],
        "limitations": scored["limitations"],
        "summary": summary,
        "parser_warnings": parsed.warnings,
        "header_analysis": _header_block(parsed),
        "body_analysis": {
            "text": body_excerpt,
            "html_present": parsed.html_present,
            "html_rendered": False,
            "note": "Untrusted HTML is never rendered in the trusted UI. Only stripped text is shown.",
        },
        "url_analysis": url_results,
        "attachment_analysis": [
            {k: v for k, v in item.items() if k != "payload"} for item in attachment_results
        ],
        "findings": findings,
        "indicators": iocs,
        "ml": ml,
        "integrations": {
            "virustotal_configured": bool(get_settings().virustotal_api_key),
            "clamav_enabled": bool(get_settings().clamav_enabled),
            "local_hash_source": "local-test-indicator-list",
        },
        "app_version": settings.app_version,
    }
    analysis = persist_analysis(db, record)
    return _public_result(analysis)


def analyze_email_file(db: Session, data: bytes, filename: str) -> dict[str, Any]:
    parsed = parse_email_bytes(data, filename)
    return analyze_parsed_email(db, parsed, "email_file", filename)


def analyze_raw_email(db: Session, raw: str) -> dict[str, Any]:
    parsed = parse_email_text(raw)
    return analyze_parsed_email(db, parsed, "raw_email", "pasted.eml")


def analyze_url_only(db: Session, url: str) -> dict[str, Any]:
    settings = get_settings()
    enabled = _enabled_map(db)
    url_results = [analyze_url(url)]
    findings = evaluate_urls(url_results, enabled)
    findings += evaluate_correlation(findings, enabled)
    scored = score_and_classify(findings, parser_unreliable=False)
    findings = scored["deduped_findings"]
    iocs = extract_iocs(None, url_results, [], findings)
    record = {
        "id": str(uuid.uuid4()),
        "analysis_type": "url",
        "original_filename": None,
        "input_hash": sha256_text(url.strip()),
        "classification": scored["classification"],
        "risk_score": scored["risk_score"],
        "severity": scored["severity"],
        "evidence_strength": scored["evidence_strength"],
        "explanation": scored["explanation"],
        "recommended_action": scored["recommended_action"],
        "limitations": scored["limitations"] + ["URL destinations are never visited by this analyzer."],
        "summary": f"URL classified as {scored['classification']} with score {scored['risk_score']}.",
        "parser_warnings": [],
        "header_analysis": {},
        "body_analysis": {"text": "", "html_present": False, "html_rendered": False},
        "url_analysis": url_results,
        "attachment_analysis": [],
        "findings": findings,
        "indicators": iocs,
        "ml": predict_optional(None, url_results, [], findings),
        "integrations": {"virustotal_configured": bool(settings.virustotal_api_key)},
        "app_version": settings.app_version,
    }
    analysis = persist_analysis(db, record)
    return _public_result(analysis)


def analyze_attachment_only(db: Session, filename: str, content_type: str, payload: bytes) -> dict[str, Any]:
    settings = get_settings()
    enabled = _enabled_map(db)
    known = local_malicious_hashes()
    attachment_results = [analyze_attachment(filename, content_type, payload, known)]
    _scan_attachments(attachment_results, [payload])
    findings = evaluate_attachments(attachment_results, enabled)
    intel_hits = []
    vt = (attachment_results[0].get("scanners") or {}).get("virustotal") or {}
    if vt.get("malicious") and vt.get("status") == "ok":
        intel_hits.append({**vt, "target": attachment_results[0]["sha256"]})
    findings += evaluate_intel(intel_hits, enabled)
    findings += evaluate_correlation(findings, enabled)
    scored = score_and_classify(findings, parser_unreliable=False)
    findings = scored["deduped_findings"]
    iocs = extract_iocs(None, [], attachment_results, findings)
    record = {
        "id": str(uuid.uuid4()),
        "analysis_type": "attachment",
        "original_filename": filename,
        "input_hash": sha256_bytes(payload),
        "classification": scored["classification"],
        "risk_score": scored["risk_score"],
        "severity": scored["severity"],
        "evidence_strength": scored["evidence_strength"],
        "explanation": scored["explanation"],
        "recommended_action": scored["recommended_action"],
        "limitations": scored["limitations"],
        "summary": f"Attachment classified as {scored['classification']} with score {scored['risk_score']}.",
        "parser_warnings": [],
        "header_analysis": {},
        "body_analysis": {"text": "", "html_present": False, "html_rendered": False},
        "url_analysis": [],
        "attachment_analysis": attachment_results,
        "findings": findings,
        "indicators": iocs,
        "ml": predict_optional(None, [], attachment_results, findings),
        "integrations": {
            "virustotal_configured": bool(settings.virustotal_api_key),
            "clamav_enabled": bool(settings.clamav_enabled),
        },
        "app_version": settings.app_version,
    }
    analysis = persist_analysis(db, record)
    return _public_result(analysis)
