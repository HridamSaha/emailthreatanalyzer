from __future__ import annotations

from app.core.config import get_settings


def score_and_classify(findings: list[dict], parser_unreliable: bool) -> dict:
    settings = get_settings()
    # Avoid counting the same rule repeatedly; keep the highest contribution.
    best: dict[str, dict] = {}
    for item in findings:
        current = best.get(item["rule_id"])
        if current is None or item["score_contribution"] > current["score_contribution"]:
            best[item["rule_id"]] = item
    capped_findings = list(best.values())
    raw = sum(item["score_contribution"] for item in capped_findings)
    score = max(0, min(100, raw))

    strong = any(item["rule_id"] in {"ATTACH-003", "INTEL-001"} and item["evidence_kind"] == "intelligence" for item in capped_findings)
    independent = {item["category"] for item in capped_findings if item["rule_id"] not in {"CORR-001", "PARSER-001"}}
    weak_only = len(capped_findings) == 1 and not strong

    threat_findings = [item for item in capped_findings if item["rule_id"] != "PARSER-001"]

    if parser_unreliable and not strong:
        classification = "manual_review"
        severity = "medium"
        evidence_strength = "insufficient"
        explanation = (
            "Critical evidence could not be extracted reliably. The case is routed to Manual Review "
            "instead of treating missing data as safety or as confirmed malice."
        )
        action = "Retain the original artifact and perform a manual analyst review. Do not execute content."
    elif strong or (score >= 60 and len(independent) >= 2):
        classification = "malicious"
        severity = "high"
        evidence_strength = "strong" if strong else "moderate"
        explanation = (
            "A trusted threat intelligence match was identified."
            if strong
            else "The risk score exceeded the high-risk threshold with multiple independent signals."
        )
        action = "Quarantine the message, do not open attachments or URLs, and escalate according to policy."
    elif score >= 60:
        classification = "suspicious"
        severity = "high"
        evidence_strength = "limited"
        explanation = (
            "The numerical score reached the high band, but a single weak anomaly is not enough "
            "for a Malicious label under the project's classification safeguards."
        )
        action = "Treat as suspicious. Seek corroborating evidence before a malicious determination."
    elif score >= settings.score_safe_max + 1 or bool(threat_findings):
        classification = "suspicious"
        severity = "medium"
        evidence_strength = "moderate" if len(independent) >= 2 else "limited"
        explanation = "One or more heuristics indicate suspicious characteristics that justify analyst review."
        action = "Do not click links or open attachments. Verify the sender through a known channel."
    else:
        classification = "safe"
        severity = "low"
        evidence_strength = "limited"
        explanation = (
            "No configured rules produced enough evidence to raise the score above the low-risk band. "
            "A low score is not a guarantee of safety."
        )
        action = "No immediate threat indicators were found. Continue standard handling policies."

    if weak_only and classification == "malicious":
        classification = "suspicious"
        evidence_strength = "limited"

    limitations = [
        "Static analysis does not execute code, macros, or visit URLs.",
        "SPF/DKIM/DMARC values are reported only when present in supplied headers and are not independently verified.",
        "Score thresholds are project defaults (0-29 Safe, 30-59 Suspicious, 60-100 Malicious) and are not a calibrated probability.",
        "Optional scanners contribute only when explicitly configured.",
    ]
    return {
        "risk_score": score,
        "classification": classification,
        "severity": severity,
        "evidence_strength": evidence_strength,
        "explanation": explanation,
        "recommended_action": action,
        "limitations": limitations,
        "independent_categories": sorted(independent),
        "strong_intelligence": strong,
        "deduped_findings": capped_findings,
    }
