from __future__ import annotations

import re

from app.core.rules_catalog import catalog_by_id
from app.services.email_parser import ParsedEmail

CREDENTIAL_PATTERNS = [
    r"\bpassword\b",
    r"\bpasswd\b",
    r"\bone[-\s]?time (?:code|password|passcode)\b",
    r"\bverification code\b",
    r"\botp\b",
    r"\blogin (?:details|credentials|information)\b",
    r"\bconfirm (?:your )?(?:account|identity|password)\b",
    r"\bupdate your (?:password|account)\b",
    r"\b2fa\b",
    r"\bsecurity code\b",
]

URGENCY_PATTERNS = [
    r"\burgent\b",
    r"\bimmediately\b",
    r"\bact now\b",
    r"\bwithin \d+ hours\b",
    r"\baccount will be (?:closed|suspended|terminated)\b",
    r"\bfinal notice\b",
    r"\bexpire",
]

FINANCIAL_PATTERNS = [
    r"\bgift card\b",
    r"\bwire transfer\b",
    r"\bbank transfer\b",
    r"\bpayment\b",
    r"\binvoice\b",
    r"\bbitcoin\b",
    r"\bcrypto",
    r"\bwestern union\b",
    r"\bunpaid\b",
    r"\brefund\b",
]

LOOKALIKE_SENDER = (
    "paypal",
    "microsoft",
    "appleid",
    "google",
    "amazon",
    "outlook",
    "office365",
    "bank",
)


def _enabled(rule_id: str, enabled_map: dict[str, bool]) -> bool:
    return enabled_map.get(rule_id, True)


def _finding(rule_id: str, evidence: str, explanation: str, score: int, kind: str = "heuristic") -> dict:
    meta = catalog_by_id()[rule_id]
    return {
        "rule_id": rule_id,
        "rule_name": meta["name"],
        "severity": meta["severity"],
        "evidence": evidence,
        "explanation": explanation,
        "score_contribution": score,
        "suggested_response": meta["suggested_response"],
        "evidence_kind": kind,
        "category": meta["category"],
    }


def _search(patterns: list[str], text: str) -> list[str]:
    hits = []
    for pattern in patterns:
        match = re.search(pattern, text, flags=re.IGNORECASE)
        if match:
            hits.append(match.group(0))
    return hits


def evaluate_sender(parsed: ParsedEmail, enabled: dict[str, bool]) -> list[dict]:
    findings: list[dict] = []
    if _enabled("EMAIL-001", enabled):
        identities = [item for item in [parsed.from_address, parsed.reply_to_address, parsed.return_path_address] if item]
        unique = {item.lower() for item in identities}
        if parsed.from_address and parsed.reply_to_address and parsed.from_address != parsed.reply_to_address:
            findings.append(
                _finding(
                    "EMAIL-001",
                    f"From={parsed.from_address}; Reply-To={parsed.reply_to_address}",
                    "From and Reply-To mailbox identities do not match.",
                    15,
                    "observed",
                )
            )
        elif parsed.from_address and parsed.return_path_address and parsed.from_address != parsed.return_path_address:
            findings.append(
                _finding(
                    "EMAIL-001",
                    f"From={parsed.from_address}; Return-Path={parsed.return_path_address}",
                    "From and Return-Path mailbox identities do not match.",
                    15,
                    "observed",
                )
            )
        elif len(unique) > 1:
            findings.append(
                _finding(
                    "EMAIL-001",
                    "; ".join(sorted(unique)),
                    "Sender-related identities are inconsistent.",
                    15,
                    "observed",
                )
            )

    if _enabled("EMAIL-002", enabled) and parsed.from_domain:
        domain = parsed.from_domain
        labels = domain.split(".")
        numeric = bool(re.search(r"\d{4,}", domain))
        lookalike = any(brand in domain.replace("-", "") and brand not in domain for brand in LOOKALIKE_SENDER)
        hyphenated_brand = any(brand in domain and "-" in domain for brand in LOOKALIKE_SENDER)
        unusual_tld = domain.endswith((".xyz", ".top", ".click", ".zip", ".mov", ".country", ".gq", ".tk"))
        if numeric or lookalike or hyphenated_brand or unusual_tld or len(labels) >= 4:
            findings.append(
                _finding(
                    "EMAIL-002",
                    f"Sender domain={domain}",
                    "Sender domain has deceptive or unusual structural characteristics.",
                    10,
                    "heuristic",
                )
            )
    return findings


def evaluate_body(parsed: ParsedEmail, enabled: dict[str, bool]) -> list[dict]:
    findings: list[dict] = []
    text = parsed.body_text or ""
    if _enabled("EMAIL-003", enabled):
        hits = _search(CREDENTIAL_PATTERNS, text)
        if hits:
            findings.append(
                _finding(
                    "EMAIL-003",
                    ", ".join(hits[:6]),
                    "Message language requests credentials, codes, or login confirmation.",
                    15,
                    "observed",
                )
            )
    if _enabled("EMAIL-004", enabled):
        urgency = _search(URGENCY_PATTERNS, text)
        financial = _search(FINANCIAL_PATTERNS, text)
        if urgency and financial:
            findings.append(
                _finding(
                    "EMAIL-004",
                    f"urgency={', '.join(urgency[:4])}; financial={', '.join(financial[:4])}",
                    "Urgency language is combined with payment or financial pressure.",
                    12,
                    "heuristic",
                )
            )
    return findings


def evaluate_urls(url_results: list[dict], enabled: dict[str, bool]) -> list[dict]:
    findings: list[dict] = []
    for item in url_results:
        rules = item.get("triggered_rules") or []
        if "URL-003" in rules and _enabled("URL-003", enabled):
            findings.append(
                _finding(
                    "URL-003",
                    item["original_url"],
                    "URL host is an IP address.",
                    10,
                    "observed",
                )
            )
        if "URL-002" in rules and _enabled("URL-002", enabled):
            findings.append(
                _finding(
                    "URL-002",
                    f"text={item.get('visible_text')}; href={item['original_url']}",
                    "Visible link text does not match the actual destination host.",
                    12,
                    "observed",
                )
            )
        if "URL-001" in rules and _enabled("URL-001", enabled):
            findings.append(
                _finding(
                    "URL-001",
                    item["original_url"],
                    "; ".join(item.get("findings") or ["Suspicious URL structure."]),
                    10,
                    "heuristic",
                )
            )
    return _dedupe_findings(findings)


def evaluate_attachments(attachment_results: list[dict], enabled: dict[str, bool]) -> list[dict]:
    findings: list[dict] = []
    for item in attachment_results:
        rules = item.get("triggered_rules") or []
        if "ATTACH-001" in rules and _enabled("ATTACH-001", enabled):
            findings.append(
                _finding(
                    "ATTACH-001",
                    f"{item['filename']} ({item.get('extension')}, {item.get('detected_type')})",
                    "; ".join(item.get("findings") or ["Risky attachment characteristics."]),
                    20,
                    "heuristic",
                )
            )
        if "ATTACH-002" in rules and _enabled("ATTACH-002", enabled):
            findings.append(
                _finding(
                    "ATTACH-002",
                    f"{item['filename']}: mime={item.get('reported_mime')} detected={item.get('detected_type')}",
                    "Extension, MIME type, and file signature disagree.",
                    18,
                    "observed",
                )
            )
        if "ATTACH-003" in rules and _enabled("ATTACH-003", enabled):
            match = item.get("intel_match") or {}
            findings.append(
                _finding(
                    "ATTACH-003",
                    f"sha256={item.get('sha256')} source={match.get('source')}",
                    "SHA-256 matched a documented indicator from a configured source.",
                    50,
                    "intelligence",
                )
            )
    return _dedupe_findings(findings)


def evaluate_parser(parsed: ParsedEmail, enabled: dict[str, bool]) -> list[dict]:
    if not _enabled("PARSER-001", enabled):
        return []
    if parsed.parse_ok and not parsed.warnings:
        return []
    if not parsed.warnings and parsed.parse_ok:
        return []
    critical = (not parsed.parse_ok) or len(parsed.missing_fields) >= 2
    if not critical and parsed.parse_ok:
        # record only when extraction is materially incomplete
        if not parsed.missing_fields:
            return []
    return [
        _finding(
            "PARSER-001",
            "; ".join(parsed.warnings[:8]) or "Incomplete extraction",
            "The message was malformed or missing fields needed for a reliable assessment.",
            5 if parsed.parse_ok else 8,
            "observed",
        )
    ]


def evaluate_correlation(findings: list[dict], enabled: dict[str, bool]) -> list[dict]:
    if not _enabled("CORR-001", enabled):
        return []
    families = {item["rule_id"].split("-")[0] for item in findings if item["rule_id"] not in {"CORR-001", "PARSER-001"}}
    independent = {item["category"] for item in findings if item["rule_id"] not in {"CORR-001", "PARSER-001"}}
    if len(independent) >= 2 or len(families) >= 2:
        return [
            _finding(
                "CORR-001",
                f"independent_categories={', '.join(sorted(independent))}",
                "Multiple independent indicator categories were observed together.",
                10,
                "heuristic",
            )
        ]
    return []


def evaluate_intel(intel_hits: list[dict], enabled: dict[str, bool]) -> list[dict]:
    if not _enabled("INTEL-001", enabled):
        return []
    out = []
    for hit in intel_hits:
        if hit.get("malicious") and hit.get("status") == "ok":
            out.append(
                _finding(
                    "INTEL-001",
                    f"provider={hit.get('provider')} target={hit.get('target')}",
                    "Configured intelligence provider reported a malicious reputation match.",
                    25,
                    "intelligence",
                )
            )
    return out


def _dedupe_findings(findings: list[dict]) -> list[dict]:
    seen: set[tuple[str, str]] = set()
    unique = []
    for item in findings:
        key = (item["rule_id"], item["evidence"][:180])
        if key in seen:
            continue
        seen.add(key)
        unique.append(item)
    return unique
