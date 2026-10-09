from __future__ import annotations

import ipaddress
from urllib.parse import urlparse

from app.services.email_parser import ParsedEmail


def _ip_from_host(host: str) -> str | None:
    value = host.strip("[]")
    try:
        ipaddress.ip_address(value)
        return value
    except ValueError:
        return None


def extract_iocs(
    parsed: ParsedEmail | None,
    url_results: list[dict],
    attachment_results: list[dict],
    findings: list[dict],
) -> list[dict]:
    iocs: list[dict] = []

    def add(kind: str, value: str, provenance: str, status: str = "unverified", notes: str = "") -> None:
        if not value:
            return
        iocs.append(
            {
                "indicator_type": kind,
                "value": value,
                "provenance": provenance,
                "verification_status": status,
                "notes": notes,
            }
        )

    if parsed:
        add("email_address", parsed.from_address, "email_from")
        add("domain", parsed.from_domain, "email_from")
        add("email_address", parsed.reply_to_address, "email_reply_to")
        if parsed.subject:
            add("subject", parsed.subject[:300], "email_subject", notes="Subject is context, not a confirmed IoC.")

    for url in url_results:
        add("url", url.get("original_url", ""), "extracted_url")
        host = url.get("hostname") or ""
        if host:
            ip_value = _ip_from_host(host)
            if ip_value:
                add("ip", ip_value, "url_host")
            else:
                add("domain", url.get("domain") or host, "url_host")

    for att in attachment_results:
        add("filename", att.get("filename", ""), "attachment")
        digest = att.get("sha256")
        status = "matched_configured_source" if att.get("intel_match") else "unverified"
        notes = ""
        if att.get("intel_match"):
            notes = f"Matched {att['intel_match'].get('source')}. Test or configured source only unless independently verified."
        add("sha256", digest, "attachment_hash", status=status, notes=notes)

    for finding in findings:
        add("rule_id", finding.get("rule_id", ""), "detection_rule", status="observed")

    # de-dupe
    seen: set[tuple[str, str]] = set()
    unique = []
    for item in iocs:
        key = (item["indicator_type"], item["value"].lower())
        if not item["value"] or key in seen:
            continue
        seen.add(key)
        unique.append(item)
    return unique
