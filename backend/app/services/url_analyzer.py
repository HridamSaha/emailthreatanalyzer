from __future__ import annotations

import ipaddress
import re
from urllib.parse import unquote, urlparse

SHORTENERS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "ow.ly",
    "is.gd",
    "buff.ly",
    "rebrand.ly",
    "cutt.ly",
    "tiny.cc",
    "rb.gy",
    "shorturl.at",
}

SUSPICIOUS_HOST_TOKENS = (
    "login",
    "secure",
    "verify",
    "update",
    "account",
    "support",
    "billing",
    "unlock",
    "reset",
)

LOOKALIKE_BRANDS = (
    "paypal",
    "microsoft",
    "apple",
    "google",
    "amazon",
    "outlook",
    "office365",
    "bankofamerica",
    "wellsfargo",
)


def _is_ip(host: str) -> bool:
    value = host.strip("[]")
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _registered_like(host: str) -> str:
    parts = [item for item in host.lower().split(".") if item]
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return host.lower()


def analyze_url(url: str, visible_text: str | None = None) -> dict:
    original = url.strip()
    findings: list[str] = []
    triggered: list[str] = []
    score = 0
    parsed = urlparse(original)
    host = (parsed.hostname or "").lower()
    scheme = (parsed.scheme or "").lower()
    normalized = original
    try:
        if parsed.scheme and parsed.netloc:
            normalized = parsed.geturl()
    except Exception:
        normalized = original

    ip_host = bool(host and _is_ip(host))
    userinfo = bool(parsed.username or parsed.password)
    punycode = "xn--" in host
    shortener = host in SHORTENERS or host.endswith(tuple("." + item for item in SHORTENERS))
    unusual_port = bool(parsed.port and parsed.port not in {80, 443, 8080})
    labels = [item for item in host.split(".") if item]
    excessive_labels = len(labels) >= 5
    long_host = len(host) >= 40
    percent = bool(re.search(r"%[0-9a-fA-F]{2}", original))
    decoded_once = unquote(original)
    layered_encoding = decoded_once != original and "%" in decoded_once
    lexical = any(token in host for token in SUSPICIOUS_HOST_TOKENS)
    lookalike = False
    for brand in LOOKALIKE_BRANDS:
        if brand in host.replace("-", "") and brand not in _registered_like(host).replace("-", ""):
            lookalike = True

    mismatch = False
    if visible_text:
        text = visible_text.strip()
        if re.match(r"(?i)^https?://", text) or "." in text:
            visible_host = urlparse(text if "://" in text else "http://" + text).hostname or ""
            if visible_host and host and visible_host.lower() != host:
                mismatch = True

    if ip_host:
        findings.append("Host is a literal IP address rather than a domain name.")
        triggered.append("URL-003")
        score += 10
    if userinfo:
        findings.append("URL contains a userinfo field that can disguise the real host.")
        triggered.append("URL-001")
        score += 8
    if punycode:
        findings.append("Hostname uses punycode/IDN encoding (xn--).")
        triggered.append("URL-001")
        score += 6
    if shortener:
        findings.append("Hostname matches a known URL shortener.")
        triggered.append("URL-001")
        score += 6
    if unusual_port:
        findings.append(f"URL uses an unusual port ({parsed.port}).")
        triggered.append("URL-001")
        score += 4
    if excessive_labels or long_host:
        findings.append("Hostname is unusually long or has excessive labels.")
        triggered.append("URL-001")
        score += 4
    if layered_encoding or (percent and ("@" in original or "http" in decoded_once.lower())):
        findings.append("Suspicious percent-encoding or nested URL encoding was observed.")
        triggered.append("URL-001")
        score += 5
    if lexical or lookalike:
        findings.append("Hostname contains login/verify tokens or lookalike-brand structure.")
        triggered.append("URL-001")
        score += 5
    if mismatch:
        findings.append("Visible link text host does not match the actual href host.")
        triggered.append("URL-002")
        score += 12
    if scheme not in {"http", "https", "ftp", ""}:
        findings.append(f"Uncommon URL scheme: {scheme or 'missing'}.")
        triggered.append("URL-001")
        score += 4

    triggered = sorted(set(triggered))
    return {
        "original_url": original,
        "normalized_url": normalized,
        "hostname": host,
        "domain": _registered_like(host) if host and not ip_host else host,
        "scheme": scheme or "unspecified",
        "ip_host": ip_host,
        "userinfo_present": userinfo,
        "unusual_port": unusual_port,
        "port": parsed.port,
        "punycode": punycode,
        "shortener": shortener,
        "suspicious_encoding": layered_encoding or percent,
        "link_text_mismatch": mismatch,
        "visible_text": visible_text or "",
        "findings": findings,
        "triggered_rules": triggered,
        "risk_contribution": min(score, 25),
        "notes": "HTTPS is not treated as proof of legitimacy. The destination was not visited.",
    }


def analyze_urls(urls: list[str], html_links: list[dict[str, str]] | None = None) -> list[dict]:
    text_by_href = {}
    for item in html_links or []:
        text_by_href[item.get("href", "")] = item.get("text", "")
    results = []
    seen: set[str] = set()
    for url in urls:
        if url in seen:
            continue
        seen.add(url)
        results.append(analyze_url(url, text_by_href.get(url)))
    for href, text in text_by_href.items():
        if href not in seen and href.lower().startswith(("http://", "https://")):
            seen.add(href)
            results.append(analyze_url(href, text))
    return results
