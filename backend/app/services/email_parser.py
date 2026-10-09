from __future__ import annotations

import re
from dataclasses import dataclass, field
from email import policy
from email.header import decode_header, make_header
from email.message import EmailMessage, Message
from email.parser import BytesParser, Parser
from email.utils import getaddresses, parseaddr
from html.parser import HTMLParser
from typing import Any

from app.services.hash_service import sha256_bytes

URL_RE = re.compile(r"""(?i)\b((?:https?|ftp)://[^\s<>"'\)\]]+)""")
AUTH_RE = re.compile(
    r"(?i)\b(spf|dkim|dmarc)\s*=\s*([a-z0-9_-]+)",
)


class _HTMLExtractor(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.parts: list[str] = []
        self.links: list[tuple[str, str]] = []
        self._current_href: str | None = None
        self._current_text: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attr_map = {key.lower(): (value or "") for key, value in attrs}
        if tag == "a" and attr_map.get("href"):
            self._current_href = attr_map["href"]
            self._current_text = []
        if tag in {"p", "br", "div", "tr"}:
            self.parts.append("\n")

    def handle_endtag(self, tag: str) -> None:
        if tag == "a" and self._current_href is not None:
            text = "".join(self._current_text).strip()
            self.links.append((text, self._current_href))
            self.parts.append(text or self._current_href)
            self._current_href = None
            self._current_text = []

    def handle_data(self, data: str) -> None:
        if self._current_href is not None:
            self._current_text.append(data)
        else:
            self.parts.append(data)


def decode_header_value(value: str | None) -> str:
    if not value:
        return ""
    try:
        return str(make_header(decode_header(value)))
    except Exception:
        return value


def mailbox_parts(value: str | None) -> tuple[str, str, str]:
    display, address = parseaddr(value or "")
    address = address.strip().lower()
    domain = address.split("@", 1)[1] if "@" in address else ""
    return display, address, domain.lower()


def extract_auth_claims(headers: dict[str, Any]) -> dict[str, dict[str, str]]:
    claims: dict[str, dict[str, str]] = {}
    blobs = []
    for key in ("authentication-results", "received-spf", "arc-authentication-results"):
        item = headers.get(key)
        if not item:
            continue
        if isinstance(item, list):
            blobs.extend(item)
        else:
            blobs.append(item)
    for blob in blobs:
        for match in AUTH_RE.finditer(blob):
            mechanism = match.group(1).lower()
            result = match.group(2).lower()
            claims[mechanism] = {
                "result": result,
                "provenance": "message_header_unverified",
                "source_header": "Authentication-Results or Received-SPF as supplied",
            }
    return claims


@dataclass
class ParsedAttachment:
    filename: str
    content_type: str
    payload: bytes
    content_id: str = ""
    content_disposition: str = ""


@dataclass
class ParsedEmail:
    headers: dict[str, Any]
    from_raw: str
    from_display: str
    from_address: str
    from_domain: str
    reply_to_raw: str
    reply_to_address: str
    reply_to_domain: str
    return_path_raw: str
    return_path_address: str
    sender_raw: str
    subject: str
    date: str
    message_id: str
    body_text: str
    html_present: bool
    urls: list[str]
    html_links: list[dict[str, str]]
    attachments: list[ParsedAttachment]
    warnings: list[str] = field(default_factory=list)
    parse_ok: bool = True
    raw_hash: str = ""
    auth_claims: dict[str, dict[str, str]] = field(default_factory=dict)
    missing_fields: list[str] = field(default_factory=list)


def _safe_get_payload(part: Message) -> bytes:
    payload = part.get_payload(decode=True)
    if payload is None:
        raw = part.get_payload()
        if isinstance(raw, str):
            return raw.encode("utf-8", errors="replace")
        return b""
    return payload


def _header_map(message: Message) -> dict[str, Any]:
    collected: dict[str, Any] = {}
    for key, value in message.items():
        decoded = decode_header_value(value)
        existing = collected.get(key.lower())
        if existing is None:
            collected[key.lower()] = decoded
        elif isinstance(existing, list):
            existing.append(decoded)
        else:
            collected[key.lower()] = [existing, decoded]
    return collected


def _extract_bodies(message: Message) -> tuple[str, bool, list[tuple[str, str]], list[str]]:
    text_parts: list[str] = []
    html_parts: list[str] = []
    links: list[tuple[str, str]] = []
    warnings: list[str] = []
    html_present = False

    for part in message.walk():
        if part.is_multipart():
            continue
        disposition = (part.get_content_disposition() or "").lower()
        content_type = (part.get_content_type() or "").lower()
        if disposition == "attachment":
            continue
        try:
            payload = _safe_get_payload(part)
            charset = part.get_content_charset() or "utf-8"
            decoded = payload.decode(charset, errors="replace")
        except Exception:
            warnings.append("Failed to decode a MIME text part; replaced undecodable bytes.")
            continue
        if content_type == "text/plain":
            text_parts.append(decoded)
        elif content_type == "text/html":
            html_present = True
            html_parts.append(decoded)
            extractor = _HTMLExtractor()
            try:
                extractor.feed(decoded)
                extractor.close()
                links.extend(extractor.links)
                text_parts.append("".join(extractor.parts))
            except Exception:
                warnings.append("HTML body could not be fully stripped; raw markup was discarded.")
    body = "\n".join(item.strip() for item in text_parts if item.strip())
    if not body and html_parts:
        warnings.append("Message was HTML-only; displayed text is a stripped extraction, not rendered HTML.")
    return body, html_present, links, warnings


def _extract_attachments(message: Message) -> list[ParsedAttachment]:
    attachments: list[ParsedAttachment] = []
    for part in message.walk():
        if part.is_multipart():
            continue
        disposition = (part.get_content_disposition() or "").lower()
        filename = part.get_filename()
        content_type = part.get_content_type() or "application/octet-stream"
        if disposition == "attachment" or filename:
            payload = _safe_get_payload(part)
            attachments.append(
                ParsedAttachment(
                    filename=decode_header_value(filename) or "unnamed",
                    content_type=content_type,
                    payload=payload,
                    content_id=part.get("Content-ID", ""),
                    content_disposition=disposition or "attachment",
                )
            )
    return attachments


def parse_email_bytes(data: bytes, source_name: str = "message.eml") -> ParsedEmail:
    warnings: list[str] = []
    raw_hash = sha256_bytes(data)
    try:
        message = BytesParser(policy=policy.default).parsebytes(data)
    except Exception:
        try:
            message = BytesParser(policy=policy.compat32).parsebytes(data)
            warnings.append("Parsed with compatibility policy because the message was malformed.")
        except Exception as exc:
            return ParsedEmail(
                headers={},
                from_raw="",
                from_display="",
                from_address="",
                from_domain="",
                reply_to_raw="",
                reply_to_address="",
                reply_to_domain="",
                return_path_raw="",
                return_path_address="",
                sender_raw="",
                subject="",
                date="",
                message_id="",
                body_text="",
                html_present=False,
                urls=[],
                html_links=[],
                attachments=[],
                warnings=[f"Message could not be parsed as RFC-compatible email: {exc.__class__.__name__}"],
                parse_ok=False,
                raw_hash=raw_hash,
            )
    return _finalize(message, warnings, raw_hash, source_name)


def parse_email_text(raw: str) -> ParsedEmail:
    return parse_email_bytes(raw.encode("utf-8", errors="replace"), source_name="pasted.eml")


def _finalize(message: Message, warnings: list[str], raw_hash: str, source_name: str) -> ParsedEmail:
    headers = _header_map(message)
    from_raw = decode_header_value(message.get("From", ""))
    reply_to_raw = decode_header_value(message.get("Reply-To", ""))
    return_path_raw = decode_header_value(message.get("Return-Path", ""))
    sender_raw = decode_header_value(message.get("Sender", ""))
    subject = decode_header_value(message.get("Subject", ""))
    date = decode_header_value(message.get("Date", ""))
    message_id = decode_header_value(message.get("Message-ID", ""))

    from_display, from_address, from_domain = mailbox_parts(from_raw)
    _, reply_to_address, reply_to_domain = mailbox_parts(reply_to_raw)
    _, return_path_address, _ = mailbox_parts(return_path_raw)

    body_text, html_present, html_links, body_warnings = _extract_bodies(message)
    warnings.extend(body_warnings)
    attachments = _extract_attachments(message)

    urls = URL_RE.findall(body_text)
    for _text, href in html_links:
        if href.lower().startswith(("http://", "https://", "ftp://")):
            urls.append(href)
    # preserve order, drop fragments-only junk
    seen: set[str] = set()
    unique_urls: list[str] = []
    for url in urls:
        cleaned = url.rstrip(".,;:)")
        if cleaned not in seen:
            seen.add(cleaned)
            unique_urls.append(cleaned)

    missing: list[str] = []
    if not from_address:
        missing.append("From")
        warnings.append("From header is missing or unusable.")
    if not subject:
        missing.append("Subject")
        warnings.append("Subject header is missing.")
    if not body_text.strip():
        missing.append("Body")
        warnings.append("No readable text body was extracted.")
    if not date:
        warnings.append("Date header is missing.")
    if isinstance(headers.get("from"), list) or len(getaddresses([from_raw])) > 1:
        warnings.append("Multiple From identities were observed.")

    links = [{"text": text, "href": href} for text, href in html_links]

    parse_ok = True
    if not from_address and not body_text and not attachments:
        parse_ok = False
        warnings.append("Critical evidence could not be extracted from this input.")

    return ParsedEmail(
        headers=headers,
        from_raw=from_raw,
        from_display=from_display,
        from_address=from_address,
        from_domain=from_domain,
        reply_to_raw=reply_to_raw,
        reply_to_address=reply_to_address,
        reply_to_domain=reply_to_domain,
        return_path_raw=return_path_raw,
        return_path_address=return_path_address,
        sender_raw=sender_raw,
        subject=subject,
        date=date,
        message_id=message_id,
        body_text=body_text[:200_000],
        html_present=html_present,
        urls=unique_urls,
        html_links=links,
        attachments=attachments,
        warnings=warnings,
        parse_ok=parse_ok,
        raw_hash=raw_hash,
        auth_claims=extract_auth_claims(headers),
        missing_fields=missing,
    )
