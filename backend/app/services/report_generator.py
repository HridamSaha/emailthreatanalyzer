from __future__ import annotations

import csv
import io
from datetime import datetime, timezone

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle


NAVY = colors.HexColor("#0b1f3a")
BLUE = colors.HexColor("#1d4ed8")
LIGHT = colors.HexColor("#e8eef7")


def _p(text: str, style) -> Paragraph:
    safe = (
        (text or "")
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace("\n", "<br/>")
    )
    return Paragraph(safe, style)


def build_pdf(result: dict, app_name: str, app_version: str) -> bytes:
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        title="Email Threat Analysis Report",
        leftMargin=0.7 * inch,
        rightMargin=0.7 * inch,
        topMargin=0.6 * inch,
        bottomMargin=0.6 * inch,
    )
    styles = getSampleStyleSheet()
    title = ParagraphStyle("TitleNavy", parent=styles["Title"], textColor=NAVY, fontSize=16, spaceAfter=8)
    heading = ParagraphStyle("HeadNavy", parent=styles["Heading2"], textColor=BLUE, fontSize=12, spaceBefore=10)
    body = ParagraphStyle("BodySmall", parent=styles["Normal"], fontSize=9, leading=12)
    muted = ParagraphStyle("Muted", parent=styles["Normal"], fontSize=8, textColor=colors.HexColor("#475569"))

    story = [
        _p("Email Threat Analysis Report", title),
        _p(f"{app_name}  |  version {app_version}", muted),
        Spacer(1, 8),
        _p("1. Identification", heading),
        _p(
            f"Analysis ID: {result.get('id')}<br/>"
            f"Timestamp (UTC): {result.get('created_at')}<br/>"
            f"Input type: {result.get('analysis_type')}<br/>"
            f"Original filename: {result.get('original_filename') or 'n/a'}<br/>"
            f"Artifact SHA-256: {result.get('input_hash') or 'n/a'}",
            body,
        ),
        _p("2. Executive summary", heading),
        _p(result.get("summary") or "", body),
        _p("3. Classification", heading),
        _p(
            f"Classification: {result.get('classification')}<br/>"
            f"Risk score: {result.get('risk_score')} / 100<br/>"
            f"Severity: {result.get('severity')}<br/>"
            f"Evidence strength: {result.get('evidence_strength')}<br/>"
            f"Explanation: {result.get('explanation')}<br/>"
            f"Recommended action: {result.get('recommended_action')}",
            body,
        ),
    ]

    header = (result.get("header_analysis") or {})
    story += [
        _p("4. Header analysis", heading),
        _p(
            f"From: {header.get('from') or 'n/a'}<br/>"
            f"Reply-To: {header.get('reply_to') or 'n/a'}<br/>"
            f"Return-Path: {header.get('return_path') or 'n/a'}<br/>"
            f"Subject: {header.get('subject') or 'n/a'}<br/>"
            f"Date: {header.get('date') or 'n/a'}<br/>"
            f"Message-ID: {header.get('message_id') or 'n/a'}<br/>"
            f"Authentication claims (unverified headers): {header.get('auth_claims') or 'none present'}",
            body,
        ),
        _p("5. URL findings", heading),
    ]
    urls = result.get("url_analysis") or []
    if not urls:
        story.append(_p("No URLs were extracted.", body))
    for item in urls[:40]:
        story.append(
            _p(
                f"{item.get('original_url')}<br/>host={item.get('hostname')} rules={item.get('triggered_rules')}",
                body,
            )
        )

    story.append(_p("6. Attachment metadata", heading))
    atts = result.get("attachment_analysis") or []
    if not atts:
        story.append(_p("No attachments were inspected.", body))
    for item in atts[:30]:
        story.append(
            _p(
                f"{item.get('filename')} | {item.get('size_bytes')} bytes | SHA-256 {item.get('sha256')}<br/>"
                f"detected={item.get('detected_type')} mime={item.get('reported_mime')}",
                body,
            )
        )

    story.append(_p("7. Triggered detection rules", heading))
    findings = result.get("findings") or []
    if not findings:
        story.append(_p("No detection rules triggered.", body))
    for item in findings:
        story.append(
            _p(
                f"{item.get('rule_id')} {item.get('rule_name')} (+{item.get('score_contribution')})<br/>"
                f"Evidence: {item.get('evidence')}<br/>Reason: {item.get('explanation')}",
                body,
            )
        )

    story.append(_p("8. Indicators", heading))
    for item in (result.get("indicators") or [])[:80]:
        story.append(
            _p(
                f"{item.get('indicator_type')}: {item.get('value')} "
                f"[{item.get('verification_status')}, {item.get('provenance')}]",
                body,
            )
        )

    story += [
        _p("9. Limitations and missing evidence", heading),
        _p(" | ".join(result.get("limitations") or []), body),
        _p("; ".join(result.get("parser_warnings") or ["None recorded."]), body),
        _p("10. Tool and integration status", heading),
        _p(str(result.get("integrations") or {}), body),
        _p(
            "This report is produced by static analysis. It does not execute malware, visit URLs, "
            "or independently verify SPF/DKIM/DMARC unless those results were supplied in the message headers.",
            muted,
        ),
    ]
    doc.build(story)
    return buffer.getvalue()


def build_csv(result: dict) -> bytes:
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(["section", "field", "value"])
    writer.writerow(["summary", "id", result.get("id")])
    writer.writerow(["summary", "classification", result.get("classification")])
    writer.writerow(["summary", "risk_score", result.get("risk_score")])
    for item in result.get("findings") or []:
        writer.writerow(["finding", item.get("rule_id"), item.get("explanation")])
    for item in result.get("indicators") or []:
        writer.writerow(["indicator", item.get("indicator_type"), item.get("value")])
    return buffer.getvalue().encode("utf-8")
