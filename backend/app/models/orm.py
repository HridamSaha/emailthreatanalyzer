from datetime import datetime, timezone

from sqlalchemy import JSON, Boolean, DateTime, Float, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Analysis(Base):
    __tablename__ = "analyses"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    analysis_type: Mapped[str] = mapped_column(String(32), index=True)
    original_filename: Mapped[str | None] = mapped_column(String(255), nullable=True, index=True)
    input_hash: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    classification: Mapped[str] = mapped_column(String(32), index=True)
    risk_score: Mapped[int] = mapped_column(Integer, index=True)
    severity: Mapped[str] = mapped_column(String(32), index=True)
    status: Mapped[str] = mapped_column(String(32), default="completed")
    summary: Mapped[str] = mapped_column(Text, default="")
    subject: Mapped[str | None] = mapped_column(String(512), nullable=True, index=True)
    sender_domain: Mapped[str | None] = mapped_column(String(255), nullable=True, index=True)
    evidence_strength: Mapped[str] = mapped_column(String(64), default="limited")
    recommended_action: Mapped[str] = mapped_column(Text, default="")
    limitations: Mapped[str] = mapped_column(Text, default="")
    parser_warnings: Mapped[list] = mapped_column(JSON, default=list)
    result_payload: Mapped[dict] = mapped_column(JSON, default=dict)
    persist_raw: Mapped[bool] = mapped_column(Boolean, default=False)
    raw_content: Mapped[str | None] = mapped_column(Text, nullable=True)

    findings: Mapped[list["DetectionFinding"]] = relationship(
        back_populates="analysis", cascade="all, delete-orphan"
    )
    indicators: Mapped[list["Indicator"]] = relationship(
        back_populates="analysis", cascade="all, delete-orphan"
    )


class DetectionFinding(Base):
    __tablename__ = "detection_findings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    analysis_id: Mapped[str] = mapped_column(String(36), ForeignKey("analyses.id"), index=True)
    rule_id: Mapped[str] = mapped_column(String(32), index=True)
    rule_name: Mapped[str] = mapped_column(String(128))
    severity: Mapped[str] = mapped_column(String(32))
    evidence: Mapped[str] = mapped_column(Text)
    explanation: Mapped[str] = mapped_column(Text)
    score_contribution: Mapped[int] = mapped_column(Integer, default=0)
    suggested_response: Mapped[str] = mapped_column(Text, default="")
    evidence_kind: Mapped[str] = mapped_column(String(32), default="heuristic")

    analysis: Mapped[Analysis] = relationship(back_populates="findings")


class Indicator(Base):
    __tablename__ = "indicators"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    analysis_id: Mapped[str] = mapped_column(String(36), ForeignKey("analyses.id"), index=True)
    indicator_type: Mapped[str] = mapped_column(String(32), index=True)
    value: Mapped[str] = mapped_column(String(1024), index=True)
    provenance: Mapped[str] = mapped_column(String(128), default="extracted")
    verification_status: Mapped[str] = mapped_column(String(32), default="unverified")
    notes: Mapped[str] = mapped_column(Text, default="")

    analysis: Mapped[Analysis] = relationship(back_populates="indicators")


class DetectionRule(Base):
    __tablename__ = "detection_rules"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    rule_id: Mapped[str] = mapped_column(String(32), unique=True, index=True)
    name: Mapped[str] = mapped_column(String(128))
    description: Mapped[str] = mapped_column(Text)
    category: Mapped[str] = mapped_column(String(32), index=True)
    severity: Mapped[str] = mapped_column(String(32))
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    parameters: Mapped[dict] = mapped_column(JSON, default=dict)
    logic_summary: Mapped[str] = mapped_column(Text, default="")
    default_score: Mapped[int] = mapped_column(Integer, default=10)


class AuditEvent(Base):
    __tablename__ = "audit_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    event_type: Mapped[str] = mapped_column(String(64), index=True)
    subject_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    outcome: Mapped[str] = mapped_column(String(32), default="success")
    details: Mapped[str] = mapped_column(Text, default="")
