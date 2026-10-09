from __future__ import annotations

from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.models.orm import Analysis, DetectionFinding, Indicator

router = APIRouter(prefix="/api/v1", tags=["stats"])


@router.get("/stats")
def stats(db: Session = Depends(get_db)):
    total = db.query(func.count(Analysis.id)).scalar() or 0
    by_class = dict(
        db.query(Analysis.classification, func.count(Analysis.id)).group_by(Analysis.classification).all()
    )
    high_risk = db.query(func.count(Analysis.id)).filter(Analysis.risk_score >= 60).scalar() or 0
    recent = (
        db.query(Analysis)
        .order_by(Analysis.created_at.desc())
        .limit(8)
        .all()
    )
    rule_counts = (
        db.query(DetectionFinding.rule_id, DetectionFinding.rule_name, func.count(DetectionFinding.id))
        .group_by(DetectionFinding.rule_id, DetectionFinding.rule_name)
        .order_by(func.count(DetectionFinding.id).desc())
        .limit(8)
        .all()
    )
    domains = (
        db.query(Indicator.value, func.count(Indicator.id))
        .filter(Indicator.indicator_type == "domain")
        .group_by(Indicator.value)
        .order_by(func.count(Indicator.id).desc())
        .limit(8)
        .all()
    )
    hashes = (
        db.query(Indicator.value)
        .filter(Indicator.indicator_type == "sha256")
        .order_by(Indicator.id.desc())
        .limit(8)
        .all()
    )
    start = datetime.now(timezone.utc) - timedelta(days=13)
    trend_rows = (
        db.query(func.date(Analysis.created_at), func.avg(Analysis.risk_score), func.count(Analysis.id))
        .filter(Analysis.created_at >= start)
        .group_by(func.date(Analysis.created_at))
        .order_by(func.date(Analysis.created_at))
        .all()
    )
    return {
        "total": total,
        "safe": by_class.get("safe", 0),
        "suspicious": by_class.get("suspicious", 0),
        "malicious": by_class.get("malicious", 0),
        "manual_review": by_class.get("manual_review", 0),
        "high_risk": high_risk,
        "classification_distribution": by_class,
        "recent": [
            {
                "id": row.id,
                "created_at": row.created_at.isoformat() if row.created_at else None,
                "classification": row.classification,
                "risk_score": row.risk_score,
                "subject": row.subject,
                "analysis_type": row.analysis_type,
            }
            for row in recent
        ],
        "top_rules": [
            {"rule_id": rule_id, "rule_name": name, "count": count} for rule_id, name, count in rule_counts
        ],
        "recent_domains": [{"domain": value, "count": count} for value, count in domains],
        "recent_hashes": [row[0] for row in hashes],
        "risk_trend": [
            {"date": str(day), "avg_score": float(avg or 0), "count": int(count or 0)}
            for day, avg, count in trend_rows
        ],
    }
