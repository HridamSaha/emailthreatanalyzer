from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.api.deps import require_admin
from app.core.database import get_db
from app.models.orm import AuditEvent, DetectionFinding, DetectionRule
from app.schemas.api import RuleUpdateRequest

router = APIRouter(prefix="/api/v1/rules", tags=["rules"])


@router.get("")
def list_rules(db: Session = Depends(get_db)):
    counts = dict(
        db.query(DetectionFinding.rule_id, func.count(DetectionFinding.id))
        .group_by(DetectionFinding.rule_id)
        .all()
    )
    rows = db.query(DetectionRule).order_by(DetectionRule.rule_id.asc()).all()
    return [
        {
            "rule_id": row.rule_id,
            "name": row.name,
            "description": row.description,
            "category": row.category,
            "severity": row.severity,
            "enabled": row.enabled,
            "logic_summary": row.logic_summary,
            "default_score": row.default_score,
            "times_triggered": int(counts.get(row.rule_id, 0)),
        }
        for row in rows
    ]


@router.patch("/{rule_id}")
def update_rule(rule_id: str, payload: RuleUpdateRequest, db: Session = Depends(get_db), _: None = Depends(require_admin)):
    row = db.query(DetectionRule).filter(DetectionRule.rule_id == rule_id).first()
    if not row:
        raise HTTPException(status_code=404, detail="Rule not found.")
    row.enabled = payload.enabled
    db.add(
        AuditEvent(
            event_type="rule_toggled",
            subject_id=rule_id,
            outcome="success",
            details=f"enabled={payload.enabled}",
        )
    )
    db.commit()
    return {"rule_id": row.rule_id, "enabled": row.enabled}
