from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, Response
from sqlalchemy import or_
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.database import get_db
from app.models.orm import Analysis, AuditEvent, DetectionFinding
from app.services.orchestrator import _public_result
from app.services.report_generator import build_csv, build_pdf

router = APIRouter(prefix="/api/v1/analyses", tags=["analyses"])


@router.get("")
def list_analyses(
    db: Session = Depends(get_db),
    q: str | None = None,
    classification: str | None = None,
    severity: str | None = None,
    sort: str = Query("created_at"),
    order: str = Query("desc"),
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
):
    query = db.query(Analysis)
    if q:
        like = f"%{q}%"
        query = query.filter(
            or_(
                Analysis.id.ilike(like),
                Analysis.original_filename.ilike(like),
                Analysis.subject.ilike(like),
                Analysis.sender_domain.ilike(like),
                Analysis.input_hash.ilike(like),
            )
        )
    if classification:
        query = query.filter(Analysis.classification == classification)
    if severity:
        query = query.filter(Analysis.severity == severity)
    sort_map = {
        "created_at": Analysis.created_at,
        "risk_score": Analysis.risk_score,
        "classification": Analysis.classification,
    }
    column = sort_map.get(sort, Analysis.created_at)
    query = query.order_by(column.asc() if order == "asc" else column.desc())
    total = query.count()
    rows = query.offset((page - 1) * page_size).limit(page_size).all()
    return {
        "total": total,
        "page": page,
        "page_size": page_size,
        "items": [
            {
                "id": row.id,
                "analysis_type": row.analysis_type,
                "original_filename": row.original_filename,
                "subject": row.subject,
                "sender_domain": row.sender_domain,
                "created_at": row.created_at.isoformat() if row.created_at else None,
                "classification": row.classification,
                "risk_score": row.risk_score,
                "severity": row.severity,
                "summary": row.summary,
            }
            for row in rows
        ],
    }


@router.get("/{analysis_id}")
def get_analysis(analysis_id: str, db: Session = Depends(get_db)):
    row = db.get(Analysis, analysis_id)
    if not row:
        raise HTTPException(status_code=404, detail="Analysis not found.")
    return _public_result(row)


@router.delete("/{analysis_id}")
def delete_analysis(analysis_id: str, db: Session = Depends(get_db)):
    row = db.get(Analysis, analysis_id)
    if not row:
        raise HTTPException(status_code=404, detail="Analysis not found.")
    db.delete(row)
    db.add(AuditEvent(event_type="analysis_deleted", subject_id=analysis_id, outcome="success"))
    db.commit()
    return {"status": "deleted", "id": analysis_id}


@router.get("/{analysis_id}/report")
def download_report(analysis_id: str, db: Session = Depends(get_db)):
    row = db.get(Analysis, analysis_id)
    if not row:
        raise HTTPException(status_code=404, detail="Analysis not found.")
    settings = get_settings()
    pdf = build_pdf(_public_result(row), settings.app_name, settings.app_version)
    return Response(
        content=pdf,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="analysis-{analysis_id}.pdf"'},
    )


@router.get("/{analysis_id}/export")
def export_analysis(analysis_id: str, format: str = "json", db: Session = Depends(get_db)):
    row = db.get(Analysis, analysis_id)
    if not row:
        raise HTTPException(status_code=404, detail="Analysis not found.")
    payload = _public_result(row)
    if format == "csv":
        return Response(
            content=build_csv(payload),
            media_type="text/csv",
            headers={"Content-Disposition": f'attachment; filename="analysis-{analysis_id}.csv"'},
        )
    return payload
