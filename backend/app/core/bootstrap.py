from sqlalchemy.orm import Session

from app.core import database as database_module
from app.core.rules_catalog import RULE_CATALOG
from app.models.orm import DetectionRule


def init_db() -> None:
    database_module.Base.metadata.create_all(bind=database_module.engine)
    assert database_module.SessionLocal is not None
    db = database_module.SessionLocal()
    try:
        seed_rules(db)
    finally:
        db.close()


def seed_rules(db: Session) -> None:
    existing = {row.rule_id for row in db.query(DetectionRule).all()}
    for item in RULE_CATALOG:
        if item["rule_id"] in existing:
            continue
        db.add(
            DetectionRule(
                rule_id=item["rule_id"],
                name=item["name"],
                description=item["description"],
                category=item["category"],
                severity=item["severity"],
                enabled=True,
                parameters={"default_score": item["default_score"]},
                logic_summary=item["logic_summary"],
                default_score=item["default_score"],
            )
        )
    db.commit()
