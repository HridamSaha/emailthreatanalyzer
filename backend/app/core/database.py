from collections.abc import Generator
from pathlib import Path

from sqlalchemy import create_engine, event
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, declarative_base, sessionmaker
from sqlalchemy.pool import StaticPool

from app.core.config import BACKEND_ROOT, get_settings

Base = declarative_base()
engine: Engine | None = None
SessionLocal: sessionmaker | None = None


def _make_engine() -> Engine:
    settings = get_settings()
    url = settings.database_url
    connect_args = {}
    engine_kwargs: dict = {"future": True}
    if url.startswith("sqlite"):
        connect_args["check_same_thread"] = False
        if url.startswith("sqlite:///./"):
            (BACKEND_ROOT / "data").mkdir(parents=True, exist_ok=True)
        if ":memory:" in url:
            engine_kwargs["poolclass"] = StaticPool
    created = create_engine(url, connect_args=connect_args, **engine_kwargs)
    if url.startswith("sqlite"):

        @event.listens_for(created, "connect")
        def _sqlite_pragma(dbapi_connection, _connection_record) -> None:  # type: ignore[no-untyped-def]
            cursor = dbapi_connection.cursor()
            cursor.execute("PRAGMA foreign_keys=ON")
            cursor.close()

    return created


def configure_engine() -> None:
    global engine, SessionLocal
    engine = _make_engine()
    SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False, future=True)


configure_engine()


def get_db() -> Generator[Session, None, None]:
    assert SessionLocal is not None
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def sqlite_path() -> Path:
    return BACKEND_ROOT / "data" / "etas.db"
