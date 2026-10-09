from __future__ import annotations

import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

BACKEND_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BACKEND_ROOT))


@pytest.fixture()
def client(tmp_path, monkeypatch):
    db_path = tmp_path / "test.db"
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{db_path.as_posix()}")
    from app.core.config import get_settings

    get_settings.cache_clear()
    from app.core import database as database_module

    database_module.configure_engine()
    from app.core.bootstrap import init_db

    init_db()
    from app.main import app

    with TestClient(app) as test_client:
        yield test_client
