"""Testes dos endpoints de scans com SQLite e Celery eager."""

from __future__ import annotations

import io
import os
import zipfile
from collections.abc import Generator

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool


@pytest.fixture()
def client(tmp_path, monkeypatch) -> Generator[TestClient, None, None]:
    """Cria uma API isolada em SQLite em memória."""
    database_url = "sqlite://"
    monkeypatch.setenv("DATABASE_URL", database_url)
    monkeypatch.setenv("CELERY_TASK_ALWAYS_EAGER", "true")
    from services.api import database

    database.engine = create_engine(
        database_url,
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    database.SessionLocal = sessionmaker(bind=database.engine, autoflush=False, autocommit=False)
    from services.api.main import app
    from services.worker import tasks

    tasks.UPLOAD_DIR = tmp_path / "scans"
    tasks.celery_app.conf.task_always_eager = True
    tasks.celery_app.conf.task_eager_propagates = True
    tasks.celery_app.conf.broker_url = "memory://"
    tasks.celery_app.conf.result_backend = "cache+memory://"
    monkeypatch.setattr(
        tasks,
        "classify_and_remediate",
        lambda finding, context: {
            "severidade": finding.severidade.value,
            "falso_positivo": False,
            "justificativa": "fallback de teste",
            "codigo_corrigido": finding.remediacao,
            "ia_origem": "fallback",
        },
    )
    database.create_tables()
    with TestClient(app) as test_client:
        yield test_client


def _zip_file(name: str, content: str) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr(name, content)
    return buffer.getvalue()


def test_create_and_list_scan(client: TestClient) -> None:
    """Upload válido deve criar scan e persistir seu resultado."""
    response = client.post(
        "/scans",
        files={"file": ("clean.zip", _zip_file("clean.py", "value = 1\n"), "application/zip")},
    )

    assert response.status_code == 202
    scan = response.json()
    assert scan["status"] == "PENDING"
    persisted = client.get(f"/scans/{scan['id']}")
    assert persisted.status_code == 200
    assert persisted.json()["status"] == "DONE"
    assert len(client.get("/scans").json()) == 1


def test_upload_rejects_zip_slip(client: TestClient) -> None:
    """ZIP com caminho escapando do destino deve ser rejeitado."""
    assert client.post(
        "/scans",
        files={"file": ("bad.zip", _zip_file("../escape.py", "x = 1"), "application/zip")},
    ).status_code == 400


def test_findings_filters(client: TestClient) -> None:
    """Findings devem ser consultáveis por scan e severidade."""
    response = client.post(
        "/scans",
        files={"file": ("vulnerable.zip", _zip_file("app.py", "eval(input())\n"), "application/zip")},
    )
    scan_id = response.json()["id"]
    findings = client.get("/findings", params={"scan_id": scan_id}).json()

    assert findings
    assert all(item["scan_id"] == scan_id for item in findings)
    assert all(item["ia_origem"] == "fallback" for item in findings)
    assert client.get("/findings", params={"severidade": "CRITICAL"}).status_code == 200
