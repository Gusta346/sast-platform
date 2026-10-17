"""Testes dos endpoints de scans com SQLite e Celery eager."""

from __future__ import annotations

import io
import os
import zipfile
from collections.abc import Generator
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from services.api.models import Finding, Scan
from services.engine.sast_engine.models import Finding as EngineFinding, Severity


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
        lambda finding, context, **kwargs: {
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
    assert scan["status"] in {"PENDING", "DONE"}
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


def test_new_scan_cancels_previous_pending_scan(client: TestClient, monkeypatch) -> None:
    """O scan novo deve cancelar o anterior ainda pendente."""
    from services.worker import tasks

    task_ids = iter(["task-old", "task-new"])
    revoked = []

    def enqueue(scan_id: str):
        return SimpleNamespace(id=next(task_ids))

    monkeypatch.setattr(tasks.run_scan, "delay", enqueue)
    monkeypatch.setattr(
        tasks.celery_app.control,
        "revoke",
        lambda task_id, terminate, signal: revoked.append((task_id, terminate, signal)),
    )
    monkeypatch.setenv("SAST_CANCEL_PREVIOUS", "true")

    first = client.post(
        "/scans",
        files={"file": ("first.zip", _zip_file("first.py", "value = 1\n"), "application/zip")},
    ).json()
    second = client.post(
        "/scans",
        files={"file": ("second.zip", _zip_file("second.py", "value = 2\n"), "application/zip")},
    ).json()

    assert second["celery_task_id"] == "task-new"
    assert client.get(f"/scans/{first['id']}").json()["status"] == "CANCELLED"
    assert revoked == [("task-old", True, "SIGTERM")]


def test_new_scan_keeps_previous_when_cancellation_disabled(
    client: TestClient,
    monkeypatch,
) -> None:
    """A flag desabilitada mantém scans anteriores em andamento."""
    from services.worker import tasks

    task_ids = iter(["task-old", "task-new"])
    monkeypatch.setattr(
        tasks.run_scan,
        "delay",
        lambda scan_id: SimpleNamespace(id=next(task_ids)),
    )
    monkeypatch.setenv("SAST_CANCEL_PREVIOUS", "false")

    first = client.post(
        "/scans",
        files={"file": ("first.zip", _zip_file("first.py", "value = 1\n"), "application/zip")},
    ).json()
    client.post(
        "/scans",
        files={"file": ("second.zip", _zip_file("second.py", "value = 2\n"), "application/zip")},
    )

    assert client.get(f"/scans/{first['id']}").json()["status"] == "PENDING"


def test_worker_does_not_persist_cancelled_scan(client: TestClient, monkeypatch) -> None:
    """A tarefa cancelada deve terminar sem gravar findings."""
    from services.api import database
    from services.worker import tasks

    monkeypatch.setattr(tasks.run_scan, "delay", lambda scan_id: SimpleNamespace(id="task-cancelled"))
    response = client.post(
        "/scans",
        files={"file": ("cancelled.zip", _zip_file("app.py", "eval(input())\n"), "application/zip")},
    )
    scan_id = response.json()["id"]
    session = database.SessionLocal()
    scan = session.get(Scan, scan_id)
    scan.status = "CANCELLED"
    session.commit()
    session.close()

    tasks.run_scan.run(scan_id)

    session = database.SessionLocal()
    try:
        assert session.query(Finding).filter_by(scan_id=scan_id).count() == 0
        assert session.get(Scan, scan_id).status == "CANCELLED"
    finally:
        session.close()


def test_worker_persists_all_findings_before_limited_ai_phase(
    client: TestClient,
    monkeypatch,
) -> None:
    """A IA deve processar no máximo cinco achados após persistir todos."""
    from services.api import database
    from services.worker import tasks

    monkeypatch.setenv("SAST_AI_MAX_FINDINGS", "5")
    session = database.SessionLocal()
    scan = Scan(nome="many.zip", status="PENDING")
    session.add(scan)
    session.commit()
    session.refresh(scan)
    scan_id = scan.id
    tasks.UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
    (tasks.UPLOAD_DIR / f"{scan_id}.zip").write_bytes(_zip_file("app.py", "value = 1\n"))
    session.close()

    engine_findings = [
        EngineFinding(
            rule_id=f"critical-{index % 3}",
            titulo="Critical",
            severidade=Severity.CRITICAL,
            arquivo="app.py",
            linha=index + 1,
            trecho="",
            cwe="CWE-89",
            owasp="A03",
            descricao="",
            remediacao="",
        )
        for index in range(12)
    ]
    calls = []

    monkeypatch.setattr(tasks, "scan_directory", lambda directory: engine_findings)

    def enrich(finding, context, **kwargs):
        check = database.SessionLocal()
        try:
            calls.append((finding.rule_id, check.query(Finding).filter_by(scan_id=scan_id).count()))
        finally:
            check.close()
        return {
            "severidade": "CRITICAL",
            "falso_positivo": False,
            "justificativa": "teste",
            "codigo_corrigido": "fix",
            "ia_origem": "llm",
        }

    monkeypatch.setattr(tasks, "classify_and_remediate", enrich)
    tasks.run_scan.run(scan_id)

    session = database.SessionLocal()
    try:
        persisted = session.query(Finding).filter_by(scan_id=scan_id).all()
        assert len(persisted) == 12
        assert len(calls) == 5
        assert all(count == 12 for _, count in calls)
        assert sum(item.ia_origem == "llm" for item in persisted) == 5
        assert sum(item.ia_origem == "fallback" for item in persisted) == 7
    finally:
        session.close()
