"""Testes dos endpoints de métricas do dashboard."""

from __future__ import annotations

from datetime import datetime, timezone
from collections.abc import Generator

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from services.api.models import Finding, Scan


@pytest.fixture()
def client(tmp_path, monkeypatch) -> Generator[TestClient, None, None]:
    """Cria uma API isolada em SQLite em memória."""
    monkeypatch.setenv("DATABASE_URL", "sqlite://")
    from services.api import database

    database.engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    database.SessionLocal = sessionmaker(bind=database.engine, autoflush=False, autocommit=False)
    from services.api.main import app
    from services.worker import tasks

    tasks.UPLOAD_DIR = tmp_path / "scans"
    database.create_tables()
    with TestClient(app) as test_client:
        yield test_client


def test_metrics_endpoints(client: TestClient) -> None:
    """Métricas devem consolidar severidade, tendência, arquivos e resumo."""
    from services.api import database

    session = database.SessionLocal()
    scan = Scan(nome="metrics.zip", status="DONE", criado_em=datetime(2026, 1, 5))
    session.add(scan)
    session.flush()
    session.add_all(
        [
            Finding(scan_id=scan.id, rule_id="a", titulo="A", severidade="CRITICAL", arquivo="a.py", linha=1, trecho="", cwe="CWE-1", owasp="", descricao="", remediacao="", falso_positivo=False),
            Finding(scan_id=scan.id, rule_id="b", titulo="B", severidade="HIGH", arquivo="a.py", linha=2, trecho="", cwe="CWE-2", owasp="", descricao="", remediacao="", falso_positivo=True),
            Finding(scan_id=scan.id, rule_id="c", titulo="C", severidade="LOW", arquivo="b.py", linha=3, trecho="", cwe="CWE-3", owasp="", descricao="", remediacao="", falso_positivo=False),
        ]
    )
    session.commit()
    try:
        assert client.get("/metrics/severity").json()["CRITICAL"] == 1
        assert client.get("/metrics/summary").json() == {"total": 3, "criticos": 1, "falsos_positivos_descartados_ia": 1}
        assert client.get("/metrics/top-files").json()[0] == {"arquivo": "a.py", "total": 1}
        assert client.get("/metrics/trend").json()[0]["total"] == 3
    finally:
        session.close()


def test_metrics_filter_by_scan(client: TestClient) -> None:
    """Métricas devem considerar somente o scan solicitado."""
    from services.api import database

    session = database.SessionLocal()
    first = Scan(nome="first.zip", status="DONE", criado_em=datetime(2026, 1, 5))
    second = Scan(nome="second.zip", status="DONE", criado_em=datetime(2026, 1, 6))
    session.add_all([first, second])
    session.flush()
    session.add_all(
        [
            Finding(scan_id=first.id, rule_id="a", titulo="A", severidade="CRITICAL", arquivo="first.py", linha=1, trecho="", cwe="CWE-1", owasp="", descricao="", remediacao="", falso_positivo=False),
            Finding(scan_id=second.id, rule_id="b", titulo="B", severidade="LOW", arquivo="second.py", linha=1, trecho="", cwe="CWE-2", owasp="", descricao="", remediacao="", falso_positivo=False),
        ]
    )
    session.commit()
    try:
        assert client.get("/metrics/summary", params={"scan_id": first.id}).json() == {
            "total": 1,
            "criticos": 1,
            "falsos_positivos_descartados_ia": 0,
        }
        assert client.get("/metrics/severity", params={"scan_id": second.id}).json() == {
            "CRITICAL": 0,
            "HIGH": 0,
            "MEDIUM": 0,
            "LOW": 1,
        }
        assert client.get("/metrics/top-files", params={"scan_id": first.id}).json() == [
            {"arquivo": "first.py", "total": 1}
        ]
        assert client.get("/metrics/trend", params={"scan_id": second.id}).json() == [
            {"semana": "2026-W02", "total": 1}
        ]
    finally:
        session.close()


def test_scan_created_at_is_serialized_as_utc_z(client: TestClient) -> None:
    """A API deve retornar datas UTC com o sufixo Z."""
    from services.api import database

    session = database.SessionLocal()
    session.add(
        Scan(
            nome="timezone.zip",
            status="DONE",
            criado_em=datetime(2026, 10, 17, 23, 4, 53, tzinfo=timezone.utc),
        )
    )
    session.commit()
    session.close()

    response = client.get("/scans")

    assert response.status_code == 200
    assert response.json()[0]["criado_em"] == "2026-10-17T23:04:53Z"


def test_trend_uses_sao_paulo_timezone(client: TestClient) -> None:
    """A tendência deve agrupar pelo calendário de São Paulo."""
    from services.api import database

    session = database.SessionLocal()
    scan = Scan(
        nome="boundary.zip",
        status="DONE",
        criado_em=datetime(2021, 1, 4, 2, 0, tzinfo=timezone.utc),
    )
    session.add(scan)
    session.flush()
    session.add(
        Finding(
            scan_id=scan.id,
            rule_id="boundary",
            titulo="Boundary",
            severidade="LOW",
            arquivo="boundary.py",
            linha=1,
            trecho="",
            cwe="CWE-1",
            owasp="",
            descricao="",
            remediacao="",
            falso_positivo=False,
        )
    )
    session.commit()
    session.close()

    assert client.get("/metrics/trend").json() == [
        {"semana": "2020-W53", "total": 1}
    ]
