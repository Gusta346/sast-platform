"""Testes da API inicial."""

from fastapi.testclient import TestClient

from services.api.main import app


client = TestClient(app)


def test_health() -> None:
    """A API deve expor um healthcheck funcional."""
    response = client.get("/health")

    assert response.status_code == 200
    assert response.json() == {"status": "ok"}
