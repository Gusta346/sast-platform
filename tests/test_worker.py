"""Testes do worker inicial."""

from services.worker.celery_app import health_task


def test_health_task() -> None:
    """A tarefa de saúde deve retornar o estado esperado."""
    assert health_task.run() == "ok"
