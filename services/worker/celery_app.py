"""Configuração inicial do worker Celery."""

import os

from celery import Celery
from celery.signals import worker_ready

celery_app = Celery(
    "sast_worker",
    broker=os.getenv("CELERY_BROKER_URL", "redis://localhost:6379/0"),
    backend=os.getenv("CELERY_RESULT_BACKEND", "redis://localhost:6379/1"),
)
celery_app.conf.update(
    task_always_eager=os.getenv("CELERY_TASK_ALWAYS_EAGER", "").lower() == "true",
    task_eager_propagates=True,
)

celery_app.autodiscover_tasks(["services.worker"])


@worker_ready.connect
def migrate_worker_schema(**kwargs) -> None:
    """Garante o schema atualizado quando o worker inicia."""
    from services.api.database import create_tables

    create_tables()


@celery_app.task
def health_task() -> str:
    """Confirma que o worker pode executar tarefas."""
    return "ok"
