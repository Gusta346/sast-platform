"""Configuração inicial do worker Celery."""

import os

from celery import Celery

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


@celery_app.task
def health_task() -> str:
    """Confirma que o worker pode executar tarefas."""
    return "ok"
