"""
Application Celery — workers pour tâches longues (CAPE Sandbox).

Démarrage worker :
    celery -A orchestrator.celery_app worker --loglevel=info --concurrency=4
"""
from __future__ import annotations

import logging

from celery import Celery

from orchestrator.core.config import get_settings

logger = logging.getLogger(__name__)
settings = get_settings()

celery_app = Celery(
    "mailguardianx",
    broker=settings.celery.broker_url,
    backend=settings.celery.result_backend,
    include=["orchestrator.tasks.cape_tasks"],
)

celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    task_time_limit=settings.celery.task_time_limit,
    task_soft_time_limit=settings.celery.task_soft_time_limit,
    task_acks_late=True,
    worker_prefetch_multiplier=1,        # Pas de pré-fetch (tâches longues)
    task_reject_on_worker_lost=True,
    result_expires=86400,                # Résultats gardés 24h
    broker_connection_retry_on_startup=True,
)


if __name__ == "__main__":
    celery_app.start()
