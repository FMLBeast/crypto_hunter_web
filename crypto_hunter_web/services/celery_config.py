# crypto_hunter_web/services/celery_config.py

import os
from celery import Celery

def make_celery():
    """
    Create and configure the Celery app to discover your background tasks.
    """
    broker_url = os.getenv("CELERY_BROKER_URL", "redis://redis:6379/0")
    result_backend = os.getenv("CELERY_RESULT_BACKEND", "redis://redis:6379/1")

    celery = Celery(
        "arweave_crypto_analyzer",
        broker=broker_url,
        backend=result_backend,
        include=[
            # Core background task modules
            "crypto_hunter_web.services.background_crypto",
            "crypto_hunter_web.services.llm_crypto_orchestrator",
        ],
    )

    # Standard Celery configuration
    celery.conf.update(
        task_serializer="json",
        accept_content=["json"],
        result_serializer="json",
        timezone=os.getenv("TZ", "UTC"),
        enable_utc=True,
    )

    return celery

# Exposed Celery application for workers/beat
celery_app = make_celery()
