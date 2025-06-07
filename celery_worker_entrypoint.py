import os
from crypto_hunter_web import create_app
from crypto_hunter_web.services.celery_config import celery_app

# Create Flask app and push context so tasks can use `current_app`
flask_app = create_app()
flask_app.app_context().push()

# (Optional) register a simple health‐check task
@celery_app.task(name="health_check")
def health_check():
    return {"status": "ok"}

# Celery will run as `celery -A celery_worker_entrypoint.celery_app worker|beat`
