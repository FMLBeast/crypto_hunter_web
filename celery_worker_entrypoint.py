from crypto_hunter_web.services.celery_config import celery_app  # assumes celery_config.py is in your PYTHONPATH

# alias for ease-of-use elsewhere
celery = celery_app
