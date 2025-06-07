from crypto_hunter_web import create_app
from crypto_hunter_web.services.celery_config import celery_app

app = create_app()
