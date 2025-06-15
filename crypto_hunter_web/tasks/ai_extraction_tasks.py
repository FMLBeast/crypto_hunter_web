#!/usr/bin/env python3
"""
Celery tasks for AI extraction
"""
from crypto_hunter_web.extensions import celery_app
from crypto_hunter_web.services.ai.ai_extraction_service import create_ai_extraction_task

# Create and register the AI extraction task
run_ai_extraction_task = create_ai_extraction_task(celery_app)
