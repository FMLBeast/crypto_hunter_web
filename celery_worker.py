#!/usr/bin/env python3
"""
Celery worker startup script
"""

import os
import sys
from app import create_app
from app.services.background_crypto import celery_app

# Create Flask app context
app = create_app()
app.app_context().push()

if __name__ == '__main__':
    # Start Celery worker
    celery_app.start()