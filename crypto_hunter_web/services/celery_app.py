# crypto_hunter_web/celery_app.py - UNIFIED CELERY CONFIGURATION

import os
from celery import Celery, group, chord, chain
from flask import Flask

def make_celery(app=None):
    """Create and configure unified Celery app with Flask context"""
    if app is None:
        # Create a minimal Flask app for Celery configuration
        app = Flask(__name__)

        # Load configuration from environment variables
        app.config.from_mapping(
            CELERY_BROKER_URL=os.environ.get('CELERY_BROKER_URL', 'redis://localhost:6379/2'),
            CELERY_RESULT_BACKEND=os.environ.get('CELERY_RESULT_BACKEND', 'redis://localhost:6379/3'),
        )

    # Create Celery instance
    celery = Celery(
        'crypto_hunter_web',
        broker=app.config['CELERY_BROKER_URL'],
        backend=app.config['CELERY_RESULT_BACKEND'],
        include=[
            # All task modules - consolidated list
            'crypto_hunter_web.services.background_service',
            'crypto_hunter_web.services.background_crypto',
            'crypto_hunter_web.services.llm_crypto_orchestrator',
            'crypto_hunter_web.tasks.maintenance_tasks',
            'crypto_hunter_web.tasks.analysis_tasks',
            'crypto_hunter_web.tasks.crypto_tasks',
        ]
    )

    # Configure Celery
    celery.conf.update(
        task_serializer='json',
        accept_content=['json'],
        result_serializer='json',
        timezone='UTC',
        enable_utc=True,

        # Task routing
        task_routes={
            'crypto_hunter_web.services.background_service.analyze_file_comprehensive': {
                'queue': 'analysis'
            },
            'crypto_hunter_web.services.background_service.analyze_crypto_patterns': {
                'queue': 'crypto'
            },
            'crypto_hunter_web.services.background_service.process_ai_analysis': {
                'queue': 'ai'
            },
            'crypto_hunter_web.services.background_service.cleanup_old_tasks': {
                'queue': 'maintenance'
            },
            'crypto_hunter_web.services.background_crypto.continuous_crypto_monitor': {
                'queue': 'crypto'
            },
            'crypto_hunter_web.services.background_crypto.system_health_check': {
                'queue': 'maintenance'
            }
        },

        # Worker settings
        worker_prefetch_multiplier=1,
        task_acks_late=True,
        worker_disable_rate_limits=False,

        # Result settings
        result_expires=3600 * 24,  # 24 hours
        task_ignore_result=False,

        # Retry settings
        task_default_retry_delay=60,
        task_max_retries=3,

        # Beat schedule for periodic tasks
        beat_schedule={
            'cleanup-old-tasks': {
                'task': 'crypto_hunter_web.tasks.maintenance_tasks.cleanup_old_tasks',
                'schedule': 3600.0,  # Every hour
            },
            'health-check': {
                'task': 'crypto_hunter_web.tasks.maintenance_tasks.system_health_check',
                'schedule': 300.0,  # Every 5 minutes
            },
            'continuous-crypto-monitor': {
                'task': 'crypto_hunter_web.services.background_crypto.continuous_crypto_monitor',
                'schedule': 600.0,  # Every 10 minutes
            }
        }
    )

    # Create task base class with Flask application context
    class ContextTask(celery.Task):
        """Make celery tasks work with Flask app context"""

        def __call__(self, *args, **kwargs):
            # For tasks that need Flask context, they should be run with the actual app
            # This minimal context is just for initialization
            if app.name == 'crypto_hunter_web.services.celery_app':
                # Running with minimal app, just execute the task
                return self.run(*args, **kwargs)
            else:
                # Running with full Flask app, use its context
                with app.app_context():
                    return self.run(*args, **kwargs)

    celery.Task = ContextTask

    return celery


# Create the global Celery instance with minimal configuration
celery_app = make_celery()

def init_app(app):
    """Initialize Celery with the actual Flask app"""
    global celery_app
    celery_app = make_celery(app)
    return celery_app

# Export commonly used decorators and utilities
task = celery_app.task
group = group
chord = chord
chain = chain
