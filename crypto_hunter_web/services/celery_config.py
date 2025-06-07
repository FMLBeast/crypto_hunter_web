"""
Enhanced Celery configuration with improved task routing and monitoring
"""

import os
import logging
from celery import Celery
from kombu import Queue, Exchange
from datetime import timedelta


class CeleryConfig:
    """Enhanced Celery configuration with intelligent routing"""

    # Broker and Backend
    broker_url = os.environ.get('CELERY_BROKER_URL', 'redis://localhost:6379/0')
    result_backend = os.environ.get('CELERY_RESULT_BACKEND', 'redis://localhost:6379/1')

    # Enhanced broker settings
    broker_transport_options = {
        'visibility_timeout': 3600,  # 1 hour
        'fanout_prefix': True,
        'fanout_patterns': True,
        'priority_steps': list(range(10)),
        'sep': ':',
        'queue_order_strategy': 'priority',
    }

    # Task Configuration
    task_serializer = 'json'
    accept_content = ['json']
    result_serializer = 'json'
    timezone = 'UTC'
    enable_utc = True

    # Enhanced task execution settings
    task_acks_late = True
    task_reject_on_worker_lost = True
    task_track_started = True
    task_time_limit = 1800  # 30 minutes hard limit
    task_soft_time_limit = 1500  # 25 minutes soft limit

    # Worker Configuration
    worker_prefetch_multiplier = 1
    worker_max_tasks_per_child = 50
    worker_disable_rate_limits = False
    worker_log_format = '[%(asctime)s: %(levelname)s/%(processName)s] %(message)s'
    worker_task_log_format = '[%(asctime)s: %(levelname)s/%(processName)s][%(task_name)s(%(task_id)s)] %(message)s'

    # Enhanced Exchanges and Queues
    task_default_exchange = 'crypto_analysis'
    task_default_exchange_type = 'topic'
    task_default_routing_key = 'task.default'

    # Define exchanges
    exchanges = (
        Exchange('crypto_analysis', type='topic'),
        Exchange('llm_analysis', type='topic'),
        Exchange('monitoring', type='topic'),
        Exchange('priority', type='topic'),
    )

    # Enhanced task queues with priorities
    task_queues = (
        # Default queue
        Queue('default',
              exchange=Exchange('crypto_analysis'),
              routing_key='task.default',
              queue_arguments={'x-max-priority': 10}),

        # Crypto analysis queues
        Queue('crypto_main',
              exchange=Exchange('crypto_analysis'),
              routing_key='crypto.main',
              queue_arguments={'x-max-priority': 10}),

        Queue('crypto_priority',
              exchange=Exchange('priority'),
              routing_key='crypto.priority',
              queue_arguments={'x-max-priority': 10}),

        Queue('ethereum',
              exchange=Exchange('crypto_analysis'),
              routing_key='crypto.ethereum',
              queue_arguments={'x-max-priority': 8}),

        Queue('cipher',
              exchange=Exchange('crypto_analysis'),
              routing_key='crypto.cipher',
              queue_arguments={'x-max-priority': 6}),

        Queue('hash_crack',
              exchange=Exchange('crypto_analysis'),
              routing_key='crypto.hash',
              queue_arguments={'x-max-priority': 4}),

        # LLM analysis queues
        Queue('llm_analysis',
              exchange=Exchange('llm_analysis'),
              routing_key='llm.analysis',
              queue_arguments={'x-max-priority': 9}),

        Queue('llm_priority',
              exchange=Exchange('priority'),
              routing_key='llm.priority',
              queue_arguments={'x-max-priority': 10}),

        # Monitoring and management
        Queue('monitor',
              exchange=Exchange('monitoring'),
              routing_key='system.monitor',
              queue_arguments={'x-max-priority': 2}),

        Queue('management',
              exchange=Exchange('monitoring'),
              routing_key='system.management',
              queue_arguments={'x-max-priority': 3}),
    )

    # Enhanced task routing
    task_routes = {
        # Core crypto analysis
        'app.services.background_crypto.analyze_file_comprehensive': {
            'queue': 'crypto_main',
            'routing_key': 'crypto.main',
            'priority': 5
        },
        'app.services.background_crypto.analyze_file_priority': {
            'queue': 'crypto_priority',
            'routing_key': 'crypto.priority',
            'priority': 9
        },

        # Specialized crypto analysis
        'app.services.background_crypto.ethereum_comprehensive_analysis': {
            'queue': 'ethereum',
            'routing_key': 'crypto.ethereum',
            'priority': 7
        },
        'app.services.background_crypto.cipher_comprehensive_analysis': {
            'queue': 'cipher',
            'routing_key': 'crypto.cipher',
            'priority': 6
        },
        'app.services.background_crypto.hash_cracking_analysis': {
            'queue': 'hash_crack',
            'routing_key': 'crypto.hash',
            'priority': 4
        },

        # LLM analysis
        'app.services.llm_crypto_orchestrator.llm_orchestrated_analysis': {
            'queue': 'llm_analysis',
            'routing_key': 'llm.analysis',
            'priority': 8
        },
        'app.services.llm_crypto_orchestrator.llm_priority_analysis': {
            'queue': 'llm_priority',
            'routing_key': 'llm.priority',
            'priority': 10
        },

        # System monitoring
        'app.services.background_crypto.continuous_crypto_monitor': {
            'queue': 'monitor',
            'routing_key': 'system.monitor',
            'priority': 1
        },
        'app.services.background_crypto.system_health_check': {
            'queue': 'management',
            'routing_key': 'system.management',
            'priority': 2
        },
        'app.services.background_crypto.cleanup_old_tasks': {
            'queue': 'management',
            'routing_key': 'system.management',
            'priority': 1
        },
    }

    # Result Configuration
    result_expires = 7200  # 2 hours
    result_compression = 'gzip'
    result_extended = True
    result_backend_transport_options = {
        'master_name': 'sentinel',
        'visibility_timeout': 3600,
    }

    # Monitoring and Events
    worker_send_task_events = True
    task_send_sent_event = True
    worker_hijack_root_logger = False
    worker_log_color = True

    # Beat Schedule for Periodic Tasks
    beat_schedule = {
        'system-health-check': {
            'task': 'app.services.background_crypto.system_health_check',
            'schedule': timedelta(minutes=5),
            'options': {'queue': 'management', 'priority': 2}
        },

        'cleanup-old-tasks': {
            'task': 'app.services.background_crypto.cleanup_old_tasks',
            'schedule': timedelta(hours=1),
            'options': {'queue': 'management', 'priority': 1}
        },

        'llm-cost-budget-check': {
            'task': 'app.services.llm_crypto_orchestrator.check_daily_budget',
            'schedule': timedelta(minutes=30),
            'options': {'queue': 'management', 'priority': 3}
        },

        'priority-queue-manager': {
            'task': 'app.services.background_crypto.manage_priority_queue',
            'schedule': timedelta(minutes=2),
            'options': {'queue': 'management', 'priority': 2}
        },

        'auto-analyze-new-files': {
            'task': 'app.services.background_crypto.auto_analyze_new_files',
            'schedule': timedelta(minutes=5),
            'options': {'queue': 'crypto_main', 'priority': 4}
        },

        'intelligent-llm-scheduling': {
            'task': 'app.services.llm_crypto_orchestrator.intelligent_scheduling',
            'schedule': timedelta(minutes=10),
            'options': {'queue': 'llm_analysis', 'priority': 3}
        },
    }

    # Error handling
    task_annotations = {
        '*': {
            'rate_limit': '100/m',
            'time_limit': 1800,
            'soft_time_limit': 1500,
        },
        'app.services.llm_crypto_orchestrator.*': {
            'rate_limit': '10/m',  # More restrictive for LLM calls
            'time_limit': 3600,
            'soft_time_limit': 3300,
        },
        'app.services.background_crypto.hash_cracking_analysis': {
            'rate_limit': '20/m',
            'time_limit': 2400,
            'soft_time_limit': 2100,
        }
    }


def create_celery_app(flask_app=None):
    """Create and configure Celery app with Flask integration"""

    celery = Celery('arweave_crypto_analyzer')
    celery.config_from_object(CeleryConfig)

    # Configure logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )

    if flask_app:
        # Integrate with Flask app context
        class ContextTask(celery.Task):
            """makefile celery tasks work with Flask app context"""

            def __call__(self, *args, **kwargs):
                with flask_app.app_context():
                    return self.run(*args, **kwargs)

        celery.Task = ContextTask

        # Initialize database connection pooling for workers
        @celery.task(bind=True)
        def init_worker_db():
            """Initialize database connections for worker"""
            with flask_app.app_context():
                from crypto_hunter_web import db
                db.engine.pool.recreate()

    return celery


# Global Celery instance
celery_app = create_celery_app()


# Worker startup script functions
def start_crypto_worker():
    """Start crypto analysis worker"""
    argv = [
        'worker',
        '--loglevel=info',
        '--queues=crypto_main,crypto_priority,ethereum,cipher,hash_crack',
        '--concurrency=4',
        '--max-tasks-per-child=50',
        '--time-limit=1800',
        '--soft-time-limit=1500'
    ]
    celery_app.worker_main(argv)


def start_llm_worker():
    """Start LLM analysis worker"""
    argv = [
        'worker',
        '--loglevel=info',
        '--queues=llm_analysis,llm_priority',
        '--concurrency=2',
        '--max-tasks-per-child=10',
        '--time-limit=3600',
        '--soft-time-limit=3300'
    ]
    celery_app.worker_main(argv)


def start_monitor_worker():
    """Start monitoring worker"""
    argv = [
        'worker',
        '--loglevel=info',
        '--queues=monitor,management',
        '--concurrency=1',
        '--max-tasks-per-child=100'
    ]
    celery_app.worker_main(argv)


def start_beat_scheduler():
    """Start beat scheduler"""
    argv = ['beat', '--loglevel=info']
    celery_app.start(argv)


if __name__ == '__main__':
    import sys

    if len(sys.argv) > 1:
        worker_type = sys.argv[1]
        if worker_type == 'crypto':
            start_crypto_worker()
        elif worker_type == 'llm':
            start_llm_worker()
        elif worker_type == 'monitor':
            start_monitor_worker()
        elif worker_type == 'beat':
            start_beat_scheduler()
        else:
            print(f"Unknown worker type: {worker_type}")
            print("Available types: crypto, llm, monitor, beat")
    else:
        print("Usage: python celery_config.py [crypto|llm|monitor|beat]")

app = celery_app
celery = celery_app