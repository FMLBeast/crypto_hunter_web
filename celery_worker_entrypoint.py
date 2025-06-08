# celery_worker_entrypoint.py - UNIFIED WORKER ENTRYPOINT

"""
Celery worker entrypoint with proper Flask app context
Consolidates all Celery configurations into single entry point
"""

import os
import sys
from datetime import datetime

# Ensure crypto_hunter_web is importable
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Import unified Celery app
from crypto_hunter_web.services.celery_app import celery_app
from crypto_hunter_web import create_app

# Create Flask app and push context for database operations
flask_app = create_app()
flask_app.app_context().push()


# Register additional health check task
@celery_app.task(name="worker_health_check", bind=True)
def worker_health_check(self):
    """Enhanced health check with worker info"""
    from crypto_hunter_web.models import db

    try:
        # Test database connection
        db.session.execute('SELECT 1')
        db_status = "healthy"
    except Exception as e:
        db_status = f"error: {str(e)}"

    return {
        "status": "ok",
        "timestamp": datetime.utcnow().isoformat(),
        "worker_id": self.request.id,
        "hostname": self.request.hostname,
        "database": db_status,
        "queue": getattr(self.request, 'delivery_info', {}).get('routing_key', 'unknown')
    }


# Register system info task
@celery_app.task(name="system_info")
def system_info():
    """Get system information"""
    import psutil

    return {
        "cpu_percent": psutil.cpu_percent(),
        "memory_percent": psutil.virtual_memory().percent,
        "disk_usage": psutil.disk_usage('/').percent,
        "active_tasks": len(celery_app.control.inspect().active() or {}),
        "timestamp": datetime.utcnow().isoformat()
    }


# Test task for debugging
@celery_app.task(name="debug_task", bind=True)
def debug_task(self, message="Hello from Celery!"):
    """Debug task to test Celery functionality"""
    print(f"Request: {self.request!r}")
    return {
        "message": message,
        "task_id": self.request.id,
        "timestamp": datetime.utcnow().isoformat()
    }


# Worker startup callback
@celery_app.task(bind=True)
def on_worker_init(self):
    """Called when worker starts up"""
    print(f"🚀 Crypto Hunter worker starting up - ID: {self.request.id}")
    print(f"📋 Registered tasks: {len(celery_app.tasks)}")
    for task_name in sorted(celery_app.tasks.keys()):
        if not task_name.startswith('celery.'):
            print(f"  ✓ {task_name}")


if __name__ == "__main__":
    # Start worker programmatically if run directly
    print("🔧 Starting Crypto Hunter Celery worker...")
    print(f"📊 Flask environment: {flask_app.config.get('ENV', 'unknown')}")
    print(f"🔗 Broker: {celery_app.conf.broker_url}")
    print(f"📝 Backend: {celery_app.conf.result_backend}")

    # List all registered tasks
    print(f"\n📋 Registered tasks ({len(celery_app.tasks)}):")
    for task_name in sorted(celery_app.tasks.keys()):
        if not task_name.startswith('celery.'):
            print(f"  ✓ {task_name}")

    # Start worker
    celery_app.worker_main([
        'worker',
        '--loglevel=info',
        '--concurrency=4',
        '--pool=threads',
        '--queues=analysis,crypto,ai,maintenance'
    ])