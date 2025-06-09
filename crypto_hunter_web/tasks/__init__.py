"""
Task management module for Crypto Hunter
"""

# Import all tasks to register them with Celery
try:
    from .crypto_tasks import *
    from .analysis_tasks import *
    from .maintenance_tasks import *
except ImportError:
    # Graceful fallback if tasks don't exist
    pass