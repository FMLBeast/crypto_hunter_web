#!/usr/bin/env python3
"""
Background Service - Real implementation for task monitoring and management
"""

import json
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
from celery import current_app as celery_app
from celery.result import AsyncResult
from sqlalchemy import desc

from crypto_hunter_web.extensions import redis_client
from crypto_hunter_web.models import db, AnalysisFile, Finding, FileContent, User, FileStatus
from crypto_hunter_web.services.celery_app import celery_app

logger = logging.getLogger(__name__)

class BackgroundService:
    """Real background service for monitoring analysis tasks"""

    # Redis keys for task tracking
    ACTIVE_TASKS_KEY = "crypto_hunter:active_tasks"
    USER_TASKS_KEY = "crypto_hunter:user_tasks:{user_id}"
    FILE_TASKS_KEY = "crypto_hunter:file_tasks:{file_id}"
    TASK_STATUS_KEY = "crypto_hunter:task_status:{task_id}"
    TASK_RESULTS_KEY = "crypto_hunter:task_results:{task_id}"

    @classmethod
    def track_task(cls, task_id: str, task_type: str, file_id: int, user_id: int, metadata: Dict = None):
        """Track a background task in Redis"""
        try:
            if not redis_client.client:
                logger.warning("Redis not available for task tracking")
                return

            task_info = {
                'task_id': task_id,
                'task_type': task_type,
                'file_id': file_id,
                'user_id': user_id,
                'created_at': datetime.utcnow().isoformat(),
                'status': 'pending',
                'metadata': metadata or {}
            }

            # Store task info
            redis_client.set(
                cls.TASK_STATUS_KEY.format(task_id=task_id),
                json.dumps(task_info),
                ex=86400  # 24 hour expiry
            )

            # Add to active tasks
            redis_client.client.sadd(cls.ACTIVE_TASKS_KEY, task_id)

            # Add to user's task list
            user_key = cls.USER_TASKS_KEY.format(user_id=user_id)
            redis_client.client.lpush(user_key, task_id)
            redis_client.client.ltrim(user_key, 0, 99)  # Keep last 100
            redis_client.client.expire(user_key, 86400 * 7)  # 7 days

            # Add to file's task list
            file_key = cls.FILE_TASKS_KEY.format(file_id=file_id)
            redis_client.client.lpush(file_key, task_id)
            redis_client.client.ltrim(file_key, 0, 19)  # Keep last 20
            redis_client.client.expire(file_key, 86400 * 3)  # 3 days

            logger.info(f"Tracked task {task_id} for file {file_id} by user {user_id}")

        except Exception as e:
            logger.error(f"Failed to track task {task_id}: {e}")

    @classmethod
    def update_task_status(cls, task_id: str, status: str, progress: int = None, 
                          stage: str = None, metadata: Dict = None):
        """Update task status in Redis"""
        try:
            if not redis_client.client:
                return

            # Get existing task info
            task_key = cls.TASK_STATUS_KEY.format(task_id=task_id)
            existing_data = redis_client.get(task_key)

            if existing_data:
                task_info = json.loads(existing_data)
            else:
                task_info = {'task_id': task_id}

            # Update status
            task_info.update({
                'status': status,
                'updated_at': datetime.utcnow().isoformat()
            })

            if progress is not None:
                task_info['progress'] = progress
            if stage:
                task_info['current_stage'] = stage
            if metadata:
                task_info.setdefault('metadata', {}).update(metadata)

            # Store updated info
            redis_client.set(task_key, json.dumps(task_info), ex=86400)

            # Remove from active tasks if completed/failed
            if status in ['completed', 'failed', 'revoked']:
                redis_client.client.srem(cls.ACTIVE_TASKS_KEY, task_id)

            logger.debug(f"Updated task {task_id} status to {status}")

        except Exception as e:
            logger.error(f"Failed to update task status {task_id}: {e}")

    @classmethod
    def get_task_status(cls, task_id: str) -> Dict[str, Any]:
        """Get detailed task status from Celery and Redis"""
        try:
            # Get Celery task result
            celery_result = AsyncResult(task_id, app=celery_app)

            task_data = {
                'task_id': task_id,
                'state': celery_result.state,
                'meta': celery_result.info or {},
                'result': None,
                'traceback': None
            }

            # Add result if completed
            if celery_result.state == 'SUCCESS':
                task_data['result'] = celery_result.result
            elif celery_result.state == 'FAILURE':
                task_data['traceback'] = str(celery_result.info)

            # Enhance with Redis data
            if redis_client.client:
                redis_key = cls.TASK_STATUS_KEY.format(task_id=task_id)
                redis_data = redis_client.get(redis_key)

                if redis_data:
                    redis_info = json.loads(redis_data)
                    task_data.update({
                        'task_type': redis_info.get('task_type'),
                        'file_id': redis_info.get('file_id'),
                        'user_id': redis_info.get('user_id'),
                        'created_at': redis_info.get('created_at'),
                        'updated_at': redis_info.get('updated_at'),
                        'progress': redis_info.get('progress'),
                        'current_stage': redis_info.get('current_stage'),
                        'metadata': redis_info.get('metadata', {})
                    })

            return task_data

        except Exception as e:
            logger.error(f"Failed to get task status {task_id}: {e}")
            return {
                'task_id': task_id,
                'state': 'UNKNOWN',
                'meta': {'error': str(e)},
                'result': None
            }

    @classmethod
    def get_user_active_tasks(cls, user_id: int) -> List[Dict[str, Any]]:
        """Get active tasks for a specific user"""
        try:
            if not redis_client.client:
                return []

            user_key = cls.USER_TASKS_KEY.format(user_id=user_id)
            task_ids = redis_client.client.lrange(user_key, 0, 20)

            tasks = []
            for task_id in task_ids:
                task_id = task_id.decode('utf-8') if isinstance(task_id, bytes) else task_id

                # Get task status
                task_info = cls.get_task_status(task_id)

                # Only include active tasks
                if task_info['state'] in ['PENDING', 'PROGRESS', 'RETRY']:
                    tasks.append(task_info)

            return tasks

        except Exception as e:
            logger.error(f"Failed to get user tasks for {user_id}: {e}")
            return []

    @classmethod  
    def get_file_tasks(cls, file_id: int) -> List[Dict[str, Any]]:
        """Get all tasks for a specific file"""
        try:
            if not redis_client.client:
                return []

            file_key = cls.FILE_TASKS_KEY.format(file_id=file_id)
            task_ids = redis_client.client.lrange(file_key, 0, 10)

            tasks = []
            for task_id in task_ids:
                task_id = task_id.decode('utf-8') if isinstance(task_id, bytes) else task_id
                task_info = cls.get_task_status(task_id)
                tasks.append(task_info)

            return tasks

        except Exception as e:
            logger.error(f"Failed to get file tasks for {file_id}: {e}")
            return []

    @classmethod
    def get_system_status(cls) -> Dict[str, Any]:
        """Get overall system status"""
        try:
            # Celery worker status
            inspect = celery_app.control.inspect()
            stats = inspect.stats()
            active_tasks = inspect.active()

            # Redis task counts
            active_count = 0
            if redis_client.client:
                active_count = redis_client.client.scard(cls.ACTIVE_TASKS_KEY)

            # Database stats
            total_files = AnalysisFile.query.count()
            analyzing_files = AnalysisFile.query.filter_by(status=FileStatus.PROCESSING).count()
            pending_files = AnalysisFile.query.filter_by(status=FileStatus.PENDING).count()

            return {
                'workers': {
                    'online': len(stats) if stats else 0,
                    'stats': stats or {},
                    'active_tasks': active_tasks or {}
                },
                'tasks': {
                    'active_count': active_count,
                    'total_files': total_files,
                    'analyzing_files': analyzing_files,
                    'pending_files': pending_files
                },
                'redis_connected': redis_client.client is not None,
                'timestamp': datetime.utcnow().isoformat()
            }

        except Exception as e:
            logger.error(f"Failed to get system status: {e}")
            return {
                'workers': {'online': 0, 'stats': {}, 'active_tasks': {}},
                'tasks': {'active_count': 0, 'total_files': 0, 'analyzing_files': 0, 'pending_files': 0},
                'redis_connected': False,
                'error': str(e),
                'timestamp': datetime.utcnow().isoformat()
            }

    @classmethod
    def cancel_task(cls, task_id: str, user_id: int) -> bool:
        """Cancel a background task"""
        try:
            # Verify user has permission to cancel this task
            task_info = cls.get_task_status(task_id)
            if task_info.get('user_id') != user_id:
                logger.warning(f"User {user_id} attempted to cancel task {task_id} they don't own")
                return False

            # Cancel in Celery
            celery_app.control.revoke(task_id, terminate=True)

            # Update status in Redis
            cls.update_task_status(task_id, 'cancelled')

            logger.info(f"Task {task_id} cancelled by user {user_id}")
            return True

        except Exception as e:
            logger.error(f"Failed to cancel task {task_id}: {e}")
            return False

    @classmethod
    def cleanup_old_tasks(cls, days: int = 7):
        """Clean up old task data from Redis"""
        try:
            if not redis_client.client:
                return

            cutoff_date = datetime.utcnow() - timedelta(days=days)
            cutoff_str = cutoff_date.isoformat()

            # Get all active task IDs
            active_task_ids = redis_client.client.smembers(cls.ACTIVE_TASKS_KEY)

            cleaned_count = 0
            for task_id in active_task_ids:
                task_id = task_id.decode('utf-8') if isinstance(task_id, bytes) else task_id

                # Get task info
                task_key = cls.TASK_STATUS_KEY.format(task_id=task_id)
                task_data = redis_client.get(task_key)

                if task_data:
                    task_info = json.loads(task_data)
                    created_at = task_info.get('created_at', '')

                    # Remove if too old
                    if created_at < cutoff_str:
                        redis_client.delete(task_key)
                        redis_client.client.srem(cls.ACTIVE_TASKS_KEY, task_id)
                        cleaned_count += 1

            logger.info(f"Cleaned up {cleaned_count} old tasks")

        except Exception as e:
            logger.error(f"Failed to cleanup old tasks: {e}")

    @classmethod
    def get_recent_findings(cls, limit: int = 10) -> List[Dict[str, Any]]:
        """Get recent findings across all files"""
        try:
            findings = Finding.query.order_by(desc(Finding.created_at)).limit(limit).all()

            return [{
                'id': finding.public_id.hex,
                'title': finding.title,
                'file_name': finding.file.filename,
                'file_sha': finding.file.sha256_hash,
                'confidence_level': finding.confidence_level,
                'category': finding.category,
                'created_at': finding.created_at.isoformat()
            } for finding in findings]

        except Exception as e:
            logger.error(f"Failed to get recent findings: {e}")
            return []

    @classmethod
    def get_analysis_stats(cls, user_id: int = None) -> Dict[str, Any]:
        """Get analysis statistics"""
        try:
            query = AnalysisFile.query
            if user_id:
                query = query.filter_by(created_by=user_id)

            total_files = query.count()
            complete_files = query.filter_by(status=FileStatus.COMPLETE).count()
            analyzing_files = query.filter_by(status=FileStatus.PROCESSING).count()
            pending_files = query.filter_by(status=FileStatus.PENDING).count()

            # Findings stats
            findings_query = Finding.query
            if user_id:
                findings_query = findings_query.join(AnalysisFile).filter(
                    AnalysisFile.created_by == user_id
                )

            total_findings = findings_query.count()
            crypto_findings = findings_query.filter_by(category='crypto').count()
            high_confidence = findings_query.filter(Finding.confidence_level >= 8).count()

            return {
                'files': {
                    'total': total_files,
                    'complete': complete_files,
                    'analyzing': analyzing_files,
                    'pending': pending_files,
                    'completion_rate': (complete_files / total_files * 100) if total_files > 0 else 0
                },
                'findings': {
                    'total': total_findings,
                    'crypto': crypto_findings,
                    'high_confidence': high_confidence,
                    'avg_per_file': (total_findings / complete_files) if complete_files > 0 else 0
                }
            }

        except Exception as e:
            logger.error(f"Failed to get analysis stats: {e}")
            return {
                'files': {'total': 0, 'complete': 0, 'analyzing': 0, 'pending': 0, 'completion_rate': 0},
                'findings': {'total': 0, 'crypto': 0, 'high_confidence': 0, 'avg_per_file': 0}
            }


# Celery task decorator for automatic tracking
def tracked_task(*args, **kwargs):
    """Decorator to automatically track Celery tasks"""
    def decorator(func):
        @celery_app.task(bind=True, *args, **kwargs)
        def wrapper(self, *task_args, **task_kwargs):
            task_id = self.request.id

            # Extract file_id and user_id from task arguments
            file_id = task_kwargs.get('file_id') or (task_args[0] if task_args else None)
            user_id = task_kwargs.get('user_id') or (task_args[2] if len(task_args) > 2 else None)

            if file_id and user_id:
                # Track task start
                BackgroundService.track_task(
                    task_id, 
                    func.__name__, 
                    file_id, 
                    user_id,
                    {'function': func.__name__}
                )

            try:
                # Update status to running
                BackgroundService.update_task_status(task_id, 'running')

                # Execute the actual task
                result = func(self, *task_args, **task_kwargs)

                # Update status to completed
                BackgroundService.update_task_status(task_id, 'completed')

                return result

            except Exception as e:
                # Update status to failed
                BackgroundService.update_task_status(
                    task_id, 
                    'failed', 
                    metadata={'error': str(e)}
                )
                raise

        return wrapper
    return decorator


# Example of using the tracked_task decorator
@tracked_task
def analyze_file_comprehensive(self, file_id: int, analysis_types: List[str], user_id: int, priority: int = 5):
    """Comprehensive file analysis with automatic tracking"""
    try:
        # Update progress
        self.update_state(state='PROGRESS', meta={'progress': 0, 'stage': 'Starting analysis'})
        BackgroundService.update_task_status(
            self.request.id, 'running', progress=0, stage='Starting analysis'
        )

        # Get file from database
        file_obj = AnalysisFile.query.get(file_id)
        if not file_obj:
            raise ValueError(f"File {file_id} not found")

        # Update file status
        file_obj.status = FileStatus.PROCESSING
        db.session.commit()

        # Progress updates throughout analysis
        stages = [
            (10, 'Reading file content'),
            (30, 'Extracting strings'),
            (50, 'Scanning crypto patterns'),
            (70, 'Analyzing metadata'),
            (90, 'Generating findings'),
            (100, 'Analysis complete')
        ]

        for progress, stage in stages:
            self.update_state(state='PROGRESS', meta={'progress': progress, 'stage': stage})
            BackgroundService.update_task_status(
                self.request.id, 'running', progress=progress, stage=stage
            )

            # Simulate analysis work (replace with real analysis)
            import time
            time.sleep(2)

        # Update file status to complete
        file_obj.status = FileStatus.COMPLETE
        file_obj.analyzed_at = datetime.utcnow()
        db.session.commit()

        return {
            'file_id': file_id,
            'analysis_types': analysis_types,
            'findings_created': 0,  # Would be actual count
            'duration': 'PT2M30S'  # ISO 8601 duration
        }

    except Exception as exc:
        # Update file status to error
        file_obj = AnalysisFile.query.get(file_id)
        if file_obj:
            file_obj.status = FileStatus.ERROR
            db.session.commit()
        raise
