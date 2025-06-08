# crypto_hunter_web/services/background_service.py - UNIFIED BACKGROUND SERVICE

import os
import json
import logging
import traceback
from datetime import datetime, timedelta
from typing import Dict, List, Any
import redis

# Import unified Celery app
from crypto_hunter_web.services.celery_app import celery_app
from crypto_hunter_web.models import db, AnalysisFile, FileContent, AuditLog

logger = logging.getLogger(__name__)


class BackgroundService:
    """Unified service for managing background analysis tasks"""

    def __init__(self):
        """Initialize background service"""
        self.redis_client = None
        try:
            redis_url = os.getenv('REDIS_URL', 'redis://localhost:6379/0')
            self.redis_client = redis.from_url(redis_url)
        except Exception as e:
            logger.warning(f"Redis not available for background service: {e}")

    @classmethod
    def queue_comprehensive_analysis(cls, file_id: int, analysis_types: List[str],
                                     user_id: int, priority: int = 5) -> str:
        """Queue comprehensive file analysis"""
        try:
            task = analyze_file_comprehensive.apply_async(
                args=[file_id, analysis_types, user_id],
                kwargs={'priority': priority},
                queue='analysis',
                priority=priority
            )

            # Track task
            cls._track_task(task.id, 'comprehensive_analysis', file_id, user_id)

            logger.info(f"Queued comprehensive analysis for file {file_id}: {task.id}")
            return task.id

        except Exception as e:
            logger.error(f"Failed to queue comprehensive analysis: {e}")
            raise

    @classmethod
    def queue_crypto_analysis(cls, file_id: int, analysis_options: Dict,
                              user_id: int) -> str:
        """Queue cryptocurrency pattern analysis"""
        try:
            task = analyze_crypto_patterns.apply_async(
                args=[file_id, analysis_options, user_id],
                queue='crypto'
            )

            # Track task
            cls._track_task(task.id, 'crypto_analysis', file_id, user_id)

            logger.info(f"Queued crypto analysis for file {file_id}: {task.id}")
            return task.id

        except Exception as e:
            logger.error(f"Failed to queue crypto analysis: {e}")
            raise

    @classmethod
    def queue_ai_analysis(cls, file_id: int, ai_options: Dict, user_id: int) -> str:
        """Queue AI-powered analysis"""
        try:
            task = process_ai_analysis.apply_async(
                args=[file_id, ai_options, user_id],
                queue='ai'
            )

            # Track task
            cls._track_task(task.id, 'ai_analysis', file_id, user_id)

            logger.info(f"Queued AI analysis for file {file_id}: {task.id}")
            return task.id

        except Exception as e:
            logger.error(f"Failed to queue AI analysis: {e}")
            raise

    @classmethod
    def get_task_status(cls, task_id: str) -> Dict[str, Any]:
        """Get task status and result"""
        try:
            from celery.result import AsyncResult
            result = AsyncResult(task_id, app=celery_app)

            return {
                'task_id': task_id,
                'state': result.state,
                'result': result.result,
                'traceback': result.traceback,
                'successful': result.successful(),
                'failed': result.failed(),
                'ready': result.ready()
            }
        except Exception as e:
            logger.error(f"Failed to get task status: {e}")
            return {'error': str(e)}

    @classmethod
    def cancel_task(cls, task_id: str) -> bool:
        """Cancel a running task"""
        try:
            celery_app.control.revoke(task_id, terminate=True)
            logger.info(f"Cancelled task: {task_id}")
            return True
        except Exception as e:
            logger.error(f"Failed to cancel task {task_id}: {e}")
            return False

    @classmethod
    def get_queue_status(cls) -> Dict[str, Any]:
        """Get status of all queues"""
        try:
            inspect = celery_app.control.inspect()

            active = inspect.active()
            reserved = inspect.reserved()
            stats = inspect.stats()

            return {
                'active_tasks': active or {},
                'reserved_tasks': reserved or {},
                'worker_stats': stats or {}
            }
        except Exception as e:
            logger.error(f"Failed to get queue status: {e}")
            return {}

    @classmethod
    def _track_task(cls, task_id: str, task_type: str, file_id: int, user_id: int):
        """Track task in Redis for monitoring"""
        try:
            service = cls()
            if not service.redis_client:
                return

            task_info = {
                'task_id': task_id,
                'task_type': task_type,
                'file_id': file_id,
                'user_id': user_id,
                'created_at': datetime.utcnow().isoformat(),
                'status': 'PENDING'
            }

            # Store task info
            task_key = f"task:{task_id}"
            service.redis_client.setex(task_key, 86400, json.dumps(task_info))  # 24 hour TTL

            # Add to user's task list
            user_tasks_key = f"user_tasks:{user_id}"
            service.redis_client.lpush(user_tasks_key, task_id)
            service.redis_client.ltrim(user_tasks_key, 0, 99)  # Keep last 100 tasks
            service.redis_client.expire(user_tasks_key, 86400 * 7)  # 7 days

        except Exception as e:
            logger.error(f"Failed to track task: {e}")


# Celery Tasks - Using unified app

@celery_app.task(bind=True, name='crypto_hunter_web.services.background_service.analyze_file_comprehensive')
def analyze_file_comprehensive(self, file_id: int, analysis_types: List[str],
                               user_id: int, priority: int = 5):
    """Comprehensive file analysis task"""
    try:
        # Update task status
        self.update_state(state='PROGRESS', meta={'progress': 0, 'stage': 'Starting analysis'})

        # Get file from database
        file_obj = AnalysisFile.query.get(file_id)
        if not file_obj:
            raise ValueError(f"File {file_id} not found")

        # Update file status
        file_obj.status = 'processing'
        db.session.commit()

        # Import analyzer here to avoid circular imports
        from crypto_hunter_web.services.content_analyzer import ContentAnalyzer
        analyzer = ContentAnalyzer()

        # Update progress
        self.update_state(state='PROGRESS', meta={'progress': 10, 'stage': 'Initializing analysis'})

        # Perform analysis
        start_time = datetime.utcnow()
        analysis_results = analyzer.analyze_file_comprehensive(file_obj, analysis_types)
        end_time = datetime.utcnow()

        duration = (end_time - start_time).total_seconds()

        # Update progress
        self.update_state(state='PROGRESS', meta={'progress': 80, 'stage': 'Saving results'})

        # Save analysis results
        content_entry = FileContent(
            file_id=file_obj.id,
            content_type='comprehensive_analysis_background',
            content_format='json',
            content_json=analysis_results,
            content_size=len(json.dumps(analysis_results)),
            extracted_by=user_id,
            extraction_method='background_comprehensive_analysis'
        )

        db.session.add(content_entry)

        # Update file status
        file_obj.status = 'analyzed'
        file_obj.analysis_completed_at = end_time
        db.session.commit()

        # Log completion
        AuditLog.log_action(
            user_id=user_id,
            action='background_analysis_completed',
            description=f'Background comprehensive analysis completed for {file_obj.filename}',
            resource_type='file',
            resource_id=file_obj.sha256_hash,
            metadata={
                'analysis_types': analysis_types,
                'duration_seconds': duration,
                'task_id': self.request.id,
                'priority': priority
            }
        )

        # Final progress update
        self.update_state(state='SUCCESS', meta={'progress': 100, 'stage': 'Analysis complete'})

        return {
            'success': True,
            'file_id': file_id,
            'duration_seconds': duration,
            'analysis_types': analysis_types,
            'findings_count': len(analysis_results.get('findings', []))
        }

    except Exception as e:
        logger.error(f"Comprehensive analysis failed for file {file_id}: {e}", exc_info=True)

        # Update file status on error
        try:
            file_obj = AnalysisFile.query.get(file_id)
            if file_obj:
                file_obj.status = 'error'
                db.session.commit()
        except:
            pass

        self.update_state(
            state='FAILURE',
            meta={
                'error': str(e),
                'traceback': traceback.format_exc(),
                'stage': 'Failed'
            }
        )

        raise


@celery_app.task(bind=True, name='crypto_hunter_web.services.background_service.analyze_crypto_patterns')
def analyze_crypto_patterns(self, file_id: int, analysis_options: Dict, user_id: int):
    """Cryptocurrency pattern analysis task"""
    try:
        # Update task status
        self.update_state(state='PROGRESS', meta={'progress': 0, 'stage': 'Starting crypto analysis'})

        # Get file from database
        file_obj = AnalysisFile.query.get(file_id)
        if not file_obj:
            raise ValueError(f"File {file_id} not found")

        # Import analyzer here to avoid circular imports
        from crypto_hunter_web.services.crypto_analyzer import CryptoAnalyzer
        analyzer = CryptoAnalyzer()

        # Update progress
        self.update_state(state='PROGRESS', meta={'progress': 20, 'stage': 'Analyzing crypto patterns'})

        # Perform crypto analysis
        start_time = datetime.utcnow()
        crypto_results = analyzer.analyze_crypto_patterns(file_obj, analysis_options)
        end_time = datetime.utcnow()

        duration = (end_time - start_time).total_seconds()

        # Update progress
        self.update_state(state='PROGRESS', meta={'progress': 80, 'stage': 'Saving crypto results'})

        # Save crypto analysis results
        content_entry = FileContent(
            file_id=file_obj.id,
            content_type='crypto_analysis_background',
            content_format='json',
            content_json=crypto_results,
            content_size=len(json.dumps(crypto_results)),
            extracted_by=user_id,
            extraction_method='background_crypto_analysis'
        )

        db.session.add(content_entry)
        db.session.commit()

        # Log completion
        AuditLog.log_action(
            user_id=user_id,
            action='background_crypto_analysis_completed',
            description=f'Background crypto analysis completed for {file_obj.filename}',
            resource_type='file',
            resource_id=file_obj.sha256_hash,
            metadata={
                'analysis_options': analysis_options,
                'duration_seconds': duration,
                'task_id': self.request.id
            }
        )

        # Final progress update
        self.update_state(state='SUCCESS', meta={'progress': 100, 'stage': 'Crypto analysis complete'})

        return {
            'success': True,
            'file_id': file_id,
            'duration_seconds': duration,
            'patterns_found': len(crypto_results.get('patterns', [])),
            'confidence_score': crypto_results.get('confidence', 0.0)
        }

    except Exception as e:
        logger.error(f"Crypto analysis failed for file {file_id}: {e}", exc_info=True)

        self.update_state(
            state='FAILURE',
            meta={
                'error': str(e),
                'traceback': traceback.format_exc(),
                'stage': 'Failed'
            }
        )

        raise


@celery_app.task(bind=True, name='crypto_hunter_web.services.background_service.process_ai_analysis')
def process_ai_analysis(self, file_id: int, ai_options: Dict, user_id: int):
    """AI-powered analysis task"""
    try:
        # Update task status
        self.update_state(state='PROGRESS', meta={'progress': 0, 'stage': 'Starting AI analysis'})

        # Get file from database
        file_obj = AnalysisFile.query.get(file_id)
        if not file_obj:
            raise ValueError(f"File {file_id} not found")

        # Import AI service here to avoid circular imports
        from crypto_hunter_web.services.ai_service import AIService
        ai_service = AIService()

        # Update progress
        self.update_state(state='PROGRESS', meta={'progress': 20, 'stage': 'Processing with AI'})

        # Perform AI analysis
        start_time = datetime.utcnow()
        ai_results = ai_service.analyze_file(file_obj, ai_options)
        end_time = datetime.utcnow()

        duration = (end_time - start_time).total_seconds()

        # Update progress
        self.update_state(state='PROGRESS', meta={'progress': 80, 'stage': 'Saving AI results'})

        # Save AI analysis results
        content_entry = FileContent(
            file_id=file_obj.id,
            content_type='ai_analysis_background',
            content_format='json',
            content_json=ai_results,
            content_size=len(json.dumps(ai_results)),
            extracted_by=user_id,
            extraction_method='background_ai_analysis'
        )

        db.session.add(content_entry)
        db.session.commit()

        # Log completion
        AuditLog.log_action(
            user_id=user_id,
            action='background_ai_analysis_completed',
            description=f'Background AI analysis completed for {file_obj.filename}',
            resource_type='file',
            resource_id=file_obj.sha256_hash,
            metadata={
                'ai_options': ai_options,
                'duration_seconds': duration,
                'task_id': self.request.id
            }
        )

        # Final progress update
        self.update_state(state='SUCCESS', meta={'progress': 100, 'stage': 'AI analysis complete'})

        return {
            'success': True,
            'file_id': file_id,
            'duration_seconds': duration,
            'ai_confidence': ai_results.get('confidence', 0.0),
            'insights_generated': len(ai_results.get('insights', []))
        }

    except Exception as e:
        logger.error(f"AI analysis failed for file {file_id}: {e}", exc_info=True)

        self.update_state(
            state='FAILURE',
            meta={
                'error': str(e),
                'traceback': traceback.format_exc(),
                'stage': 'Failed'
            }
        )

        raise


@celery_app.task(name='crypto_hunter_web.services.background_service.cleanup_old_tasks')
def cleanup_old_tasks():
    """Periodic task to clean up old task records and results"""
    try:
        # Clean up old Celery results
        cutoff_date = datetime.utcnow() - timedelta(days=7)

        # Clean up old file content entries
        old_content = FileContent.query.filter(
            FileContent.extracted_at < cutoff_date,
            FileContent.content_type.in_([
                'comprehensive_analysis_background',
                'crypto_analysis_background',
                'ai_analysis_background'
            ])
        ).all()

        for content in old_content:
            db.session.delete(content)

        db.session.commit()

        logger.info(f"Cleaned up {len(old_content)} old task records")

        return {
            'success': True,
            'cleanup_date': cutoff_date.isoformat(),
            'records_cleaned': len(old_content),
            'message': 'Old task records cleaned up successfully'
        }

    except Exception as e:
        logger.error(f"Task cleanup failed: {e}")
        raise


@celery_app.task(name='crypto_hunter_web.services.background_service.health_check')
def health_check():
    """Periodic health check task"""
    try:
        # Test database connection
        db.session.execute('SELECT 1')

        # Get basic stats
        file_count = AnalysisFile.query.count()
        content_count = FileContent.query.count()

        return {
            'success': True,
            'timestamp': datetime.utcnow().isoformat(),
            'database': 'healthy',
            'stats': {
                'total_files': file_count,
                'total_content': content_count
            }
        }
    except Exception as e:
        logger.error(f"Health check failed: {e}")
        return {
            'success': False,
            'error': str(e),
            'timestamp': datetime.utcnow().isoformat()
        }