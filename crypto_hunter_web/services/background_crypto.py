# crypto_hunter_web/services/background_crypto.py - COMPLETE IMPROVED VERSION

import json
import time
import logging
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional
from celery import chord, group
from sqlalchemy.exc import SQLAlchemyError

from crypto_hunter_web import db
from crypto_hunter_web.models import AnalysisFile, FileContent
from crypto_hunter_web.tasks.crypto_tasks import (
    crypto_pattern_deep_scan,
    ethereum_comprehensive_analysis,
    cipher_comprehensive_analysis,
    hash_cracking_analysis,
    combine_analysis_results,
    generate_summary_findings,
    continuous_crypto_monitor
)
from crypto_hunter_web.utils.redis_client_util import redis_client
from crypto_hunter_web.services.celery_app import celery_app
from crypto_hunter_web.tasks.maintenance_tasks import system_health_check

logger = logging.getLogger(__name__)

# Standalone functions for compatibility with imports
def cleanup_old_tasks():
    """Clean up old task records - standalone function that calls TaskRegistry method"""
    return TaskRegistry.cleanup_old_tasks()

# Re-export imported functions for compatibility
# These are imported from other modules but need to be available here for imports

# Re-export continuous_crypto_monitor from tasks.crypto_tasks
# This is already imported above, just making it explicitly available
__all__ = ['cleanup_old_tasks', 'continuous_crypto_monitor', 'system_health_check', 'manage_priority_queue']

def manage_priority_queue(max_items: int = 10):
    """
    Manage priority queue for crypto analysis tasks
    This is a placeholder implementation that uses BackgroundCryptoManager
    """
    logger.info(f"Managing priority queue with max_items={max_items}")
    try:
        # Use existing BackgroundCryptoManager functionality
        # to process high-priority items
        return BackgroundCryptoManager.start_continuous_analysis(
            priority_threshold=7,  # Higher priority threshold
            batch_size=max_items
        )
    except Exception as e:
        logger.error(f"Error managing priority queue: {e}")
        return 0


class TaskRegistry:
    """Enhanced task registry for monitoring and coordination"""

    ACTIVE_TASKS = "crypto_active_tasks"
    COMPLETED_TASKS = "crypto_completed_tasks"
    FAILED_TASKS = "crypto_failed_tasks"
    TASK_RESULTS = "crypto_task_results"

    @staticmethod
    def register_task(task_id: str, file_id: int, task_type: str, metadata: Dict[str, Any] = None):
        """Register a new task"""
        task_data = {
            'task_id': task_id,
            'file_id': file_id,
            'task_type': task_type,
            'started_at': datetime.utcnow().isoformat(),
            'status': 'running',
            'metadata': metadata or {}
        }

        redis_client.hset(TaskRegistry.ACTIVE_TASKS, task_id, json.dumps(task_data))
        redis_client.expire(TaskRegistry.ACTIVE_TASKS, 86400)  # 24 hour expiry

        logger.info(f"Registered task {task_id} for file {file_id} ({task_type})")

    @staticmethod
    def complete_task(task_id: str, result: Dict[str, Any]):
        """Mark task as completed with result"""
        # Move from active to completed
        task_data = redis_client.hget(TaskRegistry.ACTIVE_TASKS, task_id)
        if task_data:
            task_info = json.loads(task_data)
            task_info['status'] = 'completed'
            task_info['completed_at'] = datetime.utcnow().isoformat()
            task_info['result'] = result

            redis_client.hset(TaskRegistry.COMPLETED_TASKS, task_id, json.dumps(task_info))
            redis_client.hdel(TaskRegistry.ACTIVE_TASKS, task_id)
            redis_client.hset(TaskRegistry.TASK_RESULTS, task_id, json.dumps(result))

            # Set expiry on results
            redis_client.expire(TaskRegistry.COMPLETED_TASKS, 86400)
            redis_client.expire(TaskRegistry.TASK_RESULTS, 86400)

            logger.info(f"Completed task {task_id}")

    @staticmethod
    def fail_task(task_id: str, error: str):
        """Mark task as failed"""
        task_data = redis_client.hget(TaskRegistry.ACTIVE_TASKS, task_id)
        if task_data:
            task_info = json.loads(task_data)
            task_info['status'] = 'failed'
            task_info['failed_at'] = datetime.utcnow().isoformat()
            task_info['error'] = error

            redis_client.hset(TaskRegistry.FAILED_TASKS, task_id, json.dumps(task_info))
            redis_client.hdel(TaskRegistry.ACTIVE_TASKS, task_id)

            redis_client.expire(TaskRegistry.FAILED_TASKS, 86400)

            logger.error(f"Failed task {task_id}: {error}")

    @staticmethod
    def get_task_status(task_id: str) -> Optional[Dict[str, Any]]:
        """Get status of a task"""
        # Check active tasks first
        task_data = redis_client.hget(TaskRegistry.ACTIVE_TASKS, task_id)
        if task_data:
            return json.loads(task_data)

        # Check completed tasks
        task_data = redis_client.hget(TaskRegistry.COMPLETED_TASKS, task_id)
        if task_data:
            return json.loads(task_data)

        # Check failed tasks
        task_data = redis_client.hget(TaskRegistry.FAILED_TASKS, task_id)
        if task_data:
            return json.loads(task_data)

        return None

    @staticmethod
    def get_task_result(task_id: str) -> Optional[Dict[str, Any]]:
        """Get result of a completed task"""
        result_data = redis_client.hget(TaskRegistry.TASK_RESULTS, task_id)
        return json.loads(result_data) if result_data else None

    @staticmethod
    def cleanup_old_tasks():
        """Clean up old task records"""
        try:
            # Clean up tasks older than 24 hours
            cutoff_time = datetime.utcnow() - timedelta(hours=24)
            cutoff_str = cutoff_time.isoformat()

            for registry in [TaskRegistry.ACTIVE_TASKS, TaskRegistry.COMPLETED_TASKS, TaskRegistry.FAILED_TASKS]:
                task_ids = redis_client.hkeys(registry)
                for task_id in task_ids:
                    task_data = redis_client.hget(registry, task_id)
                    if task_data:
                        task_info = json.loads(task_data)
                        if task_info.get('started_at', '') < cutoff_str:
                            redis_client.hdel(registry, task_id)
                            redis_client.hdel(TaskRegistry.TASK_RESULTS, task_id)

            logger.info("Cleaned up old task records")
        except Exception as e:
            logger.error(f"Error cleaning up tasks: {e}")


class BackgroundCryptoManager:
    """Enhanced background crypto analysis manager using chord coordination"""

    @staticmethod
    def start_continuous_analysis(priority_threshold: int = 5, batch_size: int = 50):
        """Start background analysis for unprocessed files, using parallel task chords."""
        try:
            # Fetch files not yet fully analyzed, above priority threshold
            unprocessed_files = db.session.query(AnalysisFile).filter(
                ~AnalysisFile.id.in_(
                    db.session.query(FileContent.file_id)
                    .filter(FileContent.content_type == 'crypto_background_complete')
                ),
                AnalysisFile.priority >= priority_threshold
            ).order_by(AnalysisFile.priority.desc()).limit(batch_size).all()

            if not unprocessed_files:
                logger.info("No unprocessed files found for analysis batch.")
                return 0

            count = 0
            for file in unprocessed_files:
                # Determine which analysis tasks to run based on file or global settings
                analysis_tasks = []

                # Always include base pattern analysis (deep scan) for comprehensive coverage
                analysis_tasks.append(crypto_pattern_deep_scan.s(file.id))

                # If the file might contain blockchain data or keys, include Ethereum analysis
                analysis_tasks.append(ethereum_comprehensive_analysis.s(file.id))

                # Always include cipher analysis (it will internally skip if not applicable)
                analysis_tasks.append(cipher_comprehensive_analysis.s(file.id))

                # Include hash cracking if any hash patterns were detected in initial scan
                analysis_tasks.append(hash_cracking_analysis.s(file.id, []))

                # Register each task for monitoring (task IDs will be available after delay)
                chord_job = chord(analysis_tasks)(combine_analysis_results.s(file.id))

                # Register the chord job
                TaskRegistry.register_task(
                    str(chord_job.id), 
                    file.id, 
                    'comprehensive_analysis_chord',
                    {'subtask_count': len(analysis_tasks)}
                )

                count += 1
                logger.info(f"Queued analysis chord for file {file.id} ({file.filename}) with {len(analysis_tasks)} tasks.")

            # Ensure the monitor is running to catch new files (optional, since chords will run anyway)
            if not redis_client.get('monitor_running'):
                from crypto_hunter_web.tasks.crypto_tasks import continuous_crypto_monitor
                continuous_crypto_monitor.delay()

            logger.info(f"Started background analysis for {count} files in this batch.")
            return count

        except Exception as e:
            logger.error(f"Error in continuous analysis scheduling: {e}")
            return 0

    @staticmethod
    def queue_priority_analysis(file_id: int, analysis_types: List[str] = None) -> Dict[str, Any]:
        """Queue high-priority analysis using chord coordination"""
        try:
            file = AnalysisFile.query.get(file_id)
            if not file:
                return {'error': 'File not found', 'file_id': file_id}

            # Default analysis types if not specified
            if not analysis_types:
                analysis_types = ['pattern', 'ethereum', 'cipher', 'hash']

            # Build task list based on requested analysis types
            analysis_tasks = []
            task_mapping = {
                'pattern': crypto_pattern_deep_scan,
                'ethereum': ethereum_comprehensive_analysis,
                'cipher': cipher_comprehensive_analysis,
                'hash': hash_cracking_analysis
            }

            for analysis_type in analysis_types:
                if analysis_type in task_mapping:
                    if analysis_type == 'hash':
                        # Hash cracking needs additional parameters
                        analysis_tasks.append(task_mapping[analysis_type].s(file_id, []))
                    else:
                        analysis_tasks.append(task_mapping[analysis_type].s(file_id))

            if not analysis_tasks:
                return {'error': 'No valid analysis types specified', 'file_id': file_id}

            # Create chord with callback to combine results
            callback = combine_analysis_results.s(file_id)
            chord_job = chord(analysis_tasks)(callback)

            # Register the chord in our tracking system
            TaskRegistry.register_task(
                str(chord_job.id),
                file_id,
                'priority_analysis_chord',
                {
                    'analysis_types': analysis_types,
                    'subtask_count': len(analysis_tasks),
                    'priority': True
                }
            )

            logger.info(f"Queued priority analysis chord {chord_job.id} for file {file_id} with types: {analysis_types}")

            return {
                'success': True,
                'chord_id': str(chord_job.id),
                'file_id': file_id,
                'analysis_types': analysis_types,
                'task_count': len(analysis_tasks)
            }

        except Exception as e:
            logger.error(f"Error queueing priority analysis for file {file_id}: {e}")
            return {'error': str(e), 'file_id': file_id}

    @staticmethod
    def get_analysis_progress(file_id: int) -> Dict[str, Any]:
        """Get analysis progress for a specific file"""
        try:
            # Check for completed analysis
            completed_content = FileContent.query.filter_by(
                file_id=file_id,
                content_type='crypto_background_complete'
            ).first()

            if completed_content:
                try:
                    results = json.loads(completed_content.content_text)
                    return {
                        'status': 'completed',
                        'completed_at': completed_content.extracted_at.isoformat(),
                        'results': results
                    }
                except:
                    pass

            # Check active tasks for this file
            active_tasks = []
            task_ids = redis_client.hkeys(TaskRegistry.ACTIVE_TASKS)

            for task_id in task_ids:
                task_data = redis_client.hget(TaskRegistry.ACTIVE_TASKS, task_id)
                if task_data:
                    task_info = json.loads(task_data)
                    if task_info.get('file_id') == file_id:
                        active_tasks.append(task_info)

            if active_tasks:
                return {
                    'status': 'in_progress',
                    'active_tasks': active_tasks,
                    'task_count': len(active_tasks)
                }

            # Check for any partial results
            partial_content = FileContent.query.filter(
                FileContent.file_id == file_id,
                FileContent.content_type.like('crypto_%')
            ).all()

            if partial_content:
                return {
                    'status': 'partial',
                    'partial_results': [
                        {
                            'type': content.content_type,
                            'extracted_at': content.extracted_at.isoformat()
                        }
                        for content in partial_content
                    ]
                }

            return {'status': 'not_started'}

        except Exception as e:
            logger.error(f"Error getting analysis progress for file {file_id}: {e}")
            return {'status': 'error', 'error': str(e)}

    @staticmethod
    def get_system_stats() -> Dict[str, Any]:
        """Get comprehensive system statistics"""
        try:
            stats = {
                'active_tasks': 0,
                'completed_tasks': 0,
                'failed_tasks': 0,
                'files_analyzed': 0,
                'files_pending': 0,
                'avg_analysis_time': 0,
                'system_health': 'unknown'
            }

            # Count tasks in each state
            stats['active_tasks'] = redis_client.hlen(TaskRegistry.ACTIVE_TASKS)
            stats['completed_tasks'] = redis_client.hlen(TaskRegistry.COMPLETED_TASKS)
            stats['failed_tasks'] = redis_client.hlen(TaskRegistry.FAILED_TASKS)

            # Count files by analysis status
            stats['files_analyzed'] = db.session.query(FileContent).filter(
                FileContent.content_type == 'crypto_background_complete'
            ).count()

            total_files = db.session.query(AnalysisFile).count()
            stats['files_pending'] = total_files - stats['files_analyzed']

            # Calculate average analysis time from completed tasks
            completed_task_ids = redis_client.hkeys(TaskRegistry.COMPLETED_TASKS)
            if completed_task_ids:
                total_time = 0
                time_count = 0

                for task_id in completed_task_ids[:100]:  # Sample last 100 tasks
                    task_data = redis_client.hget(TaskRegistry.COMPLETED_TASKS, task_id)
                    if task_data:
                        task_info = json.loads(task_data)
                        if 'started_at' in task_info and 'completed_at' in task_info:
                            try:
                                start_time = datetime.fromisoformat(task_info['started_at'])
                                end_time = datetime.fromisoformat(task_info['completed_at'])
                                duration = (end_time - start_time).total_seconds()
                                total_time += duration
                                time_count += 1
                            except:
                                pass

                if time_count > 0:
                    stats['avg_analysis_time'] = total_time / time_count

            # Determine system health
            active_ratio = stats['active_tasks'] / max(1, stats['active_tasks'] + stats['completed_tasks'])
            failure_ratio = stats['failed_tasks'] / max(1, stats['completed_tasks'] + stats['failed_tasks'])

            if failure_ratio > 0.2:
                stats['system_health'] = 'critical'
            elif failure_ratio > 0.1 or active_ratio > 0.8:
                stats['system_health'] = 'warning'
            else:
                stats['system_health'] = 'healthy'

            return stats

        except Exception as e:
            logger.error(f"Error getting system stats: {e}")
            return {'error': str(e)}

    @staticmethod
    def cleanup_stale_tasks():
        """Clean up stale and abandoned tasks"""
        try:
            cleanup_count = 0
            cutoff_time = datetime.utcnow() - timedelta(hours=2)  # Tasks running > 2 hours are stale
            cutoff_str = cutoff_time.isoformat()

            # Check for stale active tasks
            task_ids = redis_client.hkeys(TaskRegistry.ACTIVE_TASKS)
            for task_id in task_ids:
                task_data = redis_client.hget(TaskRegistry.ACTIVE_TASKS, task_id)
                if task_data:
                    task_info = json.loads(task_data)
                    if task_info.get('started_at', '') < cutoff_str:
                        # Mark as failed due to timeout
                        TaskRegistry.fail_task(task_id, 'Task timeout - exceeded maximum runtime')
                        cleanup_count += 1

            # Clean up old records
            TaskRegistry.cleanup_old_tasks()

            logger.info(f"Cleaned up {cleanup_count} stale tasks")
            return cleanup_count

        except Exception as e:
            logger.error(f"Error during cleanup: {e}")
            return 0

    @staticmethod
    def store_background_results(file_id: int, results: Dict[str, Any]):
        """Store comprehensive background analysis results"""
        try:
            # Check if results already exist
            existing_content = FileContent.query.filter_by(
                file_id=file_id,
                content_type='crypto_background_complete'
            ).first()

            if existing_content:
                # Update existing results
                existing_content.content_text = json.dumps(results, indent=2)
                existing_content.content_size = len(json.dumps(results))
                existing_content.extracted_at = datetime.utcnow()
            else:
                # Create new results record
                content = FileContent(
                    file_id=file_id,
                    content_type='crypto_background_complete',
                    content_text=json.dumps(results, indent=2),
                    content_size=len(json.dumps(results)),
                    extracted_at=datetime.utcnow()
                )
                db.session.add(content)

            db.session.commit()

            # Trigger summary findings generation
            generate_summary_findings.delay(file_id, results)

            logger.info(f"Stored background results for file {file_id}")

        except SQLAlchemyError as e:
            db.session.rollback()
            logger.error(f"Database error storing results for file {file_id}: {e}")
            raise
        except Exception as e:
            logger.error(f"Error storing background results for file {file_id}: {e}")
            raise

    @staticmethod
    def get_background_results(file_id: int) -> Optional[Dict[str, Any]]:
        """Retrieve background analysis results for a file"""
        try:
            content = FileContent.query.filter_by(
                file_id=file_id,
                content_type='crypto_background_complete'
            ).first()

            if content and content.content_text:
                return {
                    'results': json.loads(content.content_text),
                    'analyzed_at': content.extracted_at.isoformat(),
                    'content_size': content.content_size
                }

        except Exception as e:
            logger.error(f"Error retrieving background results for file {file_id}: {e}")

        return None
