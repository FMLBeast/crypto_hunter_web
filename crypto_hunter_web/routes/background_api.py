#!/usr/bin/env python3
"""
Background API Routes - Real implementation for task monitoring and control
"""

from flask import Blueprint, request, jsonify, session
from datetime import datetime, timedelta
from crypto_hunter_web.services.auth_service import AuthService
from crypto_hunter_web.services.background_service import BackgroundService
from crypto_hunter_web.models import db, AnalysisFile, Finding, User, FileStatus
from crypto_hunter_web.utils.decorators import rate_limit
import logging

background_api_bp = Blueprint('background_api', __name__)
logger = logging.getLogger(__name__)

@background_api_bp.route('/system/health')
@AuthService.login_required
def system_health():
    """Get system health status"""
    try:
        # Get system status
        status = BackgroundService.get_system_status()

        # Add database health check
        try:
            db.session.execute('SELECT 1')
            status['database_healthy'] = True
        except Exception as e:
            status['database_healthy'] = False
            status['database_error'] = str(e)

        # Calculate health score
        health_score = 100
        if not status['redis_connected']:
            health_score -= 30
        if not status['database_healthy']:
            health_score -= 40
        if status['workers']['online'] == 0:
            health_score -= 20

        status['health_score'] = max(0, health_score)
        status['status'] = 'healthy' if health_score >= 80 else 'degraded' if health_score >= 50 else 'unhealthy'

        return jsonify({
            'success': True,
            'health': status,
            'timestamp': datetime.utcnow().isoformat()
        })

    except Exception as e:
        logger.error(f"Error getting system health: {e}")
        return jsonify({
            'success': False,
            'error': str(e),
            'health_score': 0,
            'status': 'unhealthy'
        }), 500

@background_api_bp.route('/tasks/user')
@AuthService.login_required
def get_user_tasks():
    """Get all tasks for the current user"""
    try:
        user_id = session['user_id']

        # Get active tasks
        active_tasks = BackgroundService.get_user_active_tasks(user_id)

        # Get recent completed tasks from database
        recent_files = AnalysisFile.query.filter_by(created_by=user_id).filter(
            AnalysisFile.analyzed_at >= datetime.utcnow() - timedelta(hours=24)
        ).order_by(AnalysisFile.analyzed_at.desc()).limit(10).all()

        completed_tasks = []
        for file in recent_files:
            if file.status == FileStatus.COMPLETE:
                completed_tasks.append({
                    'task_type': 'file_analysis',
                    'file_id': file.id,
                    'file_name': file.filename,
                    'completed_at': file.analyzed_at.isoformat() if file.analyzed_at else None,
                    'duration': file.analysis_duration,
                    'findings_count': file.findings.count()
                })

        return jsonify({
            'success': True,
            'active_tasks': active_tasks,
            'completed_tasks': completed_tasks,
            'total_active': len(active_tasks),
            'total_completed_today': len(completed_tasks)
        })

    except Exception as e:
        logger.error(f"Error getting user tasks: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@background_api_bp.route('/tasks/<task_id>/status')
@AuthService.login_required
def get_task_status(task_id):
    """Get detailed status of a specific task"""
    try:
        # Get task status
        task_status = BackgroundService.get_task_status(task_id)

        # Verify user has access to this task
        user_id = session['user_id']
        if task_status.get('user_id') and task_status['user_id'] != user_id:
            return jsonify({'success': False, 'error': 'Access denied'}), 403

        # Enhance with additional information
        if task_status.get('file_id'):
            file = AnalysisFile.query.get(task_status['file_id'])
            if file:
                task_status['file_info'] = {
                    'filename': file.filename,
                    'file_size': file.file_size,
                    'file_type': file.file_type,
                    'current_status': file.status.value if hasattr(file.status, 'value') else str(file.status)
                }

        return jsonify({
            'success': True,
            'status': task_status
        })

    except Exception as e:
        logger.error(f"Error getting task status for {task_id}: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@background_api_bp.route('/tasks/<task_id>/cancel', methods=['POST'])
@AuthService.login_required
@rate_limit(limit="10 per minute")
def cancel_task(task_id):
    """Cancel a background task"""
    try:
        user_id = session['user_id']

        # Cancel the task
        success = BackgroundService.cancel_task(task_id, user_id)

        if success:
            AuthService.log_action('task_cancelled', f'Cancelled task: {task_id}')
            return jsonify({
                'success': True,
                'message': 'Task cancelled successfully'
            })
        else:
            return jsonify({
                'success': False,
                'error': 'Failed to cancel task or access denied'
            }), 403

    except Exception as e:
        logger.error(f"Error cancelling task {task_id}: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@background_api_bp.route('/stats')
@AuthService.login_required
def get_background_stats():
    """Get background processing statistics"""
    try:
        user_id = session['user_id']

        # Get user's analysis stats
        stats = BackgroundService.get_analysis_stats(user_id)

        # Add system-wide stats if user is admin
        user = User.query.get(user_id)
        if user and hasattr(user, 'is_admin') and user.is_admin:
            system_stats = BackgroundService.get_analysis_stats()
            stats['system'] = system_stats

        # Add recent activity
        stats['recent_activity'] = BackgroundService.get_recent_findings(limit=5)

        return jsonify({
            'success': True,
            'stats': stats,
            'timestamp': datetime.utcnow().isoformat()
        })

    except Exception as e:
        logger.error(f"Error getting background stats: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@background_api_bp.route('/queue/status')
@AuthService.login_required
def get_queue_status():
    """Get task queue status"""
    try:
        # Get Celery inspect information
        from crypto_hunter_web.services.celery_app import celery_app

        inspect = celery_app.control.inspect()

        # Get queue information
        active_tasks = inspect.active() or {}
        scheduled_tasks = inspect.scheduled() or {}
        reserved_tasks = inspect.reserved() or {}

        # Calculate totals
        total_active = sum(len(tasks) for tasks in active_tasks.values())
        total_scheduled = sum(len(tasks) for tasks in scheduled_tasks.values())
        total_reserved = sum(len(tasks) for tasks in reserved_tasks.values())

        # Get worker stats
        worker_stats = inspect.stats() or {}

        queue_info = {
            'active_tasks': total_active,
            'scheduled_tasks': total_scheduled,
            'reserved_tasks': total_reserved,
            'total_workers': len(worker_stats),
            'workers': [
                {
                    'name': worker_name,
                    'status': 'online',
                    'active_tasks': len(active_tasks.get(worker_name, [])),
                    'processed_tasks': stats.get('total', {}).get('total', 0)
                }
                for worker_name, stats in worker_stats.items()
            ]
        }

        return jsonify({
            'success': True,
            'queue': queue_info,
            'timestamp': datetime.utcnow().isoformat()
        })

    except Exception as e:
        logger.error(f"Error getting queue status: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@background_api_bp.route('/start', methods=['POST'])
@AuthService.login_required
@rate_limit(limit="4 per minute")  # Equivalent to 20 per 5 minutes
def start_background_task():
    """Start a new background task"""
    try:
        data = request.get_json()
        task_type = data.get('task_type')
        file_id = data.get('file_id')
        options = data.get('options', {})

        if not task_type or not file_id:
            return jsonify({
                'success': False,
                'error': 'task_type and file_id are required'
            }), 400

        # Verify file exists and user has access
        user_id = session['user_id']
        file = AnalysisFile.query.filter_by(id=file_id, created_by=user_id).first()

        if not file:
            return jsonify({
                'success': False,
                'error': 'File not found or access denied'
            }), 404

        # Start the appropriate task based on type
        task_id = None
        estimated_duration = None

        if task_type == 'comprehensive_analysis':
            from crypto_hunter_web.services.background_service import analyze_file_comprehensive
            task = analyze_file_comprehensive.delay(
                file_id=file_id,
                analysis_types=options.get('analysis_types', ['crypto', 'strings', 'metadata']),
                user_id=user_id,
                priority=options.get('priority', 5)
            )
            task_id = task.id
            estimated_duration = '2-10 minutes'

        elif task_type == 'llm_analysis':
            from crypto_hunter_web.services.llm_crypto_orchestrator import llm_orchestrated_analysis
            # Check if user has LLM permissions
            user = User.query.get(user_id)
            if not (user and hasattr(user, 'can_verify_findings') and user.can_verify_findings()):
                return jsonify({
                    'success': False,
                    'error': 'Insufficient permissions for LLM analysis'
                }), 403

            task = llm_orchestrated_analysis.delay(file_id)
            task_id = task.id
            estimated_duration = '3-8 minutes'

        elif task_type == 'deep_crypto_scan':
            # Add other task types as needed
            return jsonify({
                'success': False,
                'error': 'Task type not yet implemented'
            }), 501

        else:
            return jsonify({
                'success': False,
                'error': f'Unknown task type: {task_type}'
            }), 400

        if task_id:
            # Track the task
            BackgroundService.track_task(task_id, task_type, file_id, user_id, options)

            # Log the action
            AuthService.log_action('background_task_started', 
                                 f'Started {task_type} for {file.filename}', 
                                 file_id=file_id)

            return jsonify({
                'success': True,
                'task_id': task_id,
                'task_type': task_type,
                'estimated_duration': estimated_duration,
                'message': f'{task_type.replace("_", " ").title()} started successfully'
            })

        return jsonify({
            'success': False,
            'error': 'Failed to start task'
        }), 500

    except Exception as e:
        logger.error(f"Error starting background task: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@background_api_bp.route('/cleanup', methods=['POST'])
@AuthService.login_required
def cleanup_old_tasks():
    """Clean up old task data (admin only)"""
    try:
        user_id = session['user_id']
        user = User.query.get(user_id)

        # Check admin permissions
        if not (user and hasattr(user, 'is_admin') and user.is_admin):
            return jsonify({
                'success': False,
                'error': 'Admin access required'
            }), 403

        data = request.get_json() or {}
        days = data.get('days', 7)

        # Perform cleanup
        BackgroundService.cleanup_old_tasks(days)

        AuthService.log_action('system_cleanup', f'Cleaned up tasks older than {days} days')

        return jsonify({
            'success': True,
            'message': f'Cleaned up tasks older than {days} days'
        })

    except Exception as e:
        logger.error(f"Error during cleanup: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@background_api_bp.route('/monitor/live')
@AuthService.login_required
def live_monitor():
    """Get live monitoring data for dashboard"""
    try:
        user_id = session['user_id']

        # Get real-time data
        active_tasks = BackgroundService.get_user_active_tasks(user_id)
        system_status = BackgroundService.get_system_status()

        # Get file analysis progress
        analyzing_files = AnalysisFile.query.filter_by(
            created_by=user_id, 
            status=FileStatus.PROCESSING
        ).count()

        pending_files = AnalysisFile.query.filter_by(
            created_by=user_id, 
            status=FileStatus.PENDING
        ).count()

        # Recent findings (last hour)
        recent_findings = Finding.query.join(AnalysisFile).filter(
            AnalysisFile.created_by == user_id,
            Finding.created_at >= datetime.utcnow() - timedelta(hours=1)
        ).count()

        monitor_data = {
            'active_tasks': len(active_tasks),
            'analyzing_files': analyzing_files,
            'pending_files': pending_files,
            'recent_findings': recent_findings,
            'workers_online': system_status['workers']['online'],
            'redis_connected': system_status['redis_connected'],
            'system_load': {
                'active_system_tasks': system_status['tasks']['active_count'],
                'total_analyzing': system_status['tasks']['analyzing_files']
            },
            'tasks_detail': [
                {
                    'id': task['task_id'],
                    'type': task.get('task_type', 'unknown'),
                    'progress': task.get('progress', 0),
                    'stage': task.get('current_stage', 'processing'),
                    'file_name': task.get('metadata', {}).get('file_name', 'Unknown')
                }
                for task in active_tasks
            ]
        }

        return jsonify({
            'success': True,
            'monitor': monitor_data,
            'timestamp': datetime.utcnow().isoformat()
        })

    except Exception as e:
        logger.error(f"Error getting live monitor data: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@background_api_bp.route('/task/<task_id>/logs')
@AuthService.login_required
def get_task_logs(task_id):
    """Get logs for a specific task"""
    try:
        user_id = session['user_id']

        # Get task status to verify access
        task_status = BackgroundService.get_task_status(task_id)

        if task_status.get('user_id') and task_status['user_id'] != user_id:
            return jsonify({'success': False, 'error': 'Access denied'}), 403

        # For now, return the task metadata as "logs"
        # In a full implementation, you'd read actual log files
        logs = []

        if task_status.get('metadata'):
            logs.append({
                'timestamp': task_status.get('created_at', ''),
                'level': 'INFO',
                'message': f"Task {task_id} started"
            })

            if task_status.get('updated_at'):
                logs.append({
                    'timestamp': task_status.get('updated_at', ''),
                    'level': 'INFO',
                    'message': f"Task status: {task_status.get('state', 'unknown')}"
                })

        # Add any error information
        if task_status.get('state') == 'FAILURE' and task_status.get('meta'):
            logs.append({
                'timestamp': task_status.get('updated_at', ''),
                'level': 'ERROR',
                'message': str(task_status['meta'])
            })

        return jsonify({
            'success': True,
            'task_id': task_id,
            'logs': logs
        })

    except Exception as e:
        logger.error(f"Error getting task logs for {task_id}: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500
