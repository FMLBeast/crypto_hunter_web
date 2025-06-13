#!/usr/bin/env python3
# crypto_hunter_web/routes/dashboard.py - Updated with real data integration

from flask import Blueprint, render_template, jsonify, current_app, session
from sqlalchemy import func, desc, and_
from datetime import datetime, timedelta
import logging

dashboard_bp = Blueprint('dashboard', __name__)
logger = logging.getLogger(__name__)

@dashboard_bp.route('/')
def index():
    """Main dashboard page with real data"""
    try:
        # Import models with error handling
        try:
            from crypto_hunter_web.models import AnalysisFile, Finding, FileContent, User, FileStatus
            from crypto_hunter_web.extensions import db
            from crypto_hunter_web.services.background_service import BackgroundService

            # Get current user if logged in
            user_id = session.get('user_id')

            # Get file statistics
            if user_id:
                # User-specific stats
                total_files = db.session.query(func.count(AnalysisFile.id)).filter(
                    AnalysisFile.created_by == user_id
                ).scalar() or 0

                complete_files = db.session.query(func.count(AnalysisFile.id)).filter(
                    and_(AnalysisFile.created_by == user_id, AnalysisFile.status == FileStatus.COMPLETE)
                ).scalar() or 0

                analyzing_files = db.session.query(func.count(AnalysisFile.id)).filter(
                    and_(AnalysisFile.created_by == user_id, AnalysisFile.status == FileStatus.PROCESSING)
                ).scalar() or 0

                # Get user's recent files
                recent_files = db.session.query(AnalysisFile).filter(
                    AnalysisFile.created_by == user_id
                ).order_by(desc(AnalysisFile.created_at)).limit(5).all()

                # Get user's recent findings
                recent_findings = db.session.query(Finding).join(AnalysisFile).filter(
                    AnalysisFile.created_by == user_id
                ).order_by(desc(Finding.created_at)).limit(5).all()

                # Get active background tasks for user
                active_tasks = BackgroundService.get_user_active_tasks(user_id)

            else:
                # System-wide stats for non-logged in users
                total_files = db.session.query(func.count(AnalysisFile.id)).scalar() or 0
                complete_files = db.session.query(func.count(AnalysisFile.id)).filter(
                    AnalysisFile.status == FileStatus.COMPLETE
                ).scalar() or 0
                analyzing_files = db.session.query(func.count(AnalysisFile.id)).filter(
                    AnalysisFile.status == FileStatus.PROCESSING
                ).scalar() or 0

                recent_files = []
                recent_findings = []
                active_tasks = []

            # Calculate progress
            progress_percentage = (complete_files / total_files * 100) if total_files > 0 else 0

            # Get analysis vectors with real data
            analysis_vectors = []

            if user_id:
                # Crypto patterns analysis
                crypto_findings = db.session.query(func.count(Finding.id)).join(AnalysisFile).filter(
                    and_(AnalysisFile.created_by == user_id, Finding.category == 'crypto')
                ).scalar() or 0

                analysis_vectors.append({
                    'name': 'Crypto Patterns',
                    'completed': crypto_findings,
                    'total': total_files,
                    'icon': '🔐',
                    'description': 'Cryptocurrency addresses, keys, hashes'
                })

                # String analysis
                string_findings = db.session.query(func.count(Finding.id)).join(AnalysisFile).filter(
                    and_(AnalysisFile.created_by == user_id, Finding.category == 'strings')
                ).scalar() or 0

                analysis_vectors.append({
                    'name': 'String Analysis',
                    'completed': string_findings,
                    'total': total_files,
                    'icon': '📝',
                    'description': 'Text patterns, encodings, metadata'
                })

                # LLM analysis
                llm_analyzed = db.session.query(func.count(FileContent.id)).join(AnalysisFile).filter(
                    and_(
                        AnalysisFile.created_by == user_id,
                        FileContent.content_type == 'llm_analysis_complete'
                    )
                ).scalar() or 0

                analysis_vectors.append({
                    'name': 'AI Analysis',
                    'completed': llm_analyzed,
                    'total': total_files,
                    'icon': '🤖',
                    'description': 'LLM insights and recommendations'
                })

                # Technical analysis
                technical_findings = db.session.query(func.count(Finding.id)).join(AnalysisFile).filter(
                    and_(AnalysisFile.created_by == user_id, Finding.category == 'technical')
                ).scalar() or 0

                analysis_vectors.append({
                    'name': 'Technical Analysis',
                    'completed': technical_findings,
                    'total': total_files,
                    'icon': '⚙️',
                    'description': 'Binary analysis, forensics, steganography'
                })

            # Get system status for background services
            system_status = BackgroundService.get_system_status()

            # Get LLM usage statistics
            llm_stats = get_llm_usage_stats(user_id) if user_id else {}

        except ImportError as e:
            logger.warning(f"Models not available, using dummy data: {e}")
            # Fallback to dummy data if models aren't available
            total_files = 0
            complete_files = 0
            analyzing_files = 0
            progress_percentage = 0
            recent_files = []
            recent_findings = []
            analysis_vectors = [
                {'name': 'Crypto Patterns', 'completed': 0, 'total': 0, 'icon': '🔐', 'description': 'Loading...'},
                {'name': 'String Analysis', 'completed': 0, 'total': 0, 'icon': '📝', 'description': 'Loading...'},
                {'name': 'AI Analysis', 'completed': 0, 'total': 0, 'icon': '🤖', 'description': 'Loading...'},
                {'name': 'Technical Analysis', 'completed': 0, 'total': 0, 'icon': '⚙️', 'description': 'Loading...'}
            ]
            active_tasks = []
            system_status = {'workers': {'online': 0}, 'tasks': {'active_count': 0}}
            llm_stats = {}

        return render_template('dashboard/index.html',
                             total_files=total_files,
                             complete_files=complete_files,
                             analyzing_files=analyzing_files,
                             progress_percentage=progress_percentage,
                             recent_files=recent_files,
                             recent_findings=recent_findings,
                             analysis_vectors=analysis_vectors,
                             active_tasks=active_tasks,
                             system_status=system_status,
                             llm_stats=llm_stats)

    except Exception as e:
        logger.error(f"Error loading dashboard: {e}")
        # Return minimal dashboard on error
        return render_template('dashboard/index.html',
                             total_files=0,
                             complete_files=0,
                             analyzing_files=0,
                             progress_percentage=0,
                             recent_files=[],
                             recent_findings=[],
                             analysis_vectors=[],
                             active_tasks=[],
                             system_status={},
                             llm_stats={})

@dashboard_bp.route('/api/stats')
def api_stats():
    """Real-time dashboard stats API endpoint"""
    try:
        from crypto_hunter_web.models import AnalysisFile, Finding, FileContent, FileStatus
        from crypto_hunter_web.extensions import db
        from crypto_hunter_web.services.background_service import BackgroundService

        user_id = session.get('user_id')

        if user_id:
            # User-specific stats
            total_files = db.session.query(func.count(AnalysisFile.id)).filter(
                AnalysisFile.created_by == user_id
            ).scalar() or 0

            complete_files = db.session.query(func.count(AnalysisFile.id)).filter(
                and_(AnalysisFile.created_by == user_id, AnalysisFile.status == FileStatus.COMPLETE)
            ).scalar() or 0

            pending_files = db.session.query(func.count(AnalysisFile.id)).filter(
                and_(AnalysisFile.created_by == user_id, AnalysisFile.status == FileStatus.PENDING)
            ).scalar() or 0

            analyzing_files = db.session.query(func.count(AnalysisFile.id)).filter(
                and_(AnalysisFile.created_by == user_id, AnalysisFile.status == FileStatus.PROCESSING)
            ).scalar() or 0

            total_findings = db.session.query(func.count(Finding.id)).join(AnalysisFile).filter(
                AnalysisFile.created_by == user_id
            ).scalar() or 0

            # Get active tasks count
            active_tasks = BackgroundService.get_user_active_tasks(user_id)
            active_tasks_count = len(active_tasks)

        else:
            # System-wide stats
            total_files = db.session.query(func.count(AnalysisFile.id)).scalar() or 0
            complete_files = db.session.query(func.count(AnalysisFile.id)).filter(
                AnalysisFile.status == FileStatus.COMPLETE
            ).scalar() or 0
            pending_files = db.session.query(func.count(AnalysisFile.id)).filter(
                AnalysisFile.status == FileStatus.PENDING
            ).scalar() or 0
            analyzing_files = db.session.query(func.count(AnalysisFile.id)).filter(
                AnalysisFile.status == FileStatus.PROCESSING
            ).scalar() or 0
            total_findings = db.session.query(func.count(Finding.id)).scalar() or 0
            active_tasks_count = 0

        return jsonify({
            'total_files': total_files,
            'complete_files': complete_files,
            'pending_files': pending_files,
            'analyzing_files': analyzing_files,
            'total_findings': total_findings,
            'active_tasks': active_tasks_count,
            'progress_percentage': (complete_files / total_files * 100) if total_files > 0 else 0,
            'timestamp': datetime.utcnow().isoformat()
        })

    except ImportError:
        return jsonify({
            'total_files': 0, 'complete_files': 0, 'pending_files': 0,
            'analyzing_files': 0, 'total_findings': 0, 'active_tasks': 0,
            'progress_percentage': 0, 'timestamp': datetime.utcnow().isoformat()
        })
    except Exception as e:
        logger.error(f"Error getting dashboard stats: {e}")
        return jsonify({'error': str(e)}), 500

@dashboard_bp.route('/api/activity')
def api_activity():
    """Real-time activity feed API endpoint"""
    try:
        from crypto_hunter_web.models import AnalysisFile, Finding
        from crypto_hunter_web.extensions import db

        user_id = session.get('user_id')

        if user_id:
            # User's recent files
            recent_files = db.session.query(AnalysisFile).filter(
                AnalysisFile.created_by == user_id
            ).order_by(desc(AnalysisFile.created_at)).limit(10).all()

            # User's recent findings
            recent_findings = db.session.query(Finding).join(AnalysisFile).filter(
                AnalysisFile.created_by == user_id
            ).order_by(desc(Finding.created_at)).limit(10).all()

            files_data = [{
                'filename': f.filename,
                'sha256': f.sha256_hash,
                'status': f.status.value if hasattr(f.status, 'value') else str(f.status),
                'created_at': f.created_at.isoformat() if f.created_at else None,
                'file_size': f.file_size,
                'file_type': f.file_type
            } for f in recent_files]

            findings_data = [{
                'id': f.public_id.hex if hasattr(f, 'public_id') else str(f.id),
                'title': f.title,
                'category': f.category,
                'finding_type': f.finding_type,
                'confidence_level': f.confidence_level,
                'file_name': f.file.filename,
                'created_at': f.created_at.isoformat() if f.created_at else None
            } for f in recent_findings]

        else:
            files_data = []
            findings_data = []

        return jsonify({
            'recent_files': files_data,
            'recent_findings': findings_data,
            'timestamp': datetime.utcnow().isoformat()
        })

    except ImportError:
        return jsonify({'recent_files': [], 'recent_findings': [], 
                       'timestamp': datetime.utcnow().isoformat()})
    except Exception as e:
        logger.error(f"Error getting activity data: {e}")
        return jsonify({'error': str(e)}), 500

@dashboard_bp.route('/api/background-status')
def api_background_status():
    """Get real-time background services status"""
    try:
        from crypto_hunter_web.services.background_service import BackgroundService

        user_id = session.get('user_id')

        # Get system status
        system_status = BackgroundService.get_system_status()

        # Get user's active tasks if logged in
        user_tasks = []
        if user_id:
            user_tasks = BackgroundService.get_user_active_tasks(user_id)

        return jsonify({
            'system': system_status,
            'user_tasks': user_tasks,
            'timestamp': datetime.utcnow().isoformat()
        })

    except Exception as e:
        logger.error(f"Error getting background status: {e}")
        return jsonify({
            'system': {
                'workers': {'online': 0},
                'tasks': {'active_count': 0},
                'redis_connected': False,
                'error': str(e)
            },
            'user_tasks': [],
            'timestamp': datetime.utcnow().isoformat()
        }), 500

@dashboard_bp.route('/api/llm-stats')
def api_llm_stats():
    """Get LLM usage and cost statistics"""
    try:
        user_id = session.get('user_id')
        if not user_id:
            return jsonify({'error': 'Authentication required'}), 401

        stats = get_llm_usage_stats(user_id)
        return jsonify({
            'success': True,
            'stats': stats,
            'timestamp': datetime.utcnow().isoformat()
        })

    except Exception as e:
        logger.error(f"Error getting LLM stats: {e}")
        return jsonify({'error': str(e)}), 500

def get_llm_usage_stats(user_id: int) -> dict:
    """Get LLM usage statistics for a user"""
    try:
        from crypto_hunter_web.models import AnalysisFile, FileContent
        from crypto_hunter_web.extensions import db

        # Get LLM analysis content for user's files
        llm_content = db.session.query(FileContent).join(AnalysisFile).filter(
            and_(
                AnalysisFile.created_by == user_id,
                FileContent.content_type == 'llm_analysis_complete'
            )
        ).all()

        total_cost = 0.0
        total_analyses = len(llm_content)
        cost_by_day = {}
        cost_by_provider = {'openai': 0.0, 'anthropic': 0.0}

        for content in llm_content:
            if content.content_json and isinstance(content.content_json, dict):
                cost = content.content_json.get('analysis_cost', 0.0)
                provider = content.content_json.get('provider', 'unknown')

                total_cost += cost

                # Group by day
                if content.created_at:
                    day_key = content.created_at.date().isoformat()
                    cost_by_day[day_key] = cost_by_day.get(day_key, 0.0) + cost

                # Group by provider
                if provider in cost_by_provider:
                    cost_by_provider[provider] += cost

        # Calculate 30-day stats
        thirty_days_ago = datetime.utcnow() - timedelta(days=30)
        recent_content = [c for c in llm_content if c.created_at and c.created_at >= thirty_days_ago]
        cost_30_days = sum(
            c.content_json.get('analysis_cost', 0.0) 
            for c in recent_content 
            if c.content_json and isinstance(c.content_json, dict)
        )

        return {
            'total_cost_30_days': cost_30_days,
            'total_analyses': total_analyses,
            'cost_by_day': cost_by_day,
            'cost_by_provider': cost_by_provider,
            'avg_cost_per_analysis': total_cost / total_analyses if total_analyses > 0 else 0.0,
            'analyses_today': len([
                c for c in llm_content 
                if c.created_at and c.created_at.date() == datetime.utcnow().date()
            ])
        }

    except Exception as e:
        logger.error(f"Error calculating LLM stats: {e}")
        return {
            'total_cost_30_days': 0.0,
            'total_analyses': 0,
            'cost_by_day': {},
            'cost_by_provider': {'openai': 0.0, 'anthropic': 0.0},
            'avg_cost_per_analysis': 0.0,
            'analyses_today': 0
        }
