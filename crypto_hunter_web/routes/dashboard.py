#!/usr/bin/env python3
# crypto_hunter_web/routes/dashboard.py

from flask import Blueprint, render_template, jsonify, current_app
from sqlalchemy import func, desc
import logging

dashboard_bp = Blueprint('dashboard', __name__)
logger = logging.getLogger(__name__)


@dashboard_bp.route('/')
def index():
    """Main dashboard page"""
    try:
        # Try to import models and get real stats
        try:
            from crypto_hunter_web.models import AnalysisFile, Finding, FileStatus
            from crypto_hunter_web.extensions import db

            # Get file statistics
            total_files = db.session.query(func.count(AnalysisFile.id)).scalar() or 0
            complete_files = db.session.query(func.count(AnalysisFile.id)).filter(
                AnalysisFile.status == FileStatus.COMPLETE
            ).scalar() or 0

            # Calculate progress
            progress_percentage = (complete_files / total_files * 100) if total_files > 0 else 0

            # Get recent files
            recent_files = db.session.query(AnalysisFile).order_by(
                desc(AnalysisFile.created_at)
            ).limit(5).all()

            # Get recent findings
            recent_findings = db.session.query(Finding).order_by(
                desc(Finding.created_at)
            ).limit(5).all()

            # Analysis vectors stats
            analysis_vectors = [
                {
                    'name': 'Crypto Patterns',
                    'completed': db.session.query(func.count(Finding.id)).filter(
                        Finding.finding_type.like('%crypto%')
                    ).scalar() or 0,
                    'total': total_files,
                    'icon': '🔐'
                },
                {
                    'name': 'String Analysis',
                    'completed': db.session.query(func.count(Finding.id)).filter(
                        Finding.finding_type.like('%string%')
                    ).scalar() or 0,
                    'total': total_files,
                    'icon': '📝'
                },
                {
                    'name': 'Metadata',
                    'completed': db.session.query(func.count(Finding.id)).filter(
                        Finding.finding_type.like('%metadata%')
                    ).scalar() or 0,
                    'total': total_files,
                    'icon': '📊'
                },
                {
                    'name': 'Binary Analysis',
                    'completed': db.session.query(func.count(Finding.id)).filter(
                        Finding.finding_type.like('%binary%')
                    ).scalar() or 0,
                    'total': total_files,
                    'icon': '⚙️'
                }
            ]

        except ImportError as e:
            logger.warning(f"Models not available, using dummy data: {e}")
            # Fallback to dummy data if models aren't available
            total_files = 0
            complete_files = 0
            progress_percentage = 0
            recent_files = []
            recent_findings = []
            analysis_vectors = [
                {'name': 'Crypto Patterns', 'completed': 0, 'total': 0, 'icon': '🔐'},
                {'name': 'String Analysis', 'completed': 0, 'total': 0, 'icon': '📝'},
                {'name': 'Metadata', 'completed': 0, 'total': 0, 'icon': '📊'},
                {'name': 'Binary Analysis', 'completed': 0, 'total': 0, 'icon': '⚙️'}
            ]

        return render_template('dashboard/index.html',
                               total_files=total_files,
                               complete_files=complete_files,
                               progress_percentage=progress_percentage,
                               recent_files=recent_files,
                               recent_findings=recent_findings,
                               analysis_vectors=analysis_vectors)

    except Exception as e:
        logger.error(f"Error loading dashboard: {e}")
        # Return minimal dashboard on error
        return render_template('dashboard/index.html',
                               total_files=0,
                               complete_files=0,
                               progress_percentage=0,
                               recent_files=[],
                               recent_findings=[],
                               analysis_vectors=[])


@dashboard_bp.route('/api/stats')
def api_stats():
    """Dashboard stats API endpoint"""
    try:
        try:
            from crypto_hunter_web.models import AnalysisFile, Finding, FileStatus
            from crypto_hunter_web.extensions import db

            total_files = db.session.query(func.count(AnalysisFile.id)).scalar() or 0
            complete_files = db.session.query(func.count(AnalysisFile.id)).filter(
                AnalysisFile.status == FileStatus.COMPLETE
            ).scalar() or 0
            pending_files = db.session.query(func.count(AnalysisFile.id)).filter(
                AnalysisFile.status == FileStatus.PENDING
            ).scalar() or 0
            total_findings = db.session.query(func.count(Finding.id)).scalar() or 0

        except ImportError:
            total_files = complete_files = pending_files = total_findings = 0

        return jsonify({
            'total_files': total_files,
            'complete_files': complete_files,
            'pending_files': pending_files,
            'total_findings': total_findings,
            'progress_percentage': (complete_files / total_files * 100) if total_files > 0 else 0
        })

    except Exception as e:
        logger.error(f"Error getting dashboard stats: {e}")
        return jsonify({'error': str(e)}), 500


@dashboard_bp.route('/api/activity')
def api_activity():
    """Recent activity API endpoint"""
    try:
        try:
            from crypto_hunter_web.models import AnalysisFile, Finding, FileStatus
            from crypto_hunter_web.extensions import db

            recent_files = db.session.query(AnalysisFile).order_by(
                desc(AnalysisFile.created_at)
            ).limit(10).all()

            recent_findings = db.session.query(Finding).order_by(
                desc(Finding.created_at)
            ).limit(10).all()

            files_data = [{
                'filename': f.filename,
                'sha256': f.sha256_hash,
                'status': f.status,
                'created_at': f.created_at.isoformat() if f.created_at else None
            } for f in recent_files]

            findings_data = [{
                'type': f.finding_type,
                'description': f.description[:100] + ('...' if len(f.description) > 100 else ''),
                'confidence': f.confidence_score,
                'created_at': f.created_at.isoformat() if f.created_at else None
            } for f in recent_findings]

        except ImportError:
            files_data = []
            findings_data = []

        return jsonify({
            'recent_files': files_data,
            'recent_findings': findings_data
        })

    except Exception as e:
        logger.error(f"Error getting activity data: {e}")
        return jsonify({'error': str(e)}), 500
