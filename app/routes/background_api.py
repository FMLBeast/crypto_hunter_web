"""
Background task management API
"""

from flask import Blueprint, request, jsonify, session
from app.services.auth_service import AuthService
from app.services.background_crypto import BackgroundCryptoManager
from app.utils.decorators import rate_limit

background_api_bp = Blueprint('background_api', __name__)


@background_api_bp.route('/background/start', methods=['POST'])
@AuthService.login_required
def start_background_processing():
    """Start background crypto processing"""
    from app.models.user import User
    user = User.query.get(session['user_id'])

    if not user.can_access_admin():
        return jsonify({'error': 'Admin access required'}), 403

    count = BackgroundCryptoManager.start_continuous_analysis()

    return jsonify({
        'success': True,
        'message': f'Background processing started for {count} files',
        'queued_files': count
    })


@background_api_bp.route('/background/queue/<int:file_id>', methods=['POST'])
@AuthService.login_required
@rate_limit(max_requests=50, window_seconds=300)
def queue_priority_analysis(file_id):
    """Queue priority analysis for specific file"""
    data = request.json or {}
    analysis_types = data.get('analysis_types', ['ethereum_validation', 'cipher_analysis'])

    task_id = BackgroundCryptoManager.queue_priority_analysis(file_id, analysis_types)

    if task_id:
        return jsonify({
            'success': True,
            'task_id': task_id,
            'message': 'Priority analysis queued'
        })
    else:
        return jsonify({
            'success': False,
            'error': 'Failed to queue analysis'
        }), 500


@background_api_bp.route('/background/status/<task_id>')
@AuthService.login_required
def get_task_status(task_id):
    """Get status of background task"""
    status = BackgroundCryptoManager.get_task_status(task_id)

    return jsonify({
        'success': True,
        'status': status
    })


@background_api_bp.route('/background/system/stats')
@AuthService.login_required
def get_system_stats():
    """Get background processing system statistics"""
    stats = BackgroundCryptoManager.get_system_stats()

    return jsonify({
        'success': True,
        'stats': stats
    })


@background_api_bp.route('/background/results/<int:file_id>')
@AuthService.login_required
def get_background_results(file_id):
    """Get background analysis results for file"""
    from app.models.file import FileContent

    content = FileContent.query.filter_by(
        file_id=file_id,
        content_type='crypto_background_complete'
    ).first()

    if content:
        return jsonify({
            'success': True,
            'results': json.loads(content.content_text or '{}'),
            'last_updated': content.updated_at.isoformat()
        })
    else:
        return jsonify({
            'success': False,
            'error': 'No background results available'
        }), 404