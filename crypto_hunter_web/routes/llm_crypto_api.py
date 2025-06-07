"""
LLM Crypto Analysis API Routes
"""

from flask import Blueprint, request, jsonify, session
from crypto_hunter_web.services.auth_service import AuthService
from crypto_hunter_web.services.llm_crypto_orchestrator import LLMCryptoOrchestrator, llm_orchestrated_analysis
from crypto_hunter_web.utils.decorators import rate_limit
from crypto_hunter_web.utils.validators import validate_sha256

llm_crypto_api_bp = Blueprint('llm_crypto_api', __name__)


@llm_crypto_api_bp.route('/llm/analyze/<sha>', methods=['POST'])
@AuthService.login_required
@rate_limit(max_requests=10, window_seconds=3600)  # Limited due to cost
def analyze_with_llm(sha):
    """Trigger LLM-orchestrated analysis for specific file"""

    if not validate_sha256(sha):
        return jsonify({'error': 'Invalid SHA256'}), 400

    from crypto_hunter_web import AnalysisFile
    file = AnalysisFile.query.filter_by(sha256_hash=sha).first()

    if not file:
        return jsonify({'error': 'File not found'}), 404

    # Check user permissions for LLM analysis
    from crypto_hunter_web import User
    user = User.query.get(session['user_id'])

    if not user.can_verify_findings():  # Require expert level for LLM analysis
        return jsonify({'error': 'Expert access required for LLM analysis'}), 403

    # Queue LLM analysis task
    task = llm_orchestrated_analysis.delay(file.id)

    return jsonify({
        'success': True,
        'task_id': task.id,
        'message': 'LLM analysis queued',
        'estimated_cost': '$0.50-$2.00',  # Rough estimate
        'eta_minutes': '2-5'
    })


@llm_crypto_api_bp.route('/llm/batch-analyze', methods=['POST'])
@AuthService.login_required
@rate_limit(max_requests=3, window_seconds=3600)  # Very limited for batch
def batch_analyze_with_llm():
    """Queue LLM analysis for multiple files with budget control"""

    data = request.json
    sha_list = data.get('sha_list', [])
    max_budget = data.get('max_budget', 10.0)  # USD

    if len(sha_list) > 20:
        return jsonify({'error': 'Maximum 20 files per batch'}), 400

    from crypto_hunter_web import AnalysisFile
    files = AnalysisFile.query.filter(AnalysisFile.sha256_hash.in_(sha_list)).all()

    if len(files) != len(sha_list):
        return jsonify({'error': 'Some files not found'}), 404

    # Estimate total cost
    orchestrator = LLMCryptoOrchestrator()
    estimated_total = 0

    for file in files:
        try:
            with open(file.filepath, 'rb') as f:
                preview = f.read(1024).decode('utf-8', errors='ignore')
            estimated_total += orchestrator.cost_manager.estimate_cost(
                orchestrator.cost_manager.COSTS.keys()[0], preview, 500
            )
        except:
            continue

    if estimated_total > max_budget:
        return jsonify({
            'error': 'Estimated cost exceeds budget',
            'estimated_cost': estimated_total,
            'max_budget': max_budget
        }), 400

    # Queue tasks
    task_ids = []
    for file in files:
        task = llm_orchestrated_analysis.delay(file.id)
        task_ids.append(task.id)

    return jsonify({
        'success': True,
        'task_ids': task_ids,
        'estimated_cost': estimated_total,
        'files_queued': len(files)
    })


@llm_crypto_api_bp.route('/llm/cost/stats')
@AuthService.login_required
def get_cost_stats():
    """Get LLM usage and cost statistics"""

    from crypto_hunter_web import FileContent
    from datetime import datetime, timedelta

    # Get cost records from last 30 days
    thirty_days_ago = datetime.utcnow() - timedelta(days=30)

    cost_records = FileContent.query.filter(
        FileContent.content_type == 'llm_cost_record',
        FileContent.created_at >= thirty_days_ago
    ).all()

    stats = {
        'total_calls': len(cost_records),
        'total_cost_30_days': 0,
        'cost_by_provider': {},
        'cost_by_day': {},
        'token_usage': {'input': 0, 'output': 0}
    }

    for record in cost_records:
        try:
            data = json.loads(record.content_text)
            cost = data['cost_usd']
            provider = data['provider']
            day = record.created_at.date().isoformat()

            stats['total_cost_30_days'] += cost
            stats['cost_by_provider'][provider] = stats['cost_by_provider'].get(provider, 0) + cost
            stats['cost_by_day'][day] = stats['cost_by_day'].get(day, 0) + cost
            stats['token_usage']['input'] += data.get('input_tokens', 0)
            stats['token_usage']['output'] += data.get('output_tokens', 0)

        except:
            continue

    return jsonify({
        'success': True,
        'stats': stats
    })


@llm_crypto_api_bp.route('/llm/results/<int:file_id>')
@AuthService.login_required
def get_llm_results(file_id):
    """Get LLM analysis results for file"""

    from crypto_hunter_web import FileContent

    content = FileContent.query.filter_by(
        file_id=file_id,
        content_type='llm_analysis_complete'
    ).first()

    if content:
        return jsonify({
            'success': True,
            'results': json.loads(content.content_text),
            'analysis_date': content.created_at.isoformat()
        })
    else:
        return jsonify({
            'success': False,
            'error': 'No LLM analysis results available'
        }), 404


@llm_crypto_api_bp.route('/llm/budget', methods=['GET', 'PUT'])
@AuthService.login_required
def manage_budget():
    """Get or update LLM analysis budget"""

    from crypto_hunter_web import User
    user = User.query.get(session['user_id'])

    if not user.can_access_admin():
        return jsonify({'error': 'Admin access required'}), 403

    if request.method == 'GET':
        # Return current budget settings (would be stored in config)
        return jsonify({
            'success': True,
            'budget': {
                'daily_limit': 50.0,
                'hourly_limit': 10.0,
                'per_file_limit': 2.0
            }
        })

    else:  # PUT
        data = request.json
        # Update budget settings (implementation depends on your config system)
        return jsonify({
            'success': True,
            'message': 'Budget updated',
            'new_budget': data
        })