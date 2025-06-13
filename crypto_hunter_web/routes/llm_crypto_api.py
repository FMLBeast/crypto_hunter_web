#!/usr/bin/env python3
"""
LLM Crypto Analysis API Routes - Real implementation
"""

import json
import logging
from datetime import datetime, timedelta

from flask import Blueprint, request, jsonify, session, current_app
from sqlalchemy import func, desc, and_

from crypto_hunter_web.models import db, AnalysisFile, FileContent, User
from crypto_hunter_web.services.auth_service import AuthService
from crypto_hunter_web.services.background_service import BackgroundService
from crypto_hunter_web.utils.decorators import rate_limit
from crypto_hunter_web.utils.validators import validate_sha256

llm_crypto_api_bp = Blueprint('llm_crypto_api', __name__)
logger = logging.getLogger(__name__)

@llm_crypto_api_bp.route('/analyze/<sha>', methods=['POST'])
@AuthService.login_required
@rate_limit(limit="10 per hour")  # Limited due to cost
def analyze_with_llm(sha):
    """Trigger LLM-orchestrated analysis for specific file"""

    if not validate_sha256(sha):
        return jsonify({'error': 'Invalid SHA256'}), 400

    file = AnalysisFile.query.filter_by(sha256_hash=sha).first()
    if not file:
        return jsonify({'error': 'File not found'}), 404

    # Check file ownership
    user_id = session['user_id']
    if file.created_by != user_id:
        return jsonify({'error': 'Access denied'}), 403

    # Check user permissions for LLM analysis
    user = User.query.get(user_id)
    if not (user and hasattr(user, 'can_verify_findings') and user.can_verify_findings()):
        return jsonify({'error': 'Expert access required for LLM analysis'}), 403

    try:
        # Check if LLM analysis already exists and is recent
        existing_llm = FileContent.query.filter_by(
            file_id=file.id,
            content_type='llm_analysis_complete'
        ).first()

        if existing_llm and existing_llm.created_at > datetime.utcnow() - timedelta(hours=24):
            return jsonify({
                'success': True,
                'message': 'Recent LLM analysis already exists',
                'existing_analysis': True,
                'analysis_date': existing_llm.created_at.isoformat(),
                'cost_estimate': '$0.00'
            })

        # Check daily budget
        daily_cost = get_user_daily_llm_cost(user_id)
        daily_limit = current_app.config.get('LLM_DAILY_LIMIT', 50.0)

        if daily_cost >= daily_limit:
            return jsonify({
                'error': f'Daily LLM budget exceeded: ${daily_cost:.2f} / ${daily_limit:.2f}'
            }), 429

        # Estimate cost based on file size
        estimated_cost = estimate_llm_cost(file)

        if daily_cost + estimated_cost > daily_limit:
            return jsonify({
                'error': f'Analysis would exceed daily budget. Current: ${daily_cost:.2f}, Estimated: ${estimated_cost:.2f}, Limit: ${daily_limit:.2f}'
            }), 429

        # Queue LLM analysis task
        from crypto_hunter_web.services.llm_crypto_orchestrator import llm_orchestrated_analysis
        task = llm_orchestrated_analysis.delay(file.id)

        # Track the task
        BackgroundService.track_task(
            task.id, 
            'llm_analysis', 
            file.id, 
            user_id,
            {
                'estimated_cost': estimated_cost,
                'file_size': file.file_size,
                'file_type': file.file_type
            }
        )

        # Log the action
        AuthService.log_action('llm_analysis_started', 
                             f'Started LLM analysis for {file.filename}', 
                             file_id=file.id)

        return jsonify({
            'success': True,
            'task_id': task.id,
            'message': 'LLM analysis queued successfully',
            'estimated_cost': f'${estimated_cost:.2f}',
            'eta_minutes': estimate_processing_time(file),
            'daily_usage': f'${daily_cost:.2f} / ${daily_limit:.2f}'
        })

    except Exception as e:
        logger.error(f"Error starting LLM analysis for {sha}: {e}")
        return jsonify({'error': 'Failed to start LLM analysis'}), 500

@llm_crypto_api_bp.route('/results/<int:file_id>')
@AuthService.login_required
def get_llm_results(file_id):
    """Get LLM analysis results for file"""

    # Get file and verify access
    file = AnalysisFile.query.get_or_404(file_id)
    user_id = session['user_id']

    if file.created_by != user_id:
        return jsonify({'error': 'Access denied'}), 403

    # Get LLM analysis content
    llm_content = FileContent.query.filter_by(
        file_id=file_id,
        content_type='llm_analysis_complete'
    ).order_by(desc(FileContent.created_at)).first()

    if not llm_content:
        return jsonify({
            'success': False,
            'error': 'No LLM analysis results available',
            'suggestions': [
                'Run LLM analysis first',
                'Check if analysis is still in progress',
                'Verify file has content to analyze'
            ]
        }), 404

    try:
        # Parse results
        results = llm_content.content_json if llm_content.content_json else json.loads(llm_content.content_text)

        # Add metadata
        enhanced_results = {
            'analysis_info': {
                'file_id': file_id,
                'file_name': file.filename,
                'analysis_date': llm_content.created_at.isoformat(),
                'analysis_cost': results.get('analysis_cost', 0.0),
                'provider': results.get('provider', 'unknown'),
                'model_used': results.get('model_used', 'unknown'),
                'processing_time': results.get('processing_time', 0)
            },
            'summary': results.get('summary', ''),
            'overall_confidence': results.get('overall_confidence', 0.0),
            'analysis_results': results.get('analysis_results', []),
            'recommendations': results.get('recommendations', []),
            'findings_created': results.get('findings_created', 0),
            'patterns_detected': results.get('patterns_detected', []),
            'security_assessment': results.get('security_assessment', {}),
            'next_steps': results.get('next_steps', [])
        }

        return jsonify({
            'success': True,
            'results': enhanced_results
        })

    except (json.JSONDecodeError, KeyError) as e:
        logger.error(f"Error parsing LLM results for file {file_id}: {e}")
        return jsonify({
            'success': False,
            'error': 'Corrupted analysis results',
            'details': str(e)
        }), 500

@llm_crypto_api_bp.route('/status/<task_id>')
@AuthService.login_required
def get_llm_task_status(task_id):
    """Get status of LLM analysis task"""

    try:
        # Get task status
        task_status = BackgroundService.get_task_status(task_id)

        # Verify user has access to this task
        user_id = session['user_id']
        if task_status.get('user_id') and task_status['user_id'] != user_id:
            return jsonify({'success': False, 'error': 'Access denied'}), 403

        # Enhance with LLM-specific information
        llm_status = {
            'task_id': task_id,
            'state': task_status.get('state', 'UNKNOWN'),
            'progress': task_status.get('progress', 0),
            'current_stage': task_status.get('current_stage', 'initializing'),
            'estimated_cost': task_status.get('metadata', {}).get('estimated_cost', 0.0),
            'elapsed_time': None,
            'eta': None
        }

        # Calculate elapsed time
        if task_status.get('created_at'):
            try:
                created_time = datetime.fromisoformat(task_status['created_at'])
                elapsed = datetime.utcnow() - created_time
                llm_status['elapsed_time'] = str(elapsed).split('.')[0]  # Remove microseconds

                # Estimate remaining time based on progress
                if task_status.get('progress', 0) > 0:
                    total_estimated = elapsed.total_seconds() / (task_status['progress'] / 100)
                    remaining = total_estimated - elapsed.total_seconds()
                    if remaining > 0:
                        llm_status['eta'] = f"{int(remaining // 60)}m {int(remaining % 60)}s"
            except ValueError:
                pass

        # Add results if completed
        if task_status.get('state') == 'SUCCESS':
            result = task_status.get('result', {})
            llm_status.update({
                'actual_cost': result.get('total_cost', 0.0),
                'findings_created': result.get('findings_created', 0),
                'confidence_score': result.get('overall_confidence', 0.0),
                'analysis_summary': result.get('summary', '')[:200] + '...' if result.get('summary', '') else ''
            })

        # Add error details if failed
        if task_status.get('state') == 'FAILURE':
            llm_status['error'] = task_status.get('traceback', 'Unknown error occurred')

        return jsonify({
            'success': True,
            'llm_status': llm_status
        })

    except Exception as e:
        logger.error(f"Error getting LLM task status for {task_id}: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@llm_crypto_api_bp.route('/usage/stats')
@AuthService.login_required
def get_llm_usage_stats():
    """Get LLM usage and cost statistics for current user"""

    try:
        user_id = session['user_id']

        # Get usage statistics
        stats = get_user_llm_stats(user_id)

        # Get budget information
        daily_limit = current_app.config.get('LLM_DAILY_LIMIT', 50.0)
        monthly_limit = current_app.config.get('LLM_MONTHLY_LIMIT', 1000.0)

        # Calculate usage percentages
        daily_percentage = (stats['daily_cost'] / daily_limit * 100) if daily_limit > 0 else 0
        monthly_percentage = (stats['monthly_cost'] / monthly_limit * 100) if monthly_limit > 0 else 0

        usage_stats = {
            'costs': {
                'today': stats['daily_cost'],
                'this_month': stats['monthly_cost'],
                'total': stats['total_cost']
            },
            'limits': {
                'daily_limit': daily_limit,
                'monthly_limit': monthly_limit,
                'daily_remaining': max(0, daily_limit - stats['daily_cost']),
                'monthly_remaining': max(0, monthly_limit - stats['monthly_cost'])
            },
            'usage': {
                'daily_percentage': min(100, daily_percentage),
                'monthly_percentage': min(100, monthly_percentage),
                'analyses_today': stats['analyses_today'],
                'analyses_this_month': stats['analyses_this_month'],
                'total_analyses': stats['total_analyses']
            },
            'providers': stats['cost_by_provider'],
            'recent_analyses': stats['recent_analyses']
        }

        return jsonify({
            'success': True,
            'stats': usage_stats,
            'timestamp': datetime.utcnow().isoformat()
        })

    except Exception as e:
        logger.error(f"Error getting LLM usage stats: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@llm_crypto_api_bp.route('/budget', methods=['GET', 'PUT'])
@AuthService.login_required
def manage_budget():
    """Get or update LLM analysis budget (admin only for PUT)"""

    user_id = session['user_id']
    user = User.query.get(user_id)

    if request.method == 'GET':
        # Anyone can view current budget settings
        budget_info = {
            'daily_limit': current_app.config.get('LLM_DAILY_LIMIT', 50.0),
            'monthly_limit': current_app.config.get('LLM_MONTHLY_LIMIT', 1000.0),
            'per_analysis_limit': current_app.config.get('LLM_PER_ANALYSIS_LIMIT', 5.0),
            'current_usage': get_user_daily_llm_cost(user_id),
            'can_modify': user and hasattr(user, 'is_admin') and user.is_admin
        }

        return jsonify({
            'success': True,
            'budget': budget_info
        })

    else:  # PUT
        # Only admins can modify budget
        if not (user and hasattr(user, 'is_admin') and user.is_admin):
            return jsonify({'error': 'Admin access required'}), 403

        try:
            data = request.get_json()

            # Validate budget values
            daily_limit = float(data.get('daily_limit', 50.0))
            monthly_limit = float(data.get('monthly_limit', 1000.0))
            per_analysis_limit = float(data.get('per_analysis_limit', 5.0))

            if daily_limit < 0 or monthly_limit < 0 or per_analysis_limit < 0:
                return jsonify({'error': 'Budget limits must be positive numbers'}), 400

            if daily_limit > monthly_limit:
                return jsonify({'error': 'Daily limit cannot exceed monthly limit'}), 400

            # Update configuration (in a real app, you'd save to database or config file)
            current_app.config['LLM_DAILY_LIMIT'] = daily_limit
            current_app.config['LLM_MONTHLY_LIMIT'] = monthly_limit
            current_app.config['LLM_PER_ANALYSIS_LIMIT'] = per_analysis_limit

            # Log the change
            AuthService.log_action('budget_updated', 
                                 f'Updated LLM budget limits: daily=${daily_limit}, monthly=${monthly_limit}')

            return jsonify({
                'success': True,
                'message': 'Budget limits updated successfully',
                'new_budget': {
                    'daily_limit': daily_limit,
                    'monthly_limit': monthly_limit,
                    'per_analysis_limit': per_analysis_limit
                }
            })

        except (ValueError, TypeError) as e:
            return jsonify({'error': f'Invalid budget values: {e}'}), 400

@llm_crypto_api_bp.route('/providers')
@AuthService.login_required
def get_llm_providers():
    """Get available LLM providers and their capabilities"""

    providers = {
        'openai': {
            'name': 'OpenAI',
            'models': ['gpt-4', 'gpt-3.5-turbo'],
            'cost_per_1k_tokens': {'gpt-4': 0.03, 'gpt-3.5-turbo': 0.002},
            'strengths': ['Code analysis', 'Technical explanations', 'Pattern recognition'],
            'available': current_app.config.get('OPENAI_API_KEY') is not None
        },
        'anthropic': {
            'name': 'Anthropic Claude',
            'models': ['claude-3-opus', 'claude-3-sonnet'],
            'cost_per_1k_tokens': {'claude-3-opus': 0.015, 'claude-3-sonnet': 0.003},
            'strengths': ['Security analysis', 'Detailed explanations', 'Crypto expertise'],
            'available': current_app.config.get('ANTHROPIC_API_KEY') is not None
        }
    }

    return jsonify({
        'success': True,
        'providers': providers,
        'default_provider': current_app.config.get('DEFAULT_LLM_PROVIDER', 'openai')
    })

@llm_crypto_api_bp.route('/reanalyze/<sha>', methods=['POST'])
@AuthService.login_required
@rate_limit(limit="5 per hour")  # Very limited
def reanalyze_with_llm(sha):
    """Re-run LLM analysis with different parameters"""

    if not validate_sha256(sha):
        return jsonify({'error': 'Invalid SHA256'}), 400

    file = AnalysisFile.query.filter_by(sha256_hash=sha).first()
    if not file:
        return jsonify({'error': 'File not found'}), 404

    user_id = session['user_id']
    if file.created_by != user_id:
        return jsonify({'error': 'Access denied'}), 403

    try:
        data = request.get_json() or {}

        # Get analysis parameters
        provider = data.get('provider', 'openai')
        model = data.get('model')
        focus_areas = data.get('focus_areas', ['crypto', 'security'])
        force_reanalysis = data.get('force', False)

        # Check if recent analysis exists
        if not force_reanalysis:
            recent_llm = FileContent.query.filter_by(
                file_id=file.id,
                content_type='llm_analysis_complete'
            ).filter(
                FileContent.created_at > datetime.utcnow() - timedelta(hours=6)
            ).first()

            if recent_llm:
                return jsonify({
                    'error': 'Recent analysis exists. Use force=true to override',
                    'last_analysis': recent_llm.created_at.isoformat()
                }), 409

        # Estimate cost for re-analysis
        estimated_cost = estimate_llm_cost(file, provider, model)

        # Check budget
        daily_cost = get_user_daily_llm_cost(user_id)
        daily_limit = current_app.config.get('LLM_DAILY_LIMIT', 50.0)

        if daily_cost + estimated_cost > daily_limit:
            return jsonify({
                'error': f'Re-analysis would exceed daily budget'
            }), 429

        # Start re-analysis
        from crypto_hunter_web.services.llm_crypto_orchestrator import llm_orchestrated_analysis
        task = llm_orchestrated_analysis.delay(
            file.id,
            provider=provider,
            model=model,
            focus_areas=focus_areas,
            force_reanalysis=True
        )

        # Track the task
        BackgroundService.track_task(
            task.id, 
            'llm_reanalysis', 
            file.id, 
            user_id,
            {
                'estimated_cost': estimated_cost,
                'provider': provider,
                'model': model,
                'focus_areas': focus_areas
            }
        )

        return jsonify({
            'success': True,
            'task_id': task.id,
            'message': 'LLM re-analysis started',
            'estimated_cost': f'${estimated_cost:.2f}',
            'provider': provider,
            'model': model
        })

    except Exception as e:
        logger.error(f"Error starting LLM re-analysis for {sha}: {e}")
        return jsonify({'error': 'Failed to start re-analysis'}), 500

# Helper functions

def get_user_daily_llm_cost(user_id: int) -> float:
    """Calculate user's LLM costs for today"""
    try:
        today = datetime.utcnow().date()

        # Get all LLM analyses for today
        llm_content = db.session.query(FileContent).join(AnalysisFile).filter(
            and_(
                AnalysisFile.created_by == user_id,
                FileContent.content_type == 'llm_analysis_complete',
                func.date(FileContent.created_at) == today
            )
        ).all()

        total_cost = 0.0
        for content in llm_content:
            if content.content_json and isinstance(content.content_json, dict):
                total_cost += content.content_json.get('analysis_cost', 0.0)

        return total_cost

    except Exception as e:
        logger.error(f"Error calculating daily LLM cost for user {user_id}: {e}")
        return 0.0

def get_user_llm_stats(user_id: int) -> dict:
    """Get comprehensive LLM usage statistics for user"""
    try:
        # Date ranges
        today = datetime.utcnow().date()
        month_start = today.replace(day=1)

        # Get all LLM analyses for user
        llm_content = db.session.query(FileContent).join(AnalysisFile).filter(
            and_(
                AnalysisFile.created_by == user_id,
                FileContent.content_type == 'llm_analysis_complete'
            )
        ).order_by(desc(FileContent.created_at)).all()

        # Calculate statistics
        total_cost = 0.0
        daily_cost = 0.0
        monthly_cost = 0.0
        analyses_today = 0
        analyses_this_month = 0
        cost_by_provider = {'openai': 0.0, 'anthropic': 0.0, 'other': 0.0}
        recent_analyses = []

        for content in llm_content:
            if content.content_json and isinstance(content.content_json, dict):
                cost = content.content_json.get('analysis_cost', 0.0)
                provider = content.content_json.get('provider', 'other')

                total_cost += cost

                # Provider costs
                if provider in cost_by_provider:
                    cost_by_provider[provider] += cost
                else:
                    cost_by_provider['other'] += cost

                # Date-based calculations
                if content.created_at:
                    analysis_date = content.created_at.date()

                    if analysis_date == today:
                        daily_cost += cost
                        analyses_today += 1

                    if analysis_date >= month_start:
                        monthly_cost += cost
                        analyses_this_month += 1

                    # Recent analyses (last 10)
                    if len(recent_analyses) < 10:
                        recent_analyses.append({
                            'date': content.created_at.isoformat(),
                            'cost': cost,
                            'provider': provider,
                            'file_name': content.file.filename if content.file else 'Unknown'
                        })

        return {
            'total_cost': total_cost,
            'daily_cost': daily_cost,
            'monthly_cost': monthly_cost,
            'total_analyses': len(llm_content),
            'analyses_today': analyses_today,
            'analyses_this_month': analyses_this_month,
            'cost_by_provider': cost_by_provider,
            'recent_analyses': recent_analyses
        }

    except Exception as e:
        logger.error(f"Error getting LLM stats for user {user_id}: {e}")
        return {
            'total_cost': 0.0, 'daily_cost': 0.0, 'monthly_cost': 0.0,
            'total_analyses': 0, 'analyses_today': 0, 'analyses_this_month': 0,
            'cost_by_provider': {'openai': 0.0, 'anthropic': 0.0, 'other': 0.0},
            'recent_analyses': []
        }

def estimate_llm_cost(file: AnalysisFile, provider: str = 'openai', model: str = None) -> float:
    """Estimate LLM analysis cost based on file size and provider"""
    try:
        # Base cost per MB for different providers
        cost_rates = {
            'openai': {'gpt-4': 0.05, 'gpt-3.5-turbo': 0.01},
            'anthropic': {'claude-3-opus': 0.04, 'claude-3-sonnet': 0.015}
        }

        # Get file size in MB
        file_size_mb = (file.file_size or 1024) / (1024 * 1024)

        # Get rate for provider/model
        if provider in cost_rates:
            if model and model in cost_rates[provider]:
                rate = cost_rates[provider][model]
            else:
                # Use average rate for provider
                rate = sum(cost_rates[provider].values()) / len(cost_rates[provider])
        else:
            rate = 0.02  # Default rate

        # Estimate based on file size (minimum $0.01)
        estimated_cost = max(0.01, file_size_mb * rate)

        # Cap at per-analysis limit
        per_analysis_limit = current_app.config.get('LLM_PER_ANALYSIS_LIMIT', 5.0)
        return min(estimated_cost, per_analysis_limit)

    except Exception as e:
        logger.error(f"Error estimating LLM cost: {e}")
        return 1.0  # Default estimate

def estimate_processing_time(file: AnalysisFile) -> str:
    """Estimate LLM processing time based on file characteristics"""
    try:
        file_size_mb = (file.file_size or 1024) / (1024 * 1024)

        # Base time: 30 seconds + 10 seconds per MB
        base_time = 30 + (file_size_mb * 10)

        # Adjust for file type complexity
        if file.file_type and any(t in file.file_type.lower() for t in ['archive', 'compressed']):
            base_time *= 1.5

        # Convert to minutes
        minutes = int(base_time / 60)
        seconds = int(base_time % 60)

        if minutes > 0:
            return f"{minutes}m {seconds}s"
        else:
            return f"{seconds}s"

    except Exception:
        return "2-5 minutes"
