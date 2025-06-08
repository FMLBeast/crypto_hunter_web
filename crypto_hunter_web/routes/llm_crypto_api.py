# crypto_hunter_web/routes/llm_crypto_api.py - COMPLETE LLM API IMPLEMENTATION

from flask import Blueprint, request, jsonify, current_app
from flask_login import login_required, current_user
from datetime import datetime, timedelta

from crypto_hunter_web.models import db, AnalysisFile, FileContent
from crypto_hunter_web.services.auth_service import AuthService
from crypto_hunter_web.services.llm_crypto_orchestrator import LLMCryptoOrchestrator
from crypto_hunter_web.utils.decorators import rate_limit, api_endpoint, validate_json
from crypto_hunter_web.utils.validators import validate_sha256

llm_crypto_api_bp = Blueprint('llm_crypto_api', __name__)

# Initialize LLM orchestrator
llm_orchestrator = LLMCryptoOrchestrator()


@llm_crypto_api_bp.route('/llm/analyze/<sha>')
@api_endpoint(rate_limit_requests=20, require_auth=True)
def analyze_with_llm(sha):
    """Analyze a specific file using LLM capabilities"""
    try:
        if not validate_sha256(sha):
            return jsonify({'error': 'Invalid SHA256 hash format'}), 400
        
        # Find file
        file = AnalysisFile.find_by_sha(sha)
        if not file:
            return jsonify({'error': 'File not found'}), 404
        
        # Get analysis parameters
        max_cost = request.args.get('max_cost', 5.0, type=float)
        force_reanalysis = request.args.get('force', 'false').lower() == 'true'
        
        # Validate max_cost
        if max_cost <= 0 or max_cost > 50:
            return jsonify({'error': 'max_cost must be between 0.01 and 50.00'}), 400
        
        # Check if analysis already exists and is recent
        if not force_reanalysis:
            existing_analysis = FileContent.query.filter_by(
                file_id=file.id,
                content_type='llm_analysis_complete'
            ).first()
            
            if existing_analysis:
                # Check if analysis is recent (within 24 hours)
                if existing_analysis.extracted_at > datetime.utcnow() - timedelta(hours=24):
                    try:
                        existing_results = json.loads(existing_analysis.content_text)
                        return jsonify({
                            'success': True,
                            'message': 'Returning cached LLM analysis',
                            'file_sha': sha,
                            'filename': file.filename,
                            'analysis': existing_results,
                            'cached': True,
                            'analyzed_at': existing_analysis.extracted_at.isoformat(),
                            'timestamp': datetime.utcnow().isoformat()
                        })
                    except json.JSONDecodeError:
                        # Invalid JSON, proceed with new analysis
                        pass
        
        # Check budget before analysis
        budget_check = llm_orchestrator.cost_manager.check_budget()
        if not budget_check['can_continue']:
            return jsonify({
                'error': 'LLM budget exceeded',
                'budget_status': budget_check,
                'retry_after': 3600  # Retry after 1 hour
            }), 429
        
        # Perform LLM analysis
        analysis_results = llm_orchestrator.analyze_file_with_llm(file.id, max_cost)
        
        if not analysis_results.get('success'):
            error_msg = analysis_results.get('error', 'Unknown error during LLM analysis')
            
            # Return specific error codes for different failure types
            if 'budget' in error_msg.lower():
                return jsonify({
                    'error': error_msg,
                    'error_type': 'budget_exceeded',
                    'budget_status': analysis_results.get('budget_status')
                }), 429
            elif 'not found' in error_msg.lower():
                return jsonify({'error': error_msg, 'error_type': 'file_not_found'}), 404
            else:
                return jsonify({'error': error_msg, 'error_type': 'analysis_failed'}), 500
        
        # Extract key insights from the analysis
        insights = _extract_key_insights(analysis_results)
        
        # Log the analysis
        AuthService.log_action('llm_analysis_performed',
                             f'LLM analysis completed for {file.filename}',
                             file_id=file.id,
                             metadata={
                                 'strategies_completed': len(analysis_results.get('strategies_completed', [])),
                                 'total_cost': analysis_results.get('total_cost', 0),
                                 'budget_limited': analysis_results.get('budget_limited', False),
                                 'max_cost_allowed': max_cost
                             })
        
        return jsonify({
            'success': True,
            'file_sha': sha,
            'filename': file.filename,
            'analysis': analysis_results,
            'insights': insights,
            'cost_summary': {
                'total_cost': analysis_results.get('total_cost', 0),
                'budget_limited': analysis_results.get('budget_limited', False),
                'strategies_completed': len(analysis_results.get('strategies_completed', []))
            },
            'cached': False,
            'timestamp': datetime.utcnow().isoformat()
        })
        
    except Exception as e:
        current_app.logger.error(f"Error in LLM analysis for {sha}: {e}")
        return jsonify({'error': str(e)}), 500


@llm_crypto_api_bp.route('/llm/batch-analyze', methods=['POST'])
@api_endpoint(rate_limit_requests=5, require_auth=True)
@validate_json(required_fields=['file_ids'])
def batch_analyze_with_llm():
    """Analyze multiple files with LLM in batch mode"""
    try:
        data = request.get_json()
        file_ids = data.get('file_ids', [])
        max_total_cost = data.get('max_total_cost', 20.0)
        
        # Validation
        if not isinstance(file_ids, list) or not file_ids:
            return jsonify({'error': 'file_ids must be a non-empty list'}), 400
        
        if len(file_ids) > 20:
            return jsonify({'error': 'Maximum 20 files can be analyzed in batch'}), 400
        
        if max_total_cost <= 0 or max_total_cost > 100:
            return jsonify({'error': 'max_total_cost must be between 0.01 and 100.00'}), 400
        
        # Validate file IDs
        try:
            file_ids = [int(fid) for fid in file_ids]
        except (ValueError, TypeError):
            return jsonify({'error': 'All file_ids must be integers'}), 400
        
        # Check that all files exist
        existing_files = AnalysisFile.query.filter(AnalysisFile.id.in_(file_ids)).all()
        if len(existing_files) != len(file_ids):
            existing_ids = {f.id for f in existing_files}
            missing_ids = [fid for fid in file_ids if fid not in existing_ids]
            return jsonify({
                'error': f'Files not found: {missing_ids}',
                'missing_file_ids': missing_ids
            }), 404
        
        # Check budget before batch analysis
        budget_check = llm_orchestrator.cost_manager.check_budget()
        if not budget_check['can_continue']:
            return jsonify({
                'error': 'LLM budget exceeded',
                'budget_status': budget_check
            }), 429
        
        # Perform batch analysis
        batch_results = llm_orchestrator.batch_analyze_files(file_ids, max_total_cost)
        
        # Generate batch summary
        successful_analyses = [r for r in batch_results['results'].values() if r.get('success')]
        failed_analyses = [r for r in batch_results['results'].values() if not r.get('success')]
        
        # Extract insights from successful analyses
        batch_insights = []
        for file_id, result in batch_results['results'].items():
            if result.get('success'):
                file = next((f for f in existing_files if f.id == int(file_id)), None)
                if file:
                    insights = _extract_key_insights(result)
                    batch_insights.append({
                        'file_id': file_id,
                        'filename': file.filename,
                        'insights': insights,
                        'cost': result.get('total_cost', 0)
                    })
        
        # Log batch analysis
        AuthService.log_action('llm_batch_analysis_performed',
                             f'LLM batch analysis for {len(file_ids)} files',
                             metadata={
                                 'file_count': len(file_ids),
                                 'successful_count': batch_results['completed_files'],
                                 'failed_count': batch_results['failed_files'],
                                 'total_cost': batch_results['total_cost'],
                                 'budget_exceeded': batch_results['budget_exceeded']
                             })
        
        return jsonify({
            'success': True,
            'batch_summary': {
                'total_files': batch_results['total_files'],
                'completed_files': batch_results['completed_files'],
                'failed_files': batch_results['failed_files'],
                'total_cost': batch_results['total_cost'],
                'budget_exceeded': batch_results['budget_exceeded']
            },
            'file_results': batch_results['results'],
            'batch_insights': batch_insights,
            'cost_breakdown': {
                'successful_analyses': len(successful_analyses),
                'average_cost_per_file': batch_results['total_cost'] / len(successful_analyses) if successful_analyses else 0,
                'budget_utilization': (batch_results['total_cost'] / max_total_cost * 100) if max_total_cost > 0 else 0
            },
            'timestamp': datetime.utcnow().isoformat()
        })
        
    except Exception as e:
        current_app.logger.error(f"Error in LLM batch analysis: {e}")
        return jsonify({'error': str(e)}), 500


@llm_crypto_api_bp.route('/llm/cost/stats')
@api_endpoint(rate_limit_requests=100, cache_ttl=60)
def get_cost_stats():
    """Get LLM cost statistics and budget information"""
    try:
        cost_stats = llm_orchestrator.get_cost_statistics()
        
        # Add additional statistics
        budget_status = llm_orchestrator.cost_manager.check_budget()
        
        # Calculate daily trend (last 7 days)
        daily_trend = []
        for i in range(7):
            date = datetime.utcnow() - timedelta(days=i)
            daily_spend = llm_orchestrator.cost_manager.get_daily_spend(date)
            daily_trend.append({
                'date': date.strftime('%Y-%m-%d'),
                'spend': daily_spend
            })
        
        enhanced_stats = {
            'current_usage': cost_stats,
            'budget_status': budget_status,
            'daily_trend': daily_trend,
            'usage_summary': {
                'can_continue_analysis': budget_status['can_continue'],
                'daily_budget_remaining': budget_status['daily_remaining'],
                'hourly_budget_remaining': budget_status['hourly_remaining'],
                'daily_usage_percentage': (budget_status['daily_spend'] / budget_status['daily_budget'] * 100) if budget_status['daily_budget'] > 0 else 0,
                'hourly_usage_percentage': (budget_status['hourly_spend'] / budget_status['hourly_budget'] * 100) if budget_status['hourly_budget'] > 0 else 0
            },
            'recommendations': _generate_cost_recommendations(budget_status, cost_stats)
        }
        
        return jsonify({
            'success': True,
            'cost_statistics': enhanced_stats,
            'timestamp': datetime.utcnow().isoformat()
        })
        
    except Exception as e:
        current_app.logger.error(f"Error getting cost stats: {e}")
        return jsonify({'error': str(e)}), 500


@llm_crypto_api_bp.route('/llm/results/<int:file_id>')
@api_endpoint(rate_limit_requests=200, cache_ttl=300)
def get_llm_results(file_id):
    """Get LLM analysis results for a specific file"""
    try:
        # Check if file exists
        file = AnalysisFile.query.get(file_id)
        if not file:
            return jsonify({'error': 'File not found'}), 404
        
        # Get LLM analysis results
        llm_content = FileContent.query.filter_by(
            file_id=file_id,
            content_type='llm_analysis_complete'
        ).first()
        
        if not llm_content:
            return jsonify({
                'file_id': file_id,
                'filename': file.filename,
                'has_llm_analysis': False,
                'message': 'No LLM analysis found for this file',
                'suggest_analysis': True
            })
        
        try:
            analysis_results = json.loads(llm_content.content_text)
        except json.JSONDecodeError:
            return jsonify({'error': 'Invalid LLM analysis data format'}), 500
        
        # Extract and enhance insights
        insights = _extract_key_insights(analysis_results)
        
        # Calculate analysis quality metrics
        quality_metrics = _calculate_analysis_quality(analysis_results)
        
        # Get analysis timeline
        timeline = []
        timeline.append({
            'event': 'Analysis Started',
            'timestamp': analysis_results.get('analysis_timestamp'),
            'details': f"Initiated LLM analysis with {len(analysis_results.get('strategies_completed', []))} strategies"
        })
        
        for strategy in analysis_results.get('strategies_completed', []):
            if strategy in analysis_results.get('provider_results', {}):
                strategy_result = analysis_results['provider_results'][strategy]
                timeline.append({
                    'event': f'Strategy Completed: {strategy}',
                    'timestamp': analysis_results.get('analysis_timestamp'),
                    'details': f"Cost: ${strategy_result.get('cost', 0):.4f}, Provider: {strategy_result.get('provider', 'unknown')}"
                })
        
        timeline.append({
            'event': 'Analysis Completed',
            'timestamp': llm_content.extracted_at.isoformat(),
            'details': f"Total cost: ${analysis_results.get('total_cost', 0):.4f}"
        })
        
        return jsonify({
            'success': True,
            'file_id': file_id,
            'filename': file.filename,
            'has_llm_analysis': True,
            'analysis_results': analysis_results,
            'insights': insights,
            'quality_metrics': quality_metrics,
            'timeline': timeline,
            'analysis_metadata': {
                'analyzed_at': llm_content.extracted_at.isoformat(),
                'content_size': llm_content.content_size,
                'strategies_used': len(analysis_results.get('strategies_completed', [])),
                'total_cost': analysis_results.get('total_cost', 0),
                'budget_limited': analysis_results.get('budget_limited', False)
            },
            'timestamp': datetime.utcnow().isoformat()
        })
        
    except Exception as e:
        current_app.logger.error(f"Error getting LLM results for file {file_id}: {e}")
        return jsonify({'error': str(e)}), 500


@llm_crypto_api_bp.route('/llm/budget', methods=['GET', 'POST'])
@api_endpoint(rate_limit_requests=50, require_auth=True)
@AuthService.admin_required
def manage_budget():
    """Manage LLM budget settings (admin only)"""
    try:
        if request.method == 'GET':
            # Get current budget settings
            current_budgets = {
                'daily_budget': llm_orchestrator.cost_manager.daily_budget,
                'hourly_budget': llm_orchestrator.cost_manager.hourly_budget
            }
            
            budget_status = llm_orchestrator.cost_manager.check_budget()
            
            return jsonify({
                'success': True,
                'current_budgets': current_budgets,
                'budget_status': budget_status,
                'usage_statistics': llm_orchestrator.get_cost_statistics(),
                'timestamp': datetime.utcnow().isoformat()
            })
        
        elif request.method == 'POST':
            # Update budget settings
            data = request.get_json() or {}
            
            daily_budget = data.get('daily_budget')
            hourly_budget = data.get('hourly_budget')
            
            updated_settings = {}
            
            if daily_budget is not None:
                if not isinstance(daily_budget, (int, float)) or daily_budget < 0:
                    return jsonify({'error': 'daily_budget must be a non-negative number'}), 400
                if daily_budget > 1000:
                    return jsonify({'error': 'daily_budget cannot exceed $1000'}), 400
                
                llm_orchestrator.cost_manager.daily_budget = float(daily_budget)
                updated_settings['daily_budget'] = daily_budget
            
            if hourly_budget is not None:
                if not isinstance(hourly_budget, (int, float)) or hourly_budget < 0:
                    return jsonify({'error': 'hourly_budget must be a non-negative number'}), 400
                if hourly_budget > 100:
                    return jsonify({'error': 'hourly_budget cannot exceed $100'}), 400
                
                llm_orchestrator.cost_manager.hourly_budget = float(hourly_budget)
                updated_settings['hourly_budget'] = hourly_budget
            
            if not updated_settings:
                return jsonify({'error': 'No valid budget settings provided'}), 400
            
            # Log budget changes
            AuthService.log_action('llm_budget_updated',
                                 f'Updated LLM budget settings: {updated_settings}',
                                 metadata=updated_settings)
            
            return jsonify({
                'success': True,
                'message': 'Budget settings updated successfully',
                'updated_settings': updated_settings,
                'new_budgets': {
                    'daily_budget': llm_orchestrator.cost_manager.daily_budget,
                    'hourly_budget': llm_orchestrator.cost_manager.hourly_budget
                },
                'timestamp': datetime.utcnow().isoformat()
            })
            
    except Exception as e:
        current_app.logger.error(f"Error managing LLM budget: {e}")
        return jsonify({'error': str(e)}), 500


def _extract_key_insights(analysis_results):
    """Extract key insights from LLM analysis results"""
    insights = {
        'security_findings': [],
        'crypto_elements': [],
        'recommendations': [],
        'confidence_scores': []
    }
    
    try:
        provider_results = analysis_results.get('provider_results', {})
        
        for strategy, result in provider_results.items():
            if not result.get('success'):
                continue
            
            content = result.get('content', '')
            
            # Extract security-related findings
            if 'vulnerability' in content.lower() or 'weakness' in content.lower():
                insights['security_findings'].append(f"From {strategy}: Security concern identified")
            
            # Extract crypto elements
            crypto_keywords = ['encryption', 'cipher', 'hash', 'key', 'certificate', 'signature']
            for keyword in crypto_keywords:
                if keyword in content.lower():
                    insights['crypto_elements'].append(f"From {strategy}: {keyword.title()} detected")
                    break
            
            # Extract recommendations
            if 'recommend' in content.lower() or 'suggest' in content.lower():
                insights['recommendations'].append(f"From {strategy}: Recommendations provided")
            
            # Track confidence
            confidence = result.get('tokens', {}).get('output', 0) / max(result.get('tokens', {}).get('input', 1), 1)
            insights['confidence_scores'].append({
                'strategy': strategy,
                'confidence': min(confidence, 1.0)
            })
    
    except Exception as e:
        current_app.logger.warning(f"Error extracting insights: {e}")
    
    return insights


def _calculate_analysis_quality(analysis_results):
    """Calculate quality metrics for the analysis"""
    quality_metrics = {
        'completeness': 0.0,
        'cost_efficiency': 0.0,
        'strategy_success_rate': 0.0,
        'overall_score': 0.0
    }
    
    try:
        total_strategies = len(analysis_results.get('strategies_completed', []))
        if total_strategies == 0:
            return quality_metrics
        
        # Completeness: how many strategies completed successfully
        successful_strategies = len([s for s in analysis_results.get('provider_results', {}).values() if s.get('success')])
        quality_metrics['completeness'] = successful_strategies / total_strategies
        
        # Cost efficiency: output tokens per dollar
        total_cost = analysis_results.get('total_cost', 0)
        total_output_tokens = sum(
            r.get('tokens', {}).get('output', 0) 
            for r in analysis_results.get('provider_results', {}).values()
            if r.get('success')
        )
        
        if total_cost > 0:
            quality_metrics['cost_efficiency'] = min(total_output_tokens / (total_cost * 1000), 1.0)
        
        # Strategy success rate
        quality_metrics['strategy_success_rate'] = quality_metrics['completeness']
        
        # Overall score (weighted average)
        quality_metrics['overall_score'] = (
            quality_metrics['completeness'] * 0.4 +
            quality_metrics['cost_efficiency'] * 0.3 +
            quality_metrics['strategy_success_rate'] * 0.3
        )
    
    except Exception as e:
        current_app.logger.warning(f"Error calculating quality metrics: {e}")
    
    return quality_metrics


def _generate_cost_recommendations(budget_status, cost_stats):
    """Generate cost optimization recommendations"""
    recommendations = []
    
    try:
        # Budget utilization recommendations
        if budget_status['daily_usage_percentage'] > 80:
            recommendations.append({
                'type': 'budget_warning',
                'message': 'Daily budget utilization is high (>80%)',
                'action': 'Consider increasing daily budget or reducing analysis frequency'
            })
        
        if budget_status['hourly_usage_percentage'] > 90:
            recommendations.append({
                'type': 'rate_limiting',
                'message': 'Hourly budget nearly exhausted (>90%)',
                'action': 'Reduce immediate LLM usage or increase hourly budget'
            })
        
        # Cost efficiency recommendations
        avg_hourly_spend = budget_status['daily_spend'] / 24 if budget_status['daily_spend'] > 0 else 0
        if avg_hourly_spend < budget_status['hourly_budget'] * 0.1:
            recommendations.append({
                'type': 'underutilization',
                'message': 'Budget appears underutilized',
                'action': 'Consider more aggressive analysis strategies or reducing budget'
            })
        
        # Model selection recommendations
        if len(cost_stats.get('last_24_hours', [])) > 5:
            high_cost_hours = [h for h in cost_stats['last_24_hours'] if h['spend'] > budget_status['hourly_budget'] * 0.5]
            if len(high_cost_hours) > 3:
                recommendations.append({
                    'type': 'model_optimization',
                    'message': 'Multiple high-cost analysis hours detected',
                    'action': 'Consider using more cost-effective models for routine analysis'
                })
    
    except Exception as e:
        current_app.logger.warning(f"Error generating cost recommendations: {e}")
    
    return recommendations


# Import json at module level
import json