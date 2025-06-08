"""
crypto_hunter_web/routes/background_api.py - Complete Background API with Forensics
"""

from flask import Blueprint, request, jsonify, current_app
from crypto_hunter_web.services.auth_service import AuthService
from crypto_hunter_web.services.background_service import BackgroundService, ForensicsToolkit
from crypto_hunter_web.models import AnalysisFile, FileContent, Finding
from crypto_hunter_web.utils.validators import validate_sha256
from celery.result import AsyncResult
import json
import logging

background_api_bp = Blueprint('background_api', __name__)
logger = logging.getLogger(__name__)

@background_api_bp.route('/tools/status', methods=['GET'])
@AuthService.login_required
def get_tools_status():
    """Get status of all forensics tools"""
    try:
        toolkit = ForensicsToolkit()

        tools_status = {}
        for tool_name in toolkit.tools.keys():
            tools_status[tool_name] = toolkit._is_tool_available(tool_name)

        # Add tool categories and descriptions
        tool_info = {}
        for tool_name, config in toolkit.tools.items():
            tool_info[tool_name] = {
                'available': tools_status[tool_name],
                'description': config.get('description', ''),
                'file_types': config.get('file_types', []),
                'timeout': config.get('timeout', 60)
            }

        return jsonify({
            'success': True,
            'tools': tools_status,
            'tool_info': tool_info,
            'total_tools': len(tools_status),
            'available_tools': sum(tools_status.values())
        })

    except Exception as e:
        logger.error(f"Failed to get tools status: {e}")
        return jsonify({'error': str(e)}), 500

@background_api_bp.route('/analyze/<sha>/comprehensive', methods=['POST'])
@AuthService.login_required
def start_comprehensive_analysis(sha):
    """Start comprehensive forensics analysis"""
    try:
        if not validate_sha256(sha):
            return jsonify({'error': 'Invalid SHA256 hash'}), 400

        file_obj = AnalysisFile.query.filter_by(sha256_hash=sha).first()
        if not file_obj:
            return jsonify({'error': 'File not found'}), 404

        # Get analysis options from request
        data = request.get_json() or {}
        analysis_types = data.get('analysis_types', [
            'steganography', 'binary_analysis', 'crypto_patterns', 'strings', 'metadata'
        ])

        # Queue comprehensive analysis
        task_id = BackgroundService.queue_comprehensive_analysis(
            file_id=file_obj.id,
            analysis_types=analysis_types,
            user_id=AuthService.get_current_user().id
        )

        return jsonify({
            'success': True,
            'task_id': task_id,
            'message': 'Comprehensive forensics analysis started',
            'estimated_duration': '5-15 minutes',
            'analysis_types': analysis_types
        })

    except Exception as e:
        logger.error(f"Failed to start comprehensive analysis: {e}")
        return jsonify({'error': str(e)}), 500

@background_api_bp.route('/analyze/<sha>/steganography', methods=['POST'])
@AuthService.login_required
def start_steganography_analysis(sha):
    """Start steganography analysis"""
    try:
        if not validate_sha256(sha):
            return jsonify({'error': 'Invalid SHA256 hash'}), 400

        file_obj = AnalysisFile.query.filter_by(sha256_hash=sha).first()
        if not file_obj:
            return jsonify({'error': 'File not found'}), 404

        # Queue steganography analysis
        task_id = BackgroundService.queue_steganography_analysis(
            file_id=file_obj.id,
            user_id=AuthService.get_current_user().id
        )

        return jsonify({
            'success': True,
            'task_id': task_id,
            'message': 'Steganography analysis started',
            'estimated_duration': '2-5 minutes'
        })

    except Exception as e:
        logger.error(f"Failed to start steganography analysis: {e}")
        return jsonify({'error': str(e)}), 500

@background_api_bp.route('/analyze/<sha>/crypto', methods=['POST'])
@AuthService.login_required
def start_crypto_analysis(sha):
    """Start cryptocurrency pattern analysis"""
    try:
        if not validate_sha256(sha):
            return jsonify({'error': 'Invalid SHA256 hash'}), 400

        file_obj = AnalysisFile.query.filter_by(sha256_hash=sha).first()
        if not file_obj:
            return jsonify({'error': 'File not found'}), 404

        # Get analysis options
        data = request.get_json() or {}
        analysis_options = {
            'deep_scan': data.get('deep_scan', True),
            'blockchain_validation': data.get('blockchain_validation', False),
            'pattern_types': data.get('pattern_types', ['addresses', 'keys', 'mnemonics'])
        }

        # Queue crypto analysis
        task_id = BackgroundService.queue_crypto_analysis(
            file_id=file_obj.id,
            analysis_options=analysis_options,
            user_id=AuthService.get_current_user().id
        )

        return jsonify({
            'success': True,
            'task_id': task_id,
            'message': 'Cryptocurrency analysis started',
            'estimated_duration': '1-3 minutes'
        })

    except Exception as e:
        logger.error(f"Failed to start crypto analysis: {e}")
        return jsonify({'error': str(e)}), 500

@background_api_bp.route('/analyze/<sha>/ai', methods=['POST'])
@AuthService.login_required
def start_ai_analysis(sha):
    """Start AI analysis"""
    try:
        if not validate_sha256(sha):
            return jsonify({'error': 'Invalid SHA256 hash'}), 400

        file_obj = AnalysisFile.query.filter_by(sha256_hash=sha).first()
        if not file_obj:
            return jsonify({'error': 'File not found'}), 404

        # Get AI options
        data = request.get_json() or {}
        ai_options = {
            'analysis_type': data.get('analysis_type', 'comprehensive'),
            'expert_mode': data.get('expert_mode', 'crypto_expert'),
            'include_recommendations': data.get('include_recommendations', True)
        }

        # Queue AI analysis
        task_id = BackgroundService.queue_ai_analysis(
            file_id=file_obj.id,
            ai_options=ai_options,
            user_id=AuthService.get_current_user().id
        )

        return jsonify({
            'success': True,
            'task_id': task_id,
            'message': 'AI analysis started',
            'estimated_duration': '2-8 minutes'
        })

    except Exception as e:
        logger.error(f"Failed to start AI analysis: {e}")
        return jsonify({'error': str(e)}), 500

@background_api_bp.route('/progress/<task_id>', methods=['GET'])
@AuthService.login_required
def get_analysis_progress(task_id):
    """Get progress of running analysis"""
    try:
        status = BackgroundService.get_task_status(task_id)

        if 'error' in status:
            return jsonify({'error': status['error']}), 500

        return jsonify(status)

    except Exception as e:
        logger.error(f"Failed to get progress for task {task_id}: {e}")
        return jsonify({'error': str(e)}), 500

@background_api_bp.route('/results/<sha>', methods=['GET'])
@AuthService.login_required
def get_analysis_results(sha):
    """Get analysis results for a file"""
    try:
        if not validate_sha256(sha):
            return jsonify({'error': 'Invalid SHA256 hash'}), 400

        file_obj = AnalysisFile.query.filter_by(sha256_hash=sha).first()
        if not file_obj:
            return jsonify({'error': 'File not found'}), 404

        # Get all analysis content
        analysis_content = FileContent.query.filter(
            FileContent.file_id == file_obj.id,
            FileContent.content_type.in_([
                'comprehensive_forensics',
                'steganography_analysis',
                'crypto_pattern_analysis',
                'ai_analysis'
            ])
        ).all()

        if not analysis_content:
            return jsonify({
                'has_results': False,
                'message': 'No analysis results found'
            })

        # Compile results
        results = {
            'has_results': True,
            'file_info': {
                'filename': file_obj.filename,
                'file_type': file_obj.file_type,
                'file_size': file_obj.file_size,
                'sha256': file_obj.sha256_hash,
                'status': file_obj.status,
                'analyzed_at': file_obj.analyzed_at.isoformat() if file_obj.analyzed_at else None
            },
            'analysis_results': {},
            'summary': {
                'total_analyses': len(analysis_content),
                'analysis_types': [c.content_type for c in analysis_content]
            }
        }

        for content in analysis_content:
            results['analysis_results'][content.content_type] = content.content_json

        # Get findings
        findings = Finding.query.filter_by(file_id=file_obj.id).all()
        results['findings'] = [
            {
                'id': f.id,
                'type': f.finding_type,
                'confidence': f.confidence,
                'description': f.description,
                'created_at': f.created_at.isoformat(),
                'details': json.loads(f.details) if f.details else {}
            }
            for f in findings
        ]
        results['summary']['total_findings'] = len(findings)

        # Calculate overall confidence
        if findings:
            avg_confidence = sum(f.confidence for f in findings) / len(findings)
            results['summary']['average_confidence'] = round(avg_confidence, 2)
        else:
            results['summary']['average_confidence'] = 0.0

        return jsonify(results)

    except Exception as e:
        logger.error(f"Failed to get results for {sha}: {e}")
        return jsonify({'error': str(e)}), 500

@background_api_bp.route('/tools/<tool_name>/run', methods=['POST'])
@AuthService.login_required
def run_individual_tool(tool_name):
    """Run individual forensics tool"""
    try:
        data = request.get_json()
        if not data or 'file_hash' not in data:
            return jsonify({'error': 'File hash required'}), 400

        sha = data['file_hash']
        if not validate_sha256(sha):
            return jsonify({'error': 'Invalid SHA256 hash'}), 400

        file_obj = AnalysisFile.query.filter_by(sha256_hash=sha).first()
        if not file_obj:
            return jsonify({'error': 'File not found'}), 404

        # Initialize toolkit and run specific tool
        toolkit = ForensicsToolkit()

        if tool_name not in toolkit.tools:
            return jsonify({'error': f'Tool {tool_name} not available'}), 400

        if not toolkit._is_tool_available(tool_name):
            return jsonify({'error': f'Tool {tool_name} not installed'}), 400

        # Run tool analysis
        result = toolkit._run_tool_analysis(
            tool_name,
            file_obj.filepath,
            file_obj.file_type
        )

        if result:
            response_data = {
                'success': result.success,
                'tool_name': result.tool_name,
                'execution_time': result.execution_time,
                'confidence': result.confidence,
                'metadata': result.metadata,
                'findings': toolkit._extract_findings(result) if result.success else []
            }

            if not result.success:
                response_data['error'] = result.error_message

            return jsonify(response_data)
        else:
            return jsonify({'error': 'Tool execution failed'}), 500

    except Exception as e:
        logger.error(f"Failed to run tool {tool_name}: {e}")
        return jsonify({'error': str(e)}), 500

@background_api_bp.route('/queue/status', methods=['GET'])
@AuthService.login_required
def get_queue_status():
    """Get status of analysis queues"""
    try:
        queue_status = BackgroundService.get_queue_status()

        # Add queue statistics
        stats = {
            'queue_status': queue_status,
            'timestamp': '2024-12-19T10:30:00Z'
        }

        # Count active tasks by queue
        active_by_queue = {}
        if 'active_tasks' in queue_status:
            for worker, tasks in queue_status['active_tasks'].items():
                for task in tasks:
                    queue_name = task.get('delivery_info', {}).get('routing_key', 'default')
                    active_by_queue[queue_name] = active_by_queue.get(queue_name, 0) + 1

        stats['active_by_queue'] = active_by_queue

        return jsonify(stats)

    except Exception as e:
        logger.error(f"Failed to get queue status: {e}")
        return jsonify({'error': str(e)}), 500

@background_api_bp.route('/statistics', methods=['GET'])
@AuthService.login_required
def get_system_statistics():
    """Get system analysis statistics"""
    try:
        # Get basic statistics
        total_files = AnalysisFile.query.count()
        analyzed_files = AnalysisFile.query.filter_by(status='complete').count()
        processing_files = AnalysisFile.query.filter_by(status='processing').count()
        failed_files = AnalysisFile.query.filter_by(status='failed').count()

        # Get findings statistics
        total_findings = Finding.query.count()

        # Analysis type statistics
        analysis_stats = {}
        content_types = FileContent.query.with_entities(FileContent.content_type).distinct().all()
        for (content_type,) in content_types:
            count = FileContent.query.filter_by(content_type=content_type).count()
            analysis_stats[content_type] = count

        statistics = {
            'file_statistics': {
                'total_files': total_files,
                'analyzed_files': analyzed_files,
                'processing_files': processing_files,
                'failed_files': failed_files,
                'completion_rate': (analyzed_files / total_files * 100) if total_files > 0 else 0
            },
            'finding_statistics': {
                'total_findings': total_findings,
                'findings_per_file': (total_findings / analyzed_files) if analyzed_files > 0 else 0
            },
            'analysis_statistics': analysis_stats,
            'timestamp': '2024-12-19T10:30:00Z'
        }

        return jsonify(statistics)

    except Exception as e:
        logger.error(f"Failed to get statistics: {e}")
        return jsonify({'error': str(e)}), 500

@background_api_bp.route('/task/<task_id>/cancel', methods=['POST'])
@AuthService.login_required
def cancel_task(task_id):
    """Cancel a running task"""
    try:
        from crypto_hunter_web.services.background_service import celery

        # Revoke the task
        celery.control.revoke(task_id, terminate=True)

        return jsonify({
            'success': True,
            'message': f'Task {task_id} cancellation requested'
        })

    except Exception as e:
        logger.error(f"Failed to cancel task {task_id}: {e}")
        return jsonify({'error': str(e)}), 500

@background_api_bp.route('/health', methods=['GET'])
@AuthService.login_required
def health_check():
    """Health check for background services"""
    try:
        # Check Celery connection
        from crypto_hunter_web.services.background_service import celery

        inspect = celery.control.inspect()
        stats = inspect.stats()

        # Check Redis connection
        import redis
        redis_client = redis.from_url(current_app.config.get('REDIS_URL', 'redis://localhost:6379/0'))
        redis_client.ping()

        # Check tools availability
        toolkit = ForensicsToolkit()
        available_tools = sum(1 for tool in toolkit.tools.keys() if toolkit._is_tool_available(tool))
        total_tools = len(toolkit.tools)

        health_status = {
            'status': 'healthy',
            'timestamp': '2024-12-19T10:30:00Z',
            'services': {
                'celery': {
                    'status': 'connected' if stats else 'disconnected',
                    'workers': len(stats) if stats else 0
                },
                'redis': {
                    'status': 'connected'
                },
                'forensics_tools': {
                    'available_tools': available_tools,
                    'total_tools': total_tools,
                    'availability_rate': (available_tools / total_tools * 100) if total_tools > 0 else 0
                }
            }
        }

        return jsonify(health_status)

    except Exception as e:
        logger.error(f"Health check failed: {e}")
        return jsonify({
            'status': 'unhealthy',
            'error': str(e),
            'timestamp': '2024-12-19T10:30:00Z'
        }), 500

@background_api_bp.route('/recommend/<sha>', methods=['GET'])
@AuthService.login_required
def get_analysis_recommendations(sha):
    """Get analysis recommendations for a file"""
    try:
        if not validate_sha256(sha):
            return jsonify({'error': 'Invalid SHA256 hash'}), 400

        file_obj = AnalysisFile.query.filter_by(sha256_hash=sha).first()
        if not file_obj:
            return jsonify({'error': 'File not found'}), 404

        # Get existing analysis
        existing_analysis = {}
        content = FileContent.query.filter_by(file_id=file_obj.id).first()
        if content:
            try:
                existing_analysis = json.loads(content.content_text or '{}')
            except:
                pass

        # Generate recommendations based on file characteristics
        recommendations = []

        # File type based recommendations
        if 'image' in file_obj.file_type:
            recommendations.extend([
                {
                    'type': 'steganography',
                    'method': 'zsteg',
                    'description': 'Try ZSteg for LSB steganography detection',
                    'priority': 'high',
                    'confidence': 0.8
                },
                {
                    'type': 'steganography',
                    'method': 'steghide',
                    'description': 'Check for Steghide hidden content',
                    'priority': 'medium',
                    'confidence': 0.6
                },
                {
                    'type': 'metadata',
                    'method': 'exiftool',
                    'description': 'Extract EXIF metadata for hidden information',
                    'priority': 'medium',
                    'confidence': 0.7
                }
            ])

        if 'audio' in file_obj.file_type:
            recommendations.extend([
                {
                    'type': 'steganography',
                    'method': 'steghide',
                    'description': 'Audio steganography analysis with Steghide',
                    'priority': 'high',
                    'confidence': 0.8
                },
                {
                    'type': 'spectral_analysis',
                    'method': 'sox',
                    'description': 'Generate spectrogram to visualize hidden data',
                    'priority': 'medium',
                    'confidence': 0.6
                }
            ])

        if 'application' in file_obj.file_type or 'executable' in file_obj.file_type:
            recommendations.extend([
                {
                    'type': 'binary_analysis',
                    'method': 'binwalk',
                    'description': 'Extract embedded files and analyze structure',
                    'priority': 'high',
                    'confidence': 0.9
                },
                {
                    'type': 'reverse_engineering',
                    'method': 'radare2',
                    'description': 'Reverse engineer binary for hidden functionality',
                    'priority': 'medium',
                    'confidence': 0.7
                }
            ])

        # File size based recommendations
        if file_obj.file_size and file_obj.file_size > 1024 * 1024:  # > 1MB
            recommendations.append({
                'type': 'file_carving',
                'method': 'foremost',
                'description': 'Large file - check for embedded files with file carving',
                'priority': 'medium',
                'confidence': 0.7
            })

        # Always recommend crypto analysis and strings
        recommendations.extend([
            {
                'type': 'crypto_analysis',
                'method': 'crypto_patterns',
                'description': 'Analyze for cryptocurrency addresses and keys',
                'priority': 'high',
                'confidence': 0.8
            },
            {
                'type': 'string_analysis',
                'method': 'strings',
                'description': 'Extract readable strings for manual analysis',
                'priority': 'medium',
                'confidence': 0.6
            }
        ])

        # If no prior analysis, recommend comprehensive
        if not existing_analysis:
            recommendations.insert(0, {
                'type': 'comprehensive',
                'method': 'comprehensive_analysis',
                'description': 'Run comprehensive analysis with all available tools',
                'priority': 'high',
                'confidence': 0.9
            })

        return jsonify({
            'success': True,
            'recommendations': recommendations,
            'file_analysis': {
                'file_type': file_obj.file_type,
                'file_size': file_obj.file_size,
                'has_existing_analysis': bool(existing_analysis)
            }
        })

    except Exception as e:
        logger.error(f"Failed to get recommendations for {sha}: {e}")
        return jsonify({'error': str(e)}), 500