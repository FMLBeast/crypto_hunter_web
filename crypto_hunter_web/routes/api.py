"""
Complete API routes for advanced features integration
"""

from flask import Blueprint, request, jsonify, session
from crypto_hunter_web.services.auth_service import AuthService
from crypto_hunter_web.models import db
from crypto_hunter_web.models import AnalysisFile, FileContent
from crypto_hunter_web.models import Finding, Vector
from crypto_hunter_web.models import User
from crypto_hunter_web.models import FileStatus, FindingStatus
from crypto_hunter_web.utils.decorators import rate_limit
from crypto_hunter_web.utils.validators import validate_sha256
import json

# Import the API route blueprints
from crypto_hunter_web.routes.background_api import background_api_bp
from .crypto_api import crypto_api_bp
from .llm_crypto_api import llm_crypto_api_bp
from .search_api import search_api_bp

# Main API blueprint
api_bp = Blueprint('api', __name__)

# Register sub-blueprints
api_bp.register_blueprint(background_api_bp, url_prefix='/background_api')
api_bp.register_blueprint(crypto_api_bp, url_prefix='/crypto_api')
api_bp.register_blueprint(llm_crypto_api_bp, url_prefix='/llm_crypto_api')
api_bp.register_blueprint(search_api_bp, url_prefix='/search_api')


@api_bp.route('/files/<sha>/mark-root', methods=['POST'])
@AuthService.login_required
def mark_file_as_root(sha):
    """Mark file as root file"""
    if not validate_sha256(sha):
        return jsonify({'error': 'Invalid SHA256'}), 400

    file = AnalysisFile.query.filter_by(sha256_hash=sha).first()
    if not file:
        return jsonify({'error': 'File not found'}), 404

    data = request.json
    is_root = data.get('is_root', True)

    file.is_root_file = is_root
    if is_root:
        file.priority = max(file.priority, 7)  # Boost priority for root files

    db.session.commit()

    AuthService.log_action('file_marked_root', f'File {file.filename} marked as root', file_id=file.id)

    return jsonify({
        'success': True,
        'message': f'File {"marked" if is_root else "unmarked"} as root'
    })


@api_bp.route('/extract', methods=['POST'])
@AuthService.login_required
@rate_limit(limit="4 per minute")
def extract_content():
    """Start content extraction"""
    data = request.json
    file_sha = data.get('file_sha')
    extraction_method = data.get('extraction_method', 'zsteg')

    if not validate_sha256(file_sha):
        return jsonify({'error': 'Invalid SHA256'}), 400

    file = AnalysisFile.query.filter_by(sha256_hash=file_sha).first()
    if not file:
        return jsonify({'error': 'File not found'}), 404

    try:
        from crypto_hunter_web.services.extraction_engine import ExtractionEngine
        result = ExtractionEngine.extract_from_file(
            file,
            extraction_method,
            parameters=data.get('parameters', {}),
            user_id=session['user_id']
        )

        if result['success']:
            return jsonify({
                'success': True,
                'message': 'Extraction completed',
                'extracted_file_id': result['extracted_file'].id,
                'relationship_id': result['relationship'].id
            })
        else:
            return jsonify({
                'success': False,
                'error': result['error'],
                'details': result.get('details', '')
            })

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@api_bp.route('/search-sha')
@AuthService.login_required
def search_sha():
    """Quick SHA search for dashboard"""
    query = request.args.get('q', '').strip()

    if len(query) < 4:
        return jsonify([])

    files = AnalysisFile.query.filter(
        AnalysisFile.sha256_hash.ilike(f'{query}%')
    ).limit(10).all()

    results = []
    for file in files:
        results.append({
            'sha': file.sha256_hash,
            'filename': file.filename,
            'status': file.status,
            'file_type': file.file_type
        })

    return jsonify(results)


@api_bp.route('/regions', methods=['POST'])
@AuthService.login_required
def create_region():
    """Create a new region of interest"""
    data = request.json

    try:
        from crypto_hunter_web import RegionOfInterest

        region = RegionOfInterest(
            file_content_id=data['content_id'],
            analyst_id=session['user_id'],
            start_offset=data['start_offset'],
            end_offset=data['end_offset'],
            title=data['title'],
            description=data.get('description', ''),
            region_type=data.get('region_type', 'suspicious'),
            confidence_level=data.get('confidence_level', 5),
            color=data.get('color', '#ef4444')
        )

        db.session.add(region)
        db.session.commit()

        AuthService.log_action('region_created', f'Created region: {region.title}')

        return jsonify({
            'success': True,
            'region_id': region.id
        })

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@api_bp.route('/regions/<int:region_id>', methods=['DELETE'])
@AuthService.login_required
def delete_region(region_id):
    """Delete a region of interest"""
    try:
        from crypto_hunter_web import RegionOfInterest

        region = RegionOfInterest.query.get_or_404(region_id)

        # Check permissions
        if region.analyst_id != session['user_id'] and session.get('role') != 'admin':
            return jsonify({'error': 'Permission denied'}), 403

        db.session.delete(region)
        db.session.commit()

        AuthService.log_action('region_deleted', f'Deleted region: {region.title}')

        return jsonify({'success': True})

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@api_bp.route('/status')
@AuthService.login_required
def system_status():
    """Get system status for dashboard"""
    try:
        # Get basic stats
        total_files = AnalysisFile.query.count()
        analyzed_files = AnalysisFile.query.filter_by(status=FileStatus.COMPLETE).count()
        pending_files = AnalysisFile.query.filter_by(status=FileStatus.PENDING).count()
        root_files = AnalysisFile.query.filter_by(is_root_file=True).count()

        # Get recent activity
        recent_files = AnalysisFile.query.order_by(
            AnalysisFile.created_at.desc()
        ).limit(5).all()

        # Get finding stats
        from crypto_hunter_web import Finding
        total_findings = Finding.query.count()
        verified_findings = Finding.query.filter_by(status=FindingStatus.CONFIRMED).count()

        return jsonify({
            'success': True,
            'stats': {
                'total_files': total_files,
                'analyzed_files': analyzed_files,
                'pending_files': pending_files,
                'root_files': root_files,
                'total_findings': total_findings,
                'verified_findings': verified_findings,
                'progress_percentage': (analyzed_files / total_files * 100) if total_files > 0 else 0
            },
            'recent_files': [
                {
                    'id': f.id,
                    'filename': f.filename,
                    'sha': f.sha256_hash,
                    'status': f.status,
                    'created_at': f.created_at.isoformat()
                }
                for f in recent_files
            ]
        })

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@api_bp.route('/files/<sha>/priority', methods=['PUT'])
@AuthService.login_required
def update_file_priority(sha):
    """Update file priority"""
    if not validate_sha256(sha):
        return jsonify({'error': 'Invalid SHA256'}), 400

    file = AnalysisFile.query.filter_by(sha256_hash=sha).first()
    if not file:
        return jsonify({'error': 'File not found'}), 404

    data = request.json
    priority = data.get('priority', 5)

    if not (1 <= priority <= 10):
        return jsonify({'error': 'Priority must be between 1 and 10'}), 400

    file.priority = priority
    db.session.commit()

    AuthService.log_action('file_priority_updated', f'Updated priority to {priority}', file_id=file.id)

    return jsonify({
        'success': True,
        'new_priority': priority
    })


@api_bp.route('/vectors/<int:vector_id>/assign', methods=['POST'])
@AuthService.login_required
def assign_file_to_vector(vector_id):
    """Assign file to analysis vector"""
    data = request.json
    file_sha = data.get('file_sha')
    user_id = data.get('user_id')

    if not validate_sha256(file_sha):
        return jsonify({'error': 'Invalid SHA256'}), 400

    file = AnalysisFile.query.filter_by(sha256_hash=file_sha).first()
    if not file:
        return jsonify({'error': 'File not found'}), 404

    vector = Vector.query.get_or_404(vector_id)

    try:
        from crypto_hunter_web import FileAssignment

        # Check if already assigned
        existing = FileAssignment.query.filter_by(
            file_id=file.id,
            vector_id=vector_id
        ).first()

        if existing:
            return jsonify({'error': 'File already assigned to this vector'}), 400

        assignment = FileAssignment(
            file_id=file.id,
            vector_id=vector_id,
            assigned_to=user_id,
            assigned_by=session['user_id']
        )

        db.session.add(assignment)
        db.session.commit()

        AuthService.log_action(
            'file_assigned',
            f'Assigned {file.filename} to {vector.name}',
            file_id=file.id
        )

        return jsonify({
            'success': True,
            'assignment_id': assignment.id
        })

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@api_bp.route('/enhanced-import', methods=['POST'])
@AuthService.login_required
def enhanced_import():
    """Enhanced import with crypto analysis"""
    if 'csv_file' not in request.files:
        return jsonify({'error': 'No CSV file uploaded'}), 400

    csv_file = request.files['csv_file']
    use_llm = request.form.get('use_llm', 'false').lower() == 'true'
    llm_budget = float(request.form.get('llm_budget', 10.0))
    offline_mode = request.form.get('offline_mode', 'false').lower() == 'true'

    try:
        # Save uploaded file
        import tempfile
        import os
        from datetime import datetime

        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"{timestamp}_{csv_file.filename}"
        filepath = os.path.join(tempfile.gettempdir(), filename)
        csv_file.save(filepath)

        # Start enhanced import using the engine approach
        from crypto_hunter_web.tasks.engine_tasks import process_api_import

        # Prepare options
        options = {
            'offline_mode': offline_mode,
            'use_llm': use_llm,
            'llm_budget': llm_budget,
            'analyze_crypto': True
        }

        # Determine engines to use
        engines = ['upload', 'analysis', 'extraction']
        if use_llm:
            engines.append('llm')
        if not offline_mode:
            engines.append('crypto')

        # Queue the task
        task = process_api_import.delay(filepath, session['user_id'], engines, options)

        # Create a placeholder bulk import record for tracking
        from crypto_hunter_web.models import BulkImport
        from datetime import datetime

        bulk_import = BulkImport(
            import_type='api',
            status='processing',
            source_file=os.path.basename(filepath),
            created_by=session['user_id'],
            created_at=datetime.utcnow(),
            updated_at=datetime.utcnow(),
            task_id=task.id
        )
        db.session.add(bulk_import)
        db.session.commit()

        return jsonify({
            'success': True,
            'import_id': bulk_import.id,
            'message': f'Enhanced import started with {bulk_import.successful_imports} files'
        })

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@api_bp.route('/graph-data')
@AuthService.login_required
def get_graph_data():
    """Get graph data for visualization"""
    try:
        from crypto_hunter_web.services.graph_builder import GraphBuilder

        filter_type = request.args.get('filter', 'all')
        focus_sha = request.args.get('focus')

        if focus_sha:
            if not validate_sha256(focus_sha):
                return jsonify({'error': 'Invalid SHA256'}), 400
            graph_data = GraphBuilder.build_focused_graph(focus_sha)
        else:
            graph_data = GraphBuilder.build_full_graph()

        return jsonify({
            'success': True,
            'nodes': graph_data['nodes'],
            'edges': graph_data['edges'],
            'stats': {
                'node_count': len(graph_data['nodes']),
                'edge_count': len(graph_data['edges'])
            }
        })

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@api_bp.route('/analysis/smart-recommendations', methods=['POST'])
@AuthService.login_required
def get_smart_recommendations():
    """Get AI-powered analysis recommendations"""
    data = request.json
    file_sha = data.get('file_sha')

    if not validate_sha256(file_sha):
        return jsonify({'error': 'Invalid SHA256'}), 400

    file = AnalysisFile.query.filter_by(sha256_hash=file_sha).first()
    if not file:
        return jsonify({'error': 'File not found'}), 404

    try:
        # Get existing analysis
        content = FileContent.query.filter_by(file_id=file.id).first()
        existing_analysis = {}
        if content:
            try:
                existing_analysis = json.loads(content.content_text or '{}')
            except:
                pass

        # Generate recommendations based on file characteristics
        recommendations = []

        # File type based recommendations
        if 'image' in file.file_type:
            recommendations.extend([
                {
                    'type': 'extraction',
                    'method': 'zsteg',
                    'description': 'Try ZSteg for LSB steganography detection',
                    'priority': 'high',
                    'confidence': 0.8
                },
                {
                    'type': 'extraction',
                    'method': 'steghide',
                    'description': 'Check for Steghide hidden content',
                    'priority': 'medium',
                    'confidence': 0.6
                }
            ])

        # Crypto pattern based recommendations
        crypto_patterns = existing_analysis.get('crypto_analysis', {}).get('crypto_patterns', [])
        if crypto_patterns:
            recommendations.append({
                'type': 'crypto_analysis',
                'method': 'llm_analysis',
                'description': f'AI analysis recommended - {len(crypto_patterns)} crypto patterns detected',
                'priority': 'high',
                'confidence': 0.9
            })

        # File size based recommendations
        if file.file_size and file.file_size > 1024 * 1024:  # > 1MB
            recommendations.append({
                'type': 'extraction',
                'method': 'binwalk',
                'description': 'Large file - check for embedded files with Binwalk',
                'priority': 'medium',
                'confidence': 0.7
            })

        return jsonify({
            'success': True,
            'recommendations': recommendations,
            'file_analysis': {
                'crypto_patterns_found': len(crypto_patterns),
                'file_type': file.file_type,
                'file_size': file.file_size
            }
        })

    except Exception as e:
        return jsonify({'error': str(e)}), 500
