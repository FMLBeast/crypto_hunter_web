"""
Complete content routes for file content analysis and viewing
"""

from flask import Blueprint, render_template, request, jsonify, session
from crypto_hunter_web.services.auth_service import AuthService
from crypto_hunter_web.services.file_analyzer import FileAnalyzer
from crypto_hunter_web import db
from crypto_hunter_web.models import AnalysisFile, FileContent
from crypto_hunter_web.models import RegionOfInterest
from crypto_hunter_web.utils.validators import validate_sha256
import os
import json

content_bp = Blueprint('content', __name__)


@content_bp.route('/files/<sha>')
@AuthService.login_required
def file_content(sha):
    """View file content with analysis tools"""
    if not validate_sha256(sha):
        return "Invalid SHA256 hash", 400

    file = AnalysisFile.query.filter_by(sha256_hash=sha).first_or_404()

    # Get or create content analysis
    content = FileContent.query.filter_by(file_id=file.id).first()
    if not content and os.path.exists(file.filepath):
        content = FileAnalyzer.analyze_file_content(file.filepath, file.id)

    # Get regions of interest
    regions = []
    regions_data = []
    if content:
        regions = RegionOfInterest.query.filter_by(file_content_id=content.id).all()
        regions_data = [
            {
                'id': r.id,
                'start_offset': r.start_offset,
                'end_offset': r.end_offset,
                'title': r.title,
                'color': r.color,
                'type': r.region_type
            }
            for r in regions
        ]

    # Get extracted strings
    strings_list = []
    interesting_strings_count = 0
    if content and os.path.exists(file.filepath):
        strings_list = FileAnalyzer.extract_strings(file.filepath)
        interesting_strings_count = len([s for s in strings_list if len(s) > 20])

    AuthService.log_action('content_viewed', f'Viewed content: {file.filename}', file_id=file.id)

    return render_template('content/file_content.html',
                           file=file,
                           content=content,
                           regions=regions,
                           regions_data=json.dumps(regions_data),
                           strings_list=strings_list,
                           interesting_strings_count=interesting_strings_count)


@content_bp.route('/files/<sha>/content/hex')
@AuthService.login_required
def get_hex_dump(sha):
    """Get hex dump of file section"""
    if not validate_sha256(sha):
        return jsonify({'error': 'Invalid SHA256'}), 400

    file = AnalysisFile.query.filter_by(sha256_hash=sha).first()
    if not file:
        return jsonify({'error': 'File not found'}), 404

    if not os.path.exists(file.filepath):
        return jsonify({'error': 'File not accessible'}), 404

    offset = request.args.get('offset', 0, type=int)
    length = request.args.get('length', 1024, type=int)

    # Limit length to prevent abuse
    length = min(length, 8192)

    try:
        hex_dump = FileAnalyzer.get_hex_dump(file.filepath, offset, length)
        return jsonify({
            'success': True,
            'hex_dump': hex_dump,
            'offset': offset,
            'length': length
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@content_bp.route('/files/<sha>/content/analyze', methods=['POST'])
@AuthService.login_required
def analyze_file_content(sha):
    """Re-analyze file content"""
    if not validate_sha256(sha):
        return jsonify({'error': 'Invalid SHA256'}), 400

    file = AnalysisFile.query.filter_by(sha256_hash=sha).first()
    if not file:
        return jsonify({'error': 'File not found'}), 404

    if not os.path.exists(file.filepath):
        return jsonify({'error': 'File not accessible'}), 404

    try:
        # Remove existing content analysis
        existing_content = FileContent.query.filter_by(file_id=file.id).first()
        if existing_content:
            db.session.delete(existing_content)

        # Create new analysis
        content = FileAnalyzer.analyze_file_content(file.filepath, file.id)

        AuthService.log_action('content_analyzed', f'Re-analyzed content: {file.filename}', file_id=file.id)

        return jsonify({
            'success': True,
            'message': 'Content analysis completed',
            'content_type': content.content_type if content else 'unknown'
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@content_bp.route('/files/<sha>/strings')
@AuthService.login_required
def extract_strings(sha):
    """Extract strings from file"""
    if not validate_sha256(sha):
        return jsonify({'error': 'Invalid SHA256'}), 400

    file = AnalysisFile.query.filter_by(sha256_hash=sha).first()
    if not file:
        return jsonify({'error': 'File not found'}), 404

    if not os.path.exists(file.filepath):
        return jsonify({'error': 'File not accessible'}), 404

    min_length = request.args.get('min_length', 4, type=int)
    min_length = max(1, min(min_length, 50))  # Limit range

    try:
        with open(file.filepath, 'rb') as f:
            content = f.read()

        strings_list = FileAnalyzer.extract_strings(content, min_length)

        # Categorize strings
        interesting_strings = []
        for string in strings_list:
            is_interesting = (
                len(string) > 20 or
                any(keyword in string.lower() for keyword in ['flag', 'key', 'password', 'secret', 'token'])
            )
            if is_interesting:
                interesting_strings.append(string)

        return jsonify({
            'success': True,
            'strings': strings_list,
            'interesting_strings': interesting_strings,
            'total_count': len(strings_list),
            'interesting_count': len(interesting_strings)
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@content_bp.route('/files/<sha>/metadata')
@AuthService.login_required
def get_file_metadata(sha):
    """Get detailed file metadata"""
    if not validate_sha256(sha):
        return jsonify({'error': 'Invalid SHA256'}), 400

    file = AnalysisFile.query.filter_by(sha256_hash=sha).first()
    if not file:
        return jsonify({'error': 'File not found'}), 404

    try:
        metadata = {
            'basic_info': {
                'filename': file.filename,
                'sha256_hash': file.sha256_hash,
                'file_type': file.file_type,
                'file_size': file.file_size,
                'status': file.status,
                'priority': file.priority,
                'is_root_file': file.is_root_file
            },
            'analysis_info': {
                'created_at': file.created_at.isoformat(),
                'depth_level': file.depth_level,
                'extraction_method': file.extraction_method,
                'findings_count': len(file.findings)
            }
        }

        # Add file-specific metadata if file exists
        if os.path.exists(file.filepath):
            try:
                from crypto_hunter_web.services.search_service import MetadataGenerator
                enhanced_metadata = MetadataGenerator.generate_file_metadata(file.filepath, file.id)
                metadata['enhanced'] = enhanced_metadata
            except Exception as e:
                metadata['enhanced_error'] = str(e)

        return jsonify({
            'success': True,
            'metadata': metadata
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@content_bp.route('/api/regions', methods=['POST'])
@AuthService.login_required
def create_region():
    """Create a new region of interest"""
    data = request.json

    try:
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


@content_bp.route('/api/regions/<int:region_id>', methods=['DELETE'])
@AuthService.login_required
def delete_region(region_id):
    """Delete a region of interest"""
    try:
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


@content_bp.route('/files/<sha>/compare/<other_sha>')
@AuthService.login_required
def compare_files(sha, other_sha):
    """Compare two files"""
    if not validate_sha256(sha) or not validate_sha256(other_sha):
        return jsonify({'error': 'Invalid SHA256 hash'}), 400

    file1 = AnalysisFile.query.filter_by(sha256_hash=sha).first()
    file2 = AnalysisFile.query.filter_by(sha256_hash=other_sha).first()

    if not file1 or not file2:
        return jsonify({'error': 'One or both files not found'}), 404

    try:
        comparison = {
            'files': {
                'file1': {
                    'filename': file1.filename,
                    'sha': file1.sha256_hash,
                    'size': file1.file_size,
                    'type': file1.file_type
                },
                'file2': {
                    'filename': file2.filename,
                    'sha': file2.sha256_hash,
                    'size': file2.file_size,
                    'type': file2.file_type
                }
            },
            'differences': {
                'size_diff': abs((file1.file_size or 0) - (file2.file_size or 0)),
                'type_match': file1.file_type == file2.file_type,
                'priority_diff': abs(file1.priority - file2.priority)
            },
            'relationships': {
                'common_parents': [],
                'common_children': []
            }
        }

        # Find common relationships
        file1_parents = {p.sha256_hash for p in file1.get_parents()}
        file2_parents = {p.sha256_hash for p in file2.get_parents()}
        comparison['relationships']['common_parents'] = list(file1_parents & file2_parents)

        file1_children = {c.sha256_hash for c in file1.get_children()}
        file2_children = {c.sha256_hash for c in file2.get_children()}
        comparison['relationships']['common_children'] = list(file1_children & file2_children)

        return jsonify({
            'success': True,
            'comparison': comparison
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@content_bp.route('/files/<sha>/export')
@AuthService.login_required
def export_file_analysis(sha):
    """Export complete file analysis"""
    if not validate_sha256(sha):
        return jsonify({'error': 'Invalid SHA256'}), 400

    file = AnalysisFile.query.filter_by(sha256_hash=sha).first()
    if not file:
        return jsonify({'error': 'File not found'}), 404

    try:
        # Build complete analysis export
        export_data = {
            'file_info': {
                'filename': file.filename,
                'sha256_hash': file.sha256_hash,
                'file_type': file.file_type,
                'file_size': file.file_size,
                'status': file.status,
                'priority': file.priority,
                'is_root_file': file.is_root_file,
                'created_at': file.created_at.isoformat()
            },
            'content_analysis': {},
            'findings': [],
            'relationships': {
                'parents': [],
                'children': []
            },
            'regions': []
        }

        # Add content analysis
        content = FileContent.query.filter_by(file_id=file.id).first()
        if content:
            export_data['content_analysis'] = {
                'content_type': content.content_type,
                'content_size': content.content_size,
                'strings_extracted': content.strings_extracted,
                'hex_analyzed': content.hex_analyzed
            }

        # Add findings
        for finding in file.findings:
            export_data['findings'].append({
                'title': finding.title,
                'description': finding.description,
                'confidence_level': finding.confidence_level,
                'status': finding.status,
                'vector': finding.vector.name,
                'created_at': finding.created_at.isoformat()
            })

        # Add relationships
        export_data['relationships']['parents'] = [
            {'filename': p.filename, 'sha': p.sha256_hash}
            for p in file.get_parents()
        ]
        export_data['relationships']['children'] = [
            {'filename': c.filename, 'sha': c.sha256_hash}
            for c in file.get_children()
        ]

        # Add regions
        if content:
            regions = RegionOfInterest.query.filter_by(file_content_id=content.id).all()
            export_data['regions'] = [
                {
                    'title': r.title,
                    'description': r.description,
                    'start_offset': r.start_offset,
                    'end_offset': r.end_offset,
                    'region_type': r.region_type,
                    'confidence_level': r.confidence_level
                }
                for r in regions
            ]

        return jsonify({
            'success': True,
            'export_data': export_data,
            'export_filename': f"{file.filename}_analysis.json"
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500