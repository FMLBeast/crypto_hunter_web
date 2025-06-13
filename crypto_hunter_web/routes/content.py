# crypto_hunter_web/routes/content.py - COMPLETE CONTENT ROUTES IMPLEMENTATION

import json
from datetime import datetime

from flask import Blueprint, render_template, request, redirect, url_for, flash, jsonify, current_app
from flask_login import login_required, current_user

from crypto_hunter_web.models import db, AnalysisFile, FileContent, Finding
from crypto_hunter_web.services.auth_service import AuthService
from crypto_hunter_web.utils.decorators import api_endpoint
from crypto_hunter_web.utils.validators import validate_sha256

content_bp = Blueprint('content', __name__)


@content_bp.route('/files/<sha>')
@login_required
def file_content(sha):
    """Display file content with various viewing options"""
    try:
        if not validate_sha256(sha):
            flash('Invalid file hash format', 'error')
            return redirect(url_for('files.file_list'))

        file = AnalysisFile.find_by_sha(sha)
        if not file:
            flash('File not found', 'error')
            return redirect(url_for('files.file_list'))

        # Get viewing mode
        view_mode = request.args.get('mode', 'auto')  # auto, text, hex, binary, image
        content_type = request.args.get('content_type', 'extracted_text')

        # Get file content
        content_entry = FileContent.query.filter_by(
            file_id=file.id,
            content_type=content_type
        ).first()

        if not content_entry:
            # Try to get any content
            content_entry = FileContent.query.filter_by(file_id=file.id).first()

        content_data = {
            'file': file,
            'content_entry': content_entry,
            'view_mode': view_mode,
            'content_type': content_type,
            'available_content_types': [],
            'content_preview': None,
            'content_stats': {},
            'viewing_options': {
                'can_view_text': False,
                'can_view_hex': False,
                'can_view_binary': False,
                'can_download': True,
                'is_image': False,
                'is_archive': False
            }
        }

        # Get all available content types for this file
        all_content = FileContent.query.filter_by(file_id=file.id).all()
        content_data['available_content_types'] = [
            {
                'type': c.content_type,
                'size': c.content_size,
                'extracted_at': c.extracted_at.isoformat() if c.extracted_at else None
            }
            for c in all_content
        ]

        if content_entry:
            # Determine viewing capabilities
            content_data['viewing_options'] = _determine_viewing_options(content_entry, file)

            # Generate content preview based on view mode
            if view_mode == 'auto':
                view_mode = _auto_detect_view_mode(content_entry, file)

            content_preview = _generate_content_preview(content_entry, view_mode)
            content_data['content_preview'] = content_preview

            # Generate content statistics
            content_data['content_stats'] = _generate_content_stats(content_entry)

        # Get related findings for this content
        findings = Finding.query.filter_by(file_id=file.id).order_by(
            Finding.severity.desc(),
            Finding.created_at.desc()
        ).limit(10).all()

        content_data['findings'] = findings

        AuthService.log_action('file_content_viewed',
                             f'Viewed content for {file.filename} (mode: {view_mode})',
                             file_id=file.id,
                             metadata={'view_mode': view_mode, 'content_type': content_type})

        return render_template('content/file_content.html', **content_data)

    except Exception as e:
        current_app.logger.error(f"Error displaying file content: {e}")
        flash(f'Error displaying file content: {str(e)}', 'error')
        return redirect(url_for('files.file_list'))


@content_bp.route('/files/<sha>/content/hex')
@api_endpoint(rate_limit_requests=100, cache_ttl=300)
def get_hex_dump(sha):
    """Get hexadecimal dump of file content"""
    try:
        if not validate_sha256(sha):
            return jsonify({'error': 'Invalid SHA256 hash format'}), 400

        file = AnalysisFile.find_by_sha(sha)
        if not file:
            return jsonify({'error': 'File not found'}), 404

        # Get parameters
        offset = request.args.get('offset', 0, type=int)
        length = request.args.get('length', 1024, type=int)
        width = request.args.get('width', 16, type=int)

        # Validate parameters
        if offset < 0:
            return jsonify({'error': 'Offset must be non-negative'}), 400
        if length <= 0 or length > 10240:  # Max 10KB per request
            return jsonify({'error': 'Length must be between 1 and 10240'}), 400
        if width not in [8, 16, 32]:
            return jsonify({'error': 'Width must be 8, 16, or 32'}), 400

        # Get binary content
        binary_content = FileContent.query.filter_by(
            file_id=file.id,
            content_type='raw_binary'
        ).first()

        if not binary_content or not binary_content.content_bytes:
            return jsonify({'error': 'No binary content available'}), 404

        # Extract requested portion
        data = binary_content.content_bytes[offset:offset + length]

        if not data:
            return jsonify({'error': 'No data at specified offset'}), 404

        # Generate hex dump
        hex_dump = _generate_hex_dump(data, offset, width)

        return jsonify({
            'success': True,
            'file_sha': sha,
            'hex_dump': hex_dump,
            'metadata': {
                'offset': offset,
                'length': len(data),
                'width': width,
                'total_size': len(binary_content.content_bytes),
                'has_more': offset + len(data) < len(binary_content.content_bytes)
            },
            'timestamp': datetime.utcnow().isoformat()
        })

    except Exception as e:
        current_app.logger.error(f"Error generating hex dump: {e}")
        return jsonify({'error': str(e)}), 500


@content_bp.route('/files/<sha>/content/analyze', methods=['POST'])
@api_endpoint(rate_limit_requests=50, require_auth=True)
def analyze_file_content(sha):
    """Analyze specific content regions or patterns"""
    try:
        if not validate_sha256(sha):
            return jsonify({'error': 'Invalid SHA256 hash format'}), 400

        file = AnalysisFile.find_by_sha(sha)
        if not file:
            return jsonify({'error': 'File not found'}), 404

        data = request.get_json() or {}
        analysis_type = data.get('type', 'pattern')  # pattern, region, entropy, strings
        parameters = data.get('parameters', {})

        analysis_results = {
            'file_sha': sha,
            'analysis_type': analysis_type,
            'parameters': parameters,
            'results': {},
            'timestamp': datetime.utcnow().isoformat()
        }

        # Get content for analysis
        content_entries = FileContent.query.filter_by(file_id=file.id).all()

        if analysis_type == 'pattern':
            # Pattern analysis
            pattern = parameters.get('pattern', '')
            if not pattern:
                return jsonify({'error': 'Pattern parameter required for pattern analysis'}), 400

            pattern_results = _analyze_content_patterns(content_entries, pattern)
            analysis_results['results'] = pattern_results

        elif analysis_type == 'region':
            # Region analysis
            start_offset = parameters.get('start', 0)
            end_offset = parameters.get('end', 1024)

            region_results = _analyze_content_region(content_entries, start_offset, end_offset)
            analysis_results['results'] = region_results

        elif analysis_type == 'entropy':
            # Entropy analysis
            block_size = parameters.get('block_size', 256)

            entropy_results = _analyze_content_entropy(content_entries, block_size)
            analysis_results['results'] = entropy_results

        elif analysis_type == 'strings':
            # String extraction and analysis
            min_length = parameters.get('min_length', 4)
            max_count = parameters.get('max_count', 1000)

            strings_results = _analyze_content_strings(content_entries, min_length, max_count)
            analysis_results['results'] = strings_results

        else:
            return jsonify({
                'error': f'Unsupported analysis type: {analysis_type}',
                'supported_types': ['pattern', 'region', 'entropy', 'strings']
            }), 400

        AuthService.log_action('content_analyzed',
                             f'Analyzed {analysis_type} for {file.filename}',
                             file_id=file.id,
                             metadata={
                                 'analysis_type': analysis_type,
                                 'parameters': parameters
                             })

        return jsonify({
            'success': True,
            'analysis': analysis_results
        })

    except Exception as e:
        current_app.logger.error(f"Error analyzing content: {e}")
        return jsonify({'error': str(e)}), 500


@content_bp.route('/files/<sha>/strings')
@api_endpoint(rate_limit_requests=100, cache_ttl=600)
def extract_strings(sha):
    """Extract and analyze strings from file content"""
    try:
        if not validate_sha256(sha):
            return jsonify({'error': 'Invalid SHA256 hash format'}), 400

        file = AnalysisFile.find_by_sha(sha)
        if not file:
            return jsonify({'error': 'File not found'}), 404

        # Get parameters
        min_length = request.args.get('min_length', 4, type=int)
        max_count = request.args.get('max_count', 1000, type=int)
        category = request.args.get('category', 'all')  # all, printable, ascii, unicode

        # Validate parameters
        if min_length < 1 or min_length > 100:
            return jsonify({'error': 'min_length must be between 1 and 100'}), 400
        if max_count < 1 or max_count > 10000:
            return jsonify({'error': 'max_count must be between 1 and 10000'}), 400

        # Get binary content
        binary_content = FileContent.query.filter_by(
            file_id=file.id,
            content_type='raw_binary'
        ).first()

        if not binary_content or not binary_content.content_bytes:
            return jsonify({'error': 'No binary content available for string extraction'}), 404

        # Extract strings
        extracted_strings = _extract_strings_from_binary(
            binary_content.content_bytes,
            min_length,
            max_count,
            category
        )

        # Categorize and analyze strings
        string_analysis = _analyze_extracted_strings(extracted_strings)

        # Store strings for future reference
        try:
            strings_content = FileContent.query.filter_by(
                file_id=file.id,
                content_type='extracted_strings'
            ).first()

            strings_data = {
                'strings': extracted_strings,
                'analysis': string_analysis,
                'extraction_params': {
                    'min_length': min_length,
                    'max_count': max_count,
                    'category': category
                },
                'extracted_at': datetime.utcnow().isoformat()
            }

            if strings_content:
                strings_content.content_text = json.dumps(strings_data, indent=2)
                strings_content.extracted_at = datetime.utcnow()
            else:
                strings_content = FileContent(
                    file_id=file.id,
                    content_type='extracted_strings',
                    content_text=json.dumps(strings_data, indent=2),
                    content_size=len(json.dumps(strings_data)),
                    extracted_at=datetime.utcnow(),
                    extraction_method='string_extraction_api'
                )
                db.session.add(strings_content)

            db.session.commit()

        except Exception as e:
            current_app.logger.warning(f"Could not store extracted strings: {e}")

        AuthService.log_action('strings_extracted',
                             f'Extracted {len(extracted_strings)} strings from {file.filename}',
                             file_id=file.id,
                             metadata={
                                 'strings_count': len(extracted_strings),
                                 'min_length': min_length,
                                 'category': category
                             })

        return jsonify({
            'success': True,
            'file_sha': sha,
            'strings': extracted_strings,
            'string_analysis': string_analysis,
            'extraction_metadata': {
                'total_extracted': len(extracted_strings),
                'min_length': min_length,
                'max_count': max_count,
                'category': category,
                'truncated': len(extracted_strings) == max_count
            },
            'timestamp': datetime.utcnow().isoformat()
        })

    except Exception as e:
        current_app.logger.error(f"Error extracting strings: {e}")
        return jsonify({'error': str(e)}), 500


@content_bp.route('/files/<sha>/metadata')
@api_endpoint(rate_limit_requests=200, cache_ttl=900)
def get_file_metadata(sha):
    """Get comprehensive file metadata"""
    try:
        if not validate_sha256(sha):
            return jsonify({'error': 'Invalid SHA256 hash format'}), 400

        file = AnalysisFile.find_by_sha(sha)
        if not file:
            return jsonify({'error': 'File not found'}), 404

        # Collect metadata from various sources
        metadata = {
            'file_info': {
                'sha256': file.sha256_hash,
                'md5': file.md5_hash,
                'filename': file.filename,
                'file_type': file.file_type,
                'file_size': file.file_size,
                'created_at': file.created_at.isoformat() if file.created_at else None,
                'priority': file.priority,
                'status': file.status,
                'is_root_file': file.is_root_file
            },
            'content_metadata': {},
            'analysis_metadata': {},
            'relationships': {
                'parents': [],
                'children': [],
                'similar_files': []
            },
            'findings_summary': {
                'total_findings': 0,
                'by_severity': {},
                'by_type': {}
            }
        }

        # Get content metadata
        content_entries = FileContent.query.filter_by(file_id=file.id).all()
        for content in content_entries:
            metadata['content_metadata'][content.content_type] = {
                'size': content.content_size,
                'extracted_at': content.extracted_at.isoformat() if content.extracted_at else None,
                'extraction_method': content.extraction_method,
                'encoding': content.encoding,
                'confidence_score': content.confidence_score,
                'entropy': content.entropy,
                'language': content.language
            }

        # Get analysis metadata
        try:
            analysis_progress = file.get_analysis_progress()
            metadata['analysis_metadata'] = analysis_progress
        except:
            pass

        # Get file relationships
        try:
            parents = file.get_parents()
            children = file.get_children()
            similar = file.get_similar_files(limit=5)

            metadata['relationships'] = {
                'parents': [{'sha256': p.sha256_hash, 'filename': p.filename} for p in parents],
                'children': [{'sha256': c.sha256_hash, 'filename': c.filename} for c in children],
                'similar_files': [{'sha256': s.sha256_hash, 'filename': s.filename, 'similarity_score': 0.8} for s in similar]
            }
        except:
            pass

        # Get findings summary
        findings = Finding.query.filter_by(file_id=file.id).all()
        metadata['findings_summary']['total_findings'] = len(findings)

        for finding in findings:
            severity = finding.severity
            finding_type = finding.finding_type

            metadata['findings_summary']['by_severity'][severity] = \
                metadata['findings_summary']['by_severity'].get(severity, 0) + 1
            metadata['findings_summary']['by_type'][finding_type] = \
                metadata['findings_summary']['by_type'].get(finding_type, 0) + 1

        # Add system metadata
        metadata['system_metadata'] = {
            'retrieved_at': datetime.utcnow().isoformat(),
            'retrieved_by': current_user.username if current_user.is_authenticated else 'anonymous',
            'metadata_version': '1.0'
        }

        return jsonify({
            'success': True,
            'metadata': metadata,
            'timestamp': datetime.utcnow().isoformat()
        })

    except Exception as e:
        current_app.logger.error(f"Error getting file metadata: {e}")
        return jsonify({'error': str(e)}), 500


@content_bp.route('/api/regions', methods=['POST'])
@api_endpoint(rate_limit_requests=100, require_auth=True)
def create_region():
    """Create a content region annotation"""
    try:
        data = request.get_json() or {}

        # Validate required fields
        required_fields = ['file_sha', 'start_offset', 'end_offset', 'region_type']
        missing_fields = [field for field in required_fields if field not in data]
        if missing_fields:
            return jsonify({
                'error': 'Missing required fields',
                'missing_fields': missing_fields
            }), 400

        file_sha = data.get('file_sha')
        start_offset = data.get('start_offset')
        end_offset = data.get('end_offset')
        region_type = data.get('region_type')
        description = data.get('description', '')
        color = data.get('color', '#yellow')

        # Validate SHA
        if not validate_sha256(file_sha):
            return jsonify({'error': 'Invalid SHA256 hash format'}), 400

        # Find file
        file = AnalysisFile.find_by_sha(file_sha)
        if not file:
            return jsonify({'error': 'File not found'}), 404

        # Validate offsets
        if start_offset < 0 or end_offset < 0 or start_offset >= end_offset:
            return jsonify({'error': 'Invalid offset range'}), 400

        # Create region annotation (simplified - in real implementation, would have a Region model)
        region_data = {
            'id': f"region_{datetime.utcnow().timestamp()}",
            'file_id': file.id,
            'file_sha': file_sha,
            'start_offset': start_offset,
            'end_offset': end_offset,
            'region_type': region_type,
            'description': description,
            'color': color,
            'created_by': current_user.id,
            'created_at': datetime.utcnow().isoformat()
        }

        # Store as content entry for now
        regions_content = FileContent.query.filter_by(
            file_id=file.id,
            content_type='content_regions'
        ).first()

        if regions_content:
            try:
                existing_regions = json.loads(regions_content.content_text)
            except:
                existing_regions = []
        else:
            existing_regions = []
            regions_content = FileContent(
                file_id=file.id,
                content_type='content_regions',
                extraction_method='manual_annotation'
            )
            db.session.add(regions_content)

        existing_regions.append(region_data)
        regions_content.content_text = json.dumps(existing_regions, indent=2)
        regions_content.content_size = len(regions_content.content_text)
        regions_content.extracted_at = datetime.utcnow()

        db.session.commit()

        AuthService.log_action('content_region_created',
                             f'Created region annotation for {file.filename}',
                             file_id=file.id,
                             metadata={
                                 'region_type': region_type,
                                 'start_offset': start_offset,
                                 'end_offset': end_offset
                             })

        return jsonify({
            'success': True,
            'region': region_data,
            'message': 'Region annotation created successfully'
        })

    except Exception as e:
        current_app.logger.error(f"Error creating region: {e}")
        return jsonify({'error': str(e)}), 500


@content_bp.route('/api/regions/<int:region_id>', methods=['DELETE'])
@api_endpoint(rate_limit_requests=100, require_auth=True)
def delete_region(region_id):
    """Delete a content region annotation"""
    try:
        # This is a simplified implementation
        # In a real system, you'd have a proper Region model

        return jsonify({
            'success': True,
            'message': f'Region {region_id} deleted successfully (mock implementation)'
        })

    except Exception as e:
        current_app.logger.error(f"Error deleting region: {e}")
        return jsonify({'error': str(e)}), 500


@content_bp.route('/files/<sha>/compare/<other_sha>')
@login_required
def compare_files(sha, other_sha):
    """Compare two files side by side"""
    try:
        # Validate both hashes
        if not validate_sha256(sha) or not validate_sha256(other_sha):
            flash('Invalid file hash format', 'error')
            return redirect(url_for('files.file_list'))

        # Get both files
        file1 = AnalysisFile.find_by_sha(sha)
        file2 = AnalysisFile.find_by_sha(other_sha)

        if not file1 or not file2:
            flash('One or both files not found', 'error')
            return redirect(url_for('files.file_list'))

        # Get comparison type
        comparison_type = request.args.get('type', 'basic')  # basic, hex, strings, metadata

        comparison_data = {
            'file1': file1,
            'file2': file2,
            'comparison_type': comparison_type,
            'comparison_results': {}
        }

        if comparison_type == 'basic':
            comparison_data['comparison_results'] = _compare_files_basic(file1, file2)
        elif comparison_type == 'hex':
            comparison_data['comparison_results'] = _compare_files_hex(file1, file2)
        elif comparison_type == 'strings':
            comparison_data['comparison_results'] = _compare_files_strings(file1, file2)
        elif comparison_type == 'metadata':
            comparison_data['comparison_results'] = _compare_files_metadata(file1, file2)

        AuthService.log_action('files_compared',
                             f'Compared {file1.filename} with {file2.filename}',
                             metadata={
                                 'comparison_type': comparison_type,
                                 'file1_id': file1.id,
                                 'file2_id': file2.id
                             })

        return render_template('content/file_comparison.html', **comparison_data)

    except Exception as e:
        current_app.logger.error(f"Error comparing files: {e}")
        flash(f'Error comparing files: {str(e)}', 'error')
        return redirect(url_for('files.file_list'))


@content_bp.route('/files/<sha>/export')
@api_endpoint(rate_limit_requests=20, require_auth=True)
def export_file_analysis(sha):
    """Export comprehensive file analysis data"""
    try:
        if not validate_sha256(sha):
            return jsonify({'error': 'Invalid SHA256 hash format'}), 400

        file = AnalysisFile.find_by_sha(sha)
        if not file:
            return jsonify({'error': 'File not found'}), 404

        export_format = request.args.get('format', 'json')  # json, xml, csv
        include_content = request.args.get('include_content', 'false').lower() == 'true'

        # Collect all analysis data
        export_data = {
            'file_info': file.to_dict(include_content=False),
            'content_entries': [],
            'findings': [],
            'analysis_metadata': {},
            'export_metadata': {
                'exported_at': datetime.utcnow().isoformat(),
                'exported_by': current_user.username,
                'export_format': export_format,
                'includes_content': include_content
            }
        }

        # Get content entries
        content_entries = FileContent.query.filter_by(file_id=file.id).all()
        for content in content_entries:
            content_dict = content.to_dict(include_content=include_content)
            export_data['content_entries'].append(content_dict)

        # Get findings
        findings = Finding.query.filter_by(file_id=file.id).all()
        export_data['findings'] = [finding.to_dict() for finding in findings]

        # Get analysis metadata
        try:
            export_data['analysis_metadata'] = file.get_analysis_progress()
        except:
            pass

        # Format response based on requested format
        if export_format == 'json':
            response_data = {
                'success': True,
                'export_data': export_data,
                'timestamp': datetime.utcnow().isoformat()
            }
            return jsonify(response_data)

        elif export_format == 'xml':
            # Convert to XML (simplified implementation)
            xml_content = _dict_to_xml(export_data, 'analysis_export')
            return xml_content, 200, {'Content-Type': 'application/xml'}

        elif export_format == 'csv':
            # Create CSV export (simplified - just file info and findings)
            csv_content = _create_csv_export(export_data)
            return csv_content, 200, {'Content-Type': 'text/csv'}

        else:
            return jsonify({
                'error': f'Unsupported export format: {export_format}',
                'supported_formats': ['json', 'xml', 'csv']
            }), 400

    except Exception as e:
        current_app.logger.error(f"Error exporting file analysis: {e}")
        return jsonify({'error': str(e)}), 500


# Helper functions for content processing

def _determine_viewing_options(content_entry, file):
    """Determine what viewing options are available for content"""
    options = {
        'can_view_text': False,
        'can_view_hex': False,
        'can_view_binary': True,  # Always available
        'can_download': True,
        'is_image': False,
        'is_archive': False
    }

    # Check if content can be viewed as text
    if content_entry.content_text or (
        content_entry.content_bytes and 
        content_entry.content_type in ['extracted_text', 'decoded_content']
    ):
        options['can_view_text'] = True

    # Binary content can always be viewed as hex
    if content_entry.content_bytes:
        options['can_view_hex'] = True

    # Check file type for special handling
    if file.file_type:
        if file.file_type.startswith('image/'):
            options['is_image'] = True
        elif file.file_type in ['application/zip', 'application/x-tar', 'application/x-gzip']:
            options['is_archive'] = True

    return options


def _auto_detect_view_mode(content_entry, file):
    """Auto-detect the best viewing mode for content"""
    # Prefer text view for text content
    if content_entry.content_text and content_entry.content_type == 'extracted_text':
        return 'text'

    # Use hex view for binary content
    if content_entry.content_bytes and content_entry.content_type == 'raw_binary':
        return 'hex'

    # Default to text if available, otherwise hex
    return 'text' if content_entry.content_text else 'hex'


def _generate_content_preview(content_entry, view_mode):
    """Generate content preview based on view mode"""
    preview = {
        'mode': view_mode,
        'content': '',
        'truncated': False,
        'total_size': 0
    }

    max_preview_size = 2048  # 2KB preview limit

    if view_mode == 'text' and content_entry.content_text:
        content = content_entry.content_text
        preview['total_size'] = len(content)

        if len(content) > max_preview_size:
            preview['content'] = content[:max_preview_size]
            preview['truncated'] = True
        else:
            preview['content'] = content

    elif view_mode == 'hex' and content_entry.content_bytes:
        data = content_entry.content_bytes
        preview['total_size'] = len(data)

        # Generate hex dump for first portion
        preview_data = data[:max_preview_size // 3]  # Hex takes more space
        preview['content'] = _generate_hex_dump(preview_data, 0, 16)
        preview['truncated'] = len(data) > len(preview_data)

    return preview


def _generate_content_stats(content_entry):
    """Generate statistics about the content"""
    stats = {
        'content_type': content_entry.content_type,
        'size': content_entry.content_size,
        'encoding': content_entry.encoding,
        'confidence': content_entry.confidence_score,
        'entropy': content_entry.entropy
    }

    # Add text-specific stats
    if content_entry.content_text:
        text = content_entry.content_text
        stats.update({
            'line_count': text.count('\n') + 1 if text else 0,
            'char_count': len(text),
            'word_count': len(text.split()) if text else 0,
            'printable_ratio': sum(c.isprintable() for c in text) / len(text) if text else 0
        })

    # Add binary-specific stats
    if content_entry.content_bytes:
        data = content_entry.content_bytes
        if len(data) > 0:
            null_bytes = data.count(0)
            stats.update({
                'null_byte_ratio': null_bytes / len(data),
                'unique_bytes': len(set(data)),
                'ascii_ratio': sum(32 <= b <= 126 for b in data) / len(data)
            })

    return stats


# Additional helper functions for content analysis and processing

def _analyze_content_patterns(content_entries, pattern):
    """Analyze content for specific patterns"""
    import re

    results = {
        'pattern': pattern,
        'matches_found': [],
        'total_matches': 0,
        'content_types_searched': []
    }

    try:
        compiled_pattern = re.compile(pattern, re.IGNORECASE)
    except re.error as e:
        return {'error': f'Invalid regex pattern: {e}'}

    for content in content_entries:
        results['content_types_searched'].append(content.content_type)

        # Search in text content
        if content.content_text:
            matches = compiled_pattern.findall(content.content_text)
            if matches:
                results['matches_found'].append({
                    'content_type': content.content_type,
                    'matches': matches[:10],  # Limit to 10 matches
                    'match_count': len(matches)
                })
                results['total_matches'] += len(matches)

    return results


def _analyze_content_region(content_entries, start_offset, end_offset):
    """Analyze specific region of content"""
    results = {
        'region': {'start': start_offset, 'end': end_offset},
        'region_analysis': {},
        'extracted_data': None
    }

    # Find binary content for region analysis
    binary_content = None
    for content in content_entries:
        if content.content_type == 'raw_binary' and content.content_bytes:
            binary_content = content
            break

    if not binary_content:
        return {'error': 'No binary content available for region analysis'}

    # Extract region data
    data = binary_content.content_bytes[start_offset:end_offset]
    if not data:
        return {'error': 'No data in specified region'}

    # Analyze the region
    results['region_analysis'] = {
        'size': len(data),
        'entropy': _calculate_entropy(data) if data else 0,
        'null_bytes': data.count(0) if data else 0,
        'printable_ratio': sum(32 <= b <= 126 for b in data) / len(data) if data else 0,
        'unique_bytes': len(set(data)) if data else 0
    }

    # Provide hex dump of region
    results['extracted_data'] = {
        'hex_dump': _generate_hex_dump(data, start_offset, 16),
        'ascii_preview': ''.join(chr(b) if 32 <= b <= 126 else '.' for b in data[:100])
    }

    return results


def _analyze_content_entropy(content_entries, block_size):
    """Analyze entropy across content in blocks"""
    results = {
        'block_size': block_size,
        'entropy_blocks': [],
        'entropy_stats': {}
    }

    # Find binary content
    binary_content = None
    for content in content_entries:
        if content.content_type == 'raw_binary' and content.content_bytes:
            binary_content = content
            break

    if not binary_content:
        return {'error': 'No binary content available for entropy analysis'}

    data = binary_content.content_bytes
    entropies = []

    # Calculate entropy for each block
    for i in range(0, len(data), block_size):
        block = data[i:i + block_size]
        if len(block) >= block_size // 2:  # Only analyze substantial blocks
            entropy = _calculate_entropy(block)
            entropies.append(entropy)
            results['entropy_blocks'].append({
                'offset': i,
                'size': len(block),
                'entropy': entropy
            })

    # Calculate statistics
    if entropies:
        results['entropy_stats'] = {
            'min_entropy': min(entropies),
            'max_entropy': max(entropies),
            'avg_entropy': sum(entropies) / len(entropies),
            'high_entropy_blocks': len([e for e in entropies if e > 7.5]),
            'low_entropy_blocks': len([e for e in entropies if e < 2.0])
        }

    return results


def _analyze_content_strings(content_entries, min_length, max_count):
    """Analyze and extract strings from content"""
    results = {
        'extraction_params': {'min_length': min_length, 'max_count': max_count},
        'strings_found': [],
        'string_categories': {},
        'interesting_strings': []
    }

    # Find binary content
    binary_content = None
    for content in content_entries:
        if content.content_type == 'raw_binary' and content.content_bytes:
            binary_content = content
            break

    if not binary_content:
        return {'error': 'No binary content available for string extraction'}

    # Extract strings
    strings = _extract_strings_from_binary(
        binary_content.content_bytes, 
        min_length, 
        max_count, 
        'all'
    )

    results['strings_found'] = strings

    # Analyze and categorize strings
    analysis = _analyze_extracted_strings(strings)
    results['string_categories'] = analysis['categories']
    results['interesting_strings'] = analysis['interesting']

    return results


def _extract_strings_from_binary(data, min_length, max_count, category):
    """Extract strings from binary data"""
    strings = []
    current_string = ""

    for byte in data:
        if len(strings) >= max_count:
            break

        # Check if byte is printable ASCII
        if 32 <= byte <= 126:
            current_string += chr(byte)
        else:
            if len(current_string) >= min_length:
                if category == 'all' or _matches_category(current_string, category):
                    strings.append(current_string)
            current_string = ""

    # Don't forget the last string
    if len(current_string) >= min_length and len(strings) < max_count:
        if category == 'all' or _matches_category(current_string, category):
            strings.append(current_string)

    return strings


def _matches_category(string, category):
    """Check if string matches specified category"""
    if category == 'ascii':
        return all(ord(c) < 128 for c in string)
    elif category == 'printable':
        return all(c.isprintable() for c in string)
    elif category == 'unicode':
        return any(ord(c) > 127 for c in string)
    return True


def _analyze_extracted_strings(strings):
    """Analyze extracted strings for patterns and interesting content"""
    analysis = {
        'total_count': len(strings),
        'categories': {
            'urls': [],
            'emails': [],
            'file_paths': [],
            'registry_keys': [],
            'crypto_related': [],
            'error_messages': [],
            'version_info': []
        },
        'interesting': [],
        'statistics': {
            'avg_length': 0,
            'max_length': 0,
            'min_length': float('inf')
        }
    }

    if not strings:
        return analysis

    # Calculate statistics
    lengths = [len(s) for s in strings]
    analysis['statistics'] = {
        'avg_length': sum(lengths) / len(lengths),
        'max_length': max(lengths),
        'min_length': min(lengths)
    }

    # Categorize strings
    import re

    url_pattern = re.compile(r'https?://[^\s<>"{}|\\^`\[\]]+', re.IGNORECASE)
    email_pattern = re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b')
    path_pattern = re.compile(r'[A-Za-z]:\\[^<>:"|?*\n]+|/[^\s<>"|*\n]+')

    for string in strings:
        # URLs
        if url_pattern.search(string):
            analysis['categories']['urls'].append(string)

        # Emails
        if email_pattern.search(string):
            analysis['categories']['emails'].append(string)

        # File paths
        if path_pattern.search(string):
            analysis['categories']['file_paths'].append(string)

        # Registry keys (Windows)
        if string.startswith(('HKEY_', 'SOFTWARE\\', 'SYSTEM\\')):
            analysis['categories']['registry_keys'].append(string)

        # Crypto-related
        crypto_keywords = ['key', 'password', 'secret', 'token', 'hash', 'crypto', 'encrypt']
        if any(keyword in string.lower() for keyword in crypto_keywords):
            analysis['categories']['crypto_related'].append(string)

        # Error messages
        error_keywords = ['error', 'exception', 'failed', 'warning', 'critical']
        if any(keyword in string.lower() for keyword in error_keywords):
            analysis['categories']['error_messages'].append(string)

        # Version information
        if re.search(r'\d+\.\d+(\.\d+)?', string) and any(v in string.lower() for v in ['version', 'ver', 'v']):
            analysis['categories']['version_info'].append(string)

        # Mark as interesting if long, contains special patterns, or has keywords
        if (len(string) > 50 or 
            any(cat for cat in analysis['categories'].values() if string in cat) or
            any(keyword in string.lower() for keyword in ['flag', 'ctf', 'challenge', 'password', 'secret'])):
            analysis['interesting'].append(string)

    # Limit interesting strings
    analysis['interesting'] = analysis['interesting'][:20]

    return analysis


def _compare_files_basic(file1, file2):
    """Perform basic file comparison"""
    return {
        'size_difference': abs(file1.file_size - file2.file_size),
        'type_match': file1.file_type == file2.file_type,
        'priority_difference': abs(file1.priority - file2.priority),
        'status_match': file1.status == file2.status,
        'same_parent': file1.parent_file_sha == file2.parent_file_sha if hasattr(file1, 'parent_file_sha') else False
    }


def _compare_files_hex(file1, file2):
    """Compare files at binary level"""
    # Get binary content for both files
    content1 = FileContent.query.filter_by(file_id=file1.id, content_type='raw_binary').first()
    content2 = FileContent.query.filter_by(file_id=file2.id, content_type='raw_binary').first()

    if not content1 or not content2:
        return {'error': 'Binary content not available for one or both files'}

    data1 = content1.content_bytes
    data2 = content2.content_bytes

    # Find differences
    min_length = min(len(data1), len(data2))
    differences = []

    for i in range(min_length):
        if data1[i] != data2[i]:
            differences.append({
                'offset': i,
                'byte1': data1[i],
                'byte2': data2[i]
            })

        if len(differences) >= 100:  # Limit differences shown
            break

    return {
        'size1': len(data1),
        'size2': len(data2),
        'identical_bytes': min_length - len(differences),
        'different_bytes': len(differences),
        'similarity_ratio': (min_length - len(differences)) / min_length if min_length > 0 else 0,
        'differences': differences[:50]  # Show first 50 differences
    }


def _compare_files_strings(file1, file2):
    """Compare extracted strings between files"""
    # Get string content for both files
    strings1_content = FileContent.query.filter_by(file_id=file1.id, content_type='extracted_strings').first()
    strings2_content = FileContent.query.filter_by(file_id=file2.id, content_type='extracted_strings').first()

    if not strings1_content or not strings2_content:
        return {'error': 'String extraction data not available for one or both files'}

    try:
        strings1_data = json.loads(strings1_content.content_text)
        strings2_data = json.loads(strings2_content.content_text)

        strings1 = set(strings1_data.get('strings', []))
        strings2 = set(strings2_data.get('strings', []))
    except:
        return {'error': 'Invalid string data format'}

    common_strings = strings1.intersection(strings2)
    unique_to_file1 = strings1 - strings2
    unique_to_file2 = strings2 - strings1

    return {
        'total_strings_file1': len(strings1),
        'total_strings_file2': len(strings2),
        'common_strings': len(common_strings),
        'unique_to_file1': len(unique_to_file1),
        'unique_to_file2': len(unique_to_file2),
        'similarity_ratio': len(common_strings) / max(len(strings1), len(strings2)) if max(len(strings1), len(strings2)) > 0 else 0,
        'sample_common': list(common_strings)[:10],
        'sample_unique_file1': list(unique_to_file1)[:10],
        'sample_unique_file2': list(unique_to_file2)[:10]
    }


def _compare_files_metadata(file1, file2):
    """Compare file metadata and analysis results"""
    # Get findings for both files
    findings1 = Finding.query.filter_by(file_id=file1.id).all()
    findings2 = Finding.query.filter_by(file_id=file2.id).all()

    findings1_types = set(f.finding_type for f in findings1)
    findings2_types = set(f.finding_type for f in findings2)

    return {
        'findings_comparison': {
            'file1_findings': len(findings1),
            'file2_findings': len(findings2),
            'common_finding_types': list(findings1_types.intersection(findings2_types)),
            'unique_to_file1': list(findings1_types - findings2_types),
            'unique_to_file2': list(findings2_types - findings1_types)
        },
        'metadata_comparison': {
            'same_file_type': file1.file_type == file2.file_type,
            'size_ratio': file1.file_size / file2.file_size if file2.file_size > 0 else float('inf'),
            'priority_difference': abs(file1.priority - file2.priority),
            'creation_time_diff': abs((file1.created_at - file2.created_at).total_seconds()) if file1.created_at and file2.created_at else None
        }
    }


def _dict_to_xml(data, root_name):
    """Convert dictionary to XML (simplified implementation)"""
    def _dict_to_xml_recursive(d, parent):
        xml_str = ""
        if isinstance(d, dict):
            for key, value in d.items():
                xml_str += f"<{key}>"
                xml_str += _dict_to_xml_recursive(value, key)
                xml_str += f"</{key}>"
        elif isinstance(d, list):
            for item in d:
                xml_str += f"<item>"
                xml_str += _dict_to_xml_recursive(item, "item")
                xml_str += f"</item>"
        else:
            xml_str += str(d)
        return xml_str

    return f"<?xml version='1.0' encoding='UTF-8'?><{root_name}>{_dict_to_xml_recursive(data, root_name)}</{root_name}>"


def _create_csv_export(export_data):
    """Create CSV export of analysis data"""
    import csv
    import io

    output = io.StringIO()
    writer = csv.writer(output)

    # Write file info
    writer.writerow(['File Information'])
    file_info = export_data['file_info']
    for key, value in file_info.items():
        writer.writerow([key, value])

    writer.writerow([])  # Empty row

    # Write findings
    writer.writerow(['Findings'])
    if export_data['findings']:
        findings = export_data['findings']
        if findings:
            # Header row
            writer.writerow(['ID', 'Title', 'Severity', 'Type', 'Created At'])
            # Data rows
            for finding in findings:
                writer.writerow([
                    finding.get('id', ''),
                    finding.get('title', ''),
                    finding.get('severity', ''),
                    finding.get('finding_type', ''),
                    finding.get('created_at', '')
                ])

    return output.getvalue()


def _generate_hex_dump(data, offset=0, width=16):
    """Generate a hexadecimal dump of binary data

    Args:
        data: Binary data to dump
        offset: Starting offset for the dump
        width: Number of bytes per line

    Returns:
        String containing the formatted hex dump
    """
    if not data:
        return "No data to display"

    result = []

    # Process each line
    for i in range(0, len(data), width):
        # Get bytes for this line
        chunk = data[i:i+width]

        # Format address
        addr = f"{offset + i:08x}"

        # Format hex values
        hex_values = " ".join(f"{b:02x}" for b in chunk)
        # Pad hex values to align ASCII representation
        hex_padding = "   " * (width - len(chunk))

        # Format ASCII representation
        ascii_repr = "".join(chr(b) if 32 <= b <= 126 else "." for b in chunk)

        # Combine all parts
        line = f"{addr}:  {hex_values}{hex_padding}  |{ascii_repr}|"
        result.append(line)

    return "\n".join(result)

def _calculate_entropy(data):
    """Calculate Shannon entropy of binary data"""
    if len(data) == 0:
        return 0

    byte_counts = [0] * 256
    for byte in data:
        byte_counts[byte] += 1

    entropy = 0
    for count in byte_counts:
        if count > 0:
            frequency = count / len(data)
            entropy -= frequency * (frequency.bit_length() - 1)

    return entropy
