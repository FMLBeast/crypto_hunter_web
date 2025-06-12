# crypto_hunter_web/routes/search_api.py - COMPLETE SEARCH API IMPLEMENTATION

from flask import Blueprint, request, jsonify, current_app
from flask_login import login_required, current_user
from datetime import datetime, timedelta

from crypto_hunter_web.models import db, AnalysisFile, FileContent, Finding
from crypto_hunter_web.services.auth_service import AuthService
from crypto_hunter_web.services.search_service import SearchService, MetadataGenerator
from crypto_hunter_web.utils.decorators import rate_limit, cache_response, api_endpoint, validate_json
from crypto_hunter_web.utils.validators import validate_sha256, sanitize_search_query

search_api_bp = Blueprint('search_api', __name__)


@search_api_bp.route('/search/hyperfast')
@api_endpoint(rate_limit_requests=1000, cache_ttl=30)
def hyperfast_search():
    """Ultra-fast search endpoint with intelligent matching"""
    try:
        query = request.args.get('q', '').strip()
        page = request.args.get('page', 1, type=int)
        limit = min(request.args.get('limit', 50, type=int), 1000)

        # Sanitize search query
        query = sanitize_search_query(query)

        # Extract and validate filters
        filters = {}

        if request.args.get('file_type'):
            filters['file_type'] = request.args.get('file_type').strip()

        if request.args.get('status'):
            filters['status'] = request.args.get('status').strip()

        if request.args.get('is_root'):
            filters['is_root'] = request.args.get('is_root').lower() == 'true'

        if request.args.get('min_size'):
            try:
                filters['min_size'] = int(request.args.get('min_size'))
            except ValueError:
                return jsonify({'error': 'min_size must be an integer'}), 400

        if request.args.get('max_size'):
            try:
                filters['max_size'] = int(request.args.get('max_size'))
            except ValueError:
                return jsonify({'error': 'max_size must be an integer'}), 400

        if request.args.get('priority_min'):
            try:
                filters['priority_min'] = int(request.args.get('priority_min'))
                if not 1 <= filters['priority_min'] <= 10:
                    return jsonify({'error': 'priority_min must be between 1 and 10'}), 400
            except ValueError:
                return jsonify({'error': 'priority_min must be an integer'}), 400

        # Date range filters
        if request.args.get('created_after'):
            try:
                filters['created_after'] = datetime.strptime(
                    request.args.get('created_after'), '%Y-%m-%d'
                )
            except ValueError:
                return jsonify({'error': 'created_after must be in YYYY-MM-DD format'}), 400

        if request.args.get('created_before'):
            try:
                filters['created_before'] = datetime.strptime(
                    request.args.get('created_before'), '%Y-%m-%d'
                ) + timedelta(days=1)
            except ValueError:
                return jsonify({'error': 'created_before must be in YYYY-MM-DD format'}), 400

        # Perform search
        results = SearchService.hyperfast_search(query, filters, limit)

        # Calculate pagination info
        total_results = results.get('total', 0)
        has_more = total_results >= limit

        # Log search for analytics
        AuthService.log_action('search_performed', 
                             f'Hyperfast search: "{query}"',
                             metadata={
                                 'query': query,
                                 'filters': filters,
                                 'results_count': total_results,
                                 'search_type': results.get('search_type'),
                                 'execution_time': results.get('execution_time')
                             })

        return jsonify({
            'success': True,
            'query': query,
            'results': results['files'],
            'search_metadata': {
                'search_type': results.get('search_type'),
                'total_found': total_results,
                'returned_count': len(results['files']),
                'has_more': has_more,
                'query_processed': query != request.args.get('q', '').strip()
            },
            'filters_applied': filters,
            'pagination': {
                'page': page,
                'limit': limit,
                'has_next': has_more
            },
            'timestamp': datetime.utcnow().isoformat()
        })

    except Exception as e:
        current_app.logger.error(f"Error in hyperfast search: {e}")
        return jsonify({'error': str(e)}), 500


@search_api_bp.route('/search/magic')
@api_endpoint(rate_limit_requests=100, cache_ttl=60)
def magic_search():
    """Magic search for patterns and content analysis"""
    try:
        query = request.args.get('q', '').strip()
        search_type = request.args.get('type', 'all')  # all, patterns, content
        limit = min(request.args.get('limit', 50, type=int), 500)

        if not query:
            return jsonify({'error': 'Query parameter is required'}), 400

        if len(query) < 2:
            return jsonify({'error': 'Query must be at least 2 characters'}), 400

        # Sanitize query
        query = sanitize_search_query(query)

        # Validate search type
        if search_type not in ['all', 'patterns', 'content', 'hashes', 'crypto']:
            return jsonify({
                'error': 'Invalid search type',
                'valid_types': ['all', 'patterns', 'content', 'hashes', 'crypto']
            }), 400

        # Extract filters
        filters = {}
        if request.args.get('file_type'):
            filters['file_type'] = request.args.get('file_type')
        if request.args.get('status'):
            filters['status'] = request.args.get('status')

        # Perform magic search
        results = SearchService._magic_search(query, filters, limit)

        # Enhance results with pattern analysis
        enhanced_results = []
        pattern_matches = {}

        for file_data in results['files']:
            enhanced_file = file_data.copy()

            # Check for pattern matches in the query
            for pattern_name, pattern in SearchService.PATTERNS.items():
                matches = pattern.findall(query)
                if matches:
                    if pattern_name not in pattern_matches:
                        pattern_matches[pattern_name] = []
                    pattern_matches[pattern_name].extend(matches[:5])  # Limit to 5 matches

            enhanced_results.append(enhanced_file)

        # Generate search suggestions based on patterns found
        suggestions = []
        if pattern_matches:
            for pattern_type, matches in pattern_matches.items():
                suggestions.append({
                    'type': 'pattern_refinement',
                    'pattern': pattern_type,
                    'suggestion': f'Search for more {pattern_type} patterns',
                    'example_matches': matches[:3]
                })

        AuthService.log_action('magic_search_performed',
                             f'Magic search: "{query}" (type: {search_type})',
                             metadata={
                                 'query': query,
                                 'search_type': search_type,
                                 'results_count': len(enhanced_results),
                                 'patterns_found': list(pattern_matches.keys())
                             })

        return jsonify({
            'success': True,
            'query': query,
            'search_type': search_type,
            'results': enhanced_results,
            'pattern_analysis': {
                'patterns_found': pattern_matches,
                'pattern_count': len(pattern_matches),
                'total_matches': sum(len(matches) for matches in pattern_matches.values())
            },
            'suggestions': suggestions,
            'metadata': {
                'total_found': len(enhanced_results),
                'search_engine': 'magic',
                'includes_content_search': True,
                'includes_pattern_detection': True
            },
            'timestamp': datetime.utcnow().isoformat()
        })

    except Exception as e:
        current_app.logger.error(f"Error in magic search: {e}")
        return jsonify({'error': str(e)}), 500


@search_api_bp.route('/search/xor')
@api_endpoint(rate_limit_requests=50, cache_ttl=120)
def xor_search():
    """XOR correlation search for file relationships"""
    try:
        sha_list = request.args.getlist('sha')

        if not sha_list:
            return jsonify({'error': 'At least one SHA hash is required'}), 400

        if len(sha_list) > 20:
            return jsonify({'error': 'Maximum 20 files can be compared at once'}), 400

        # Validate SHA hashes
        invalid_hashes = [sha for sha in sha_list if not validate_sha256(sha)]
        if invalid_hashes:
            return jsonify({
                'error': 'Invalid SHA256 hashes',
                'invalid_hashes': invalid_hashes
            }), 400

        # Perform XOR correlation analysis
        results = SearchService.xor_search(sha_list)

        if 'error' in results:
            return jsonify(results), 400

        # Enhance correlation analysis with additional insights
        enhanced_correlations = results['correlations'].copy()

        # Add temporal correlation analysis
        files = results['files']
        creation_times = [f['created_at'] for f in files if f.get('created_at')]
        if len(creation_times) > 1:
            time_deltas = []
            sorted_times = sorted([datetime.fromisoformat(t.replace('Z', '+00:00')) for t in creation_times])
            for i in range(len(sorted_times) - 1):
                delta = (sorted_times[i + 1] - sorted_times[i]).total_seconds()
                time_deltas.append(delta)

            enhanced_correlations['temporal_analysis'] = {
                'creation_span_seconds': (sorted_times[-1] - sorted_times[0]).total_seconds(),
                'average_interval': sum(time_deltas) / len(time_deltas) if time_deltas else 0,
                'sequential_creation': all(delta < 3600 for delta in time_deltas)  # Within 1 hour
            }

        # Add finding correlation analysis
        file_ids = [f['id'] for f in files]
        common_findings = db.session.query(
            Finding.finding_type,
            db.func.count(Finding.id).label('count')
        ).filter(
            Finding.file_id.in_(file_ids)
        ).group_by(Finding.finding_type).having(
            db.func.count(Finding.id) > 1
        ).all()

        enhanced_correlations['finding_correlations'] = [
            {'finding_type': cf[0], 'shared_count': cf[1]} 
            for cf in common_findings
        ]

        AuthService.log_action('xor_search_performed',
                             f'XOR correlation analysis for {len(sha_list)} files',
                             metadata={
                                 'file_count': len(sha_list),
                                 'correlations_found': len(enhanced_correlations),
                                 'sha_hashes': sha_list
                             })

        return jsonify({
            'success': True,
            'operation': 'xor_correlation',
            'input_files': len(sha_list),
            'files': files,
            'correlations': enhanced_correlations,
            'analysis_summary': {
                'strong_correlations': len([k for k, v in enhanced_correlations.items() 
                                          if isinstance(v, list) and len(v) > 0]),
                'temporal_patterns': 'temporal_analysis' in enhanced_correlations,
                'shared_findings': len(enhanced_correlations.get('finding_correlations', []))
            },
            'timestamp': datetime.utcnow().isoformat()
        })

    except Exception as e:
        current_app.logger.error(f"Error in XOR search: {e}")
        return jsonify({'error': str(e)}), 500


@search_api_bp.route('/search/group')
@api_endpoint(rate_limit_requests=200, cache_ttl=60)
def group_search():
    """Group files by various criteria with filtering"""
    try:
        group_by = request.args.get('group_by', 'type')

        # Validate group_by parameter
        valid_groupings = ['type', 'status', 'size', 'priority', 'date', 'findings_count']
        if group_by not in valid_groupings:
            return jsonify({
                'error': f'Invalid group_by parameter: {group_by}',
                'valid_options': valid_groupings
            }), 400

        # Extract filters
        filters = {}
        if request.args.get('file_type'):
            filters['file_type'] = request.args.get('file_type')
        if request.args.get('status'):
            filters['status'] = request.args.get('status')
        if request.args.get('min_priority'):
            try:
                filters['priority_min'] = int(request.args.get('min_priority'))
            except ValueError:
                return jsonify({'error': 'min_priority must be an integer'}), 400

        # Date range filters
        if request.args.get('date_from'):
            try:
                filters['created_after'] = datetime.strptime(
                    request.args.get('date_from'), '%Y-%m-%d'
                )
            except ValueError:
                return jsonify({'error': 'date_from must be in YYYY-MM-DD format'}), 400

        # Perform grouping
        if group_by == 'date':
            # Special handling for date grouping
            results = _group_by_date(filters)
        elif group_by == 'findings_count':
            # Special handling for findings count grouping
            results = _group_by_findings_count(filters)
        else:
            results = SearchService.group_files(group_by, filters)

        if 'error' in results:
            return jsonify(results), 400

        # Calculate additional statistics
        total_files = sum(group['count'] for group in results['groups'])

        # Sort groups by count (descending)
        sorted_groups = sorted(results['groups'], key=lambda x: x['count'], reverse=True)

        # Calculate percentages
        for group in sorted_groups:
            group['percentage'] = round((group['count'] / total_files * 100), 2) if total_files > 0 else 0

        AuthService.log_action('group_search_performed',
                             f'Grouped files by {group_by}',
                             metadata={
                                 'group_by': group_by,
                                 'filters': filters,
                                 'total_files': total_files,
                                 'groups_count': len(sorted_groups)
                             })

        return jsonify({
            'success': True,
            'group_by': group_by,
            'groups': sorted_groups,
            'statistics': {
                'total_files': total_files,
                'total_groups': len(sorted_groups),
                'largest_group': sorted_groups[0] if sorted_groups else None,
                'smallest_group': sorted_groups[-1] if sorted_groups else None
            },
            'filters_applied': filters,
            'timestamp': datetime.utcnow().isoformat()
        })

    except Exception as e:
        current_app.logger.error(f"Error in group search: {e}")
        return jsonify({'error': str(e)}), 500


@search_api_bp.route('/search/suggestions')
@api_endpoint(rate_limit_requests=500, cache_ttl=300)
def search_suggestions():
    """Get search suggestions based on partial query"""
    try:
        partial_query = request.args.get('q', '').strip()
        suggestion_type = request.args.get('type', 'all')  # all, filenames, types, patterns
        limit = min(request.args.get('limit', 10, type=int), 50)

        if len(partial_query) < 2:
            return jsonify({
                'suggestions': [],
                'message': 'Query too short for suggestions'
            })

        suggestions = []

        # Filename suggestions
        if suggestion_type in ['all', 'filenames']:
            filename_suggestions = db.session.query(
                AnalysisFile.filename
            ).filter(
                AnalysisFile.filename.ilike(f'%{partial_query}%')
            ).distinct().limit(limit // 2).all()

            for filename_tuple in filename_suggestions:
                suggestions.append({
                    'type': 'filename',
                    'value': filename_tuple[0],
                    'display': f'📄 {filename_tuple[0]}',
                    'score': 0.8
                })

        # File type suggestions
        if suggestion_type in ['all', 'types']:
            type_suggestions = db.session.query(
                AnalysisFile.file_type
            ).filter(
                AnalysisFile.file_type.ilike(f'%{partial_query}%')
            ).distinct().limit(limit // 3).all()

            for type_tuple in type_suggestions:
                if type_tuple[0]:  # Skip None values
                    suggestions.append({
                        'type': 'file_type',
                        'value': type_tuple[0],
                        'display': f'🏷️ Type: {type_tuple[0]}',
                        'score': 0.6
                    })

        # Pattern-based suggestions
        if suggestion_type in ['all', 'patterns']:
            pattern_suggestions = []
            query_lower = partial_query.lower()

            # Check if query matches known patterns
            for pattern_name, pattern in SearchService.PATTERNS.items():
                if pattern_name.startswith(query_lower) or query_lower in pattern_name:
                    pattern_suggestions.append({
                        'type': 'pattern',
                        'value': pattern_name,
                        'display': f'🔍 Pattern: {pattern_name}',
                        'score': 0.9
                    })

            suggestions.extend(pattern_suggestions[:limit // 3])

        # SHA hash suggestions (if query looks like hex)
        if len(partial_query) >= 8 and all(c in '0123456789abcdefABCDEF' for c in partial_query):
            hash_matches = db.session.query(
                AnalysisFile.sha256_hash,
                AnalysisFile.filename
            ).filter(
                AnalysisFile.sha256_hash.ilike(f'{partial_query}%')
            ).limit(5).all()

            for hash_tuple in hash_matches:
                suggestions.append({
                    'type': 'hash',
                    'value': hash_tuple[0],
                    'display': f'🔑 {hash_tuple[0][:16]}... ({hash_tuple[1]})',
                    'score': 1.0
                })

        # Sort suggestions by score and remove duplicates
        unique_suggestions = []
        seen_values = set()

        for suggestion in sorted(suggestions, key=lambda x: x['score'], reverse=True):
            if suggestion['value'] not in seen_values:
                unique_suggestions.append(suggestion)
                seen_values.add(suggestion['value'])

        return jsonify({
            'success': True,
            'query': partial_query,
            'suggestions': unique_suggestions[:limit],
            'suggestion_types': {
                'filename': len([s for s in unique_suggestions if s['type'] == 'filename']),
                'file_type': len([s for s in unique_suggestions if s['type'] == 'file_type']),
                'pattern': len([s for s in unique_suggestions if s['type'] == 'pattern']),
                'hash': len([s for s in unique_suggestions if s['type'] == 'hash'])
            },
            'timestamp': datetime.utcnow().isoformat()
        })

    except Exception as e:
        current_app.logger.error(f"Error getting search suggestions: {e}")
        return jsonify({'error': str(e)}), 500


@search_api_bp.route('/metadata/generate/<sha>')
@api_endpoint(rate_limit_requests=20, cache_ttl=1800)
def generate_metadata(sha):
    """Generate intelligent metadata for a specific file"""
    try:
        if not validate_sha256(sha):
            return jsonify({'error': 'Invalid SHA256 hash format'}), 400

        # Find file
        file = AnalysisFile.find_by_sha(sha)
        if not file:
            return jsonify({'error': 'File not found'}), 404

        if not file.filepath or not file.filepath.strip():
            return jsonify({'error': 'File path not available for metadata generation'}), 400

        # Check if file exists on disk
        import os
        if not os.path.exists(file.filepath):
            return jsonify({'error': 'File not accessible on disk'}), 404

        # Generate metadata
        metadata = MetadataGenerator.generate_file_metadata(file.filepath, file.id)

        # Store metadata in database
        try:
            existing_content = FileContent.query.filter_by(
                file_id=file.id,
                content_type='metadata_generated'
            ).first()

            if existing_content:
                existing_content.content_text = json.dumps(metadata, indent=2)
                existing_content.extracted_at = datetime.utcnow()
            else:
                content_entry = FileContent(
                    file_id=file.id,
                    content_type='metadata_generated',
                    content_text=json.dumps(metadata, indent=2),
                    content_size=len(json.dumps(metadata)),
                    extracted_at=datetime.utcnow(),
                    extraction_method='metadata_generator'
                )
                db.session.add(content_entry)

            db.session.commit()

        except Exception as e:
            current_app.logger.warning(f"Could not store metadata for file {file.id}: {e}")

        # Generate summary insights
        insights = []

        if metadata.get('magic_patterns'):
            pattern_count = len(metadata['magic_patterns'])
            insights.append(f"Detected {pattern_count} cryptographic patterns")

        if metadata.get('content_signatures'):
            entropy_sig = next((s for s in metadata['content_signatures'] if s['type'] == 'entropy'), None)
            if entropy_sig:
                entropy_val = float(entropy_sig['signature'])
                if entropy_val > 7.5:
                    insights.append("High entropy detected - likely encrypted or compressed")
                elif entropy_val < 1.0:
                    insights.append("Low entropy detected - likely plain text or structured data")

        if metadata.get('cross_references'):
            ref_count = len(metadata['cross_references'])
            if ref_count > 0:
                insights.append(f"Found {ref_count} cross-references to other files")

        AuthService.log_action('metadata_generated',
                             f'Generated metadata for file {file.filename}',
                             file_id=file.id,
                             metadata={
                                 'patterns_found': len(metadata.get('magic_patterns', [])),
                                 'signatures_generated': len(metadata.get('content_signatures', [])),
                                 'insights_count': len(insights)
                             })

        return jsonify({
            'success': True,
            'file_sha': sha,
            'filename': file.filename,
            'metadata': metadata,
            'insights': insights,
            'generation_summary': {
                'patterns_detected': len(metadata.get('magic_patterns', [])),
                'signatures_created': len(metadata.get('content_signatures', [])),
                'cross_references_found': len(metadata.get('cross_references', [])),
                'intelligence_hints': len(metadata.get('intelligence_hints', []))
            },
            'timestamp': datetime.utcnow().isoformat()
        })

    except Exception as e:
        current_app.logger.error(f"Error generating metadata for {sha}: {e}")
        return jsonify({'error': str(e)}), 500


@search_api_bp.route('/search/build-index', methods=['POST'])
@login_required
@AuthService.admin_required
@api_endpoint(rate_limit_requests=5, csrf_exempt=False)
def build_search_index():
    """Build or rebuild search indexes (admin only)"""
    try:
        force_rebuild = request.args.get('force', 'false').lower() == 'true'

        # Build indexes
        success = SearchService.build_search_index()

        if success:
            AuthService.log_action('search_index_built',
                                 'Built search indexes',
                                 metadata={'force_rebuild': force_rebuild})

            return jsonify({
                'success': True,
                'message': 'Search indexes built successfully',
                'force_rebuild': force_rebuild,
                'timestamp': datetime.utcnow().isoformat()
            })
        else:
            return jsonify({
                'success': False,
                'message': 'Failed to build some indexes (may already exist)',
                'timestamp': datetime.utcnow().isoformat()
            }), 500

    except Exception as e:
        current_app.logger.error(f"Error building search index: {e}")
        return jsonify({'error': str(e)}), 500


def _group_by_date(filters):
    """Group files by creation date"""
    try:
        query = AnalysisFile.query
        query = SearchService._apply_filters(query, filters)

        # Group by date (day)
        date_groups = db.session.query(
            db.func.date(AnalysisFile.created_at).label('date'),
            db.func.count(AnalysisFile.id).label('count')
        ).filter(query.whereclause if query.whereclause is not None else True)\
         .group_by(db.func.date(AnalysisFile.created_at))\
         .order_by(db.func.date(AnalysisFile.created_at).desc()).all()

        groups = [
            {'key': str(dg[0]) if dg[0] else 'Unknown', 'count': dg[1]}
            for dg in date_groups
        ]

        return {'group_by': 'date', 'groups': groups}

    except Exception as e:
        return {'error': f'Date grouping failed: {str(e)}'}


def _group_by_findings_count(filters):
    """Group files by number of findings"""
    try:
        query = AnalysisFile.query
        query = SearchService._apply_filters(query, filters)

        # Group by findings count ranges
        subquery = db.session.query(
            AnalysisFile.id,
            db.func.count(Finding.id).label('findings_count')
        ).outerjoin(Finding).group_by(AnalysisFile.id).subquery()

        findings_groups = db.session.query(
            db.func.case([
                (subquery.c.findings_count == 0, 'No findings'),
                (subquery.c.findings_count.between(1, 5), '1-5 findings'),
                (subquery.c.findings_count.between(6, 20), '6-20 findings'),
                (subquery.c.findings_count.between(21, 50), '21-50 findings')
            ], else_='50+ findings').label('findings_range'),
            db.func.count(subquery.c.id).label('count')
        ).group_by('findings_range').all()

        groups = [
            {'key': fg[0], 'count': fg[1]}
            for fg in findings_groups
        ]

        return {'group_by': 'findings_count', 'groups': groups}

    except Exception as e:
        return {'error': f'Findings count grouping failed: {str(e)}'}


# Import json at module level
import json
