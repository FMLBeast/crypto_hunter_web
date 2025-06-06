"""
Advanced search API routes
"""

from flask import Blueprint, request, jsonify, session
from app.services.auth_service import AuthService
from app.services.search_service import SearchService, MetadataGenerator
from app.utils.decorators import rate_limit
from app.utils.validators import validate_sha256

search_api_bp = Blueprint('search_api', __name__)


@search_api_bp.route('/search/hyperfast')
@AuthService.login_required
@rate_limit(max_requests=1000, window_seconds=60)
def hyperfast_search():
    """Ultra-fast search endpoint"""
    query = request.args.get('q', '').strip()
    page = request.args.get('page', 1, type=int)
    limit = min(request.args.get('limit', 50, type=int), 1000)

    # Extract filters
    filters = {}
    if request.args.get('file_type'):
        filters['file_type'] = request.args.get('file_type')
    if request.args.get('status'):
        filters['status'] = request.args.get('status')
    if request.args.get('is_root'):
        filters['is_root'] = request.args.get('is_root').lower() == 'true'
    if request.args.get('min_size'):
        filters['min_size'] = int(request.args.get('min_size'))
    if request.args.get('max_size'):
        filters['max_size'] = int(request.args.get('max_size'))
    if request.args.get('priority_min'):
        filters['priority_min'] = int(request.args.get('priority_min'))

    results = SearchService.hyperfast_search(query, filters, limit)

    return jsonify({
        'success': True,
        'results': results,
        'pagination': {
            'page': page,
            'limit': limit,
            'total': results.get('total', 0)
        }
    })


@search_api_bp.route('/search/magic')
@AuthService.login_required
@rate_limit(max_requests=100, window_seconds=60)
def magic_search():
    """Magic search for patterns and content"""
    query = request.args.get('q', '').strip()
    search_type = request.args.get('type', 'all')  # all, patterns, content, cross_ref

    if not query:
        return jsonify({'error': 'Query required'}), 400

    results = SearchService._magic_search(query, {}, 100)

    return jsonify({
        'success': True,
        'results': results,
        'magic_patterns_detected': SearchService._detect_query_type(query)
    })


@search_api_bp.route('/search/xor', methods=['POST'])
@AuthService.login_required
@rate_limit(max_requests=50, window_seconds=60)
def xor_search():
    """XOR correlation search"""
    data = request.json
    sha_list = data.get('sha_list', [])

    if not sha_list or len(sha_list) < 2:
        return jsonify({'error': 'At least 2 SHA hashes required'}), 400

    # Validate SHA hashes
    for sha in sha_list:
        if not validate_sha256(sha):
            return jsonify({'error': f'Invalid SHA256: {sha}'}), 400

    results = SearchService.xor_search(sha_list)

    return jsonify({
        'success': True,
        'results': results
    })


@search_api_bp.route('/search/group')
@AuthService.login_required
@rate_limit(max_requests=100, window_seconds=60)
def group_search():
    """Group files by various criteria"""
    group_by = request.args.get('group_by', 'type')

    # Extract filters
    filters = {}
    if request.args.get('file_type'):
        filters['file_type'] = request.args.get('file_type')
    if request.args.get('status'):
        filters['status'] = request.args.get('status')

    results = SearchService.group_files(group_by, filters)

    return jsonify({
        'success': True,
        'results': results
    })


@search_api_bp.route('/search/suggestions')
@AuthService.login_required
@rate_limit(max_requests=500, window_seconds=60)
def search_suggestions():
    """Get search suggestions based on query"""
    query = request.args.get('q', '').strip()

    if len(query) < 2:
        return jsonify({'suggestions': []})

    # Quick filename matches
    suggestions = SearchService.hyperfast_search(query, {}, 10)

    suggestion_list = []
    for file in suggestions['files']:
        suggestion_list.append({
            'text': file['filename'],
            'type': 'filename',
            'sha': file['sha256_hash'],
            'file_type': file['file_type']
        })

    # Add pattern suggestions
    if len(query) >= 6:
        if all(c in '0123456789abcdefABCDEF' for c in query):
            suggestion_list.append({
                'text': f"SHA hash: {query}*",
                'type': 'sha',
                'sha': query
            })

    return jsonify({'suggestions': suggestion_list[:10]})


@search_api_bp.route('/metadata/generate/<sha>')
@AuthService.login_required
@rate_limit(max_requests=50, window_seconds=300)
def generate_metadata(sha):
    """Generate metadata for a file"""
    if not validate_sha256(sha):
        return jsonify({'error': 'Invalid SHA256'}), 400

    from app.models.file import AnalysisFile
    file = AnalysisFile.query.filter_by(sha256_hash=sha).first()

    if not file:
        return jsonify({'error': 'File not found'}), 404

    if not os.path.exists(file.filepath):
        return jsonify({'error': 'File not accessible'}), 404

    metadata = MetadataGenerator.generate_file_metadata(file.filepath, file.id)

    return jsonify({
        'success': True,
        'metadata': metadata,
        'file': {
            'filename': file.filename,
            'sha256_hash': file.sha256_hash,
            'file_type': file.file_type
        }
    })


@search_api_bp.route('/search/build-index', methods=['POST'])
@AuthService.login_required
def build_search_index():
    """Build search indexes (admin only)"""
    from app.models.user import User
    user = User.query.get(session['user_id'])

    if not user.can_access_admin():
        return jsonify({'error': 'Admin access required'}), 403

    success = SearchService.build_search_index()

    return jsonify({
        'success': success,
        'message': 'Search indexes built successfully' if success else 'Index build failed'
    })