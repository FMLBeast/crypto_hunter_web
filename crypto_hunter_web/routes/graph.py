"""
Visual graph routes
"""

from flask import Blueprint, render_template, request, jsonify
import json

from crypto_hunter_web.services.auth_service import AuthService
from crypto_hunter_web.services.graph_builder import GraphBuilder
from crypto_hunter_web.utils.validators import validate_sha256

graph_bp = Blueprint('graph', __name__)

@graph_bp.route('/graph')
@AuthService.login_required
def visual_graph():
    """Interactive visual graph of file relationships"""
    # Build graph data
    graph_data = GraphBuilder.build_full_graph()
    
    AuthService.log_action('graph_viewed', 'Viewed visual graph')
    
    return render_template('graph/visual_graph.html',
                         nodes=json.dumps(graph_data['nodes']),
                         edges=json.dumps(graph_data['edges']),
                         total_files=len(graph_data['nodes']),
                         total_relationships=len(graph_data['edges']))

@graph_bp.route('/graph/focus/<sha>')
@AuthService.login_required
def graph_focus(sha):
    """Graph focused on specific file"""
    if not validate_sha256(sha):
        return "Invalid SHA256 hash", 400
    
    # Build focused graph
    graph_data = GraphBuilder.build_focused_graph(sha, depth=2)
    
    if not graph_data['nodes']:
        return "File not found", 404
    
    AuthService.log_action('graph_focused', f'Focused graph on file: {sha}')
    
    return render_template('graph/visual_graph.html',
                         nodes=json.dumps(graph_data['nodes']),
                         edges=json.dumps(graph_data['edges']),
                         total_files=len(graph_data['nodes']),
                         total_relationships=len(graph_data['edges']),
                         focus_file_sha=sha)

@graph_bp.route('/api/graph-data')
@AuthService.login_required
def api_graph_data():
    """API endpoint for graph data"""
    filter_type = request.args.get('filter', 'all')
    focus_sha = request.args.get('focus')
    
    if focus_sha:
        if not validate_sha256(focus_sha):
            return jsonify({'error': 'Invalid SHA256 hash'}), 400
        graph_data = GraphBuilder.build_focused_graph(focus_sha)
    else:
        graph_data = GraphBuilder.build_full_graph()
        
        # Apply filters
        if filter_type == 'root_trees':
            # Filter to show only root files and their descendants
            root_nodes = [n for n in graph_data['nodes'] if n.get('is_root')]
            if root_nodes:
                root_ids = {n['id'] for n in root_nodes}
                # Add descendants
                for edge in graph_data['edges']:
                    if edge['from'] in root_ids:
                        root_ids.add(edge['to'])
                
                graph_data['nodes'] = [n for n in graph_data['nodes'] if n['id'] in root_ids]
                graph_data['edges'] = [e for e in graph_data['edges'] 
                                     if e['from'] in root_ids and e['to'] in root_ids]
        
        elif filter_type == 'orphans':
            # Show files with no relationships
            connected_ids = set()
            for edge in graph_data['edges']:
                connected_ids.add(edge['from'])
                connected_ids.add(edge['to'])
            
            graph_data['nodes'] = [n for n in graph_data['nodes'] if n['id'] not in connected_ids]
            graph_data['edges'] = []
    
    return jsonify(graph_data)
