# crypto_hunter_web/routes/graph.py - COMPLETE GRAPH ROUTES IMPLEMENTATION

from flask import Blueprint, render_template, request, jsonify, current_app
from flask_login import login_required, current_user
from datetime import datetime, timedelta
import json
import math

from crypto_hunter_web.models import db, AnalysisFile, Finding, FileContent, FileStatus
from crypto_hunter_web.services.auth_service import AuthService
from crypto_hunter_web.services.relationship_manager import RelationshipManager
from crypto_hunter_web.utils.decorators import rate_limit, api_endpoint, cache_response
from crypto_hunter_web.utils.validators import validate_sha256

graph_bp = Blueprint('graph', __name__)


@graph_bp.route('/graph')
@login_required
def visual_graph():
    """Interactive visual graph of file relationships"""
    try:
        # Get graph parameters
        filter_type = request.args.get('filter', 'all')  # all, root_only, recent, high_priority
        max_nodes = request.args.get('max_nodes', 100, type=int)
        include_findings = request.args.get('include_findings', 'true').lower() == 'true'
        layout_type = request.args.get('layout', 'force')  # force, hierarchical, circular

        # Validate parameters
        if max_nodes > 1000:
            max_nodes = 1000

        # Build graph data
        graph_data = GraphBuilder.build_full_graph(
            filter_type=filter_type,
            max_nodes=max_nodes,
            include_findings=include_findings
        )

        # Get additional metadata for the graph
        graph_metadata = {
            'total_files': AnalysisFile.query.count(),
            'total_nodes': len(graph_data['nodes']),
            'total_edges': len(graph_data['edges']),
            'filter_applied': filter_type,
            'layout_type': layout_type,
            'includes_findings': include_findings,
            'generated_at': datetime.utcnow().isoformat()
        }

        # Get graph statistics
        graph_stats = _calculate_graph_statistics(graph_data)

        AuthService.log_action('graph_viewed', 
                             f'Viewed visual graph with {len(graph_data["nodes"])} nodes',
                             metadata={
                                 'filter_type': filter_type,
                                 'node_count': len(graph_data['nodes']),
                                 'edge_count': len(graph_data['edges'])
                             })

        return render_template('graph/visual_graph.html',
                             nodes=json.dumps(graph_data['nodes']),
                             edges=json.dumps(graph_data['edges']),
                             graph_metadata=graph_metadata,
                             graph_stats=graph_stats,
                             layout_type=layout_type)

    except Exception as e:
        current_app.logger.error(f"Error loading visual graph: {e}")
        return render_template('graph/error.html', 
                             error_message=f'Error loading graph: {str(e)}'), 500


@graph_bp.route('/graph/focus/<sha>')
@login_required
def graph_focus(sha):
    """Graph focused on specific file with its relationships"""
    try:
        if not validate_sha256(sha):
            return render_template('graph/error.html', 
                                 error_message='Invalid file hash format'), 400

        # Get focus parameters
        depth = request.args.get('depth', 2, type=int)
        include_similar = request.args.get('include_similar', 'true').lower() == 'true'
        include_findings = request.args.get('include_findings', 'true').lower() == 'true'

        # Validate depth
        if depth > 5:
            depth = 5

        # Build focused graph
        graph_data = GraphBuilder.build_focused_graph(
            sha, 
            depth=depth,
            include_similar=include_similar,
            include_findings=include_findings
        )

        if not graph_data['nodes']:
            return render_template('graph/error.html', 
                                 error_message='File not found or no relationships available'), 404

        # Get the focus file for context
        focus_file = AnalysisFile.find_by_sha(sha)

        # Calculate focus-specific statistics
        focus_stats = _calculate_focus_statistics(graph_data, sha)

        graph_metadata = {
            'focus_file_sha': sha,
            'focus_file_name': focus_file.filename if focus_file else 'Unknown',
            'depth': depth,
            'total_nodes': len(graph_data['nodes']),
            'total_edges': len(graph_data['edges']),
            'includes_similar': include_similar,
            'includes_findings': include_findings,
            'generated_at': datetime.utcnow().isoformat()
        }

        AuthService.log_action('graph_focused', 
                             f'Focused graph on file: {sha}',
                             metadata={
                                 'focus_sha': sha,
                                 'depth': depth,
                                 'node_count': len(graph_data['nodes']),
                                 'edge_count': len(graph_data['edges'])
                             })

        return render_template('graph/focused_graph.html',
                             nodes=json.dumps(graph_data['nodes']),
                             edges=json.dumps(graph_data['edges']),
                             focus_file=focus_file,
                             graph_metadata=graph_metadata,
                             focus_stats=focus_stats)

    except Exception as e:
        current_app.logger.error(f"Error loading focused graph: {e}")
        return render_template('graph/error.html', 
                             error_message=f'Error loading focused graph: {str(e)}'), 500


@graph_bp.route('/api/graph-data')
@api_endpoint(rate_limit_requests=200, cache_ttl=300)
def api_graph_data():
    """API endpoint for graph data"""
    try:
        # Get parameters
        filter_type = request.args.get('filter', 'all')
        focus_sha = request.args.get('focus')
        max_nodes = request.args.get('max_nodes', 100, type=int)
        include_findings = request.args.get('include_findings', 'true').lower() == 'true'
        format_type = request.args.get('format', 'vis')  # vis, d3, cytoscape, raw

        # Validate parameters
        if max_nodes > 1000:
            max_nodes = 1000

        # Build graph data
        if focus_sha:
            if not validate_sha256(focus_sha):
                return jsonify({'error': 'Invalid SHA256 hash format'}), 400

            depth = request.args.get('depth', 2, type=int)
            graph_data = GraphBuilder.build_focused_graph(
                focus_sha, 
                depth=depth,
                include_findings=include_findings
            )
        else:
            graph_data = GraphBuilder.build_full_graph(
                filter_type=filter_type,
                max_nodes=max_nodes,
                include_findings=include_findings
            )

        # Format data according to requested format
        formatted_data = _format_graph_data(graph_data, format_type)

        # Add metadata
        response_data = {
            'success': True,
            'graph_data': formatted_data,
            'metadata': {
                'node_count': len(graph_data['nodes']),
                'edge_count': len(graph_data['edges']),
                'filter_type': filter_type,
                'format': format_type,
                'focus_sha': focus_sha,
                'includes_findings': include_findings,
                'generated_at': datetime.utcnow().isoformat()
            }
        }

        return jsonify(response_data)

    except Exception as e:
        current_app.logger.error(f"Error getting graph data: {e}")
        return jsonify({'error': str(e)}), 500


@graph_bp.route('/api/graph/analyze')
@api_endpoint(rate_limit_requests=50, require_auth=True)
def analyze_graph():
    """Analyze graph structure and provide insights"""
    try:
        # Get analysis parameters
        analysis_type = request.args.get('type', 'centrality')  # centrality, clusters, paths, anomalies
        target_sha = request.args.get('target_sha')

        # Build graph for analysis
        if target_sha:
            if not validate_sha256(target_sha):
                return jsonify({'error': 'Invalid SHA256 hash format'}), 400
            graph_data = GraphBuilder.build_focused_graph(target_sha, depth=3)
        else:
            graph_data = GraphBuilder.build_full_graph(max_nodes=500)

        if not graph_data['nodes']:
            return jsonify({'error': 'No graph data available for analysis'}), 404

        # Perform analysis based on type
        analysis_results = {}

        if analysis_type == 'centrality':
            analysis_results = _analyze_centrality(graph_data)
        elif analysis_type == 'clusters':
            analysis_results = _analyze_clusters(graph_data)
        elif analysis_type == 'paths':
            analysis_results = _analyze_paths(graph_data, target_sha)
        elif analysis_type == 'anomalies':
            analysis_results = _detect_anomalies(graph_data)
        else:
            return jsonify({
                'error': f'Unsupported analysis type: {analysis_type}',
                'supported_types': ['centrality', 'clusters', 'paths', 'anomalies']
            }), 400

        AuthService.log_action('graph_analyzed',
                             f'Performed {analysis_type} analysis on graph',
                             metadata={
                                 'analysis_type': analysis_type,
                                 'target_sha': target_sha,
                                 'node_count': len(graph_data['nodes'])
                             })

        return jsonify({
            'success': True,
            'analysis_type': analysis_type,
            'target_sha': target_sha,
            'results': analysis_results,
            'graph_metadata': {
                'node_count': len(graph_data['nodes']),
                'edge_count': len(graph_data['edges'])
            },
            'timestamp': datetime.utcnow().isoformat()
        })

    except Exception as e:
        current_app.logger.error(f"Error analyzing graph: {e}")
        return jsonify({'error': str(e)}), 500


@graph_bp.route('/api/graph/derive-relationships', methods=['POST'])
@api_endpoint(rate_limit_requests=10, require_auth=True)
def derive_relationships():
    """Automatically derive relationships between files based on filenames"""
    try:
        # Call the relationship manager to derive relationships
        results = RelationshipManager.derive_relationships_from_filenames()

        # Log the action
        AuthService.log_action('relationships_derived',
                             f"Derived {results['relationships_created']} relationships from filenames",
                             metadata=results)

        return jsonify({
            'success': True,
            'results': results,
            'message': f"Successfully derived {results['relationships_created']} relationships from filenames"
        })

    except Exception as e:
        current_app.logger.error(f"Error deriving relationships: {e}")
        return jsonify({'error': str(e)}), 500


@graph_bp.route('/api/graph/create-relationship', methods=['POST'])
@api_endpoint(rate_limit_requests=20, require_auth=True)
def create_relationship():
    """Manually create a relationship between two files"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'success': False, 'error': 'No data provided'}), 400

        parent_sha = data.get('parent_sha')
        child_sha = data.get('child_sha')
        relationship_type = data.get('relationship_type', 'manual')

        if not parent_sha or not child_sha:
            return jsonify({'success': False, 'error': 'Parent and child SHA values are required'}), 400

        if not validate_sha256(parent_sha) or not validate_sha256(child_sha):
            return jsonify({'success': False, 'error': 'Invalid SHA256 hash format'}), 400

        # Create the relationship
        result = RelationshipManager.create_extraction_relationship(
            source_sha=parent_sha,
            derived_sha=child_sha,
            extraction_method=relationship_type,
            notes=f"Manually defined relationship via graph UI",
            user_id=current_user.id if current_user.is_authenticated else None,
            confidence_level=8  # High confidence for manual relationships
        )

        if not result.get('success', False):
            return jsonify({'success': False, 'error': result.get('error', 'Failed to create relationship')}), 400

        # Log the action
        AuthService.log_action('relationship_created',
                             f"Manually created relationship between {parent_sha[:8]} and {child_sha[:8]}",
                             metadata={
                                 'parent_sha': parent_sha,
                                 'child_sha': child_sha,
                                 'relationship_type': relationship_type
                             })

        return jsonify({
            'success': True,
            'relationship_id': result.get('relationship_id'),
            'message': 'Relationship created successfully'
        })

    except Exception as e:
        current_app.logger.error(f"Error creating relationship: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@graph_bp.route('/api/graph/export')
@api_endpoint(rate_limit_requests=20, require_auth=True)
def export_graph():
    """Export graph data in various formats"""
    try:
        # Get export parameters
        export_format = request.args.get('format', 'json')  # json, gexf, graphml, csv
        filter_type = request.args.get('filter', 'all')
        focus_sha = request.args.get('focus_sha')
        include_metadata = request.args.get('include_metadata', 'true').lower() == 'true'

        # Build graph data
        if focus_sha:
            if not validate_sha256(focus_sha):
                return jsonify({'error': 'Invalid SHA256 hash format'}), 400
            graph_data = GraphBuilder.build_focused_graph(focus_sha, depth=3)
        else:
            graph_data = GraphBuilder.build_full_graph(filter_type=filter_type, max_nodes=1000)

        if not graph_data['nodes']:
            return jsonify({'error': 'No graph data to export'}), 404

        # Export in requested format
        if export_format == 'json':
            export_data = _export_json(graph_data, include_metadata)
            return jsonify(export_data)

        elif export_format == 'gexf':
            gexf_content = _export_gexf(graph_data)
            return gexf_content, 200, {
                'Content-Type': 'application/xml',
                'Content-Disposition': 'attachment; filename=graph.gexf'
            }

        elif export_format == 'graphml':
            graphml_content = _export_graphml(graph_data)
            return graphml_content, 200, {
                'Content-Type': 'application/xml',
                'Content-Disposition': 'attachment; filename=graph.graphml'
            }

        elif export_format == 'csv':
            csv_content = _export_csv(graph_data)
            return csv_content, 200, {
                'Content-Type': 'text/csv',
                'Content-Disposition': 'attachment; filename=graph.csv'
            }

        else:
            return jsonify({
                'error': f'Unsupported export format: {export_format}',
                'supported_formats': ['json', 'gexf', 'graphml', 'csv']
            }), 400

    except Exception as e:
        current_app.logger.error(f"Error exporting graph: {e}")
        return jsonify({'error': str(e)}), 500


class GraphBuilder:
    """Enhanced graph builder for file relationship visualization"""

    @staticmethod
    def build_full_graph(filter_type='all', max_nodes=100, include_findings=True):
        """Build complete graph of file relationships"""
        try:
            # Start with base query
            query = AnalysisFile.query

            # Apply filters
            if filter_type == 'root_only':
                query = query.filter(AnalysisFile.is_root_file == True)
            elif filter_type == 'recent':
                recent_date = datetime.utcnow() - timedelta(days=7)
                query = query.filter(AnalysisFile.created_at >= recent_date)
            elif filter_type == 'high_priority':
                query = query.filter(AnalysisFile.priority >= 7)

            # Limit results and order by priority
            files = query.order_by(
                AnalysisFile.priority.desc(),
                AnalysisFile.created_at.desc()
            ).limit(max_nodes).all()

            # Build nodes and edges
            nodes = []
            edges = []
            node_ids = set()

            for file in files:
                node = _create_file_node(file, include_findings)
                nodes.append(node)
                node_ids.add(file.sha256_hash)

            # Build edges based on relationships
            for file in files:
                # Parent-child relationships
                if hasattr(file, 'parent_file_sha') and file.parent_file_sha:
                    if file.parent_file_sha in node_ids:
                        edges.append({
                            'id': f"{file.parent_file_sha}-{file.sha256_hash}",
                            'from': file.parent_file_sha,
                            'to': file.sha256_hash,
                            'type': 'derivation',
                            'label': 'derived from',
                            'color': {'color': '#2196F3'},
                            'width': 2
                        })

                # Similar file relationships
                similar_files = file.get_similar_files(limit=3)
                for similar_file in similar_files:
                    if similar_file.sha256_hash in node_ids and similar_file.sha256_hash != file.sha256_hash:
                        edge_id = f"{min(file.sha256_hash, similar_file.sha256_hash)}-{max(file.sha256_hash, similar_file.sha256_hash)}"
                        # Avoid duplicate edges
                        if not any(e['id'] == edge_id for e in edges):
                            edges.append({
                                'id': edge_id,
                                'from': file.sha256_hash,
                                'to': similar_file.sha256_hash,
                                'type': 'similarity',
                                'label': 'similar',
                                'color': {'color': '#4CAF50'},
                                'width': 1,
                                'dashes': True
                            })

            return {'nodes': nodes, 'edges': edges}

        except Exception as e:
            current_app.logger.error(f"Error building full graph: {e}")
            return {'nodes': [], 'edges': []}

    @staticmethod
    def build_focused_graph(sha, depth=2, include_similar=True, include_findings=True):
        """Build graph focused on specific file"""
        try:
            focus_file = AnalysisFile.find_by_sha(sha)
            if not focus_file:
                return {'nodes': [], 'edges': []}

            visited_files = set()
            nodes = []
            edges = []

            # BFS to build graph at specified depth
            queue = [(focus_file, 0)]
            visited_files.add(focus_file.sha256_hash)

            while queue:
                current_file, current_depth = queue.pop(0)

                # Create node for current file
                node = _create_file_node(current_file, include_findings, is_focus=(current_depth == 0))
                nodes.append(node)

                if current_depth < depth:
                    # Get related files
                    related_files = []

                    # Add parents
                    parents = current_file.get_parents()
                    for parent in parents:
                        if parent.sha256_hash not in visited_files:
                            related_files.append((parent, 'parent'))
                            visited_files.add(parent.sha256_hash)
                            queue.append((parent, current_depth + 1))

                    # Add children
                    children = current_file.get_children()
                    for child in children:
                        if child.sha256_hash not in visited_files:
                            related_files.append((child, 'child'))
                            visited_files.add(child.sha256_hash)
                            queue.append((child, current_depth + 1))

                    # Add similar files if requested
                    if include_similar and current_depth < depth - 1:
                        similar_files = current_file.get_similar_files(limit=2)
                        for similar in similar_files:
                            if similar.sha256_hash not in visited_files:
                                related_files.append((similar, 'similar'))
                                visited_files.add(similar.sha256_hash)
                                queue.append((similar, current_depth + 1))

                    # Create edges
                    for related_file, relationship in related_files:
                        edge = _create_relationship_edge(current_file, related_file, relationship)
                        edges.append(edge)

            return {'nodes': nodes, 'edges': edges}

        except Exception as e:
            current_app.logger.error(f"Error building focused graph: {e}")
            return {'nodes': [], 'edges': []}


def _create_file_node(file, include_findings=True, is_focus=False):
    """Create a node representation of a file"""
    # Determine node color based on file properties
    color = _get_node_color(file)

    # Determine node size based on priority and findings
    size = _get_node_size(file, include_findings)

    # Get node shape based on file type
    shape = _get_node_shape(file)

    node = {
        'id': file.sha256_hash,
        'label': file.filename[:30] + ('...' if len(file.filename) > 30 else ''),
        'title': _create_node_tooltip(file),
        'color': color,
        'size': size,
        'shape': shape,
        'font': {'size': 12, 'color': '#000000'},
        'borderWidth': 3 if is_focus else 1,
        'borderColor': '#FF9800' if is_focus else color,
        'metadata': {
            'sha256': file.sha256_hash,
            'filename': file.filename,
            'file_type': file.file_type,
            'file_size': file.file_size,
            'priority': file.priority,
            'status': file.status,
            'is_root': file.is_root_file,
            'created_at': file.created_at.isoformat() if file.created_at else None
        }
    }

    # Add findings information if requested
    if include_findings:
        findings_count = len(file.findings) if hasattr(file, 'findings') else 0
        node['metadata']['findings_count'] = findings_count

        if findings_count > 0:
            node['label'] += f' ({findings_count})'

    return node


def _create_relationship_edge(file1, file2, relationship_type):
    """Create an edge representing a relationship between files"""
    edge_configs = {
        'parent': {
            'color': '#2196F3',
            'width': 2,
            'label': 'parent',
            'arrows': {'to': {'enabled': True}}
        },
        'child': {
            'color': '#2196F3',
            'width': 2,
            'label': 'child',
            'arrows': {'to': {'enabled': True}}
        },
        'similar': {
            'color': '#4CAF50',
            'width': 1,
            'label': 'similar',
            'dashes': True
        },
        'finding': {
            'color': '#FF5722',
            'width': 1,
            'label': 'finding',
            'dashes': [5, 5]
        }
    }

    config = edge_configs.get(relationship_type, edge_configs['similar'])

    return {
        'id': f"{file1.sha256_hash}-{file2.sha256_hash}-{relationship_type}",
        'from': file1.sha256_hash,
        'to': file2.sha256_hash,
        'type': relationship_type,
        'color': {'color': config['color']},
        'width': config['width'],
        'label': config['label'],
        'dashes': config.get('dashes', False),
        'arrows': config.get('arrows', {})
    }


def _get_node_color(file):
    """Determine node color based on file properties"""
    # Priority-based coloring
    if file.priority >= 9:
        return '#F44336'  # Red for critical
    elif file.priority >= 7:
        return '#FF9800'  # Orange for high
    elif file.priority >= 5:
        return '#FFC107'  # Yellow for medium
    elif file.status == FileStatus.COMPLETE:
        return '#4CAF50'  # Green for complete
    else:
        return '#9E9E9E'  # Grey for pending


def _get_node_size(file, include_findings):
    """Determine node size based on file importance"""
    base_size = 20

    # Size based on priority
    priority_multiplier = file.priority / 10
    size = base_size + (priority_multiplier * 10)

    # Size based on file size (logarithmic scale)
    if file.file_size:
        size_factor = min(math.log10(file.file_size + 1) / 10, 1.0)
        size += size_factor * 15

    # Size based on findings
    if include_findings and hasattr(file, 'findings'):
        findings_count = len(file.findings)
        size += min(findings_count * 2, 20)

    return min(max(size, 15), 60)  # Clamp between 15 and 60


def _get_node_shape(file):
    """Determine node shape based on file type"""
    if file.is_root_file:
        return 'star'
    elif file.file_type and 'archive' in file.file_type.lower():
        return 'box'
    elif file.file_type and 'image' in file.file_type.lower():
        return 'image'
    elif file.file_type and 'executable' in file.file_type.lower():
        return 'triangle'
    else:
        return 'dot'


def _create_node_tooltip(file):
    """Create tooltip text for a node"""
    tooltip_parts = [
        f"<b>{file.filename}</b>",
        f"SHA256: {file.sha256_hash[:16]}...",
        f"Type: {file.file_type or 'Unknown'}",
        f"Size: {_format_file_size(file.file_size)}",
        f"Priority: {file.priority}/10",
        f"Status: {file.status}"
    ]

    if file.is_root_file:
        tooltip_parts.append("<b>ROOT FILE</b>")

    if hasattr(file, 'findings') and file.findings:
        tooltip_parts.append(f"Findings: {len(file.findings)}")

    return "<br>".join(tooltip_parts)


def _format_file_size(size_bytes):
    """Format file size in human readable format"""
    if not size_bytes:
        return "Unknown"

    for unit in ['B', 'KB', 'MB', 'GB']:
        if size_bytes < 1024.0:
            return f"{size_bytes:.1f} {unit}"
        size_bytes /= 1024.0
    return f"{size_bytes:.1f} TB"


def _calculate_graph_statistics(graph_data):
    """Calculate interesting statistics about the graph"""
    nodes = graph_data['nodes']
    edges = graph_data['edges']

    if not nodes:
        return {}

    # Node statistics
    priorities = [node['metadata']['priority'] for node in nodes]
    file_types = [node['metadata']['file_type'] for node in nodes if node['metadata']['file_type']]

    # Edge statistics
    edge_types = [edge['type'] for edge in edges]

    return {
        'node_count': len(nodes),
        'edge_count': len(edges),
        'avg_priority': sum(priorities) / len(priorities) if priorities else 0,
        'max_priority': max(priorities) if priorities else 0,
        'common_file_types': _get_top_items(file_types, 5),
        'edge_type_distribution': _get_item_counts(edge_types),
        'connectivity': len(edges) / len(nodes) if nodes else 0,
        'isolated_nodes': len([n for n in nodes if not any(
            e['from'] == n['id'] or e['to'] == n['id'] for e in edges
        )])
    }


def _calculate_focus_statistics(graph_data, focus_sha):
    """Calculate statistics specific to focused graph"""
    nodes = graph_data['nodes']
    edges = graph_data['edges']

    # Find focus node
    focus_node = next((n for n in nodes if n['id'] == focus_sha), None)
    if not focus_node:
        return {}

    # Calculate relationships
    outgoing_edges = [e for e in edges if e['from'] == focus_sha]
    incoming_edges = [e for e in edges if e['to'] == focus_sha]

    return {
        'focus_file': focus_node['metadata']['filename'],
        'total_relationships': len(outgoing_edges) + len(incoming_edges),
        'outgoing_relationships': len(outgoing_edges),
        'incoming_relationships': len(incoming_edges),
        'relationship_types': _get_item_counts([e['type'] for e in outgoing_edges + incoming_edges]),
        'depth_reached': max([_calculate_distance(focus_sha, n['id'], edges) for n in nodes if n['id'] != focus_sha], default=0)
    }


def _calculate_distance(node1, node2, edges):
    """Calculate shortest path distance between two nodes"""
    # Simple BFS implementation
    if node1 == node2:
        return 0

    visited = set()
    queue = [(node1, 0)]

    while queue:
        current, distance = queue.pop(0)
        if current in visited:
            continue
        visited.add(current)

        # Find neighbors
        neighbors = set()
        for edge in edges:
            if edge['from'] == current:
                neighbors.add(edge['to'])
            elif edge['to'] == current:
                neighbors.add(edge['from'])

        for neighbor in neighbors:
            if neighbor == node2:
                return distance + 1
            if neighbor not in visited:
                queue.append((neighbor, distance + 1))

    return float('inf')  # No path found


def _get_top_items(items, count):
    """Get top N most common items"""
    from collections import Counter
    counter = Counter(items)
    return counter.most_common(count)


def _get_item_counts(items):
    """Get counts of all items"""
    from collections import Counter
    return dict(Counter(items))


def _format_graph_data(graph_data, format_type):
    """Format graph data for different visualization libraries"""
    if format_type == 'vis':
        # Format for vis.js (default)
        return graph_data

    elif format_type == 'd3':
        # Format for D3.js
        return {
            'nodes': [{'id': n['id'], 'group': 1, **n} for n in graph_data['nodes']],
            'links': [{'source': e['from'], 'target': e['to'], **e} for e in graph_data['edges']]
        }

    elif format_type == 'cytoscape':
        # Format for Cytoscape.js
        elements = []

        # Add nodes
        for node in graph_data['nodes']:
            elements.append({
                'data': {
                    'id': node['id'],
                    'label': node['label'],
                    **node['metadata']
                }
            })

        # Add edges
        for edge in graph_data['edges']:
            elements.append({
                'data': {
                    'id': edge['id'],
                    'source': edge['from'],
                    'target': edge['to'],
                    'type': edge['type']
                }
            })

        return {'elements': elements}

    elif format_type == 'raw':
        # Raw format with all metadata
        return {
            'nodes': graph_data['nodes'],
            'edges': graph_data['edges'],
            'metadata': {
                'node_count': len(graph_data['nodes']),
                'edge_count': len(graph_data['edges']),
                'generated_at': datetime.utcnow().isoformat()
            }
        }

    else:
        return graph_data


# Graph analysis functions

def _analyze_centrality(graph_data):
    """Analyze centrality measures of nodes"""
    nodes = {n['id']: n for n in graph_data['nodes']}
    edges = graph_data['edges']

    # Calculate degree centrality
    degree_centrality = {}
    for node_id in nodes:
        degree = sum(1 for e in edges if e['from'] == node_id or e['to'] == node_id)
        degree_centrality[node_id] = degree

    # Find most central nodes
    top_central = sorted(degree_centrality.items(), key=lambda x: x[1], reverse=True)[:10]

    return {
        'degree_centrality': degree_centrality,
        'most_central_nodes': [
            {
                'node_id': node_id,
                'filename': nodes[node_id]['metadata']['filename'],
                'degree': degree
            }
            for node_id, degree in top_central
        ],
        'average_degree': sum(degree_centrality.values()) / len(degree_centrality) if degree_centrality else 0
    }


def _analyze_clusters(graph_data):
    """Analyze graph clusters and communities"""
    # Simple clustering based on connected components
    nodes = set(n['id'] for n in graph_data['nodes'])
    edges = graph_data['edges']

    # Find connected components
    visited = set()
    clusters = []

    for node in nodes:
        if node not in visited:
            cluster = set()
            stack = [node]

            while stack:
                current = stack.pop()
                if current not in visited:
                    visited.add(current)
                    cluster.add(current)

                    # Find neighbors
                    neighbors = set()
                    for edge in edges:
                        if edge['from'] == current:
                            neighbors.add(edge['to'])
                        elif edge['to'] == current:
                            neighbors.add(edge['from'])

                    for neighbor in neighbors:
                        if neighbor not in visited:
                            stack.append(neighbor)

            clusters.append(list(cluster))

    return {
        'cluster_count': len(clusters),
        'largest_cluster_size': max(len(c) for c in clusters) if clusters else 0,
        'isolated_nodes': len([c for c in clusters if len(c) == 1]),
        'clusters': [{'size': len(c), 'nodes': c} for c in clusters]
    }


def _analyze_paths(graph_data, target_sha):
    """Analyze paths in the graph"""
    if not target_sha:
        return {'error': 'Target SHA required for path analysis'}

    nodes = {n['id']: n for n in graph_data['nodes']}
    edges = graph_data['edges']

    if target_sha not in nodes:
        return {'error': 'Target node not found in graph'}

    # Find shortest paths from target to all other nodes
    paths = {}
    for node_id in nodes:
        if node_id != target_sha:
            distance = _calculate_distance(target_sha, node_id, edges)
            if distance != float('inf'):
                paths[node_id] = distance

    # Find most distant and closest nodes
    if paths:
        closest = min(paths.items(), key=lambda x: x[1])
        farthest = max(paths.items(), key=lambda x: x[1])

        return {
            'reachable_nodes': len(paths),
            'unreachable_nodes': len(nodes) - len(paths) - 1,  # -1 for target node
            'average_distance': sum(paths.values()) / len(paths),
            'closest_node': {
                'node_id': closest[0],
                'filename': nodes[closest[0]]['metadata']['filename'],
                'distance': closest[1]
            },
            'farthest_node': {
                'node_id': farthest[0],
                'filename': nodes[farthest[0]]['metadata']['filename'],
                'distance': farthest[1]
            }
        }
    else:
        return {
            'reachable_nodes': 0,
            'unreachable_nodes': len(nodes) - 1,
            'message': 'Target node is isolated'
        }


def _detect_anomalies(graph_data):
    """Detect anomalies in the graph structure"""
    nodes = graph_data['nodes']
    edges = graph_data['edges']

    anomalies = []

    # Detect highly connected nodes (potential hubs)
    degree_counts = {}
    for edge in edges:
        degree_counts[edge['from']] = degree_counts.get(edge['from'], 0) + 1
        degree_counts[edge['to']] = degree_counts.get(edge['to'], 0) + 1

    if degree_counts:
        avg_degree = sum(degree_counts.values()) / len(degree_counts)
        threshold = avg_degree + 2 * (max(degree_counts.values()) - avg_degree) / 3

        for node_id, degree in degree_counts.items():
            if degree > threshold:
                node = next((n for n in nodes if n['id'] == node_id), None)
                if node:
                    anomalies.append({
                        'type': 'hub_node',
                        'node_id': node_id,
                        'filename': node['metadata']['filename'],
                        'degree': degree,
                        'description': f'Highly connected node with {degree} connections'
                    })

    # Detect isolated high-priority nodes
    isolated_nodes = [
        n for n in nodes 
        if not any(e['from'] == n['id'] or e['to'] == n['id'] for e in edges)
        and n['metadata']['priority'] >= 7
    ]

    for node in isolated_nodes:
        anomalies.append({
            'type': 'isolated_high_priority',
            'node_id': node['id'],
            'filename': node['metadata']['filename'],
            'priority': node['metadata']['priority'],
            'description': 'High priority file with no relationships'
        })

    return {
        'anomaly_count': len(anomalies),
        'anomalies': anomalies
    }


# Export functions

def _export_json(graph_data, include_metadata):
    """Export graph as JSON"""
    export_data = {
        'format': 'json',
        'graph': graph_data,
        'exported_at': datetime.utcnow().isoformat()
    }

    if include_metadata:
        export_data['metadata'] = _calculate_graph_statistics(graph_data)

    return export_data


def _export_gexf(graph_data):
    """Export graph as GEXF format"""
    # Simplified GEXF export
    gexf_content = '''<?xml version="1.0" encoding="UTF-8"?>
<gexf xmlns="http://www.gexf.net/1.2draft" version="1.2">
    <graph mode="static" defaultedgetype="directed">
        <nodes>
'''

    for node in graph_data['nodes']:
        gexf_content += f'            <node id="{node["id"]}" label="{node["label"]}" />\n'

    gexf_content += '''        </nodes>
        <edges>
'''

    for i, edge in enumerate(graph_data['edges']):
        gexf_content += f'            <edge id="{i}" source="{edge["from"]}" target="{edge["to"]}" />\n'

    gexf_content += '''        </edges>
    </graph>
</gexf>'''

    return gexf_content


def _export_graphml(graph_data):
    """Export graph as GraphML format"""
    # Simplified GraphML export
    graphml_content = '''<?xml version="1.0" encoding="UTF-8"?>
<graphml xmlns="http://graphml.graphdrawing.org/xmlns">
    <graph id="G" edgedefault="directed">
'''

    for node in graph_data['nodes']:
        graphml_content += f'        <node id="{node["id"]}" />\n'

    for edge in graph_data['edges']:
        graphml_content += f'        <edge source="{edge["from"]}" target="{edge["to"]}" />\n'

    graphml_content += '''    </graph>
</graphml>'''

    return graphml_content


def _export_csv(graph_data):
    """Export graph as CSV (nodes and edges in separate sections)"""
    import csv
    import io

    output = io.StringIO()
    writer = csv.writer(output)

    # Write nodes
    writer.writerow(['# NODES'])
    writer.writerow(['id', 'label', 'filename', 'file_type', 'priority', 'file_size'])

    for node in graph_data['nodes']:
        writer.writerow([
            node['id'],
            node['label'],
            node['metadata']['filename'],
            node['metadata']['file_type'],
            node['metadata']['priority'],
            node['metadata']['file_size']
        ])

    writer.writerow([])  # Empty row

    # Write edges
    writer.writerow(['# EDGES'])
    writer.writerow(['from', 'to', 'type', 'label'])

    for edge in graph_data['edges']:
        writer.writerow([
            edge['from'],
            edge['to'],
            edge['type'],
            edge.get('label', '')
        ])

    return output.getvalue()
