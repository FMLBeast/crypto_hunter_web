"""
Graph visualization service
"""

import json
from app.models.file import AnalysisFile
from app.models.relationship import ExtractionRelationship, CombinationRelationship

class GraphBuilder:
    """Build graph data for visualization"""
    
    @staticmethod
    def build_full_graph():
        """Build complete graph with all files and relationships"""
        files = AnalysisFile.query.all()
        relationships = ExtractionRelationship.query.all()
        combinations = CombinationRelationship.query.all()
        
        nodes = []
        edges = []
        
        # Build nodes
        for file in files:
            nodes.append(GraphBuilder._build_file_node(file))
        
        # Build extraction edges
        for rel in relationships:
            edges.append(GraphBuilder._build_extraction_edge(rel))
        
        # Build combination edges
        for combo in combinations:
            for source in combo.source_files:
                edges.append(GraphBuilder._build_combination_edge(source, combo))
        
        return {'nodes': nodes, 'edges': edges}
    
    @staticmethod
    def build_focused_graph(target_sha, depth=2):
        """Build graph focused on specific file with limited depth"""
        target_file = AnalysisFile.query.filter_by(sha256_hash=target_sha).first()
        if not target_file:
            return {'nodes': [], 'edges': []}
        
        # Get related files within depth limit
        related_files = set([target_file])
        
        # Add parents and children up to depth limit
        for _ in range(depth):
            current_files = list(related_files)
            for file in current_files:
                related_files.update(file.get_parents())
                related_files.update(file.get_children())
        
        # Build graph data for related files
        nodes = []
        edges = []
        
        for file in related_files:
            node = GraphBuilder._build_file_node(file)
            if file.id == target_file.id:
                node['is_target'] = True
                node['size'] = 40
                node['color'] = '#fbbf24'
            nodes.append(node)
        
        # Get relationships between related files
        file_ids = {f.id for f in related_files}
        relationships = ExtractionRelationship.query.filter(
            ExtractionRelationship.source_file_id.in_(file_ids),
            ExtractionRelationship.derived_file_id.in_(file_ids)
        ).all()
        
        for rel in relationships:
            edges.append(GraphBuilder._build_extraction_edge(rel))
        
        return {'nodes': nodes, 'edges': edges}
    
    @staticmethod
    def _build_file_node(file):
        """Build node data for a file"""
        return {
            'id': file.id,
            'sha': file.sha256_hash,
            'label': file.filename[:30] + ('...' if len(file.filename) > 30 else ''),
            'title': GraphBuilder._build_node_tooltip(file),
            'color': file.node_color or GraphBuilder._get_file_type_color(file.file_type),
            'shape': 'diamond' if file.is_root_file else 'dot',
            'size': 30 if file.is_root_file else 20,
            'borderWidth': 3 if file.is_root_file else 2,
            'is_root': file.is_root_file,
            'file_type': file.file_type,
            'status': file.status,
            'depth': file.depth_level,
            'findings_count': len(file.findings)
        }
    
    @staticmethod
    def _build_extraction_edge(relationship):
        """Build edge data for extraction relationship"""
        return {
            'id': f"extraction_{relationship.id}",
            'from': relationship.source_file_id,
            'to': relationship.derived_file_id,
            'label': relationship.method_display_name,
            'color': relationship.edge_color,
            'width': relationship.edge_weight * 2,
            'dashes': relationship.edge_style == 'dashed',
            'arrows': {'to': {'enabled': True, 'scaleFactor': 1.2}},
            'title': GraphBuilder._build_edge_tooltip(relationship),
            'type': 'extraction'
        }
    
    @staticmethod
    def _build_combination_edge(source, combination):
        """Build edge data for combination relationship"""
        return {
            'id': f"combination_{combination.id}_{source.id}",
            'from': source.source_file_id,
            'to': combination.result_file_id,
            'label': f"Combine ({combination.combination_method})",
            'color': '#9333ea',
            'width': 3,
            'dashes': True,
            'arrows': {'to': {'enabled': True}},
            'title': f"Combination: {combination.combination_method}",
            'type': 'combination'
        }
    
    @staticmethod
    def _build_node_tooltip(file):
        """Build tooltip text for file node"""
        return f"{file.filename}<br>SHA: {file.sha256_hash[:16]}...<br>Type: {file.file_type}<br>Status: {file.status}"
    
    @staticmethod
    def _build_edge_tooltip(relationship):
        """Build tooltip text for relationship edge"""
        return f"Method: {relationship.extraction_method}<br>Tool: {relationship.tool_used}<br>Confidence: {relationship.confidence_level}/10"
    
    @staticmethod
    def _get_file_type_color(file_type):
        """Get color based on file type"""
        colors = {
            'image': '#ef4444', 'audio': '#f97316', 'video': '#eab308',
            'text': '#22c55e', 'binary': '#3b82f6', 'archive': '#8b5cf6',
            'executable': '#ec4899', 'unknown': '#6b7280'
        }
        
        file_type_lower = file_type.lower() if file_type else 'unknown'
        for key, color in colors.items():
            if key in file_type_lower:
                return color
        return colors['unknown']
