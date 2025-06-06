"""
File relationship management service
"""

from app.models import db
from app.models.file import AnalysisFile
from app.models.relationship import ExtractionRelationship, CombinationRelationship, CombinationSource

class RelationshipManager:
    """Manage file relationships and extraction chains"""
    
    @staticmethod
    def create_extraction_relationship(source_sha, derived_sha, extraction_method, 
                                     tool_used='', command_line='', notes='', 
                                     confidence_level=5, user_id=None):
        """Create a new extraction relationship"""
        source_file = AnalysisFile.find_by_sha(source_sha)
        derived_file = AnalysisFile.find_by_sha(derived_sha)
        
        if not source_file or not derived_file:
            return {'success': False, 'error': 'Source or derived file not found'}
        
        # Check if relationship already exists
        existing = ExtractionRelationship.query.filter_by(
            source_file_id=source_file.id,
            derived_file_id=derived_file.id,
            extraction_method=extraction_method
        ).first()
        
        if existing:
            return {'success': False, 'error': 'Relationship already exists'}
        
        # Create new relationship
        relationship = ExtractionRelationship(
            source_file_id=source_file.id,
            derived_file_id=derived_file.id,
            extraction_method=extraction_method,
            tool_used=tool_used,
            command_line=command_line,
            notes=notes,
            confidence_level=confidence_level,
            discovered_by=user_id,
            edge_color=RelationshipManager._get_extraction_method_color(extraction_method)
        )
        
        # Update derived file depth
        derived_file.depth_level = max(derived_file.depth_level, source_file.depth_level + 1)
        
        db.session.add(relationship)
        db.session.commit()
        
        return {'success': True, 'relationship_id': relationship.id}
    
    @staticmethod
    def create_combination_relationship(source_shas, result_sha, combination_method, 
                                      notes='', user_id=None):
        """Create a new combination relationship"""
        if len(source_shas) < 2:
            return {'success': False, 'error': 'At least 2 source files required'}
        
        result_file = AnalysisFile.find_by_sha(result_sha)
        if not result_file:
            return {'success': False, 'error': 'Result file not found'}
        
        source_files = []
        for sha in source_shas:
            file = AnalysisFile.find_by_sha(sha)
            if not file:
                return {'success': False, 'error': f'Source file {sha} not found'}
            source_files.append(file)
        
        # Create combination relationship
        combination = CombinationRelationship(
            result_file_id=result_file.id,
            combination_method=combination_method,
            notes=notes,
            discovered_by=user_id
        )
        db.session.add(combination)
        db.session.flush()  # Get the ID
        
        # Add source files
        for i, source_file in enumerate(source_files):
            source = CombinationSource(
                combination_id=combination.id,
                source_file_id=source_file.id,
                order_index=i
            )
            db.session.add(source)
        
        db.session.commit()
        
        return {'success': True, 'combination_id': combination.id}
    
    @staticmethod
    def get_extraction_tree(file_id, max_depth=5):
        """Get the complete extraction tree for a file"""
        file = AnalysisFile.query.get(file_id)
        if not file:
            return None
        
        return RelationshipManager._build_tree_recursive(file, set(), 0, max_depth)
    
    @staticmethod
    def _build_tree_recursive(file, visited, current_depth, max_depth):
        """Recursively build extraction tree"""
        if file.id in visited or current_depth >= max_depth:
            return {'file': file, 'children': []}
        
        visited.add(file.id)
        
        children = []
        relationships = ExtractionRelationship.query.filter_by(source_file_id=file.id).all()
        
        for rel in relationships:
            child_tree = RelationshipManager._build_tree_recursive(
                rel.derived_file, visited, current_depth + 1, max_depth
            )
            child_tree['relationship'] = rel
            children.append(child_tree)
        
        return {'file': file, 'children': children}
    
    @staticmethod
    def find_extraction_paths(start_file_id, end_file_id):
        """Find all extraction paths between two files"""
        paths = []
        RelationshipManager._find_paths_recursive(
            start_file_id, end_file_id, [], set(), paths
        )
        return paths
    
    @staticmethod
    def _find_paths_recursive(current_id, target_id, current_path, visited, all_paths):
        """Recursively find paths between files"""
        if current_id == target_id:
            all_paths.append(current_path.copy())
            return
        
        if current_id in visited:
            return
        
        visited.add(current_id)
        
        # Find all outgoing relationships
        relationships = ExtractionRelationship.query.filter_by(source_file_id=current_id).all()
        
        for rel in relationships:
            current_path.append(rel)
            RelationshipManager._find_paths_recursive(
                rel.derived_file_id, target_id, current_path, visited, all_paths
            )
            current_path.pop()
        
        visited.remove(current_id)
    
    @staticmethod
    def _get_extraction_method_color(method):
        """Get color for extraction method"""
        colors = {
            'zsteg': '#ef4444',
            'steghide': '#f97316', 
            'binwalk': '#eab308',
            'strings': '#22c55e',
            'hexdump': '#3b82f6',
            'exiftool': '#8b5cf6'
        }
        
        for key, color in colors.items():
            if key in method.lower():
                return color
        
        return '#64748b'
