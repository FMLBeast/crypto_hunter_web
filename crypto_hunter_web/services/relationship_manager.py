"""
File relationship management service
"""

import re
import logging
from crypto_hunter_web.models import db
from crypto_hunter_web.models import AnalysisFile
from crypto_hunter_web.models import ExtractionRelationship, CombinationRelationship, CombinationSource

logger = logging.getLogger(__name__)

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
    def derive_relationships_from_filenames():
        """
        Analyze filenames to automatically derive relationships between files.
        Particularly useful for steganography operations like zsteg.

        Returns:
            dict: Results of the operation with counts of relationships created
        """
        # Get all files
        files = AnalysisFile.query.all()

        # Track results
        results = {
            'total_files_analyzed': len(files),
            'relationships_created': 0,
            'errors': []
        }

        # Define patterns to recognize
        patterns = [
            # zsteg pattern: image_b5_r_lsb_xy.bin.BINARY_PAYLOAD
            {
                'regex': r'(.+?)_b(\d+)_([a-z])_(lsb|msb)_(xy|yx)\.bin\.BINARY_PAYLOAD',
                'method': 'zsteg',
                'confidence': 0.9
            },
            # Other steganography patterns can be added here
        ]

        # Find root file (image.png)
        root_file = AnalysisFile.query.filter_by(filename='image.png').first()

        if not root_file:
            logger.warning("Root file 'image.png' not found")
            results['errors'].append("Root file 'image.png' not found")

        # Process each file
        for file in files:
            try:
                # Skip files that don't match our patterns
                if file.filename == 'image.png':
                    continue

                parent_file = None
                extraction_method = None
                confidence = 0.5
                parameters = ""

                # Check if filename matches any of our patterns
                for pattern in patterns:
                    match = re.match(pattern['regex'], file.filename)
                    if match:
                        # Extract information from the filename
                        parent_name = match.group(1)
                        bitplane = match.group(2)
                        color_channel = match.group(3)
                        bit_order = match.group(4)
                        pixel_order = match.group(5)

                        # Find parent file
                        if parent_name == 'image':
                            parent_file = root_file
                        else:
                            parent_file = AnalysisFile.query.filter_by(filename=f"{parent_name}").first()

                        extraction_method = f"{pattern['method']}_b{bitplane}_{color_channel}_{bit_order}_{pixel_order}"
                        confidence = pattern['confidence']
                        parameters = f"bitplane={bitplane}, channel={color_channel}, bit_order={bit_order}, pixel_order={pixel_order}"
                        break

                # If no pattern matched but filename starts with "image", assume it's derived from root
                if not parent_file and file.filename.startswith('image_'):
                    parent_file = root_file
                    extraction_method = "derived_from_image"
                    confidence = 0.7

                # Create relationship if parent was found
                if parent_file:
                    # Check if relationship already exists
                    existing = ExtractionRelationship.query.filter_by(
                        source_file_id=parent_file.id,
                        derived_file_id=file.id
                    ).first()

                    if not existing:
                        relationship = ExtractionRelationship(
                            source_file_id=parent_file.id,
                            derived_file_id=file.id,
                            extraction_method=extraction_method or "unknown",
                            tool_used=extraction_method.split('_')[0] if extraction_method else "unknown",
                            command_line="",
                            notes=f"Automatically derived from filename: {file.filename}",
                            confidence_level=int(confidence * 10),
                            edge_color=RelationshipManager._get_extraction_method_color(extraction_method or "unknown")
                        )

                        # Update derived file depth
                        file.depth_level = max(file.depth_level, parent_file.depth_level + 1)

                        db.session.add(relationship)
                        results['relationships_created'] += 1

            except Exception as e:
                error_msg = f"Error processing file {file.filename}: {str(e)}"
                logger.error(error_msg)
                results['errors'].append(error_msg)

        # Commit all changes
        if results['relationships_created'] > 0:
            db.session.commit()
            logger.info(f"Created {results['relationships_created']} relationships from filenames")

        return results

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
