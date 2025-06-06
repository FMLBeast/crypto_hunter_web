"""
Steganography extraction engine
"""

import subprocess
import os
import tempfile
from datetime import datetime

from app.models import db
from app.models.file import AnalysisFile
from app.models.relationship import ExtractionRelationship
from app.extractors.base import BaseExtractor
from app.extractors import get_extractor

class ExtractionEngine:
    """Orchestrate steganography extraction operations"""
    
    @staticmethod
    def extract_from_file(source_file, extraction_method, parameters=None, user_id=None):
        """Extract hidden data from a file using specified method"""
        try:
            # Get appropriate extractor
            extractor = get_extractor(extraction_method)
            if not extractor:
                raise ValueError(f"Unknown extraction method: {extraction_method}")
            
            # Perform extraction
            result = extractor.extract(source_file.filepath, parameters or {})
            
            if result['success']:
                # Create new file for extracted data
                extracted_file = ExtractionEngine._create_extracted_file(
                    source_file, result, extraction_method, user_id
                )
                
                # Create relationship
                relationship = ExtractionRelationship(
                    source_file_id=source_file.id,
                    derived_file_id=extracted_file.id,
                    extraction_method=extraction_method,
                    tool_used=extractor.tool_name,
                    command_line=result.get('command_line', ''),
                    confidence_level=result.get('confidence', 5),
                    discovered_by=user_id,
                    edge_color=ExtractionEngine._get_method_color(extraction_method)
                )
                
                db.session.add(relationship)
                db.session.commit()
                
                return {
                    'success': True,
                    'extracted_file': extracted_file,
                    'relationship': relationship,
                    'details': result.get('details', '')
                }
            else:
                return {
                    'success': False,
                    'error': result.get('error', 'Extraction failed'),
                    'details': result.get('details', '')
                }
                
        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }
    
    @staticmethod
    def _create_extracted_file(source_file, extraction_result, extraction_method, user_id):
        """Create a new AnalysisFile for extracted data"""
        # Generate filename for extracted data
        method_suffix = extraction_method.replace('_', '-')
        extracted_filename = f"{source_file.filename}_{method_suffix}_extracted"
        
        # Save extracted data to file
        extracted_path = os.path.join('bulk_uploads/discovered_files', extracted_filename)
        
        with open(extracted_path, 'wb') as f:
            f.write(extraction_result['data'])
        
        # Calculate hash
        sha256_hash = AnalysisFile.calculate_sha256(extracted_path)
        
        # Create file record
        extracted_file = AnalysisFile(
            sha256_hash=sha256_hash,
            filename=extracted_filename,
            filepath=extracted_path,
            file_type='application/octet-stream',
            file_size=len(extraction_result['data']),
            parent_file_sha=source_file.sha256_hash,
            extraction_method=extraction_method,
            discovered_by=user_id,
            status='pending',
            depth_level=source_file.depth_level + 1,
            node_color=ExtractionEngine._get_file_type_color('binary')
        )
        
        db.session.add(extracted_file)
        db.session.flush()  # Get the ID
        
        return extracted_file
    
    @staticmethod
    def _get_method_color(method):
        """Get color based on extraction method"""
        colors = {
            'zsteg': '#ef4444',
            'steghide': '#f97316',
            'binwalk': '#eab308',
            'strings': '#22c55e',
            'hexdump': '#3b82f6',
            'exiftool': '#8b5cf6',
            'foremost': '#ec4899',
            'dd': '#6b7280',
            'manual': '#64748b'
        }
        
        method_lower = method.lower() if method else 'manual'
        
        for key, color in colors.items():
            if key in method_lower:
                return color
        
        return colors['manual']
    
    @staticmethod
    def _get_file_type_color(file_type):
        """Get color based on file type"""
        colors = {
            'image': '#ef4444',
            'audio': '#f97316',
            'video': '#eab308',
            'text': '#22c55e',
            'binary': '#3b82f6',
            'archive': '#8b5cf6',
            'executable': '#ec4899',
            'unknown': '#6b7280'
        }
        
        file_type_lower = file_type.lower() if file_type else 'unknown'
        
        for key, color in colors.items():
            if key in file_type_lower:
                return color
        
        return colors['unknown']
    
    @staticmethod
    def suggest_extraction_methods(file_type):
        """Suggest extraction methods based on file type"""
        suggestions = {
            'image/jpeg': ['zsteg_bitplane_1', 'steghide', 'exiftool'],
            'image/png': ['zsteg_bitplane_1', 'binwalk'],
            'audio/mp3': ['binwalk', 'strings'],
            'application/octet-stream': ['hexdump', 'strings', 'binwalk']
        }
        
        return suggestions.get(file_type, ['strings', 'hexdump'])
