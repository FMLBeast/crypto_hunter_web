"""
Steganography extraction engine
"""

import os
import logging
from flask import current_app

from crypto_hunter_web.models import db
from crypto_hunter_web.models import AnalysisFile
from crypto_hunter_web.models import ExtractionRelationship
from crypto_hunter_web.services.extractors import get_extractor

logger = logging.getLogger(__name__)

class ExtractionEngine:
    """Orchestrate steganography extraction operations"""

    @staticmethod
    def is_llm_mode_enabled():
        """Check if LLM orchestration mode is enabled"""
        try:
            # Check if we're in a Flask application context
            if current_app:
                # First check environment variable
                use_llm = current_app.config.get('USE_LLM_ORCHESTRATOR', False)

                # If not set in config, check environment variable
                if not use_llm and os.environ.get('USE_LLM_ORCHESTRATOR', '').lower() in ('true', '1', 'yes'):
                    use_llm = True

                return use_llm
        except Exception as e:
            logger.warning(f"Error checking LLM mode: {e}")

        return False

    @staticmethod
    def extract_from_file(source_file, extraction_method, parameters=None, user_id=None):
        """Extract hidden data from a file using specified method"""
        try:
            # Check if we should use LLM orchestration
            if ExtractionEngine.is_llm_mode_enabled():
                return ExtractionEngine._extract_with_llm(source_file, extraction_method, parameters, user_id)

            # Manual extraction (current implementation)
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
            logger.error(f"Extraction error: {e}", exc_info=True)
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
    def _extract_with_llm(source_file, extraction_method, parameters=None, user_id=None):
        """Extract hidden data from a file using LLM orchestration"""
        try:
            logger.info(f"Using LLM orchestration for extraction: {extraction_method} on file {source_file.id}")

            # Import here to avoid circular imports
            from crypto_hunter_web.services.llm_crypto_orchestrator import llm_orchestrated_analysis
            from crypto_hunter_web.services.background_service import BackgroundService

            # Queue LLM analysis task with extraction method as a parameter
            task = llm_orchestrated_analysis.delay(
                source_file.id,
                extraction_method=extraction_method,
                parameters=parameters or {}
            )

            # Track the task
            BackgroundService.track_task(
                task.id, 
                'llm_extraction', 
                source_file.id, 
                user_id,
                {
                    'extraction_method': extraction_method,
                    'parameters': parameters or {},
                    'file_size': source_file.file_size,
                    'file_type': source_file.file_type
                }
            )

            # Return task information
            return {
                'success': True,
                'task_id': task.id,
                'message': f'LLM-orchestrated extraction queued successfully using {extraction_method}',
                'details': 'The extraction is being processed by an AI assistant. Check task status for results.',
                'is_async': True
            }

        except Exception as e:
            logger.error(f"LLM extraction error: {e}", exc_info=True)

            # Fall back to manual extraction if LLM fails
            logger.info(f"Falling back to manual extraction due to LLM error")

            # Temporarily disable LLM mode to avoid infinite recursion
            old_env = os.environ.get('USE_LLM_ORCHESTRATOR')
            if old_env:
                os.environ['USE_LLM_ORCHESTRATOR'] = 'false'

            try:
                # Call the original method with LLM disabled
                result = ExtractionEngine.extract_from_file(source_file, extraction_method, parameters, user_id)
                return result
            finally:
                # Restore environment variable
                if old_env:
                    os.environ['USE_LLM_ORCHESTRATOR'] = old_env
                else:
                    os.environ.pop('USE_LLM_ORCHESTRATOR', None)

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
