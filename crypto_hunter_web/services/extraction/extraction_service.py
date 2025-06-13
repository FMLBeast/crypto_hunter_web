"""
Extraction service module
This module provides a unified interface for extraction operations.
"""

import os
import logging
from typing import Dict, Any, List, Optional
from datetime import datetime

from crypto_hunter_web.models import db, AnalysisFile, FileContent, Finding, ExtractionRelationship, FileStatus
from crypto_hunter_web.services.background_service import BackgroundService
from crypto_hunter_web.services.extractors import get_extractor, get_recommended_extractors
from crypto_hunter_web.services.extraction_engine import ExtractionEngine
from crypto_hunter_web.tasks.extraction.extraction_tasks import (
    extract_from_file, extract_all_methods, extract_to_production
)

logger = logging.getLogger(__name__)

class ExtractionService:
    """Service for extraction operations"""
    
    @staticmethod
    def extract_from_file(file_id: int, extraction_method: str, parameters: Dict = None, 
                         user_id: int = None, async_mode: bool = True) -> Dict[str, Any]:
        """
        Extract hidden data from a file using specified method
        
        Args:
            file_id: ID of the file to extract from
            extraction_method: Name of the extraction method to use
            parameters: Parameters for the extraction method
            user_id: ID of the user who initiated the extraction
            async_mode: Whether to run the extraction asynchronously
        
        Returns:
            Dict with extraction results or task information
        """
        try:
            # Get file from database
            file_obj = AnalysisFile.query.get(file_id)
            if not file_obj:
                raise ValueError(f"File {file_id} not found")
            
            # Run extraction
            if async_mode:
                # Run in background using Celery
                task = extract_from_file.delay(file_id, extraction_method, parameters, user_id)
                
                return {
                    'success': True,
                    'task_id': task.id,
                    'message': f'Extraction queued successfully using {extraction_method}',
                    'details': 'The extraction is being processed in the background. Check task status for results.',
                    'is_async': True
                }
            else:
                # Run synchronously
                return extract_from_file(file_id, extraction_method, parameters, user_id)
        
        except Exception as e:
            logger.error(f"Error in extract_from_file: {e}", exc_info=True)
            return {
                'success': False,
                'error': str(e),
                'is_async': False
            }
    
    @staticmethod
    def extract_all_methods(file_id: int, user_id: int = None, async_mode: bool = True) -> Dict[str, Any]:
        """
        Extract hidden data from a file using all recommended methods
        
        Args:
            file_id: ID of the file to extract from
            user_id: ID of the user who initiated the extraction
            async_mode: Whether to run the extraction asynchronously
        
        Returns:
            Dict with extraction results or task information
        """
        try:
            # Get file from database
            file_obj = AnalysisFile.query.get(file_id)
            if not file_obj:
                raise ValueError(f"File {file_id} not found")
            
            # Run extraction
            if async_mode:
                # Run in background using Celery
                task = extract_all_methods.delay(file_id, user_id)
                
                return {
                    'success': True,
                    'task_id': task.id,
                    'message': 'Extraction with all methods queued successfully',
                    'details': 'The extraction is being processed in the background. Check task status for results.',
                    'is_async': True
                }
            else:
                # Run synchronously
                return extract_all_methods(file_id, user_id)
        
        except Exception as e:
            logger.error(f"Error in extract_all_methods: {e}", exc_info=True)
            return {
                'success': False,
                'error': str(e),
                'is_async': False
            }
    
    @staticmethod
    def extract_to_production(file_id: int, output_dir: str = "production", 
                             user_id: int = None, async_mode: bool = True) -> Dict[str, Any]:
        """
        Extract hidden data from a file and save to production directory
        
        Args:
            file_id: ID of the file to extract from
            output_dir: Directory to save extracted files
            user_id: ID of the user who initiated the extraction
            async_mode: Whether to run the extraction asynchronously
        
        Returns:
            Dict with extraction results or task information
        """
        try:
            # Get file from database
            file_obj = AnalysisFile.query.get(file_id)
            if not file_obj:
                raise ValueError(f"File {file_id} not found")
            
            # Run extraction
            if async_mode:
                # Run in background using Celery
                task = extract_to_production.delay(file_id, output_dir, user_id)
                
                return {
                    'success': True,
                    'task_id': task.id,
                    'message': f'Production extraction queued successfully to {output_dir}',
                    'details': 'The extraction is being processed in the background. Check task status for results.',
                    'is_async': True
                }
            else:
                # Run synchronously
                return extract_to_production(file_id, output_dir, user_id)
        
        except Exception as e:
            logger.error(f"Error in extract_to_production: {e}", exc_info=True)
            return {
                'success': False,
                'error': str(e),
                'is_async': False
            }
    
    @staticmethod
    def get_task_status(task_id: str) -> Dict[str, Any]:
        """
        Get status of an extraction task
        
        Args:
            task_id: ID of the task to check
        
        Returns:
            Dict with task status information
        """
        return BackgroundService.get_task_status(task_id)
    
    @staticmethod
    def get_available_extractors() -> List[str]:
        """
        Get list of available extractors
        
        Returns:
            List of extractor names
        """
        from crypto_hunter_web.services.extractors import list_extractors
        return list_extractors()
    
    @staticmethod
    def get_recommended_extractors(file_type: str) -> List[str]:
        """
        Get recommended extractors for a file type
        
        Args:
            file_type: MIME type of the file
        
        Returns:
            List of recommended extractor names
        """
        return get_recommended_extractors(file_type)
    
    @staticmethod
    def get_extraction_history(file_id: int) -> List[Dict[str, Any]]:
        """
        Get extraction history for a file
        
        Args:
            file_id: ID of the file
        
        Returns:
            List of extraction records
        """
        try:
            # Get file from database
            file_obj = AnalysisFile.query.get(file_id)
            if not file_obj:
                raise ValueError(f"File {file_id} not found")
            
            # Get extraction relationships
            relationships = ExtractionRelationship.query.filter_by(source_file_id=file_id).all()
            
            # Format results
            results = []
            for rel in relationships:
                results.append({
                    'id': rel.id,
                    'extraction_method': rel.extraction_method,
                    'extraction_tool_version': rel.extraction_tool_version,
                    'extraction_command': rel.extraction_command,
                    'confidence_score': rel.confidence_score,
                    'created_at': rel.created_at.isoformat() if rel.created_at else None,
                    'extracted_file_id': rel.extracted_file_id,
                    'extracted_file_sha': rel.extracted_file_sha,
                    'extra_data': rel.extra_data
                })
            
            return results
        
        except Exception as e:
            logger.error(f"Error in get_extraction_history: {e}", exc_info=True)
            return []
    
    @staticmethod
    def get_file_content(file_id: int, content_type: str = 'extracted_data') -> List[Dict[str, Any]]:
        """
        Get file content records for a file
        
        Args:
            file_id: ID of the file
            content_type: Type of content to retrieve
        
        Returns:
            List of content records
        """
        try:
            # Get file from database
            file_obj = AnalysisFile.query.get(file_id)
            if not file_obj:
                raise ValueError(f"File {file_id} not found")
            
            # Get content records
            contents = FileContent.query.filter_by(file_id=file_id, content_type=content_type).all()
            
            # Format results
            results = []
            for content in contents:
                results.append({
                    'id': content.id,
                    'content_type': content.content_type,
                    'content_format': content.content_format,
                    'content_size': content.content_size,
                    'extracted_at': content.extracted_at.isoformat() if content.extracted_at else None,
                    'extraction_method': content.extraction_method,
                    'extraction_extra_data': content.extraction_extra_data
                })
            
            return results
        
        except Exception as e:
            logger.error(f"Error in get_file_content: {e}", exc_info=True)
            return []