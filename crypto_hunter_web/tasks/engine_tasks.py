"""
Engine Tasks - Celery tasks for the engine service.

This module defines Celery tasks that use the EngineService to process files
for each of the 5 methods of adding files to the project:
1. Manual upload through webapp
2. Manual upload of bulk CSV through webapp
3. Upload through API
4. Files uncovered by automated analyzers
5. Automated run started by admin targeting a specific file or directory
"""
import os
import logging
from typing import Dict, List, Any, Optional, Union
from datetime import datetime

from crypto_hunter_web.services.celery_app import celery_app
from crypto_hunter_web.services.engine_service import EngineService
from crypto_hunter_web.models import db, AnalysisFile, BulkImport, FileStatus

logger = logging.getLogger(__name__)

@celery_app.task(bind=True, max_retries=3)
def process_file(self, file_id: int, engines: List[str] = None, options: Dict[str, Any] = None) -> Dict[str, Any]:
    """
    Process a file through multiple engines.
    
    This task is used for method 1 (manual upload through webapp) and
    can also be used by other methods.
    
    Args:
        file_id: ID of the file to process
        engines: List of engine types to use for processing
        options: Additional options for processing
        
    Returns:
        Dictionary containing the results of processing
    """
    try:
        logger.info(f"Starting file processing for file {file_id} with engines {engines}")
        
        if engines is None:
            engines = ['analysis']
            
        if options is None:
            options = {}
            
        # Process the file through the specified engines
        result = EngineService.process_file(file_id, engines, options)
        
        logger.info(f"File processing completed for file {file_id}")
        return result
        
    except Exception as exc:
        logger.error(f"File processing failed for file {file_id}: {exc}")
        self.retry(countdown=60, exc=exc)

@celery_app.task(bind=True, max_retries=3)
def process_bulk_import(self, bulk_import_id: int, csv_content: str, engines: List[str] = None, options: Dict[str, Any] = None) -> Dict[str, Any]:
    """
    Process a bulk import through multiple engines.
    
    This task is used for method 2 (manual upload of bulk CSV through webapp).
    
    Args:
        bulk_import_id: ID of the bulk import to process
        csv_content: Content of the CSV file
        engines: List of engine types to use for processing
        options: Additional options for processing
        
    Returns:
        Dictionary containing the results of processing
    """
    try:
        logger.info(f"Starting bulk import processing for import ID {bulk_import_id}")
        
        if engines is None:
            engines = ['upload', 'analysis']
            
        if options is None:
            options = {}
            
        # Update bulk import status
        bulk_import = BulkImport.query.get(bulk_import_id)
        if not bulk_import:
            raise ValueError(f"Bulk import {bulk_import_id} not found")
            
        bulk_import.status = 'processing'
        db.session.commit()
        
        # Process the bulk import
        result = EngineService.process_bulk_import(bulk_import_id, csv_content, engines, options)
        
        logger.info(f"Bulk import processing completed for import ID {bulk_import_id}")
        return result
        
    except Exception as exc:
        logger.error(f"Bulk import processing failed for import ID {bulk_import_id}: {exc}")
        
        # Update bulk import status
        bulk_import = BulkImport.query.get(bulk_import_id)
        if bulk_import:
            bulk_import.status = 'failed'
            bulk_import.error_message = str(exc)
            db.session.commit()
            
        self.retry(countdown=60, exc=exc)

@celery_app.task(bind=True, max_retries=3)
def process_api_import(self, file_path: str, user_id: int, engines: List[str] = None, options: Dict[str, Any] = None) -> Dict[str, Any]:
    """
    Process a file uploaded through the API through multiple engines.
    
    This task is used for method 3 (upload through API).
    
    Args:
        file_path: Path to the file to process
        user_id: ID of the user initiating the processing
        engines: List of engine types to use for processing
        options: Additional options for processing
        
    Returns:
        Dictionary containing the results of processing
    """
    try:
        logger.info(f"Starting API import processing for file {file_path}")
        
        if engines is None:
            engines = ['upload', 'analysis']
            
        if options is None:
            options = {}
            
        # Process the file
        result = EngineService.process_api_import(file_path, user_id, engines, options)
        
        logger.info(f"API import processing completed for file {file_path}")
        return result
        
    except Exception as exc:
        logger.error(f"API import processing failed for file {file_path}: {exc}")
        self.retry(countdown=60, exc=exc)

@celery_app.task(bind=True, max_retries=3)
def process_extracted_file(self, parent_file_id: int, extracted_file_path: str, engines: List[str] = None, options: Dict[str, Any] = None) -> Dict[str, Any]:
    """
    Process a file extracted from another file through multiple engines.
    
    This task is used for method 4 (files uncovered by automated analyzers).
    
    Args:
        parent_file_id: ID of the parent file
        extracted_file_path: Path to the extracted file
        engines: List of engine types to use for processing
        options: Additional options for processing
        
    Returns:
        Dictionary containing the results of processing
    """
    try:
        logger.info(f"Starting extracted file processing for file {extracted_file_path} from parent {parent_file_id}")
        
        if engines is None:
            engines = ['upload', 'analysis']
            
        if options is None:
            options = {}
            
        # Process the extracted file
        result = EngineService.process_extracted_file(parent_file_id, extracted_file_path, engines, options)
        
        logger.info(f"Extracted file processing completed for file {extracted_file_path}")
        return result
        
    except Exception as exc:
        logger.error(f"Extracted file processing failed for file {extracted_file_path}: {exc}")
        self.retry(countdown=60, exc=exc)

@celery_app.task(bind=True, max_retries=3)
def process_directory(self, directory_path: str, user_id: int, engines: List[str] = None, options: Dict[str, Any] = None) -> Dict[str, Any]:
    """
    Process all files in a directory through multiple engines.
    
    This task is used for method 5 (automated run started by admin targeting a specific file or directory).
    
    Args:
        directory_path: Path to the directory to process
        user_id: ID of the user initiating the processing
        engines: List of engine types to use for processing
        options: Additional options for processing
        
    Returns:
        Dictionary containing the results of processing
    """
    try:
        logger.info(f"Starting directory processing for directory {directory_path}")
        
        if engines is None:
            engines = ['upload', 'analysis']
            
        if options is None:
            options = {}
            
        # Process the directory
        result = EngineService.process_directory(directory_path, user_id, engines, options)
        
        logger.info(f"Directory processing completed for directory {directory_path}")
        return result
        
    except Exception as exc:
        logger.error(f"Directory processing failed for directory {directory_path}: {exc}")
        self.retry(countdown=60, exc=exc)

@celery_app.task
def run_extraction_engine(file_id: int, options: Dict[str, Any] = None) -> Dict[str, Any]:
    """
    Run the extraction engine on a file to extract embedded files.
    
    This task is used to support method 4 (files uncovered by automated analyzers).
    
    Args:
        file_id: ID of the file to extract from
        options: Additional options for extraction
        
    Returns:
        Dictionary containing the results of extraction
    """
    try:
        logger.info(f"Starting extraction engine for file {file_id}")
        
        if options is None:
            options = {}
            
        # Get the extraction engine
        extraction_engine = EngineService.get_engine('extraction')
        
        # Process the file
        result = extraction_engine.process_file(file_id, options)
        
        logger.info(f"Extraction engine completed for file {file_id}")
        return result
        
    except Exception as exc:
        logger.error(f"Extraction engine failed for file {file_id}: {exc}")
        raise