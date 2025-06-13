"""
Extraction tasks for background processing
This module contains Celery tasks for extraction operations.
"""

import os
import time
import logging
import shutil
from typing import Dict, Any, List, Optional
from datetime import datetime

from crypto_hunter_web.models import db, AnalysisFile, FileContent, Finding, ExtractionRelationship, FileStatus
from crypto_hunter_web.services.celery_app import celery_app
from crypto_hunter_web.services.background_service import BackgroundService, tracked_task
from crypto_hunter_web.services.extractors import get_extractor, get_recommended_extractors
from crypto_hunter_web.services.extraction_engine import ExtractionEngine

logger = logging.getLogger(__name__)

@tracked_task(bind=True, max_retries=3)
def extract_from_file(self, file_id: int, extraction_method: str, parameters: Dict = None, user_id: int = None):
    """
    Extract hidden data from a file using specified method
    
    Args:
        file_id: ID of the file to extract from
        extraction_method: Name of the extraction method to use
        parameters: Parameters for the extraction method
        user_id: ID of the user who initiated the extraction
    
    Returns:
        Dict with extraction results
    """
    try:
        # Update progress
        self.update_state(state='PROGRESS', meta={'progress': 0, 'stage': 'Starting extraction'})
        BackgroundService.update_task_status(
            self.request.id, 'running', progress=0, stage='Starting extraction'
        )
        
        # Get file from database
        file_obj = AnalysisFile.query.get(file_id)
        if not file_obj:
            raise ValueError(f"File {file_id} not found")
        
        # Update file status
        file_obj.status = FileStatus.PROCESSING
        db.session.commit()
        
        # Log extraction start
        logger.info(f"Starting extraction from file {file_id} using {extraction_method}")
        
        # Update progress
        self.update_state(state='PROGRESS', meta={'progress': 10, 'stage': 'Preparing extraction'})
        BackgroundService.update_task_status(
            self.request.id, 'running', progress=10, stage='Preparing extraction'
        )
        
        # Get extractor
        extractor = get_extractor(extraction_method)
        if not extractor:
            raise ValueError(f"Unknown extraction method: {extraction_method}")
        
        # Update progress
        self.update_state(state='PROGRESS', meta={'progress': 20, 'stage': 'Running extraction'})
        BackgroundService.update_task_status(
            self.request.id, 'running', progress=20, stage='Running extraction'
        )
        
        # Perform extraction
        result = extractor.extract(file_obj.filepath, parameters or {})
        
        # Update progress
        self.update_state(state='PROGRESS', meta={'progress': 60, 'stage': 'Processing results'})
        BackgroundService.update_task_status(
            self.request.id, 'running', progress=60, stage='Processing results'
        )
        
        if result['success']:
            # Create new file for extracted data
            extracted_file = ExtractionEngine._create_extracted_file(
                file_obj, result, extraction_method, user_id
            )
            
            # Create relationship
            relationship = ExtractionRelationship(
                source_file_id=file_obj.id,
                source_file_sha=file_obj.sha256_hash,
                extracted_file_id=extracted_file.id,
                extracted_file_sha=extracted_file.sha256_hash,
                extraction_method=extraction_method,
                extraction_tool_version=getattr(extractor, 'version', '1.0'),
                extraction_command=result.get('command_line', ''),
                confidence_score=result.get('confidence', 0.5),
                extra_data={
                    'details': result.get('details', ''),
                    'metadata': result.get('metadata', {})
                }
            )
            
            db.session.add(relationship)
            db.session.commit()
            
            # Update progress
            self.update_state(state='PROGRESS', meta={'progress': 90, 'stage': 'Finalizing'})
            BackgroundService.update_task_status(
                self.request.id, 'running', progress=90, stage='Finalizing'
            )
            
            # Log success
            logger.info(f"Extraction successful: {extraction_method} on file {file_id}")
            
            return {
                'success': True,
                'file_id': file_id,
                'extracted_file_id': extracted_file.id,
                'relationship_id': relationship.id,
                'details': result.get('details', ''),
                'extraction_method': extraction_method,
                'data_size': len(result['data']) if result.get('data') else 0
            }
        else:
            # Log failure
            logger.warning(f"Extraction failed: {extraction_method} on file {file_id} - {result.get('error', 'Unknown error')}")
            
            return {
                'success': False,
                'file_id': file_id,
                'error': result.get('error', 'Extraction failed'),
                'details': result.get('details', ''),
                'extraction_method': extraction_method
            }
    
    except Exception as exc:
        # Log error
        logger.error(f"Extraction error: {extraction_method} on file {file_id} - {exc}", exc_info=True)
        
        # Update file status to error
        try:
            file_obj = AnalysisFile.query.get(file_id)
            if file_obj:
                file_obj.status = FileStatus.ERROR
                db.session.commit()
        except:
            pass
        
        # Retry or raise
        self.retry(countdown=60, exc=exc)

@tracked_task(bind=True, max_retries=3)
def extract_all_methods(self, file_id: int, user_id: int = None):
    """
    Extract hidden data from a file using all recommended methods
    
    Args:
        file_id: ID of the file to extract from
        user_id: ID of the user who initiated the extraction
    
    Returns:
        Dict with extraction results
    """
    try:
        # Get file from database
        file_obj = AnalysisFile.query.get(file_id)
        if not file_obj:
            raise ValueError(f"File {file_id} not found")
        
        # Get recommended extractors
        extractors = get_recommended_extractors(file_obj.file_type)
        
        # Update progress
        self.update_state(state='PROGRESS', meta={
            'progress': 0, 
            'stage': f'Starting extraction with {len(extractors)} methods'
        })
        BackgroundService.update_task_status(
            self.request.id, 'running', progress=0, 
            stage=f'Starting extraction with {len(extractors)} methods'
        )
        
        # Run each extractor
        results = []
        for i, extractor_name in enumerate(extractors):
            # Update progress
            progress = int((i / len(extractors)) * 100)
            self.update_state(state='PROGRESS', meta={
                'progress': progress, 
                'stage': f'Running {extractor_name} ({i+1}/{len(extractors)})'
            })
            BackgroundService.update_task_status(
                self.request.id, 'running', progress=progress, 
                stage=f'Running {extractor_name} ({i+1}/{len(extractors)})'
            )
            
            # Run extraction
            try:
                result = extract_from_file(file_id, extractor_name, {}, user_id)
                results.append({
                    'extractor': extractor_name,
                    'success': result.get('success', False),
                    'details': result.get('details', ''),
                    'error': result.get('error', None)
                })
            except Exception as e:
                logger.error(f"Error running {extractor_name} on file {file_id}: {e}")
                results.append({
                    'extractor': extractor_name,
                    'success': False,
                    'error': str(e)
                })
        
        # Update progress
        self.update_state(state='PROGRESS', meta={'progress': 100, 'stage': 'Extraction complete'})
        BackgroundService.update_task_status(
            self.request.id, 'running', progress=100, stage='Extraction complete'
        )
        
        # Count successes
        successful = sum(1 for r in results if r.get('success', False))
        
        return {
            'file_id': file_id,
            'total_extractors': len(extractors),
            'successful_extractions': successful,
            'results': results
        }
    
    except Exception as exc:
        logger.error(f"Error in extract_all_methods for file {file_id}: {exc}", exc_info=True)
        self.retry(countdown=60, exc=exc)

@tracked_task(bind=True, max_retries=3)
def extract_to_production(self, file_id: int, output_dir: str = "production", user_id: int = None):
    """
    Extract hidden data from a file and save to production directory
    
    Args:
        file_id: ID of the file to extract from
        output_dir: Directory to save extracted files
        user_id: ID of the user who initiated the extraction
    
    Returns:
        Dict with extraction results
    """
    try:
        # Get file from database
        file_obj = AnalysisFile.query.get(file_id)
        if not file_obj:
            raise ValueError(f"File {file_id} not found")
        
        # Create output directory
        os.makedirs(output_dir, exist_ok=True)
        
        # Copy the original file to the output directory and mark it as root
        root_file_path = os.path.join(output_dir, os.path.basename(file_obj.filepath))
        shutil.copy2(file_obj.filepath, root_file_path)
        
        # Get recommended extractors
        extractors = ['zsteg', 'binwalk', 'foremost', 'steghide']
        
        # Update progress
        self.update_state(state='PROGRESS', meta={
            'progress': 10, 
            'stage': f'Starting extraction with {len(extractors)} methods'
        })
        BackgroundService.update_task_status(
            self.request.id, 'running', progress=10, 
            stage=f'Starting extraction with {len(extractors)} methods'
        )
        
        # Run each extractor
        results = []
        for i, extractor_name in enumerate(extractors):
            # Update progress
            progress = 10 + int((i / len(extractors)) * 80)
            self.update_state(state='PROGRESS', meta={
                'progress': progress, 
                'stage': f'Running {extractor_name} ({i+1}/{len(extractors)})'
            })
            BackgroundService.update_task_status(
                self.request.id, 'running', progress=progress, 
                stage=f'Running {extractor_name} ({i+1}/{len(extractors)})'
            )
            
            # Create extractor-specific output directory
            extractor_output_dir = os.path.join(output_dir, f"{extractor_name}_extracted")
            os.makedirs(extractor_output_dir, exist_ok=True)
            
            # Get extractor
            extractor = get_extractor(extractor_name)
            if not extractor:
                logger.warning(f"Extractor {extractor_name} not found")
                results.append({
                    'extractor': extractor_name,
                    'success': False,
                    'error': 'Extractor not found'
                })
                continue
            
            # Run extraction with output directory parameter
            try:
                result = extractor.extract(file_obj.filepath, {'output_dir': extractor_output_dir})
                
                # Save extracted data to file if it's not empty
                if result['success'] and result['data']:
                    data_file_path = os.path.join(extractor_output_dir, f"{extractor_name}_data.bin")
                    with open(data_file_path, 'wb') as f:
                        f.write(result['data'])
                    
                    # Process metadata if available
                    if 'metadata' in result and 'extracted_files' in result['metadata']:
                        files = result['metadata']['extracted_files']
                        
                        # Copy extracted files to output directory if they exist
                        for file_info in files:
                            if 'path' in file_info and os.path.exists(file_info['path']):
                                dest_path = os.path.join(extractor_output_dir, os.path.basename(file_info['path']))
                                shutil.copy2(file_info['path'], dest_path)
                
                # Store result in database
                if result['success'] and result['data']:
                    # Create file content record
                    content = FileContent(
                        file_id=file_obj.id,
                        content_type='extracted_data',
                        content_format='binary',
                        extracted_at=datetime.utcnow(),
                        extracted_by=user_id,
                        extraction_method=extractor_name,
                        extraction_extra_data={
                            'output_dir': extractor_output_dir,
                            'details': result.get('details', ''),
                            'command_line': result.get('command_line', '')
                        }
                    )
                    content.set_content(result['data'])
                    db.session.add(content)
                    db.session.commit()
                
                results.append({
                    'extractor': extractor_name,
                    'success': result['success'],
                    'details': result.get('details', ''),
                    'data_size': len(result['data']) if result.get('data') else 0,
                    'output_dir': extractor_output_dir
                })
            except Exception as e:
                logger.error(f"Error running {extractor_name} on file {file_id}: {e}")
                results.append({
                    'extractor': extractor_name,
                    'success': False,
                    'error': str(e)
                })
        
        # Update progress
        self.update_state(state='PROGRESS', meta={'progress': 100, 'stage': 'Extraction complete'})
        BackgroundService.update_task_status(
            self.request.id, 'running', progress=100, stage='Extraction complete'
        )
        
        # Count successes
        successful = sum(1 for r in results if r.get('success', False))
        
        return {
            'file_id': file_id,
            'output_dir': output_dir,
            'total_extractors': len(extractors),
            'successful_extractions': successful,
            'results': results
        }
    
    except Exception as exc:
        logger.error(f"Error in extract_to_production for file {file_id}: {exc}", exc_info=True)
        self.retry(countdown=60, exc=exc)