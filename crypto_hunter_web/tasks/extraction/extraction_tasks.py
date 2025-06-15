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
def extract_from_file(self, file_id: int, extraction_method: str, parameters: Dict = None, user_id: int = None, use_llm: bool = None):
    """
    Extract hidden data from a file using specified method

    Args:
        file_id: ID of the file to extract from
        extraction_method: Name of the extraction method to use
        parameters: Parameters for the extraction method
        user_id: ID of the user who initiated the extraction
        use_llm: Whether to use LLM orchestration (None = use default setting)

    Returns:
        Dict with extraction results
    """
    # Store original LLM setting if we're going to change it
    old_env = None
    if use_llm is not None:
        old_env = os.environ.get('USE_LLM_ORCHESTRATOR')
        os.environ['USE_LLM_ORCHESTRATOR'] = 'true' if use_llm else 'false'

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

        # Update progress
        self.update_state(state='PROGRESS', meta={'progress': 20, 'stage': 'Running extraction'})
        BackgroundService.update_task_status(
            self.request.id, 'running', progress=20, stage='Running extraction'
        )

        # Use ExtractionEngine to perform extraction (supports LLM orchestration)
        extraction_result = ExtractionEngine.extract_from_file(file_obj, extraction_method, parameters, user_id)

        # Update progress
        self.update_state(state='PROGRESS', meta={'progress': 60, 'stage': 'Processing results'})
        BackgroundService.update_task_status(
            self.request.id, 'running', progress=60, stage='Processing results'
        )

        # Check if this is an async LLM task
        if extraction_result.get('is_async', False):
            # This is an LLM-orchestrated task, return task information
            return {
                'success': True,
                'file_id': file_id,
                'is_llm_task': True,
                'llm_task_id': extraction_result.get('task_id'),
                'message': extraction_result.get('message', 'LLM extraction queued'),
                'details': extraction_result.get('details', ''),
                'extraction_method': extraction_method
            }

        # Process regular extraction result
        if extraction_result.get('success', False):
            # Get extracted file and relationship from result
            extracted_file = extraction_result.get('extracted_file')
            relationship = extraction_result.get('relationship')

            if not extracted_file or not relationship:
                raise ValueError("Extraction succeeded but no file or relationship was created")

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
                'details': extraction_result.get('details', ''),
                'extraction_method': extraction_method
            }
        else:
            # Log failure
            logger.warning(f"Extraction failed: {extraction_method} on file {file_id} - {extraction_result.get('error', 'Unknown error')}")

            return {
                'success': False,
                'file_id': file_id,
                'error': extraction_result.get('error', 'Extraction failed'),
                'details': extraction_result.get('details', ''),
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
def extract_all_methods(self, file_id: int, user_id: int = None, use_llm: bool = None):
    """
    Extract hidden data from a file using all recommended methods

    Args:
        file_id: ID of the file to extract from
        user_id: ID of the user who initiated the extraction
        use_llm: Whether to use LLM orchestration (None = use default setting)

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
                result = extract_from_file(file_id, extractor_name, {}, user_id, use_llm)
                results.append({
                    'extractor': extractor_name,
                    'success': result.get('success', False),
                    'details': result.get('details', ''),
                    'error': result.get('error', None),
                    'is_llm_task': result.get('is_llm_task', False),
                    'llm_task_id': result.get('llm_task_id', None)
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
def extract_to_production(self, file_id: int, output_dir: str = "production", user_id: int = None, use_llm: bool = None):
    """
    Extract hidden data from a file and save to production directory

    Args:
        file_id: ID of the file to extract from
        output_dir: Directory to save extracted files
        user_id: ID of the user who initiated the extraction
        use_llm: Whether to use LLM orchestration (None = use default setting)

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

            # Run extraction using extract_from_file which supports LLM orchestration
            try:
                # Prepare parameters for extraction
                parameters = {
                    'output_dir': extractor_output_dir,
                    'save_to_disk': True
                }

                # Call extract_from_file which handles LLM orchestration if enabled
                result = extract_from_file(file_id, extractor_name, parameters, user_id, use_llm)

                # Check if this is an LLM task
                if result.get('is_llm_task', False):
                    logger.info(f"LLM-orchestrated extraction queued for {extractor_name}: {result.get('llm_task_id')}")

                    # Add LLM task info to results
                    results.append({
                        'extractor': extractor_name,
                        'success': True,
                        'is_llm_task': True,
                        'llm_task_id': result.get('llm_task_id'),
                        'message': result.get('message', 'LLM extraction queued'),
                        'output_dir': extractor_output_dir
                    })
                    continue

                # For non-LLM extractions, process the result as before
                if result.get('success', False):
                    extracted_file = result.get('extracted_file')
                    relationship = result.get('relationship')

                    # Copy the extracted file to the output directory if it exists
                    if extracted_file and os.path.exists(extracted_file.filepath):
                        dest_path = os.path.join(extractor_output_dir, os.path.basename(extracted_file.filepath))
                        shutil.copy2(extracted_file.filepath, dest_path)

                    results.append({
                        'extractor': extractor_name,
                        'success': True,
                        'details': result.get('details', ''),
                        'extracted_file_id': extracted_file.id if extracted_file else None,
                        'output_dir': extractor_output_dir
                    })
                else:
                    # Fallback to direct extraction if extract_from_file failed
                    logger.warning(f"Falling back to direct extraction for {extractor_name}")
                    direct_result = extractor.extract(file_obj.filepath, {'output_dir': extractor_output_dir})

                    # Save extracted data to file if it's not empty
                    if direct_result['success'] and direct_result['data']:
                        data_file_path = os.path.join(extractor_output_dir, f"{extractor_name}_data.bin")
                        with open(data_file_path, 'wb') as f:
                            f.write(direct_result['data'])

                        # Store result in database
                        content = FileContent(
                            file_id=file_obj.id,
                            content_type='extracted_data',
                            content_format='binary',
                            extracted_at=datetime.utcnow(),
                            extracted_by=user_id,
                            extraction_method=extractor_name,
                            extraction_extra_data={
                                'output_dir': extractor_output_dir,
                                'details': direct_result.get('details', ''),
                                'command_line': direct_result.get('command_line', '')
                            }
                        )
                        content.set_content(direct_result['data'])
                        db.session.add(content)
                        db.session.commit()

                        results.append({
                            'extractor': extractor_name,
                            'success': True,
                            'details': direct_result.get('details', ''),
                            'data_size': len(direct_result['data']),
                            'output_dir': extractor_output_dir,
                            'fallback': True
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
