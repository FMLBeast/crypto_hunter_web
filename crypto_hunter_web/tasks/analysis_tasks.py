"""
Background tasks for file analysis
"""
import logging
import time
from typing import Dict, Any

from celery import shared_task, Task
from celery.utils.log import get_task_logger

from crypto_hunter_web import db
from crypto_hunter_web.models import AnalysisFile, FileStatus
from crypto_hunter_web.services.analysis_service import AnalysisService
from crypto_hunter_web.services.background_service import BackgroundService

logger = get_task_logger(__name__)


class AnalysisTask(Task):
    """Base task class for analysis tasks with progress tracking"""
    
    def on_success(self, retval, task_id, args, kwargs):
        """Handle successful task completion"""
        BackgroundService.update_task_status(
            task_id=task_id,
            status={
                'state': 'SUCCESS',
                'result': retval,
                'progress': 100,
                'meta': {'stage': 'completed'}
            }
        )
        return super().on_success(retval, task_id, args, kwargs)
    
    def on_failure(self, exc, task_id, args, kwargs, einfo):
        """Handle task failure"""
        BackgroundService.update_task_status(
            task_id=task_id,
            status={
                'state': 'FAILURE',
                'error': str(exc),
                'meta': {'stage': 'failed', 'error_details': str(einfo)}
            }
        )
        return super().on_failure(exc, task_id, args, kwargs, einfo)


@shared_task(bind=True, base=AnalysisTask)
def analyze_file_task(self, file_id: int, user_id: int) -> Dict[str, Any]:
    """
    Background task to analyze a file
    
    Args:
        file_id: ID of the file to analyze
        user_id: ID of the user requesting analysis
        
    Returns:
        Dictionary with analysis results
    """
    # Update task status
    self.update_state(
        state='PROGRESS',
        meta={
            'stage': 'initializing',
            'progress': 0,
            'file_id': file_id
        }
    )
    
    # Get file
    file = AnalysisFile.query.get(file_id)
    if not file:
        return {'success': False, 'error': 'File not found'}
    
    try:
        # Update task status
        self.update_state(
            state='PROGRESS',
            meta={
                'stage': 'analyzing_file',
                'progress': 10,
                'file_id': file_id,
                'filename': file.filename
            }
        )
        
        # Perform basic file analysis
        results = AnalysisService._perform_analysis(file, user_id)
        
        # Update task status
        self.update_state(
            state='PROGRESS',
            meta={
                'stage': 'analysis_complete',
                'progress': 100,
                'file_id': file_id,
                'findings_count': len(results.get('findings', []))
            }
        )
        
        return results
    
    except Exception as e:
        logger.error(f"Error in analyze_file_task for file {file_id}: {str(e)}")
        # Update file status to error
        file.status = FileStatus.ERROR
        db.session.commit()
        
        # Re-raise exception to trigger on_failure
        raise


@shared_task(bind=True, base=AnalysisTask)
def analyze_crypto_pattern_task(self, text: str, pattern_type: str = None) -> Dict[str, Any]:
    """
    Background task to analyze text for cryptographic patterns
    
    Args:
        text: Text to analyze
        pattern_type: Specific pattern type to analyze for
        
    Returns:
        Dictionary with analysis results
    """
    # Update task status
    self.update_state(
        state='PROGRESS',
        meta={
            'stage': 'initializing',
            'progress': 0,
            'text_length': len(text),
            'pattern_type': pattern_type
        }
    )
    
    try:
        # Update task status
        self.update_state(
            state='PROGRESS',
            meta={
                'stage': 'analyzing_patterns',
                'progress': 50,
                'text_length': len(text),
                'pattern_type': pattern_type
            }
        )
        
        # Perform crypto pattern analysis
        results = AnalysisService.analyze_crypto_pattern(text, pattern_type)
        
        # Update task status
        self.update_state(
            state='PROGRESS',
            meta={
                'stage': 'analysis_complete',
                'progress': 100,
                'patterns_found': len(results.get('patterns', []))
            }
        )
        
        return results
    
    except Exception as e:
        logger.error(f"Error in analyze_crypto_pattern_task: {str(e)}")
        # Re-raise exception to trigger on_failure
        raise


@shared_task(bind=True, base=AnalysisTask)
def tag_region_task(self, file_content_id: int, start_offset: int, end_offset: int, 
                   title: str, description: str = None, region_type: str = 'text',
                   user_id: int = None, color: str = '#yellow', 
                   highlight_style: str = 'background') -> Dict[str, Any]:
    """
    Background task to tag a region of interest
    
    Args:
        file_content_id: ID of the file content
        start_offset: Start offset of the region
        end_offset: End offset of the region
        title: Title of the region
        description: Description of the region
        region_type: Type of the region (text, crypto, binary, etc.)
        user_id: ID of the user creating the region
        color: Color for highlighting the region
        highlight_style: Style for highlighting the region
        
    Returns:
        Dictionary with region information
    """
    # Update task status
    self.update_state(
        state='PROGRESS',
        meta={
            'stage': 'creating_region',
            'progress': 50,
            'file_content_id': file_content_id,
            'title': title
        }
    )
    
    try:
        # Create region of interest
        region = AnalysisService.tag_region_of_interest(
            file_content_id=file_content_id,
            start_offset=start_offset,
            end_offset=end_offset,
            title=title,
            description=description,
            region_type=region_type,
            user_id=user_id,
            color=color,
            highlight_style=highlight_style
        )
        
        if not region:
            return {'success': False, 'error': 'Failed to create region'}
        
        # Update task status
        self.update_state(
            state='PROGRESS',
            meta={
                'stage': 'region_created',
                'progress': 100,
                'region_id': region.id,
                'title': region.title
            }
        )
        
        return {
            'success': True,
            'region_id': region.id,
            'title': region.title,
            'description': region.description,
            'start_offset': region.start_offset,
            'end_offset': region.end_offset,
            'region_type': region.region_type,
            'color': region.color,
            'highlight_style': region.highlight_style
        }
    
    except Exception as e:
        logger.error(f"Error in tag_region_task: {str(e)}")
        # Re-raise exception to trigger on_failure
        raise


@shared_task(bind=True, base=AnalysisTask)
def batch_analyze_files_task(self, file_ids: list, user_id: int) -> Dict[str, Any]:
    """
    Background task to analyze multiple files in batch
    
    Args:
        file_ids: List of file IDs to analyze
        user_id: ID of the user requesting analysis
        
    Returns:
        Dictionary with batch analysis results
    """
    total_files = len(file_ids)
    results = {
        'success': True,
        'total_files': total_files,
        'completed': 0,
        'failed': 0,
        'file_results': {}
    }
    
    # Update task status
    self.update_state(
        state='PROGRESS',
        meta={
            'stage': 'initializing_batch',
            'progress': 0,
            'total_files': total_files,
            'completed': 0
        }
    )
    
    for i, file_id in enumerate(file_ids):
        try:
            # Update task status
            self.update_state(
                state='PROGRESS',
                meta={
                    'stage': f'analyzing_file_{i+1}_of_{total_files}',
                    'progress': int((i / total_files) * 100),
                    'total_files': total_files,
                    'completed': i,
                    'current_file_id': file_id
                }
            )
            
            # Analyze file
            file_result = AnalysisService.analyze_file(file_id, user_id, async_mode=False)
            
            # Store result
            results['file_results'][file_id] = file_result
            
            if file_result.get('success', False):
                results['completed'] += 1
            else:
                results['failed'] += 1
                
        except Exception as e:
            logger.error(f"Error analyzing file {file_id} in batch: {str(e)}")
            results['failed'] += 1
            results['file_results'][file_id] = {
                'success': False,
                'error': str(e),
                'file_id': file_id
            }
    
    # Update task status
    self.update_state(
        state='PROGRESS',
        meta={
            'stage': 'batch_complete',
            'progress': 100,
            'total_files': total_files,
            'completed': results['completed'],
            'failed': results['failed']
        }
    )
    
    return results