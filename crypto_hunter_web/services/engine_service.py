"""
Engine Service - Defines the engines and their responsibilities for file processing.

This service implements the "engines" approach with clear responsibility separation,
where each engine is responsible for a specific type of processing and tasks are
orchestrated between engines using Celery workers.
"""
import os
import logging
from typing import Dict, List, Any, Optional, Union
from datetime import datetime

from crypto_hunter_web.models import db, AnalysisFile, FileContent, Finding, BulkImport, FileStatus
from crypto_hunter_web.services.celery_app import celery_app
from crypto_hunter_web.services.file_service import FileService
from crypto_hunter_web.services.background_service import BackgroundService
from crypto_hunter_web.services.content_analyzer import ContentAnalyzer
from crypto_hunter_web.services.llm_crypto_orchestrator import LLMCryptoOrchestrator

logger = logging.getLogger(__name__)

class EngineService:
    """
    Service for managing and orchestrating the different processing engines.
    """

    @staticmethod
    def get_engine(engine_type: str) -> 'BaseEngine':
        """
        Factory method to get the appropriate engine based on the engine type.

        Args:
            engine_type: Type of engine to get

        Returns:
            An instance of the appropriate engine
        """
        engines = {
            'upload': UploadEngine(),
            'analysis': AnalysisEngine(),
            'extraction': ExtractionEngine(),
            'llm': LLMEngine(),
            'crypto': CryptoEngine()
        }

        if engine_type not in engines:
            raise ValueError(f"Unknown engine type: {engine_type}")

        return engines[engine_type]

    @staticmethod
    def process_file(file_id: int, engines: List[str] = None, options: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Process a file through multiple engines.

        Args:
            file_id: ID of the file to process
            engines: List of engine types to use for processing
            options: Additional options for processing

        Returns:
            Dictionary containing the results of processing
        """
        if engines is None:
            engines = ['analysis']

        if options is None:
            options = {}

        results = {}

        for engine_type in engines:
            engine = EngineService.get_engine(engine_type)
            engine_result = engine.process_file(file_id, options)
            results[engine_type] = engine_result

        return results

    @staticmethod
    def process_directory(directory_path: str, user_id: int, engines: List[str] = None, options: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Process all files in a directory through multiple engines.

        Args:
            directory_path: Path to the directory to process
            user_id: ID of the user initiating the processing
            engines: List of engine types to use for processing
            options: Additional options for processing

        Returns:
            Dictionary containing the results of processing
        """
        if engines is None:
            engines = ['upload', 'analysis']

        if options is None:
            options = {}

        # Create a bulk import record
        bulk_import = BulkImport(
            import_type='directory',
            status='processing',
            source_file=directory_path,
            created_by=user_id,
            created_at=datetime.utcnow(),
            updated_at=datetime.utcnow()
        )
        db.session.add(bulk_import)
        db.session.commit()

        # Get the upload engine to handle file discovery and initial processing
        upload_engine = EngineService.get_engine('upload')
        upload_result = upload_engine.process_directory(directory_path, user_id, bulk_import.id, options)

        # Process each file through the specified engines
        for file_id in upload_result.get('file_ids', []):
            EngineService.process_file(file_id, engines, options)

        # Update the bulk import record
        bulk_import.status = 'completed'
        bulk_import.completed_at = datetime.utcnow()
        bulk_import.total_items = len(upload_result.get('file_ids', []))
        bulk_import.processed_items = len(upload_result.get('file_ids', []))
        bulk_import.successful_items = len(upload_result.get('file_ids', []))
        db.session.commit()

        return {
            'bulk_import_id': bulk_import.id,
            'total_files': len(upload_result.get('file_ids', [])),
            'engines_used': engines,
            'status': 'completed'
        }

    @staticmethod
    def process_bulk_import(bulk_import_id: int, csv_content: str, engines: List[str] = None, options: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Process a bulk import through multiple engines.

        Args:
            bulk_import_id: ID of the bulk import to process
            csv_content: Content of the CSV file
            engines: List of engine types to use for processing
            options: Additional options for processing

        Returns:
            Dictionary containing the results of processing
        """
        if engines is None:
            engines = ['upload', 'analysis']

        if options is None:
            options = {}

        # Get the upload engine to handle file discovery and initial processing
        upload_engine = EngineService.get_engine('upload')
        upload_result = upload_engine.process_bulk_import(bulk_import_id, csv_content, options)

        # Process each file through the specified engines
        for file_id in upload_result.get('file_ids', []):
            EngineService.process_file(file_id, engines, options)

        return {
            'bulk_import_id': bulk_import_id,
            'total_files': len(upload_result.get('file_ids', [])),
            'engines_used': engines,
            'status': 'completed'
        }

    @staticmethod
    def process_api_import(file_path: str, user_id: int, engines: List[str] = None, options: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Process a file uploaded through the API through multiple engines.

        Args:
            file_path: Path to the file to process
            user_id: ID of the user initiating the processing
            engines: List of engine types to use for processing
            options: Additional options for processing

        Returns:
            Dictionary containing the results of processing
        """
        if engines is None:
            engines = ['upload', 'analysis']

        if options is None:
            options = {}

        # Get the upload engine to handle file discovery and initial processing
        upload_engine = EngineService.get_engine('upload')
        upload_result = upload_engine.process_file_path(file_path, user_id, options)

        # Process the file through the specified engines
        file_id = upload_result.get('file_id')
        if file_id:
            EngineService.process_file(file_id, engines, options)

        return {
            'file_id': file_id,
            'engines_used': engines,
            'status': 'completed'
        }

    @staticmethod
    def process_extracted_file(parent_file_id: int, extracted_file_path: str, engines: List[str] = None, options: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Process a file extracted from another file through multiple engines.

        Args:
            parent_file_id: ID of the parent file
            extracted_file_path: Path to the extracted file
            engines: List of engine types to use for processing
            options: Additional options for processing

        Returns:
            Dictionary containing the results of processing
        """
        if engines is None:
            engines = ['upload', 'analysis']

        if options is None:
            options = {}

        # Get the parent file to determine the user ID
        parent_file = AnalysisFile.query.get(parent_file_id)
        if not parent_file:
            raise ValueError(f"Parent file not found: {parent_file_id}")

        user_id = parent_file.created_by

        # Get the upload engine to handle file discovery and initial processing
        upload_engine = EngineService.get_engine('upload')
        upload_result = upload_engine.process_extracted_file(parent_file_id, extracted_file_path, user_id, options)

        # Process the file through the specified engines
        file_id = upload_result.get('file_id')
        if file_id:
            EngineService.process_file(file_id, engines, options)

        return {
            'file_id': file_id,
            'parent_file_id': parent_file_id,
            'engines_used': engines,
            'status': 'completed'
        }


class BaseEngine:
    """
    Base class for all engines.
    """

    def process_file(self, file_id: int, options: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Process a file.

        Args:
            file_id: ID of the file to process
            options: Additional options for processing

        Returns:
            Dictionary containing the results of processing
        """
        raise NotImplementedError("Subclasses must implement this method")


class UploadEngine(BaseEngine):
    """
    Engine for handling file uploads and initial processing.
    """

    def process_file(self, file_id: int, options: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Process a file that has already been uploaded.

        Args:
            file_id: ID of the file to process
            options: Additional options for processing

        Returns:
            Dictionary containing the results of processing
        """
        if options is None:
            options = {}

        file_obj = AnalysisFile.query.get(file_id)
        if not file_obj:
            raise ValueError(f"File not found: {file_id}")

        # Update file status
        file_obj.status = FileStatus.UPLOADED
        db.session.commit()

        return {
            'file_id': file_id,
            'status': 'uploaded',
            'filename': file_obj.filename,
            'file_size': file_obj.file_size,
            'file_type': file_obj.file_type
        }

    def process_file_path(self, file_path: str, user_id: int, options: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Process a file from a file path.

        Args:
            file_path: Path to the file to process
            user_id: ID of the user initiating the processing
            options: Additional options for processing

        Returns:
            Dictionary containing the results of processing
        """
        if options is None:
            options = {}

        # Create a FileStorage object from the file path
        from werkzeug.datastructures import FileStorage
        import io
        import mimetypes

        with open(file_path, 'rb') as f:
            file_content = f.read()

        file_name = os.path.basename(file_path)
        file_storage = FileStorage(
            stream=io.BytesIO(file_content),
            filename=file_name,
            content_type=mimetypes.guess_type(file_name)[0]
        )

        # Process the upload
        result = FileService.process_upload(
            file=file_storage,
            user_id=user_id,
            priority=options.get('priority', 5),
            is_root_file=options.get('is_root_file', True),
            notes=options.get('notes', ''),
            tags=options.get('tags', [])
        )

        if not result['success']:
            raise ValueError(result['error'])

        return {
            'file_id': result['file'].id,
            'status': 'uploaded',
            'filename': result['file'].filename,
            'file_size': result['file'].file_size,
            'file_type': result['file'].file_type
        }

    def process_directory(self, directory_path: str, user_id: int, bulk_import_id: int, options: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Process all files in a directory.

        Args:
            directory_path: Path to the directory to process
            user_id: ID of the user initiating the processing
            bulk_import_id: ID of the bulk import record
            options: Additional options for processing

        Returns:
            Dictionary containing the results of processing
        """
        if options is None:
            options = {}

        # Get all valid files in the directory
        from pathlib import Path

        recursive = options.get('recursive', True)

        if recursive:
            file_generator = Path(directory_path).rglob('*')
        else:
            file_generator = Path(directory_path).iterdir()

        file_ids = []

        for file_path in file_generator:
            if file_path.is_file() and os.access(file_path, os.R_OK):
                try:
                    result = self.process_file_path(str(file_path), user_id, options)
                    file_ids.append(result['file_id'])
                except Exception as e:
                    logger.error(f"Error processing file {file_path}: {e}")

        return {
            'file_ids': file_ids,
            'total_files': len(file_ids),
            'directory_path': directory_path,
            'bulk_import_id': bulk_import_id
        }

    def process_bulk_import(self, bulk_import_id: int, csv_content: str, options: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Process a bulk import from a CSV file.

        Args:
            bulk_import_id: ID of the bulk import record
            csv_content: Content of the CSV file
            options: Additional options for processing

        Returns:
            Dictionary containing the results of processing
        """
        if options is None:
            options = {}

        # Get the bulk import record
        bulk_import = BulkImport.query.get(bulk_import_id)
        if not bulk_import:
            raise ValueError(f"Bulk import not found: {bulk_import_id}")

        # Parse the CSV content
        import csv
        import io

        csv_reader = csv.reader(io.StringIO(csv_content))

        # Skip header row
        next(csv_reader, None)

        file_ids = []

        for row in csv_reader:
            if len(row) < 1:
                continue

            file_path = row[0]

            # Skip if file path is empty
            if not file_path:
                continue

            # Validate file path
            if not os.path.exists(file_path):
                logger.warning(f"File not found: {file_path}")
                continue

            try:
                result = self.process_file_path(file_path, bulk_import.created_by, options)
                file_ids.append(result['file_id'])
            except Exception as e:
                logger.error(f"Error processing file {file_path}: {e}")

        # Update the bulk import record
        bulk_import.total_items = len(file_ids)
        bulk_import.processed_items = len(file_ids)
        bulk_import.successful_items = len(file_ids)
        bulk_import.status = 'completed'
        bulk_import.completed_at = datetime.utcnow()
        db.session.commit()

        return {
            'file_ids': file_ids,
            'total_files': len(file_ids),
            'bulk_import_id': bulk_import_id
        }

    def process_extracted_file(self, parent_file_id: int, extracted_file_path: str, user_id: int, options: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Process a file extracted from another file.

        Args:
            parent_file_id: ID of the parent file
            extracted_file_path: Path to the extracted file
            user_id: ID of the user initiating the processing
            options: Additional options for processing

        Returns:
            Dictionary containing the results of processing
        """
        if options is None:
            options = {}

        # Process the file
        result = self.process_file_path(extracted_file_path, user_id, options)

        # Create a relationship between the parent file and the extracted file
        from crypto_hunter_web.models import ExtractionRelationship

        relationship = ExtractionRelationship(
            parent_file_id=parent_file_id,
            child_file_id=result['file_id'],
            extraction_method=options.get('extraction_method', 'automated'),
            extraction_time=datetime.utcnow()
        )
        db.session.add(relationship)
        db.session.commit()

        return {
            'file_id': result['file_id'],
            'parent_file_id': parent_file_id,
            'status': 'uploaded',
            'filename': result['filename'],
            'file_size': result['file_size'],
            'file_type': result['file_type']
        }


class AnalysisEngine(BaseEngine):
    """
    Engine for analyzing files.
    """

    def process_file(self, file_id: int, options: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Analyze a file.

        Args:
            file_id: ID of the file to analyze
            options: Additional options for analysis

        Returns:
            Dictionary containing the results of analysis
        """
        if options is None:
            options = {}

        file_obj = AnalysisFile.query.get(file_id)
        if not file_obj:
            raise ValueError(f"File not found: {file_id}")

        # Determine analysis types
        analysis_types = options.get('analysis_types', ['basic', 'strings', 'crypto', 'metadata', 'hex'])

        # Create a ContentAnalyzer instance
        analyzer = ContentAnalyzer()

        # Analyze the file
        analysis_results = analyzer.analyze_file_comprehensive(file_obj, analysis_types)

        # Update file status
        file_obj.status = FileStatus.ANALYZED
        file_obj.analyzed_at = datetime.utcnow()
        db.session.commit()

        return {
            'file_id': file_id,
            'status': FileStatus.ANALYZED,
            'analysis_types': analysis_types,
            'analysis_results': analysis_results
        }


class ExtractionEngine(BaseEngine):
    """
    Engine for extracting files from other files.
    """

    def process_file(self, file_id: int, options: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Extract files from a file.

        Args:
            file_id: ID of the file to extract from
            options: Additional options for extraction

        Returns:
            Dictionary containing the results of extraction
        """
        if options is None:
            options = {}

        file_obj = AnalysisFile.query.get(file_id)
        if not file_obj:
            raise ValueError(f"File not found: {file_id}")

        # Create a temporary directory for extraction
        import tempfile
        import shutil

        temp_dir = tempfile.mkdtemp()

        try:
            # Determine extraction methods
            extraction_methods = options.get('extraction_methods', ['binwalk', 'strings', 'exotic'])

            # Extract files using recursive_extract.py script
            from crypto_hunter_web.scripts.recursive_extract import process_file as extract_files

            # Process the file
            extract_files(file_obj.filepath, temp_dir, 0)

            # Get all extracted files
            extracted_files = []
            for root, _, files in os.walk(temp_dir):
                for file in files:
                    extracted_file_path = os.path.join(root, file)

                    # Queue the extracted file for processing using a Celery task
                    from crypto_hunter_web.tasks.engine_tasks import process_extracted_file

                    # Queue the task
                    task = process_extracted_file.delay(
                        file_id,
                        extracted_file_path,
                        ['upload', 'analysis'],  # Default engines for extracted files
                        {'extraction_method': 'automated'}
                    )

                    logger.info(f"Queued extracted file {extracted_file_path} for processing with task ID {task.id}")

                    # We don't have the file ID yet since it's processed asynchronously,
                    # but we'll track the task ID instead
                    extracted_files.append({
                        'path': extracted_file_path,
                        'task_id': task.id
                    })

            return {
                'file_id': file_id,
                'status': 'extracted',
                'extracted_files': extracted_files,
                'total_extracted': len(extracted_files)
            }

        finally:
            # Clean up temporary directory
            shutil.rmtree(temp_dir)


class LLMEngine(BaseEngine):
    """
    Engine for LLM-based analysis.
    """

    def process_file(self, file_id: int, options: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Analyze a file using LLM.

        Args:
            file_id: ID of the file to analyze
            options: Additional options for analysis

        Returns:
            Dictionary containing the results of analysis
        """
        if options is None:
            options = {}

        file_obj = AnalysisFile.query.get(file_id)
        if not file_obj:
            raise ValueError(f"File not found: {file_id}")

        # Get content preview
        content = FileContent.query.filter_by(file_id=file_id).first()
        content_preview = ""
        if content:
            try:
                content_preview = content.content_text[:1000] if content.content_text else ""
            except:
                pass

        # Get existing analysis
        existing_analysis = {}
        if content:
            try:
                import json
                existing_analysis = json.loads(content.content_json or '{}')
            except:
                pass

        # Create an LLMCryptoOrchestrator instance
        orchestrator = LLMCryptoOrchestrator()

        # Analyze the file with LLM
        llm_results = orchestrator.analyze_file_with_llm(file_id, content_preview, existing_analysis)

        return {
            'file_id': file_id,
            'status': 'llm_analyzed',
            'llm_results': llm_results
        }


class CryptoEngine(BaseEngine):
    """
    Engine for crypto-specific analysis.
    """

    def process_file(self, file_id: int, options: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Analyze a file for crypto-specific patterns.

        Args:
            file_id: ID of the file to analyze
            options: Additional options for analysis

        Returns:
            Dictionary containing the results of analysis
        """
        if options is None:
            options = {}

        file_obj = AnalysisFile.query.get(file_id)
        if not file_obj:
            raise ValueError(f"File not found: {file_id}")

        # Create a ContentAnalyzer instance
        analyzer = ContentAnalyzer()

        # Analyze the file for crypto patterns
        crypto_results = analyzer._analyze_crypto_patterns(file_obj)

        # Create findings for significant crypto discoveries
        analyzer._create_crypto_findings(file_obj, crypto_results)

        return {
            'file_id': file_id,
            'status': 'crypto_analyzed',
            'crypto_results': crypto_results
        }
