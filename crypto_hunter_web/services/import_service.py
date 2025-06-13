"""
Comprehensive bulk import service with crypto intelligence integration
"""

import csv
import hashlib
import logging
import mimetypes
import os
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any

import chardet

from crypto_hunter_web.models import db, AnalysisFile, BulkImport
from crypto_hunter_web.services.auth_service import AuthService
from crypto_hunter_web.services.file_analyzer import FileAnalyzer

logger = logging.getLogger(__name__)


class ImportService:
    """Comprehensive bulk import with crypto intelligence and background processing"""

    # Configuration constants
    MAX_FILE_SIZE_ANALYSIS = 50 * 1024 * 1024  # 50MB
    MAX_FILE_SIZE_DIRECTORY_SCAN = 20 * 1024 * 1024  # 20MB
    BATCH_SIZE = 500  # Optimized for memory management
    MAX_ERROR_LOG_SIZE = 50000
    SUPPORTED_ENCODINGS = ['utf-8', 'utf-8-sig', 'latin1', 'cp1252', 'iso-8859-1']

    @staticmethod
    def import_from_csv(csv_path: str, user_id: int) -> BulkImport:
        """Import files from CSV with comprehensive error handling and crypto analysis"""
        bulk_import = BulkImport(
            filename=os.path.basename(csv_path),
            imported_by=user_id,
            status='processing',
            started_at=datetime.utcnow()
        )
        db.session.add(bulk_import)
        db.session.commit()

        try:
            # Validate CSV file
            if not os.path.exists(csv_path):
                raise FileNotFoundError(f"CSV file not found: {csv_path}")

            if not os.access(csv_path, os.R_OK):
                raise PermissionError(f"Cannot read CSV file: {csv_path}")

            # Analyze CSV structure with advanced encoding detection
            csv_info = ImportService._analyze_csv_structure(csv_path)
            bulk_import.total_files = csv_info['row_count']
            db.session.commit()

            logger.info(f"Starting import of {csv_info['row_count']} rows from {csv_path}")

            # Process CSV in batches with crypto intelligence
            processed_count = ImportService._process_csv_batches(
                csv_path, csv_info, bulk_import, user_id
            )

            # Finalize import and start background processing
            bulk_import.status = 'completed'
            bulk_import.completed_at = datetime.utcnow()
            bulk_import.processed_files = processed_count
            db.session.commit()

            # Start background crypto analysis for imported files
            ImportService.finalize_import_with_background_processing(bulk_import)

            logger.info(f"Import completed: {bulk_import.successful_imports} imported, "
                        f"{bulk_import.duplicates_found} duplicates, {bulk_import.errors_count} errors")

            AuthService.log_action(
                'bulk_import_completed',
                f'Imported {bulk_import.successful_imports} files from {bulk_import.filename}',
                user_id
            )

            return bulk_import

        except Exception as e:
            bulk_import.status = 'failed'
            bulk_import.error_log = f"Critical error: {str(e)}"
            bulk_import.completed_at = datetime.utcnow()

            with ImportService._db_transaction():
                db.session.add(bulk_import)

            logger.error(f"Import failed: {e}")
            raise

    @staticmethod
    def scan_directory(directory_path: str, user_id: int, recursive: bool = True) -> BulkImport:
        """Directory scanning with engines approach and background processing"""
        # Create a bulk import record
        bulk_import = BulkImport(
            filename=f"Directory: {os.path.basename(directory_path)}",
            imported_by=user_id,
            status='queued',
            started_at=datetime.utcnow()
        )
        db.session.add(bulk_import)
        db.session.commit()

        try:
            if not os.path.exists(directory_path):
                raise FileNotFoundError(f"Directory not found: {directory_path}")

            if not os.access(directory_path, os.R_OK):
                raise PermissionError(f"Cannot read directory: {directory_path}")

            # Prepare options
            options = {
                'recursive': recursive,
                'priority': 5,  # Default priority
                'auto_analyze': True
            }

            # Queue the directory processing task using the engine approach
            from crypto_hunter_web.tasks.engine_tasks import process_directory
            task = process_directory.delay(
                directory_path,
                user_id,
                ['upload', 'analysis', 'extraction', 'crypto'],  # Default engines for directory scan
                options
            )

            # Update bulk import with task ID
            bulk_import.task_id = task.id
            bulk_import.status = 'processing'
            db.session.commit()

            # Log action
            AuthService.log_action(
                'directory_scan_queued',
                f'Queued directory scan for {directory_path}',
                user_id
            )

            logger.info(f"Directory scan queued for {directory_path} with task ID {task.id}")

            return bulk_import

        except Exception as e:
            bulk_import.status = 'failed'
            bulk_import.error_log = f"Directory scan failed: {str(e)}"
            bulk_import.completed_at = datetime.utcnow()
            db.session.commit()

            logger.error(f"Directory scan failed: {e}")
            raise

    @staticmethod
    def _analyze_csv_structure(csv_path: str) -> Dict[str, Any]:
        """Advanced CSV analysis with encoding detection"""
        csv_info = {
            'encoding': 'utf-8',
            'delimiter': ',',
            'row_count': 0,
            'columns': [],
            'sample_data': []
        }

        # Auto-detect encoding using chardet
        with open(csv_path, 'rb') as f:
            raw_data = f.read(10000)
            detected = chardet.detect(raw_data)
            if detected['confidence'] > 0.7:
                csv_info['encoding'] = detected['encoding']

        # Try detected encoding first, then fallbacks
        encodings_to_try = [csv_info['encoding']] + [
            enc for enc in ImportService.SUPPORTED_ENCODINGS
            if enc != csv_info['encoding']
        ]

        for encoding in encodings_to_try:
            try:
                with open(csv_path, 'r', encoding=encoding, errors='ignore') as f:
                    # Detect delimiter
                    sample = f.read(8192)
                    f.seek(0)

                    sniffer = csv.Sniffer()
                    try:
                        dialect = sniffer.sniff(sample, delimiters=',;\t|')
                        csv_info['delimiter'] = dialect.delimiter
                    except csv.Error:
                        csv_info['delimiter'] = ','

                    # Get column info and count rows
                    reader = csv.DictReader(f, delimiter=csv_info['delimiter'])
                    csv_info['columns'] = reader.fieldnames or []

                    # Count rows and get sample data
                    row_count = 0
                    sample_data = []

                    for row in reader:
                        row_count += 1
                        if len(sample_data) < 5:
                            sample_data.append(dict(row))

                    csv_info['row_count'] = row_count
                    csv_info['sample_data'] = sample_data
                    csv_info['encoding'] = encoding

                    logger.info(f"CSV analysis complete: {row_count} rows, encoding: {encoding}, "
                                f"delimiter: '{csv_info['delimiter']}', columns: {len(csv_info['columns'])}")

                    return csv_info

            except (UnicodeError, UnicodeDecodeError):
                continue
            except Exception as e:
                logger.warning(f"Error analyzing CSV with encoding {encoding}: {e}")
                continue

        raise ValueError(f"Could not parse CSV file {csv_path} with any supported encoding")

    @staticmethod
    def _process_csv_batches(csv_path: str, csv_info: Dict, bulk_import: BulkImport, user_id: int) -> int:
        """Process CSV file in batches with crypto intelligence"""
        processed_count = 0

        try:
            with open(csv_path, 'r', encoding=csv_info['encoding'], errors='ignore') as f:
                reader = csv.DictReader(f, delimiter=csv_info['delimiter'])

                batch = []

                for row_num, row in enumerate(reader, 1):
                    try:
                        # Validate row has required data
                        if not ImportService._validate_csv_row(row):
                            ImportService._log_detailed_error(
                                bulk_import, f"Row {row_num}: Missing required fields"
                            )
                            continue

                        # Prepare file data from CSV row
                        file_data = ImportService._prepare_csv_row_data(row)
                        if file_data:
                            batch.append(file_data)

                        # Process batch when full
                        if len(batch) >= ImportService.BATCH_SIZE:
                            processed_batch = ImportService._process_file_batch(
                                batch, bulk_import, user_id
                            )
                            processed_count += len(batch)
                            bulk_import.processed_files = processed_count

                            with ImportService._db_transaction():
                                pass  # Commit batch

                            logger.info(f"Processed batch: {processed_count}/{bulk_import.total_files} files")
                            batch = []

                    except Exception as e:
                        ImportService._log_detailed_error(
                            bulk_import, f"Row {row_num}: {str(e)}"
                        )
                        logger.error(f"Error processing row {row_num}: {e}")

                # Process remaining batch
                if batch:
                    processed_batch = ImportService._process_file_batch(
                        batch, bulk_import, user_id
                    )
                    processed_count += len(batch)
                    bulk_import.processed_files = processed_count

        except Exception as e:
            logger.error(f"Error processing CSV batches: {e}")
            raise

        return processed_count

    @staticmethod
    def _process_file_batch(batch: List[Dict], bulk_import: BulkImport, user_id: int) -> int:
        """Process batch of files with crypto intelligence"""
        successful_imports = 0

        try:
            with ImportService._db_transaction():
                for file_data in batch:
                    try:
                        result = ImportService._import_single_file(file_data, user_id, bulk_import)
                        if result == 'imported':
                            successful_imports += 1
                            bulk_import.successful_imports += 1
                        elif result == 'duplicate':
                            bulk_import.duplicates_found += 1

                    except Exception as e:
                        bulk_import.errors_count += 1
                        ImportService._log_detailed_error(
                            bulk_import, f"File {file_data.get('filename', 'unknown')}: {str(e)}"
                        )
                        logger.error(f"Error importing file {file_data.get('filename', 'unknown')}: {e}")

        except Exception as e:
            logger.error(f"Batch processing failed: {e}")

        return successful_imports

    @staticmethod
    def _import_single_file(file_data: Dict, user_id: int, bulk_import: BulkImport) -> str:
        """Import single file with crypto intelligence and background analysis queue"""

        # Check for duplicates
        existing_file = AnalysisFile.query.filter_by(
            sha256_hash=file_data['sha256_hash']
        ).first()

        if existing_file:
            return 'duplicate'

        # Validate file data
        if not ImportService._validate_file_data(file_data):
            raise ValueError("Invalid file data")

        # Calculate priority with crypto intelligence
        priority = ImportService._calculate_file_priority(file_data)

        # Create AnalysisFile record
        analysis_file = AnalysisFile(
            sha256_hash=file_data['sha256_hash'],
            filename=file_data['filename'],
            filepath=file_data.get('filepath'),
            file_type=file_data['file_type'],
            file_size=file_data['file_size'],
            extraction_method=file_data.get('extraction_method', 'bulk_import'),
            discovered_by=user_id,
            is_root_file=file_data.get('is_root_file', False),
            status='pending_analysis',
            priority=priority,
            node_color=ImportService._get_file_type_color(file_data['file_type']),
            depth_level=0
        )

        db.session.add(analysis_file)
        db.session.flush()  # Get the ID

        # Queue immediate analysis for high-priority crypto files
        if priority > 7 and file_data.get('filepath') and os.path.exists(file_data['filepath']):
            try:
                ImportService._queue_immediate_analysis(analysis_file.id, file_data)
            except Exception as e:
                logger.warning(f"Failed to queue immediate analysis for {file_data['filename']}: {e}")

        # Perform basic content analysis for suitable files
        if (file_data.get('filepath') and
                os.path.exists(file_data['filepath']) and
                file_data['file_size'] < ImportService.MAX_FILE_SIZE_ANALYSIS):

            try:
                analysis_success = FileAnalyzer.analyze_file_content(file_data['filepath'], analysis_file.id)

                if analysis_success:
                    analysis_file.status = 'basic_analysis_complete'
                    # Queue for comprehensive background analysis
                    ImportService._queue_background_analysis(analysis_file.id, priority)
                else:
                    analysis_file.status = 'analysis_partial'

            except Exception as e:
                logger.warning(f"Content analysis failed for {file_data['filename']}: {e}")
                analysis_file.status = 'analysis_failed'

        return 'imported'

    @staticmethod
    def _calculate_file_priority(file_data: Dict) -> int:
        """Calculate file analysis priority with crypto intelligence"""
        priority = 5  # Base priority

        filename = file_data.get('filename', '').lower()
        file_type = file_data.get('file_type', '').lower()
        file_size = file_data.get('file_size', 0)

        # High priority crypto indicators
        crypto_keywords = [
            'wallet', 'private', 'key', 'bitcoin', 'ethereum', 'crypto',
            'seed', 'mnemonic', 'keystore', 'utc', 'password', 'secret',
            'pgp', 'gpg', 'ssh', 'cert', 'pem', 'p12', 'pfx'
        ]

        # Filename analysis for crypto indicators
        for keyword in crypto_keywords:
            if keyword in filename:
                priority += 2
                break

        # High-priority file extensions for crypto
        high_priority_extensions = [
            '.json', '.key', '.pem', '.p12', '.pfx', '.wallet', '.dat',
            '.txt', '.csv', '.log', '.conf', '.config', '.asc', '.gpg'
        ]

        for ext in high_priority_extensions:
            if filename.endswith(ext):
                priority += 1
                break

        # File type analysis
        if file_type in ['text', 'application']:
            priority += 1

        # Size considerations for crypto files
        if 1000 < file_size < 1024 * 1024:  # 1KB to 1MB (optimal crypto file size)
            priority += 1
        elif file_size > 100 * 1024 * 1024:  # Very large files
            priority -= 2

        return min(max(priority, 1), 10)  # Clamp between 1-10

    @staticmethod
    def _queue_immediate_analysis(file_id: int, file_data: Dict):
        """Queue immediate crypto analysis for high-priority files"""
        try:
            # Import background crypto service
            from crypto_hunter_web.services.background_crypto import BackgroundCryptoService

            # Determine analysis types based on file characteristics
            analysis_types = []
            filename = file_data.get('filename', '').lower()

            # Ethereum analysis for wallet files
            if any(keyword in filename for keyword in ['wallet', 'keystore', 'ethereum', 'eth']):
                analysis_types.append('ethereum_validation')

            # Cipher analysis for text files
            if file_data.get('file_type') == 'text' or filename.endswith(('.txt', '.log', '.conf')):
                analysis_types.append('cipher_analysis')

            # Pattern analysis for all high-priority files
            analysis_types.append('pattern_analysis')

            # Queue priority analysis
            task_id = BackgroundCryptoService.queue_priority_analysis(
                file_id, analysis_types, high_priority=True
            )

            if task_id:
                logger.info(f"Queued immediate analysis for file {file_id}: {task_id}")

        except Exception as e:
            logger.error(f"Failed to queue immediate analysis: {e}")

    @staticmethod
    def _queue_background_analysis(file_id: int, priority: int):
        """Queue comprehensive background crypto analysis"""
        try:
            # Import background crypto service
            from crypto_hunter_web.services.background_crypto import BackgroundCryptoService

            # For high priority files, queue comprehensive analysis
            if priority >= 7:
                from crypto_hunter_web.services.background_crypto import analyze_file_comprehensive

                task = analyze_file_comprehensive.delay(file_id)
                logger.info(f"Queued comprehensive analysis for file {file_id}: {task.id}")

            # For medium priority files, add to batch processing queue
            elif priority >= 5:
                ImportService._add_to_batch_queue(file_id)

        except Exception as e:
            logger.error(f"Failed to queue background analysis: {e}")

    @staticmethod
    def _add_to_batch_queue(file_id: int):
        """Add file to batch processing queue for later crypto analysis"""
        try:
            import redis
            redis_client = redis.Redis(host='localhost', port=6379, db=2, decode_responses=True)

            # Add to pending analysis queue
            redis_client.lpush('pending_analysis_queue', file_id)
            redis_client.expire('pending_analysis_queue', 86400)  # 24 hour expiry

            logger.debug(f"Added file {file_id} to batch analysis queue")

        except Exception as e:
            logger.warning(f"Failed to add to batch queue: {e}")

    @staticmethod
    def finalize_import_with_background_processing(bulk_import: BulkImport):
        """Finalize import and start comprehensive background crypto processing"""
        try:
            # Start continuous crypto monitoring if not already running
            from crypto_hunter_web.services.background_crypto import BackgroundCryptoService

            # Get count of newly imported files
            newly_imported = AnalysisFile.query.filter(
                AnalysisFile.discovered_by == bulk_import.imported_by,
                AnalysisFile.created_at >= bulk_import.started_at,
                AnalysisFile.status.in_(['pending_analysis', 'basic_analysis_complete'])
            ).count()

            if newly_imported > 0:
                # Start batch processing for remaining files
                BackgroundCryptoService.start_continuous_analysis(batch_size=50)

                logger.info(f"Started background crypto processing for {newly_imported} newly imported files")

        except Exception as e:
            logger.error(f"Failed to start background processing: {e}")

    @staticmethod
    def _get_valid_files(directory_path: str, recursive: bool = True) -> List[Dict]:
        """Get list of valid files with crypto intelligence filtering"""
        valid_files = []

        if recursive:
            file_generator = Path(directory_path).rglob('*')
        else:
            file_generator = Path(directory_path).iterdir()

        for file_path in file_generator:
            try:
                if file_path.is_file() and os.access(file_path, os.R_OK):
                    file_size = file_path.stat().st_size

                    # Skip empty files or extremely large files
                    if 0 < file_size < 10 * 1024 * 1024 * 1024:  # 10GB max
                        valid_files.append({
                            'path': str(file_path),
                            'size': file_size,
                            'name': file_path.name
                        })

            except (OSError, PermissionError) as e:
                logger.warning(f"Cannot access file {file_path}: {e}")
                continue

        return valid_files

    @staticmethod
    def _prepare_file_data(file_info: Dict, extraction_method: str) -> Optional[Dict]:
        """Prepare file data dictionary with crypto intelligence"""
        try:
            file_path = file_info['path']

            # Calculate SHA256
            sha256_hash = ImportService._calculate_sha256_safe(file_path)
            if not sha256_hash:
                return None

            # Determine file type
            file_type, _ = mimetypes.guess_type(file_path)
            if not file_type:
                file_type = 'application/octet-stream'

            return {
                'sha256_hash': sha256_hash,
                'filename': file_info['name'],
                'filepath': file_path,
                'file_type': file_type.split('/')[0],  # Get main type
                'file_size': file_info['size'],
                'extraction_method': extraction_method,
                'is_root_file': False
            }

        except Exception as e:
            logger.error(f"Error preparing file data for {file_info.get('path', 'unknown')}: {e}")
            return None

    @staticmethod
    def _prepare_csv_row_data(row: Dict) -> Optional[Dict]:
        """Prepare file data from CSV row with crypto intelligence"""
        try:
            # Get values using multiple possible column names
            sha256_hash = ImportService._get_field_value(
                row, ['sha256', 'sha256_hash', 'hash', 'SHA256', 'Hash']
            )

            filename = ImportService._get_field_value(
                row, ['filename', 'file_name', 'name', 'Filename', 'File Name']
            )

            filepath = ImportService._get_field_value(
                row, ['filepath', 'file_path', 'path', 'Filepath', 'File Path']
            )

            file_type = ImportService._get_field_value(
                row, ['file_type', 'type', 'filetype', 'File Type', 'Type']
            )

            file_size_str = ImportService._get_field_value(
                row, ['file_size', 'size', 'filesize', 'File Size', 'Size']
            )

            # Validate required fields
            if not sha256_hash or not filename:
                return None

            # Parse file size
            try:
                file_size = int(file_size_str) if file_size_str else 0
            except (ValueError, TypeError):
                file_size = 0

            # Determine file type if not provided
            if not file_type and filepath:
                file_type, _ = mimetypes.guess_type(filepath)

            if not file_type:
                file_type = 'application/octet-stream'

            return {
                'sha256_hash': sha256_hash.lower(),
                'filename': filename,
                'filepath': filepath,
                'file_type': file_type.split('/')[0] if '/' in file_type else file_type,
                'file_size': file_size,
                'extraction_method': 'bulk_import',
                'is_root_file': False
            }

        except Exception as e:
            logger.error(f"Error preparing CSV row data: {e}")
            return None

    @staticmethod
    def _validate_csv_row(row: Dict) -> bool:
        """Validate CSV row has minimum required data"""
        required_fields = [
            ['sha256', 'sha256_hash', 'hash', 'SHA256', 'Hash'],
            ['filename', 'file_name', 'name', 'Filename', 'File Name']
        ]

        for field_options in required_fields:
            if not ImportService._get_field_value(row, field_options):
                return False

        return True

    @staticmethod
    def _validate_file_data(file_data: Dict) -> bool:
        """Validate file data before import"""
        required_fields = ['sha256_hash', 'filename', 'file_type', 'file_size']

        for field in required_fields:
            if field not in file_data or not file_data[field]:
                return False

        # Validate SHA256 format
        sha256 = file_data['sha256_hash']
        if not isinstance(sha256, str) or len(sha256) != 64:
            return False

        try:
            int(sha256, 16)  # Verify it's a valid hex string
        except ValueError:
            return False

        return True

    @staticmethod
    def _calculate_sha256_safe(file_path: str) -> Optional[str]:
        """Safely calculate SHA256 hash with error handling"""
        sha256_hash = hashlib.sha256()

        try:
            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(8192), b""):
                    sha256_hash.update(chunk)
            return sha256_hash.hexdigest()

        except (OSError, PermissionError, MemoryError) as e:
            logger.error(f"Error calculating SHA256 for {file_path}: {e}")
            return None

    @staticmethod
    def _get_field_value(row: Dict, possible_names: List[str]) -> Optional[str]:
        """Get field value using multiple possible column names"""
        for name in possible_names:
            if name in row and row[name] and str(row[name]).strip():
                return str(row[name]).strip()
        return None

    @staticmethod
    def _log_detailed_error(bulk_import: BulkImport, error_message: str):
        """Log detailed error with size limits"""
        if not bulk_import.error_log:
            bulk_import.error_log = ""

        timestamp = datetime.now().strftime('%H:%M:%S')
        new_error = f"{timestamp}: {error_message}\n"

        # Maintain size limit
        if len(bulk_import.error_log) + len(new_error) > ImportService.MAX_ERROR_LOG_SIZE:
            keep_size = ImportService.MAX_ERROR_LOG_SIZE - len(new_error) - 100
            bulk_import.error_log = "...[truncated]\n" + bulk_import.error_log[-keep_size:]

        bulk_import.error_log += new_error

    @staticmethod
    def _get_file_type_color(file_type: str) -> str:
        """Get color based on file type"""
        colors = {
            'image': '#ef4444',
            'audio': '#f97316',
            'video': '#eab308',
            'text': '#22c55e',
            'application': '#3b82f6',
            'binary': '#8b5cf6'
        }

        file_type_lower = file_type.lower() if file_type else 'application'

        for type_key in colors:
            if type_key in file_type_lower:
                return colors[type_key]

        return colors['application']

    @staticmethod
    @contextmanager
    def _db_transaction():
        """Context manager for database transactions with proper error handling"""
        try:
            yield
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            logger.error(f"Database transaction failed: {e}")
            raise
