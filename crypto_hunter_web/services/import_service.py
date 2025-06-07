"""
Enhanced bulk import service for handling large datasets
"""

import csv
import os
import hashlib
from datetime import datetime
from pathlib import Path
import mimetypes
import logging

from crypto_hunter_web.models import db
from crypto_hunter_web.models import AnalysisFile
from crypto_hunter_web.models import ExtractionRelationship
from crypto_hunter_web.models import BulkImport
from crypto_hunter_web.services.file_analyzer import FileAnalyzer
from crypto_hunter_web.services.auth_service import AuthService

logger = logging.getLogger(__name__)

class ImportService:
    """Enhanced bulk import operations with better CSV handling"""
    
    @staticmethod
    def import_from_csv(csv_path, user_id):
        """Import files from CSV with enhanced error handling and progress tracking"""
        bulk_import = BulkImport(
            filename=os.path.basename(csv_path),
            imported_by=user_id,
            status='processing'
        )
        db.session.add(bulk_import)
        db.session.commit()
        
        try:
            # First pass: detect CSV format and count rows
            csv_info = ImportService._analyze_csv_structure(csv_path)
            bulk_import.total_files = csv_info['row_count']
            db.session.commit()
            
            logger.info(f"Starting import of {csv_info['row_count']} rows from {csv_path}")
            
            # Second pass: import files in batches
            with open(csv_path, 'r', encoding=csv_info['encoding'], errors='ignore') as f:
                reader = csv.DictReader(f, delimiter=csv_info['delimiter'])
                
                batch = []
                batch_size = 1000
                processed = 0
                
                for row_num, row in enumerate(reader, 1):
                    try:
                        batch.append(row)
                        
                        # Process batch when it's full
                        if len(batch) >= batch_size:
                            ImportService._process_batch(batch, bulk_import, user_id)
                            processed += len(batch)
                            bulk_import.processed_files = processed
                            db.session.commit()
                            logger.info(f"Processed {processed}/{bulk_import.total_files} files")
                            batch = []
                            
                    except Exception as e:
                        ImportService._log_error(bulk_import, f"Row {row_num}: {str(e)}")
                        logger.error(f"Error processing row {row_num}: {e}")
                
                # Process remaining batch
                if batch:
                    ImportService._process_batch(batch, bulk_import, user_id)
                    processed += len(batch)
                    bulk_import.processed_files = processed
            
            bulk_import.status = 'completed'
            bulk_import.completed_at = datetime.utcnow()
            db.session.commit()
            
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
            bulk_import.error_log = str(e)
            bulk_import.completed_at = datetime.utcnow()
            db.session.commit()
            logger.error(f"Import failed: {e}")
            raise
    
    @staticmethod
    def _analyze_csv_structure(csv_path):
        """Analyze CSV file structure and encoding"""
        csv_info = {
            'encoding': 'utf-8',
            'delimiter': ',',
            'row_count': 0,
            'columns': []
        }
        
        # Try different encodings
        encodings = ['utf-8', 'utf-8-sig', 'latin1', 'cp1252']
        
        for encoding in encodings:
            try:
                with open(csv_path, 'r', encoding=encoding) as f:
                    # Read first few lines to detect delimiter
                    sample = f.read(4096)
                    f.seek(0)
                    
                    # Detect delimiter
                    sniffer = csv.Sniffer()
                    try:
                        dialect = sniffer.sniff(sample, delimiters=',;\t|')
                        csv_info['delimiter'] = dialect.delimiter
                    except:
                        csv_info['delimiter'] = ','
                    
                    # Count rows and get columns
                    reader = csv.DictReader(f, delimiter=csv_info['delimiter'])
                    csv_info['columns'] = reader.fieldnames or []
                    
                    # Count rows efficiently
                    csv_info['row_count'] = sum(1 for _ in reader)
                    csv_info['encoding'] = encoding
                    
                    logger.info(f"CSV analysis: {csv_info['row_count']} rows, "
                               f"delimiter='{csv_info['delimiter']}', encoding={encoding}")
                    break
                    
            except UnicodeDecodeError:
                continue
            except Exception as e:
                logger.warning(f"Error analyzing CSV with encoding {encoding}: {e}")
                continue
        
        return csv_info
    
    @staticmethod
    def _process_batch(batch, bulk_import, user_id):
        """Process a batch of CSV rows efficiently"""
        for row in batch:
            try:
                ImportService._process_csv_row(row, bulk_import, user_id)
            except Exception as e:
                bulk_import.errors_count += 1
                ImportService._log_error(bulk_import, f"Batch processing error: {str(e)}")
        
        # Commit the batch
        try:
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            logger.error(f"Database commit error: {e}")
            bulk_import.errors_count += len(batch)
    
    @staticmethod
    def _process_csv_row(row, bulk_import, user_id):
        """Process a single CSV row with flexible field mapping"""
        # Flexible field mapping - try multiple possible column names
        field_mappings = {
            'sha256_hash': ['sha256_hash', 'sha256', 'hash', 'SHA256', 'sha', 'file_hash'],
            'filename': ['filename', 'name', 'file_name', 'description', 'title', 'file'],
            'filepath': ['filepath', 'path', 'file_path', 'fullpath', 'location', 'url'],
            'file_type': ['file_type', 'type', 'mimetype', 'mime_type', 'content_type'],
            'file_size': ['file_size', 'size', 'filesize', 'bytes', 'length'],
            'md5_hash': ['md5_hash', 'md5', 'MD5'],
            'parent_sha': ['parent_sha', 'parent_hash', 'parent', 'source_sha'],
            'extraction_method': ['extraction_method', 'method', 'tool', 'extractor'],
            'is_root': ['is_root', 'root', 'is_root_file', 'root_file']
        }
        
        # Extract data using flexible mapping
        data = {}
        for field, possible_names in field_mappings.items():
            data[field] = ImportService._get_field_value(row, possible_names)
        
        # Use filename as description if available but no filename
        if not data['filename'] and data.get('description'):
            data['filename'] = data['description']
        
        # Handle missing SHA256 - generate fake one if needed
        if not data['sha256_hash']:
            if data['filepath'] and os.path.exists(data['filepath']):
                data['sha256_hash'] = ImportService._calculate_sha256(data['filepath'])
            else:
                # Generate deterministic fake SHA256 based on available data
                fake_data = f"{data['filename']}{data['filepath']}{data['file_size']}{user_id}".encode()
                data['sha256_hash'] = hashlib.sha256(fake_data).hexdigest()
        
        # Check for duplicates
        existing = AnalysisFile.query.filter_by(sha256_hash=data['sha256_hash']).first()
        if existing:
            bulk_import.duplicates_found += 1
            return
        
        # Determine file type
        if not data['file_type'] and data['filepath']:
            data['file_type'], _ = mimetypes.guess_type(data['filepath'])
        if not data['file_type']:
            data['file_type'] = 'application/octet-stream'
        
        # Parse file size
        file_size = 0
        if data['file_size']:
            try:
                file_size = int(float(data['file_size']))
            except:
                file_size = 0
        elif data['filepath'] and os.path.exists(data['filepath']):
            try:
                file_size = os.path.getsize(data['filepath'])
            except:
                file_size = 0
        
        # Parse is_root
        is_root = False
        if data['is_root']:
            is_root = str(data['is_root']).lower() in ['true', '1', 'yes', 'y', 'root']
        
        # Create file record
        analysis_file = AnalysisFile(
            sha256_hash=data['sha256_hash'],
            filename=data['filename'] or 'Unknown',
            filepath=data['filepath'] or '',
            file_type=data['file_type'],
            file_size=file_size,
            md5_hash=data['md5_hash'] or '',
            parent_file_sha=data['parent_sha'] or '',
            extraction_method=data['extraction_method'] or 'bulk_import',
            discovered_by=user_id,
            is_root_file=is_root,
            status='pending',
            node_color=ImportService._get_file_type_color(data['file_type']),
            depth_level=0
        )
        
        db.session.add(analysis_file)
        db.session.flush()  # Get the ID
        
        # Try content analysis for existing files
        if data['filepath'] and os.path.exists(data['filepath']):
            try:
                if file_size < 50 * 1024 * 1024:  # Only analyze files under 50MB
                    FileAnalyzer.analyze_file_content(data['filepath'], analysis_file.id)
            except Exception as e:
                logger.warning(f"Content analysis failed for {data['filename']}: {e}")
        
        bulk_import.successful_imports += 1
    
    @staticmethod
    def _get_field_value(row, possible_names):
        """Get field value using multiple possible column names"""
        for name in possible_names:
            if name in row and row[name] and str(row[name]).strip():
                return str(row[name]).strip()
        return None
    
    @staticmethod
    def _calculate_sha256(file_path):
        """Calculate SHA256 hash of file"""
        sha256_hash = hashlib.sha256()
        try:
            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(8192), b""):
                    sha256_hash.update(chunk)
            return sha256_hash.hexdigest()
        except Exception as e:
            logger.error(f"Error calculating SHA256 for {file_path}: {e}")
            return None
    
    @staticmethod
    def _log_error(bulk_import, error_message):
        """Log error to bulk import record"""
        if not bulk_import.error_log:
            bulk_import.error_log = ""
        
        # Limit error log size
        if len(bulk_import.error_log) < 10000:
            bulk_import.error_log += f"{datetime.now().strftime('%H:%M:%S')}: {error_message}\n"
    
    @staticmethod
    def _get_file_type_color(file_type):
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
        for key, color in colors.items():
            if key in file_type_lower:
                return color
        return colors['application']
    
    @staticmethod
    def create_sample_csv(output_path='sample_import.csv', num_rows=100):
        """Create a comprehensive sample CSV for testing"""
        import random
        
        sample_data = []
        
        # Generate sample data
        for i in range(num_rows):
            # Generate fake SHA256
            fake_sha = hashlib.sha256(f"sample_file_{i}_{random.randint(1000, 9999)}".encode()).hexdigest()
            
            # Sample file types
            file_types = [
                ('image.jpg', 'image/jpeg'),
                ('audio.wav', 'audio/wav'),
                ('document.pdf', 'application/pdf'),
                ('archive.zip', 'application/zip'),
                ('data.bin', 'application/octet-stream'),
                ('text.txt', 'text/plain')
            ]
            
            filename, file_type = random.choice(file_types)
            
            sample_data.append({
                'sha256_hash': fake_sha,
                'filename': f"sample_{i}_{filename}",
                'filepath': f"/path/to/sample_{i}_{filename}",
                'file_type': file_type,
                'file_size': random.randint(1024, 10*1024*1024),
                'description': f"Sample file {i} for testing import functionality",
                'is_root': 'true' if i % 20 == 0 else 'false',  # Every 20th file is root
                'extraction_method': random.choice(['manual', 'zsteg', 'steghide', 'binwalk']) if i % 5 == 0 else 'manual'
            })
        
        # Write CSV
        with open(output_path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=sample_data[0].keys())
            writer.writeheader()
            writer.writerows(sample_data)
        
        logger.info(f"Created sample CSV with {num_rows} rows: {output_path}")
        return output_path
    
    @staticmethod
    def import_from_directory_scan(directory_path, user_id, extensions=None, recursive=True):
        """Import files by scanning a directory structure"""
        if not os.path.exists(directory_path):
            raise ValueError(f"Directory not found: {directory_path}")
        
        # Create import record
        bulk_import = BulkImport(
            filename=f"Directory scan: {os.path.basename(directory_path)}",
            imported_by=user_id,
            status='processing'
        )
        db.session.add(bulk_import)
        db.session.commit()
        
        try:
            # Default extensions for steganography analysis
            if extensions is None:
                extensions = {'.jpg', '.jpeg', '.png', '.gif', '.bmp', '.tiff',
                             '.wav', '.mp3', '.flac', '.ogg', '.mp4', '.avi',
                             '.pdf', '.zip', '.tar', '.gz', '.7z', '.rar'}
            
            # Convert to lowercase for comparison
            extensions = {ext.lower() for ext in extensions}
            
            file_count = 0
            imported_count = 0
            
            # Walk directory
            walk_func = os.walk if recursive else lambda d: [(d, [], os.listdir(d))]
            
            for root, dirs, files in walk_func(directory_path):
                for file in files:
                    file_path = os.path.join(root, file)
                    file_ext = Path(file).suffix.lower()
                    
                    if extensions and file_ext not in extensions:
                        continue
                    
                    try:
                        # Calculate SHA256
                        sha256_hash = ImportService._calculate_sha256(file_path)
                        if not sha256_hash:
                            continue
                        
                        # Check for duplicates
                        existing = AnalysisFile.query.filter_by(sha256_hash=sha256_hash).first()
                        if existing:
                            bulk_import.duplicates_found += 1
                            continue
                        
                        # Get file info
                        file_size = os.path.getsize(file_path)
                        file_type, _ = mimetypes.guess_type(file_path)
                        if not file_type:
                            file_type = 'application/octet-stream'
                        
                        # Create file record
                        analysis_file = AnalysisFile(
                            sha256_hash=sha256_hash,
                            filename=file,
                            filepath=file_path,
                            file_type=file_type,
                            file_size=file_size,
                            discovered_by=user_id,
                            is_root_file=False,
                            status='pending',
                            node_color=ImportService._get_file_type_color(file_type),
                            extraction_method='directory_scan'
                        )
                        
                        db.session.add(analysis_file)
                        imported_count += 1
                        
                        # Analyze content for smaller files
                        if file_size < 20 * 1024 * 1024:  # 20MB limit for directory scans
                            try:
                                FileAnalyzer.analyze_file_content(file_path, analysis_file.id)
                            except:
                                pass
                        
                        # Commit in batches
                        if imported_count % 100 == 0:
                            db.session.commit()
                            logger.info(f"Directory scan: processed {imported_count} files...")
                        
                    except Exception as e:
                        bulk_import.errors_count += 1
                        ImportService._log_error(bulk_import, f"Error processing {file_path}: {str(e)}")
                        logger.error(f"Error processing {file_path}: {e}")
                    
                    file_count += 1
            
            bulk_import.total_files = file_count
            bulk_import.processed_files = file_count
            bulk_import.successful_imports = imported_count
            bulk_import.status = 'completed'
            bulk_import.completed_at = datetime.utcnow()
            db.session.commit()
            
            logger.info(f"Directory scan completed: {imported_count} files imported from {directory_path}")
            
            AuthService.log_action(
                'directory_scan_completed',
                f'Scanned {directory_path}, imported {imported_count} files',
                user_id
            )
            
            return bulk_import
            
        except Exception as e:
            bulk_import.status = 'failed'
            bulk_import.error_log = str(e)
            bulk_import.completed_at = datetime.utcnow()
            db.session.commit()
            logger.error(f"Directory scan failed: {e}")
            raise