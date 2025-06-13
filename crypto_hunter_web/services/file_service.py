# crypto_hunter_web/services/file_service.py - COMPLETE FILE MANAGEMENT SERVICE

import hashlib
import logging
import mimetypes
import os
import shutil
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any

import magic
from werkzeug.datastructures import FileStorage
from werkzeug.utils import secure_filename
from flask import current_app

from crypto_hunter_web.models import db, AnalysisFile, FileContent
from crypto_hunter_web.utils.crypto_patterns import CryptoPatterns
from crypto_hunter_web.utils.validators import validate_filename, validate_file_size

logger = logging.getLogger(__name__)


class FileService:
    """Comprehensive file management service with security and performance optimizations"""

    # Configuration
    ALLOWED_EXTENSIONS = {
        'txt', 'log', 'md', 'json', 'xml', 'html', 'css', 'js', 'py', 'java', 'c', 'cpp', 'h',
        'pdf', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx',
        'zip', 'rar', '7z', 'tar', 'gz', 'bz2', 'xz',
        'exe', 'dll', 'so', 'bin', 'img', 'iso', 'raw',
        'jpg', 'jpeg', 'png', 'gif', 'bmp', 'tiff', 'webp',
        'mp3', 'wav', 'mp4', 'avi', 'mov', 'mkv',
        'pcap', 'pcapng', 'cap',
        'key', 'pem', 'crt', 'cer', 'p12', 'pfx'
    }

    DANGEROUS_EXTENSIONS = {
        'exe', 'bat', 'cmd', 'com', 'pif', 'scr', 'vbs', 'js', 'jar'
    }

    MAX_FILE_SIZE = 1 * 1024 * 1024 * 1024  # 1GB
    CHUNK_SIZE = 65536  # 64KB for file operations

    @classmethod
    def validate_upload(cls, file: FileStorage) -> bool:
        """Validate uploaded file for security and policy compliance"""
        try:
            # Check if file exists
            if not file or not file.filename:
                logger.warning("File validation failed: No file or filename")
                return False

            # Validate filename
            if not validate_filename(file.filename):
                logger.warning(f"File validation failed: Invalid filename {file.filename}")
                return False

            # Check file extension
            file_ext = Path(file.filename).suffix.lower().lstrip('.')
            if file_ext not in cls.ALLOWED_EXTENSIONS:
                logger.warning(f"File validation failed: Extension {file_ext} not allowed")
                return False

            # Check if file has content
            file.seek(0, 2)  # Seek to end
            file_size = file.tell()
            file.seek(0)  # Reset to beginning

            if file_size == 0:
                logger.warning("File validation failed: Empty file")
                return False

            if not validate_file_size(file_size, cls.MAX_FILE_SIZE):
                logger.warning(f"File validation failed: File too large {file_size}")
                return False

            # Read file header for content validation
            header = file.read(1024)
            file.seek(0)

            # Check for malicious patterns in header
            if cls._has_malicious_patterns(header):
                logger.warning("File validation failed: Malicious patterns detected")
                return False

            # MIME type validation
            if not cls._validate_mime_type(file, file_ext):
                logger.warning("File validation failed: MIME type mismatch")
                return False

            return True

        except Exception as e:
            logger.error(f"File validation error: {e}")
            return False

    @classmethod
    def process_upload(cls, file: FileStorage, user_id: int,
                       priority: int = 5, is_root_file: bool = False,
                       notes: str = '', tags: List[str] = None) -> Dict[str, Any]:
        """Process file upload with comprehensive metadata extraction"""
        try:
            # Generate secure filename
            original_filename = file.filename
            secure_name = secure_filename(original_filename)

            # Calculate file hash while uploading
            hasher = hashlib.sha256()
            md5_hasher = hashlib.md5()
            sha1_hasher = hashlib.sha1()

            # Create temporary file for processing
            with tempfile.NamedTemporaryFile(delete=False) as temp_file:
                temp_path = temp_file.name
                file_size = 0

                # Write file in chunks while calculating hashes
                file.seek(0)
                while chunk := file.read(cls.CHUNK_SIZE):
                    temp_file.write(chunk)
                    hasher.update(chunk)
                    md5_hasher.update(chunk)
                    sha1_hasher.update(chunk)
                    file_size += len(chunk)

            # Get hashes
            sha256_hash = hasher.hexdigest()
            md5_hash = md5_hasher.hexdigest()
            sha1_hash = sha1_hasher.hexdigest()

            # Check for duplicate files
            existing_file = AnalysisFile.find_by_sha(sha256_hash)
            if existing_file:
                os.unlink(temp_path)
                return {
                    'success': False,
                    'error': f'File already exists: {existing_file.filename}',
                    'existing_file': existing_file
                }

            # Determine final storage path
            upload_dir = Path(current_app.config['UPLOAD_FOLDER'])
            upload_dir.mkdir(exist_ok=True)

            # Create directory structure based on hash (for distribution)
            subdir = upload_dir / sha256_hash[:2] / sha256_hash[2:4]
            subdir.mkdir(parents=True, exist_ok=True)

            final_path = subdir / f"{sha256_hash}_{secure_name}"

            # Move file to final location
            shutil.move(temp_path, final_path)

            # Detect file type and additional metadata
            file_metadata = cls._extract_file_metadata(final_path, original_filename)

            # Create database record
            analysis_file = AnalysisFile(
                filename=original_filename,
                filepath=str(final_path),
                original_path=original_filename,
                file_size=file_size,
                file_type=file_metadata['file_type'],
                mime_type=file_metadata['mime_type'],
                sha256_hash=sha256_hash,
                md5_hash=md5_hash,
                sha1_hash=sha1_hash,
                priority=priority,
                is_root_file=is_root_file,
                is_encrypted=file_metadata.get('is_encrypted', False),
                is_archive=file_metadata.get('is_archive', False),
                is_executable=file_metadata.get('is_executable', False),
                created_by=user_id,
                notes=notes[:1000] if notes else '',
                tags=tags or [],
                analysis_metadata=file_metadata
            )

            db.session.add(analysis_file)
            db.session.commit()

            # Create initial file content entry (raw binary)
            cls._create_raw_content_entry(analysis_file)

            # Quick crypto scan
            if file_metadata.get('is_text', False) or file_size < 10 * 1024 * 1024:  # 10MB limit
                contains_crypto = cls._quick_crypto_scan(final_path)
                analysis_file.contains_crypto = contains_crypto
                db.session.commit()

            logger.info(f"Successfully processed upload: {original_filename} -> {sha256_hash}")

            return {
                'success': True,
                'file': analysis_file,
                'message': f'File {original_filename} uploaded successfully'
            }

        except Exception as e:
            # Cleanup on error
            if 'temp_path' in locals() and os.path.exists(temp_path):
                os.unlink(temp_path)
            if 'final_path' in locals() and os.path.exists(final_path):
                os.unlink(final_path)

            logger.error(f"Upload processing failed: {e}", exc_info=True)
            return {
                'success': False,
                'error': f'Upload failed: {str(e)}'
            }

    @classmethod
    def _extract_file_metadata(cls, file_path: Path, original_filename: str) -> Dict[str, Any]:
        """Extract comprehensive file metadata"""
        metadata = {
            'file_type': 'unknown',
            'mime_type': 'application/octet-stream',
            'is_text': False,
            'is_binary': True,
            'is_archive': False,
            'is_executable': False,
            'is_encrypted': False,
            'encoding': None,
            'file_description': '',
            'extracted_at': datetime.utcnow().isoformat()
        }

        try:
            # Get file extension
            file_ext = file_path.suffix.lower().lstrip('.')

            # MIME type detection
            try:
                metadata['mime_type'] = magic.from_file(str(file_path), mime=True)
            except Exception:
                metadata['mime_type'] = mimetypes.guess_type(str(file_path))[0] or 'application/octet-stream'

            # File description
            try:
                metadata['file_description'] = magic.from_file(str(file_path))
            except Exception:
                metadata['file_description'] = f'{file_ext.upper()} file'

            # Determine file type category
            if file_ext in {'txt', 'log', 'md', 'json', 'xml', 'html', 'css', 'js', 'py', 'java', 'c', 'cpp'}:
                metadata['file_type'] = 'text'
                metadata['is_text'] = True
                metadata['is_binary'] = False
            elif file_ext in {'zip', 'rar', '7z', 'tar', 'gz', 'bz2', 'xz'}:
                metadata['file_type'] = 'archive'
                metadata['is_archive'] = True
            elif file_ext in {'exe', 'dll', 'so', 'bin'}:
                metadata['file_type'] = 'executable'
                metadata['is_executable'] = True
            elif file_ext in {'jpg', 'jpeg', 'png', 'gif', 'bmp', 'tiff', 'webp'}:
                metadata['file_type'] = 'image'
            elif file_ext in {'pdf', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx'}:
                metadata['file_type'] = 'document'
            elif file_ext in {'mp3', 'wav', 'mp4', 'avi', 'mov', 'mkv'}:
                metadata['file_type'] = 'media'
            elif file_ext in {'pcap', 'pcapng', 'cap'}:
                metadata['file_type'] = 'network'
            elif file_ext in {'key', 'pem', 'crt', 'cer', 'p12', 'pfx'}:
                metadata['file_type'] = 'certificate'
            else:
                metadata['file_type'] = file_ext or 'unknown'

            # Encoding detection for text files
            if metadata['is_text']:
                try:
                    import chardet
                    with open(file_path, 'rb') as f:
                        raw_data = f.read(10000)  # Read first 10KB
                    result = chardet.detect(raw_data)
                    metadata['encoding'] = result['encoding']
                except Exception:
                    metadata['encoding'] = 'utf-8'

            # Check for encryption (basic heuristics)
            metadata['is_encrypted'] = cls._check_encryption(file_path, metadata)

            # Additional format-specific metadata
            if metadata['file_type'] == 'executable':
                metadata.update(cls._analyze_executable_metadata(file_path))
            elif metadata['file_type'] == 'archive':
                metadata.update(cls._analyze_archive_metadata(file_path))
            elif metadata['file_type'] == 'image':
                metadata.update(cls._analyze_image_metadata(file_path))

        except Exception as e:
            logger.error(f"Metadata extraction failed for {file_path}: {e}")

        return metadata

    @classmethod
    def _check_encryption(cls, file_path: Path, metadata: Dict) -> bool:
        """Check if file appears to be encrypted"""
        try:
            # Check file extension
            if file_path.suffix.lower() in {'.gpg', '.pgp', '.enc', '.encrypted'}:
                return True

            # Check MIME type
            if 'encrypted' in metadata.get('file_description', '').lower():
                return True

            # Basic entropy check for small files
            if file_path.stat().st_size < 1024 * 1024:  # 1MB
                with open(file_path, 'rb') as f:
                    data = f.read(65536)  # Read first 64KB

                if data:
                    # Calculate byte frequency
                    byte_counts = [0] * 256
                    for byte in data:
                        byte_counts[byte] += 1

                    # Calculate entropy
                    entropy = 0.0
                    data_len = len(data)

                    for count in byte_counts:
                        if count > 0:
                            frequency = count / data_len
                            entropy -= frequency * (frequency).bit_length()

                    # High entropy might indicate encryption/compression
                    if entropy > 7.5:  # Threshold for high entropy
                        return True

            return False

        except Exception:
            return False

    @classmethod
    def _analyze_executable_metadata(cls, file_path: Path) -> Dict[str, Any]:
        """Analyze executable file metadata"""
        metadata = {}

        try:
            with open(file_path, 'rb') as f:
                header = f.read(1024)

            # PE file (Windows)
            if header.startswith(b'MZ'):
                metadata['executable_type'] = 'PE'
                metadata['platform'] = 'Windows'
                # Could extract more PE metadata here

            # ELF file (Linux)
            elif header.startswith(b'\x7fELF'):
                metadata['executable_type'] = 'ELF'
                metadata['platform'] = 'Linux'
                # Could extract more ELF metadata here

            # Mach-O file (macOS)
            elif header.startswith((b'\xfe\xed\xfa\xce', b'\xfe\xed\xfa\xcf')):
                metadata['executable_type'] = 'Mach-O'
                metadata['platform'] = 'macOS'

        except Exception as e:
            logger.warning(f"Executable analysis failed: {e}")

        return metadata

    @classmethod
    def _analyze_archive_metadata(cls, file_path: Path) -> Dict[str, Any]:
        """Analyze archive file metadata"""
        metadata = {}

        try:
            file_ext = file_path.suffix.lower()

            if file_ext == '.zip':
                try:
                    import zipfile
                    with zipfile.ZipFile(file_path, 'r') as zf:
                        metadata['archive_files'] = len(zf.infolist())
                        metadata['archive_compressed_size'] = sum(info.compress_size for info in zf.infolist())
                        metadata['archive_uncompressed_size'] = sum(info.file_size for info in zf.infolist())
                        metadata['has_password'] = any(info.flag_bits & 0x1 for info in zf.infolist())
                except Exception:
                    pass

            elif file_ext in ['.tar', '.tar.gz', '.tar.bz2', '.tar.xz']:
                try:
                    import tarfile
                    with tarfile.open(file_path, 'r') as tf:
                        metadata['archive_files'] = len(tf.getmembers())
                        metadata['archive_uncompressed_size'] = sum(member.size for member in tf.getmembers())
                except Exception:
                    pass

        except Exception as e:
            logger.warning(f"Archive analysis failed: {e}")

        return metadata

    @classmethod
    def _analyze_image_metadata(cls, file_path: Path) -> Dict[str, Any]:
        """Analyze image file metadata"""
        metadata = {}

        try:
            from PIL import Image
            from PIL.ExifTags import TAGS

            with Image.open(file_path) as img:
                metadata['image_width'] = img.width
                metadata['image_height'] = img.height
                metadata['image_format'] = img.format
                metadata['image_mode'] = img.mode

                # Extract EXIF data
                exif_data = img._getexif()
                if exif_data:
                    exif = {}
                    for tag_id, value in exif_data.items():
                        tag = TAGS.get(tag_id, tag_id)
                        exif[tag] = str(value)
                    metadata['exif_data'] = exif

        except Exception as e:
            logger.warning(f"Image analysis failed: {e}")

        return metadata

    @classmethod
    def _create_raw_content_entry(cls, file_obj: AnalysisFile):
        """Create raw binary content entry"""
        try:
            with open(file_obj.filepath, 'rb') as f:
                # For large files, store only first chunk
                if file_obj.file_size > 10 * 1024 * 1024:  # 10MB
                    content = f.read(1024 * 1024)  # 1MB
                    is_truncated = True
                    truncated_at = 1024 * 1024
                else:
                    content = f.read()
                    is_truncated = False
                    truncated_at = None

            content_entry = FileContent(
                file_id=file_obj.id,
                content_type='raw_binary',
                content_format='binary',
                content_bytes=content,
                content_size=len(content),
                is_truncated=is_truncated,
                truncated_at=truncated_at,
                extracted_by=file_obj.created_by,
                extraction_method='upload'
            )

            db.session.add(content_entry)
            db.session.commit()

        except Exception as e:
            logger.error(f"Failed to create raw content entry: {e}")

    @classmethod
    def _quick_crypto_scan(cls, file_path: Path) -> bool:
        """Perform quick crypto pattern scan"""
        try:
            crypto_patterns = CryptoPatterns()

            # Read file content (limited for performance)
            with open(file_path, 'rb') as f:
                content = f.read(1024 * 1024)  # 1MB max

            # Try to decode as text
            try:
                text_content = content.decode('utf-8', errors='ignore')
            except:
                text_content = content.decode('latin1', errors='ignore')

            # Quick pattern check
            result = crypto_patterns.quick_scan(text_content)
            return result.get('has_crypto_content', False)

        except Exception as e:
            logger.warning(f"Quick crypto scan failed: {e}")
            return False

    @classmethod
    def _has_malicious_patterns(cls, data: bytes) -> bool:
        """Check for known malicious patterns"""
        try:
            # Check for common malware signatures
            malicious_patterns = [
                b'\x4d\x5a\x90\x00',  # PE header variant
                b'This program cannot be run in DOS mode',
                b'BEGINDATA',
                b'base64,',  # Potential data URI
            ]

            for pattern in malicious_patterns:
                if pattern in data:
                    return True

            return False

        except Exception:
            return False

    @classmethod
    def _validate_mime_type(cls, file: FileStorage, expected_ext: str) -> bool:
        """Validate MIME type matches file extension"""
        try:
            # Read file header
            header = file.read(1024)
            file.seek(0)

            # Get MIME type from magic
            try:
                detected_mime = magic.from_buffer(header, mime=True)
            except:
                return True  # If we can't detect, allow it

            # Expected MIME types for common extensions
            mime_mappings = {
                'txt': ['text/plain'],
                'pdf': ['application/pdf'],
                'zip': ['application/zip'],
                'exe': ['application/x-executable', 'application/x-dosexec'],
                'jpg': ['image/jpeg'],
                'png': ['image/png'],
                'gif': ['image/gif'],
            }

            expected_mimes = mime_mappings.get(expected_ext, [])
            if expected_mimes and detected_mime not in expected_mimes:
                logger.warning(f"MIME type mismatch: expected {expected_mimes}, got {detected_mime}")
                return False

            return True

        except Exception:
            return True  # If validation fails, allow it

    @classmethod
    def get_disk_usage(cls) -> Dict[str, Any]:
        """Get disk usage statistics"""
        try:
            from crypto_hunter_web import current_app
            upload_dir = Path(current_app.config['UPLOAD_FOLDER'])

            # Calculate total size of uploaded files
            total_size = 0
            file_count = 0

            for file_path in upload_dir.rglob('*'):
                if file_path.is_file():
                    total_size += file_path.stat().st_size
                    file_count += 1

            # Get disk space info
            import shutil
            disk_usage = shutil.disk_usage(upload_dir)

            return {
                'total_files': file_count,
                'total_size': total_size,
                'total_size_human': cls._humanize_bytes(total_size),
                'disk_total': disk_usage.total,
                'disk_used': disk_usage.used,
                'disk_free': disk_usage.free,
                'disk_usage_percent': (disk_usage.used / disk_usage.total) * 100
            }

        except Exception as e:
            logger.error(f"Disk usage calculation failed: {e}")
            return {}

    @classmethod
    def get_average_analysis_time(cls) -> float:
        """Get average analysis time"""
        try:
            result = db.session.query(db.func.avg(AnalysisFile.analysis_duration)) \
                .filter(AnalysisFile.analysis_duration.isnot(None)).scalar()
            return float(result) if result else 0.0
        except Exception:
            return 0.0

    @classmethod
    def get_analysis_success_rate(cls) -> float:
        """Get analysis success rate percentage"""
        try:
            total = AnalysisFile.query.filter(AnalysisFile.status.in_(['complete', 'error'])).count()
            successful = AnalysisFile.query.filter_by(status='complete').count()

            if total == 0:
                return 100.0

            return (successful / total) * 100.0

        except Exception:
            return 0.0

    @classmethod
    def get_queue_size(cls) -> int:
        """Get current analysis queue size"""
        try:
            return AnalysisFile.query.filter_by(status='pending').count()
        except Exception:
            return 0

    @classmethod
    def get_analysis_progress(cls, file_obj: AnalysisFile) -> Dict[str, Any]:
        """Get analysis progress for a file"""
        try:
            # Count different types of content
            content_counts = {}
            for content in file_obj.content_entries:
                content_type = content.content_type
                content_counts[content_type] = content_counts.get(content_type, 0) + 1

            # Calculate progress based on available analysis types
            expected_types = ['raw_binary', 'strings_output', 'crypto_analysis', 'metadata_analysis']
            completed_types = [t for t in expected_types if t in content_counts]

            progress_percent = (len(completed_types) / len(expected_types)) * 100

            return {
                'status': file_obj.status,
                'progress_percent': progress_percent,
                'completed_analyses': completed_types,
                'content_entries_count': len(content_counts),
                'findings_count': file_obj.findings.count(),
                'last_updated': file_obj.updated_at.isoformat() if file_obj.updated_at else None
            }

        except Exception as e:
            logger.error(f"Progress calculation failed: {e}")
            return {
                'status': 'unknown',
                'progress_percent': 0,
                'completed_analyses': [],
                'content_entries_count': 0,
                'findings_count': 0
            }

    @classmethod
    def cleanup_orphaned_files(cls) -> Dict[str, int]:
        """Clean up orphaned files and database entries"""
        try:
            from crypto_hunter_web import current_app
            upload_dir = Path(current_app.config['UPLOAD_FOLDER'])

            # Find files in database that don't exist on disk
            missing_files = []
            for file_obj in AnalysisFile.query.all():
                if not os.path.exists(file_obj.filepath):
                    missing_files.append(file_obj)

            # Find files on disk that aren't in database
            orphaned_files = []
            db_files = {f.filepath for f in AnalysisFile.query.all()}

            for file_path in upload_dir.rglob('*'):
                if file_path.is_file() and str(file_path) not in db_files:
                    orphaned_files.append(file_path)

            # Clean up missing files from database
            for file_obj in missing_files:
                db.session.delete(file_obj)

            # Clean up orphaned files from disk
            for file_path in orphaned_files:
                try:
                    os.remove(file_path)
                except OSError:
                    pass

            db.session.commit()

            return {
                'database_records_removed': len(missing_files),
                'orphaned_files_removed': len(orphaned_files)
            }

        except Exception as e:
            logger.error(f"Cleanup failed: {e}")
            db.session.rollback()
            return {'database_records_removed': 0, 'orphaned_files_removed': 0}

    @staticmethod
    def _humanize_bytes(bytes_value: int) -> str:
        """Convert bytes to human readable format"""
        if bytes_value == 0:
            return '0 B'

        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if bytes_value < 1024.0:
                return f"{bytes_value:.1f} {unit}"
            bytes_value /= 1024.0
        return f"{bytes_value:.1f} PB"
