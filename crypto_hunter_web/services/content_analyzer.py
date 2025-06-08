# crypto_hunter_web/services/content_analyzer.py - COMPLETE FILE ANALYSIS ENGINE

import os
import re
import hashlib
import mimetypes
import subprocess
import tempfile
import logging
from typing import Dict, List, Optional, Any, Tuple, Union
from pathlib import Path
from contextlib import contextmanager
from datetime import datetime
import magic
import chardet
from collections import defaultdict, Counter

from crypto_hunter_web.models import db, AnalysisFile, FileContent, Finding
from crypto_hunter_web.utils.crypto_patterns import CryptoPatterns
from crypto_hunter_web.utils.validators import validate_file_size, sanitize_filename

logger = logging.getLogger(__name__)


class ContentAnalyzer:
    """Comprehensive file content analysis with crypto intelligence"""

    # Configuration constants
    MAX_CONTENT_SIZE = 500 * 1024 * 1024  # 500MB max for analysis
    CHUNK_SIZE = 65536  # 64KB chunks for reading
    MAX_TEXT_PREVIEW = 50000  # Max characters for text preview
    MAX_STRINGS_OUTPUT = 100000  # Max string extraction output
    MIN_STRING_LENGTH = 4  # Minimum string length to extract
    MAX_STRING_LENGTH = 1000  # Maximum string length to consider

    # File type categories
    TEXT_EXTENSIONS = {'.txt', '.log', '.md', '.json', '.xml', '.html', '.css', '.js', '.py', '.java', '.c', '.cpp',
                       '.h'}
    BINARY_EXTENSIONS = {'.exe', '.dll', '.so', '.bin', '.img', '.iso', '.raw'}
    ARCHIVE_EXTENSIONS = {'.zip', '.rar', '.7z', '.tar', '.gz', '.bz2', '.xz'}
    IMAGE_EXTENSIONS = {'.jpg', '.jpeg', '.png', '.gif', '.bmp', '.tiff', '.webp'}

    def __init__(self):
        """Initialize the content analyzer"""
        self.crypto_patterns = CryptoPatterns()
        self.temp_dir = tempfile.mkdtemp(prefix='crypto_hunter_')

    def __del__(self):
        """Cleanup temporary directory"""
        try:
            import shutil
            if hasattr(self, 'temp_dir') and os.path.exists(self.temp_dir):
                shutil.rmtree(self.temp_dir)
        except Exception:
            pass

    def analyze_file_comprehensive(self, file_obj: AnalysisFile,
                                   analysis_types: List[str] = None) -> Dict[str, Any]:
        """
        Perform comprehensive file analysis

        Args:
            file_obj: AnalysisFile database object
            analysis_types: List of analysis types to perform

        Returns:
            Dictionary containing all analysis results
        """
        if analysis_types is None:
            analysis_types = ['basic', 'strings', 'crypto', 'metadata', 'hex']

        logger.info(f"Starting comprehensive analysis of {file_obj.filename}")
        start_time = datetime.utcnow()

        try:
            # Validate file exists and is accessible
            if not os.path.exists(file_obj.filepath):
                raise FileNotFoundError(f"File not found: {file_obj.filepath}")

            # Check file size
            if not validate_file_size(file_obj.file_size, self.MAX_CONTENT_SIZE):
                raise ValueError(f"File too large for analysis: {file_obj.file_size} bytes")

            analysis_results = {
                'file_info': self._get_file_info(file_obj),
                'analysis_metadata': {
                    'started_at': start_time.isoformat(),
                    'analysis_types': analysis_types,
                    'analyzer_version': '2.0.0'
                }
            }

            # Perform basic analysis
            if 'basic' in analysis_types:
                analysis_results['basic'] = self._analyze_basic_properties(file_obj)

            # Extract and analyze strings
            if 'strings' in analysis_types:
                analysis_results['strings'] = self._extract_and_analyze_strings(file_obj)

            # Crypto pattern analysis
            if 'crypto' in analysis_types:
                analysis_results['crypto'] = self._analyze_crypto_patterns(file_obj)

            # File metadata analysis
            if 'metadata' in analysis_types:
                analysis_results['metadata'] = self._analyze_file_metadata(file_obj)

            # Hex dump analysis
            if 'hex' in analysis_types:
                analysis_results['hex'] = self._generate_hex_analysis(file_obj)

            # Binary analysis for executables
            if 'binary' in analysis_types and self._is_executable(file_obj):
                analysis_results['binary'] = self._analyze_binary_file(file_obj)

            # Archive analysis
            if 'archive' in analysis_types and self._is_archive(file_obj):
                analysis_results['archive'] = self._analyze_archive_file(file_obj)

            # Network artifact analysis
            if 'network' in analysis_types:
                analysis_results['network'] = self._analyze_network_artifacts(file_obj)

            # Complete analysis
            end_time = datetime.utcnow()
            duration = (end_time - start_time).total_seconds()

            analysis_results['analysis_metadata'].update({
                'completed_at': end_time.isoformat(),
                'duration_seconds': duration,
                'success': True
            })

            # Save analysis results to database
            self._save_analysis_results(file_obj, analysis_results)

            logger.info(f"Completed analysis of {file_obj.filename} in {duration:.2f}s")
            return analysis_results

        except Exception as e:
            logger.error(f"Analysis failed for {file_obj.filename}: {e}", exc_info=True)

            error_result = {
                'analysis_metadata': {
                    'started_at': start_time.isoformat(),
                    'failed_at': datetime.utcnow().isoformat(),
                    'success': False,
                    'error': str(e)
                }
            }

            # Save error to database
            self._save_analysis_error(file_obj, str(e))
            return error_result

    def _get_file_info(self, file_obj: AnalysisFile) -> Dict[str, Any]:
        """Get comprehensive file information"""
        file_path = Path(file_obj.filepath)

        # Get file stats
        stat = file_path.stat()

        # Detect MIME type
        try:
            mime_type = magic.from_file(str(file_path), mime=True)
        except Exception:
            mime_type = mimetypes.guess_type(str(file_path))[0] or 'application/octet-stream'

        # Get file type description
        try:
            file_description = magic.from_file(str(file_path))
        except Exception:
            file_description = 'Unknown file type'

        return {
            'filename': file_obj.filename,
            'file_size': file_obj.file_size,
            'mime_type': mime_type,
            'file_description': file_description,
            'created_time': stat.st_ctime,
            'modified_time': stat.st_mtime,
            'accessed_time': stat.st_atime,
            'file_extension': file_path.suffix.lower(),
            'is_text_file': self._is_text_file(file_obj),
            'is_binary_file': self._is_binary_file(file_obj),
            'is_archive': self._is_archive(file_obj),
            'is_executable': self._is_executable(file_obj),
            'estimated_entropy': self._calculate_entropy_estimate(file_obj)
        }

    def _analyze_basic_properties(self, file_obj: AnalysisFile) -> Dict[str, Any]:
        """Analyze basic file properties"""
        results = {
            'checksums': {},
            'encoding_info': {},
            'structure_analysis': {}
        }

        # Calculate additional checksums
        with open(file_obj.filepath, 'rb') as f:
            md5_hash = hashlib.md5()
            sha1_hash = hashlib.sha1()

            while chunk := f.read(self.CHUNK_SIZE):
                md5_hash.update(chunk)
                sha1_hash.update(chunk)

        results['checksums'] = {
            'md5': md5_hash.hexdigest(),
            'sha1': sha1_hash.hexdigest(),
            'sha256': file_obj.sha256_hash
        }

        # Encoding detection for text files
        if self._is_text_file(file_obj):
            try:
                with open(file_obj.filepath, 'rb') as f:
                    raw_data = f.read(min(10000, file_obj.file_size))
                    encoding_result = chardet.detect(raw_data)
                    results['encoding_info'] = encoding_result
            except Exception as e:
                logger.warning(f"Encoding detection failed: {e}")
                results['encoding_info'] = {'encoding': 'unknown', 'confidence': 0.0}

        # Basic structure analysis
        results['structure_analysis'] = self._analyze_file_structure(file_obj)

        return results

    def _extract_and_analyze_strings(self, file_obj: AnalysisFile) -> Dict[str, Any]:
        """Extract and analyze strings from file"""
        logger.info(f"Extracting strings from {file_obj.filename}")

        strings_data = {
            'extraction_method': 'regex',
            'total_strings': 0,
            'interesting_strings': [],
            'categories': {
                'urls': [],
                'email_addresses': [],
                'ip_addresses': [],
                'file_paths': [],
                'registry_keys': [],
                'api_calls': [],
                'crypto_indicators': [],
                'version_info': [],
                'error_messages': [],
                'debug_info': []
            },
            'statistics': {},
            'patterns_found': []
        }

        try:
            # Extract strings using different methods
            if self._is_text_file(file_obj):
                strings_list = self._extract_text_strings(file_obj)
            else:
                strings_list = self._extract_binary_strings(file_obj)

            strings_data['total_strings'] = len(strings_list)

            if strings_list:
                # Analyze and categorize strings
                strings_data = self._categorize_strings(strings_list, strings_data)

                # Generate statistics
                strings_data['statistics'] = self._generate_string_statistics(strings_list)

                # Find interesting patterns
                strings_data['patterns_found'] = self._find_string_patterns(strings_list)

                # Save strings to database
                self._save_strings_content(file_obj, strings_data, strings_list[:10000])  # Limit for storage

        except Exception as e:
            logger.error(f"String extraction failed for {file_obj.filename}: {e}")
            strings_data['error'] = str(e)

        return strings_data

    def _extract_text_strings(self, file_obj: AnalysisFile) -> List[str]:
        """Extract strings from text files"""
        strings_list = []

        try:
            with open(file_obj.filepath, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read(self.MAX_TEXT_PREVIEW)

            # Split into lines and clean
            lines = content.split('\n')
            for line in lines:
                line = line.strip()
                if len(line) >= self.MIN_STRING_LENGTH:
                    strings_list.append(line)

        except Exception as e:
            logger.warning(f"Text string extraction failed: {e}")

        return strings_list

    def _extract_binary_strings(self, file_obj: AnalysisFile) -> List[str]:
        """Extract strings from binary files"""
        strings_list = []

        try:
            # Use multiple methods for string extraction

            # Method 1: Simple regex extraction
            with open(file_obj.filepath, 'rb') as f:
                content = f.read(min(self.MAX_STRINGS_OUTPUT, file_obj.file_size))

            # ASCII strings
            ascii_pattern = rb'[!-~]{4,}'
            ascii_strings = re.findall(ascii_pattern, content)
            strings_list.extend([s.decode('ascii', errors='ignore') for s in ascii_strings])

            # Unicode strings (UTF-16)
            try:
                unicode_pattern = rb'(?:[!-~]\x00){4,}'
                unicode_strings = re.findall(unicode_pattern, content)
                for s in unicode_strings:
                    try:
                        decoded = s.decode('utf-16le', errors='ignore').rstrip('\x00')
                        if len(decoded) >= self.MIN_STRING_LENGTH:
                            strings_list.append(decoded)
                    except UnicodeDecodeError:
                        continue
            except Exception:
                pass

            # Method 2: Use system 'strings' command if available
            try:
                result = subprocess.run(
                    ['strings', '-n', str(self.MIN_STRING_LENGTH), file_obj.filepath],
                    capture_output=True,
                    text=True,
                    timeout=30
                )
                if result.returncode == 0:
                    system_strings = result.stdout.strip().split('\n')
                    strings_list.extend([s for s in system_strings if s.strip()])
            except (subprocess.TimeoutExpired, FileNotFoundError):
                pass

        except Exception as e:
            logger.warning(f"Binary string extraction failed: {e}")

        # Remove duplicates and filter
        unique_strings = list(set(strings_list))
        filtered_strings = [
            s for s in unique_strings
            if self.MIN_STRING_LENGTH <= len(s) <= self.MAX_STRING_LENGTH
        ]

        return filtered_strings

    def _categorize_strings(self, strings_list: List[str], strings_data: Dict) -> Dict[str, Any]:
        """Categorize strings into different types"""

        # Patterns for categorization
        patterns = {
            'urls': re.compile(r'https?://[^\s<>"\']+|ftp://[^\s<>"\']+', re.I),
            'email_addresses': re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'),
            'ip_addresses': re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b'),
            'file_paths': re.compile(r'[A-Za-z]:\\[^<>:"|?*\n\r]+|/[^<>:"|?*\n\r\s]+'),
            'registry_keys': re.compile(r'HKEY_[A-Z_]+\\[^<>:"|?*\n\r]+', re.I),
            'api_calls': re.compile(r'\b[A-Z][a-z]+[A-Z][A-Za-z]*[A-Z]\b'),
            'version_info': re.compile(r'v?\d+\.\d+(?:\.\d+)?(?:\.\d+)?', re.I),
            'crypto_indicators': re.compile(r'(?:crypto|cipher|encrypt|decrypt|hash|key|aes|rsa|sha|md5)', re.I)
        }

        for string in strings_list:
            # Check each pattern
            for category, pattern in patterns.items():
                if pattern.search(string):
                    if len(strings_data['categories'][category]) < 100:  # Limit per category
                        strings_data['categories'][category].append(string)

            # Mark interesting strings (long, contains special patterns, etc.)
            if self._is_interesting_string(string):
                if len(strings_data['interesting_strings']) < 50:
                    strings_data['interesting_strings'].append(string)

        return strings_data

    def _is_interesting_string(self, string: str) -> bool:
        """Determine if a string is interesting for analysis"""
        # Length-based interest
        if len(string) > 100:
            return True

        # Pattern-based interest
        interesting_patterns = [
            r'flag\{.*\}',  # CTF flags
            r'password|secret|key|token',  # Security-related
            r'BEGIN [A-Z ]+END',  # PEM blocks
            r'[A-Za-z0-9+/]{40,}={0,2}',  # Base64
            r'0x[0-9A-Fa-f]{8,}',  # Long hex values
            r'\$[A-Za-z0-9]{20,}',  # Potential hashes
        ]

        for pattern in interesting_patterns:
            if re.search(pattern, string, re.I):
                return True

        return False

    def _generate_string_statistics(self, strings_list: List[str]) -> Dict[str, Any]:
        """Generate statistics about extracted strings"""
        if not strings_list:
            return {}

        lengths = [len(s) for s in strings_list]

        # Character distribution
        char_counter = Counter()
        for string in strings_list:
            char_counter.update(string.lower())

        return {
            'total_count': len(strings_list),
            'unique_count': len(set(strings_list)),
            'average_length': sum(lengths) / len(lengths),
            'min_length': min(lengths),
            'max_length': max(lengths),
            'most_common_chars': char_counter.most_common(10),
            'contains_unicode': any(ord(c) > 127 for s in strings_list for c in s),
            'longest_strings': sorted(strings_list, key=len, reverse=True)[:10]
        }

    def _find_string_patterns(self, strings_list: List[str]) -> List[Dict[str, Any]]:
        """Find interesting patterns in strings"""
        patterns_found = []

        # Pattern definitions
        crypto_patterns = [
            ('Bitcoin Address', r'\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b'),
            ('Ethereum Address', r'\b0x[a-fA-F0-9]{40}\b'),
            ('Private Key (Hex)', r'\b[a-fA-F0-9]{64}\b'),
            ('SSH Key', r'ssh-[a-z0-9]+ [A-Za-z0-9+/=]+'),
            ('PEM Block', r'-----BEGIN [A-Z ]+-----.*?-----END [A-Z ]+-----'),
            ('Base64 Token', r'[A-Za-z0-9+/]{32,}={0,2}'),
            ('UUID', r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}'),
            ('JWT Token', r'eyJ[A-Za-z0-9+/=]+\.[A-Za-z0-9+/=]+\.[A-Za-z0-9+/=]*'),
        ]

        content = '\n'.join(strings_list)

        for pattern_name, pattern_regex in crypto_patterns:
            matches = re.findall(pattern_regex, content, re.IGNORECASE | re.DOTALL)
            if matches:
                patterns_found.append({
                    'pattern_name': pattern_name,
                    'match_count': len(matches),
                    'matches': matches[:10],  # Limit matches stored
                    'pattern_regex': pattern_regex
                })

        return patterns_found

    def _analyze_crypto_patterns(self, file_obj: AnalysisFile) -> Dict[str, Any]:
        """Analyze file for cryptocurrency and cryptographic patterns"""
        logger.info(f"Analyzing crypto patterns in {file_obj.filename}")

        crypto_results = {
            'has_crypto_content': False,
            'confidence_score': 0.0,
            'patterns_found': [],
            'crypto_categories': {
                'wallets': [],
                'keys': [],
                'certificates': [],
                'hashes': [],
                'addresses': [],
                'signatures': []
            },
            'analysis_metadata': {
                'patterns_checked': 0,
                'total_matches': 0
            }
        }

        try:
            # Read file content (limited for large files)
            content_size = min(file_obj.file_size, 10 * 1024 * 1024)  # 10MB max
            with open(file_obj.filepath, 'rb') as f:
                raw_content = f.read(content_size)

            # Try to decode as text
            try:
                text_content = raw_content.decode('utf-8', errors='ignore')
            except UnicodeDecodeError:
                text_content = raw_content.decode('latin1', errors='ignore')

            # Analyze patterns using CryptoPatterns utility
            crypto_analysis = self.crypto_patterns.analyze_content(text_content)

            # Process results
            crypto_results.update(crypto_analysis)

            # Create findings for significant discoveries
            self._create_crypto_findings(file_obj, crypto_analysis)

        except Exception as e:
            logger.error(f"Crypto pattern analysis failed: {e}")
            crypto_results['error'] = str(e)

        return crypto_results

    def _analyze_file_metadata(self, file_obj: AnalysisFile) -> Dict[str, Any]:
        """Analyze file metadata and headers"""
        metadata = {
            'file_signature': {},
            'embedded_metadata': {},
            'structural_info': {}
        }

        try:
            # Read file header
            with open(file_obj.filepath, 'rb') as f:
                header = f.read(1024)  # First 1KB

            # Analyze file signature
            metadata['file_signature'] = self._analyze_file_signature(header)

            # Extract embedded metadata for specific file types
            if file_obj.file_type in ['pdf', 'jpg', 'png', 'docx', 'xlsx']:
                metadata['embedded_metadata'] = self._extract_embedded_metadata(file_obj)

            # Structural analysis
            metadata['structural_info'] = self._analyze_file_structure(file_obj)

        except Exception as e:
            logger.error(f"Metadata analysis failed: {e}")
            metadata['error'] = str(e)

        return metadata

    def _generate_hex_analysis(self, file_obj: AnalysisFile,
                               offset: int = 0, length: int = 512) -> Dict[str, Any]:
        """Generate hex dump and analysis"""
        hex_data = {
            'offset': offset,
            'length': length,
            'hex_dump': '',
            'ascii_representation': '',
            'interesting_bytes': [],
            'entropy_regions': []
        }

        try:
            with open(file_obj.filepath, 'rb') as f:
                f.seek(offset)
                data = f.read(length)

            # Generate hex dump
            hex_lines = []
            ascii_lines = []

            for i in range(0, len(data), 16):
                chunk = data[i:i + 16]
                hex_part = ' '.join(f'{b:02x}' for b in chunk)
                ascii_part = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in chunk)

                hex_lines.append(f'{offset + i:08x}: {hex_part:<48} {ascii_part}')
                ascii_lines.append(ascii_part)

            hex_data['hex_dump'] = '\n'.join(hex_lines)
            hex_data['ascii_representation'] = ''.join(ascii_lines)

            # Find interesting byte patterns
            hex_data['interesting_bytes'] = self._find_interesting_bytes(data, offset)

        except Exception as e:
            logger.error(f"Hex analysis failed: {e}")
            hex_data['error'] = str(e)

        return hex_data

    def _analyze_binary_file(self, file_obj: AnalysisFile) -> Dict[str, Any]:
        """Analyze binary/executable files"""
        binary_analysis = {
            'file_format': 'unknown',
            'architecture': 'unknown',
            'entry_points': [],
            'sections': [],
            'imports': [],
            'exports': [],
            'strings_analysis': {},
            'packer_detection': {}
        }

        try:
            # Basic format detection
            with open(file_obj.filepath, 'rb') as f:
                header = f.read(1024)

            # PE file analysis
            if header.startswith(b'MZ'):
                binary_analysis.update(self._analyze_pe_file(file_obj))
            # ELF file analysis
            elif header.startswith(b'\x7fELF'):
                binary_analysis.update(self._analyze_elf_file(file_obj))
            # Mach-O file analysis
            elif header.startswith((b'\xfe\xed\xfa\xce', b'\xfe\xed\xfa\xcf')):
                binary_analysis.update(self._analyze_macho_file(file_obj))

        except Exception as e:
            logger.error(f"Binary analysis failed: {e}")
            binary_analysis['error'] = str(e)

        return binary_analysis

    def _analyze_archive_file(self, file_obj: AnalysisFile) -> Dict[str, Any]:
        """Analyze archive files"""
        archive_analysis = {
            'archive_type': 'unknown',
            'total_files': 0,
            'file_listing': [],
            'compression_ratio': 0.0,
            'encrypted': False,
            'suspicious_files': []
        }

        try:
            # Determine archive type and analyze
            file_ext = Path(file_obj.filepath).suffix.lower()

            if file_ext == '.zip':
                archive_analysis.update(self._analyze_zip_file(file_obj))
            elif file_ext in ['.tar', '.tar.gz', '.tar.bz2', '.tar.xz']:
                archive_analysis.update(self._analyze_tar_file(file_obj))
            elif file_ext == '.rar':
                archive_analysis.update(self._analyze_rar_file(file_obj))
            elif file_ext == '.7z':
                archive_analysis.update(self._analyze_7z_file(file_obj))

        except Exception as e:
            logger.error(f"Archive analysis failed: {e}")
            archive_analysis['error'] = str(e)

        return archive_analysis

    def _analyze_network_artifacts(self, file_obj: AnalysisFile) -> Dict[str, Any]:
        """Analyze network-related artifacts in file"""
        network_analysis = {
            'urls_found': [],
            'ip_addresses': [],
            'domain_names': [],
            'network_protocols': [],
            'suspicious_indicators': []
        }

        try:
            # Extract network indicators from strings
            if hasattr(self, '_cached_strings'):
                strings_list = self._cached_strings
            else:
                strings_list = self._extract_binary_strings(file_obj)

            # URL pattern
            url_pattern = re.compile(r'https?://[^\s<>"\']+', re.I)
            # IP pattern
            ip_pattern = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
            # Domain pattern
            domain_pattern = re.compile(
                r'\b[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*\b')

            content = '\n'.join(strings_list)

            network_analysis['urls_found'] = url_pattern.findall(content)[:50]
            network_analysis['ip_addresses'] = list(set(ip_pattern.findall(content)))[:50]
            network_analysis['domain_names'] = list(set(domain_pattern.findall(content)))[:50]

            # Look for suspicious network indicators
            suspicious_domains = [
                'bit.ly', 'tinyurl.com', 'pastebin.com', 'discord.gg',
                '.tk', '.ml', '.ga', '.cf'  # Free TLDs often used maliciously
            ]

            for url in network_analysis['urls_found']:
                for suspicious in suspicious_domains:
                    if suspicious in url.lower():
                        network_analysis['suspicious_indicators'].append({
                            'type': 'suspicious_domain',
                            'value': url,
                            'reason': f'Contains suspicious domain: {suspicious}'
                        })

        except Exception as e:
            logger.error(f"Network analysis failed: {e}")
            network_analysis['error'] = str(e)

        return network_analysis

    # Helper methods

    def _is_text_file(self, file_obj: AnalysisFile) -> bool:
        """Check if file is text-based"""
        return Path(file_obj.filepath).suffix.lower() in self.TEXT_EXTENSIONS

    def _is_binary_file(self, file_obj: AnalysisFile) -> bool:
        """Check if file is binary"""
        return Path(file_obj.filepath).suffix.lower() in self.BINARY_EXTENSIONS

    def _is_archive(self, file_obj: AnalysisFile) -> bool:
        """Check if file is an archive"""
        return Path(file_obj.filepath).suffix.lower() in self.ARCHIVE_EXTENSIONS

    def _is_executable(self, file_obj: AnalysisFile) -> bool:
        """Check if file is executable"""
        ext = Path(file_obj.filepath).suffix.lower()
        return ext in {'.exe', '.dll', '.so', '.bin'} or file_obj.is_executable

    def _calculate_entropy_estimate(self, file_obj: AnalysisFile) -> float:
        """Calculate entropy estimate for file"""
        try:
            with open(file_obj.filepath, 'rb') as f:
                # Read sample for entropy calculation
                sample_size = min(65536, file_obj.file_size)
                data = f.read(sample_size)

            if not data:
                return 0.0

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

            return min(entropy, 8.0)  # Max entropy for byte data is 8

        except Exception:
            return 0.0

    def _save_analysis_results(self, file_obj: AnalysisFile, results: Dict[str, Any]):
        """Save analysis results to database"""
        try:
            # Save main analysis as JSON content
            analysis_content = FileContent(
                file_id=file_obj.id,
                content_type='comprehensive_analysis',
                content_format='json',
                content_json=results,
                content_size=len(str(results))
            )

            db.session.add(analysis_content)

            # Update file status
            file_obj.status = 'complete'
            file_obj.analyzed_at = datetime.utcnow()
            file_obj.confidence_score = results.get('confidence_score', 0.5)

            db.session.commit()
            logger.info(f"Saved analysis results for {file_obj.filename}")

        except Exception as e:
            logger.error(f"Failed to save analysis results: {e}")
            db.session.rollback()

    def _save_analysis_error(self, file_obj: AnalysisFile, error_message: str):
        """Save analysis error to database"""
        try:
            file_obj.status = 'error'
            file_obj.analysis_metadata = {'error': error_message, 'error_time': datetime.utcnow().isoformat()}
            db.session.commit()
        except Exception:
            db.session.rollback()

    def _save_strings_content(self, file_obj: AnalysisFile, strings_data: Dict, strings_list: List[str]):
        """Save strings content to database"""
        try:
            # Save strings output
            strings_content = FileContent(
                file_id=file_obj.id,
                content_type='strings_output',
                content_format='json',
                content_json={
                    'metadata': strings_data,
                    'strings': strings_list
                },
                content_size=len('\n'.join(strings_list))
            )

            db.session.add(strings_content)
            db.session.commit()

        except Exception as e:
            logger.error(f"Failed to save strings content: {e}")
            db.session.rollback()

    def _create_crypto_findings(self, file_obj: AnalysisFile, crypto_analysis: Dict):
        """Create findings for significant crypto discoveries"""
        try:
            findings_created = 0

            for pattern_result in crypto_analysis.get('patterns_found', []):
                if pattern_result.get('match_count', 0) > 0:
                    finding = Finding(
                        file_id=file_obj.id,
                        finding_type='crypto_pattern',
                        category='cryptography',
                        title=f"{pattern_result['pattern_name']} Found",
                        description=f"Found {pattern_result['match_count']} instances of {pattern_result['pattern_name']}",
                        confidence_level=8,
                        priority=7,
                        evidence_data=pattern_result,
                        analysis_method='regex_pattern',
                        created_by=1  # System user
                    )

                    db.session.add(finding)
                    findings_created += 1

            if findings_created > 0:
                db.session.commit()
                logger.info(f"Created {findings_created} crypto findings for {file_obj.filename}")

        except Exception as e:
            logger.error(f"Failed to create crypto findings: {e}")
            db.session.rollback()

    # Placeholder methods for specific file type analysis
    # These would be implemented based on specific requirements

    def _analyze_file_signature(self, header: bytes) -> Dict[str, Any]:
        """Analyze file signature from header bytes"""
        # Implementation would check known file signatures
        return {'signature': 'unknown', 'confidence': 0.0}

    def _extract_embedded_metadata(self, file_obj: AnalysisFile) -> Dict[str, Any]:
        """Extract embedded metadata from specific file types"""
        # Implementation would use libraries like exifread, PyPDF2, etc.
        return {}

    def _analyze_file_structure(self, file_obj: AnalysisFile) -> Dict[str, Any]:
        """Analyze internal file structure"""
        # Implementation would analyze file format-specific structures
        return {}

    def _find_interesting_bytes(self, data: bytes, offset: int) -> List[Dict[str, Any]]:
        """Find interesting byte patterns in hex data"""
        # Implementation would look for specific byte patterns
        return []

    def _analyze_pe_file(self, file_obj: AnalysisFile) -> Dict[str, Any]:
        """Analyze PE (Windows executable) file"""
        # Implementation would use pefile library
        return {'file_format': 'PE'}

    def _analyze_elf_file(self, file_obj: AnalysisFile) -> Dict[str, Any]:
        """Analyze ELF (Linux executable) file"""
        # Implementation would use pyelftools
        return {'file_format': 'ELF'}

    def _analyze_macho_file(self, file_obj: AnalysisFile) -> Dict[str, Any]:
        """Analyze Mach-O (macOS executable) file"""
        # Implementation would use macholib
        return {'file_format': 'Mach-O'}

    def _analyze_zip_file(self, file_obj: AnalysisFile) -> Dict[str, Any]:
        """Analyze ZIP archive file"""
        # Implementation would use zipfile library
        return {'archive_type': 'ZIP'}

    def _analyze_tar_file(self, file_obj: AnalysisFile) -> Dict[str, Any]:
        """Analyze TAR archive file"""
        # Implementation would use tarfile library
        return {'archive_type': 'TAR'}

    def _analyze_rar_file(self, file_obj: AnalysisFile) -> Dict[str, Any]:
        """Analyze RAR archive file"""
        # Implementation would use rarfile library
        return {'archive_type': 'RAR'}

    def _analyze_7z_file(self, file_obj: AnalysisFile) -> Dict[str, Any]:
        """Analyze 7-Zip archive file"""
        # Implementation would use py7zr library
        return {'archive_type': '7Z'}


# Export the main class
__all__ = ['ContentAnalyzer']