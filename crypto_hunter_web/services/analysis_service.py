"""
Consolidated Analysis Service for Crypto Hunter
"""
import logging
import time
from datetime import datetime
from typing import Dict, List, Any, Optional, Tuple, Union

from crypto_hunter_web.extensions import db
from crypto_hunter_web.models import (
    AnalysisFile, FileContent, Finding, RegionOfInterest, FileStatus
)
from crypto_hunter_web.services.background_service import BackgroundService
from crypto_hunter_web.services.crypto_intelligence import (
    CryptoIntelligence, CipherAnalyzer, AdvancedCryptoAnalyzer
)
from crypto_hunter_web.services.file_analyzer import FileAnalyzer
from crypto_hunter_web.services.extraction.extraction_service import ExtractionService
from crypto_hunter_web.utils.redis_client_util import (
    cache_result, get_cached_result, cache_file_analysis, get_cached_file_analysis,
    cache_crypto_analysis, get_cached_crypto_analysis, invalidate_file_cache
)

logger = logging.getLogger(__name__)

class AnalysisService:
    """
    Consolidated service for file analysis, crypto analysis, and extraction

    This service provides a unified interface for:
    - File analysis (metadata, content extraction)
    - Cryptographic pattern detection and analysis
    - Steganography and file carving
    - Region of interest tagging
    - Finding management
    """

    @staticmethod
    def analyze_file(file_id: int, user_id: int, async_mode: bool = True) -> Dict[str, Any]:
        """
        Analyze a file comprehensively

        Args:
            file_id: ID of the file to analyze
            user_id: ID of the user requesting analysis
            async_mode: Whether to run analysis asynchronously

        Returns:
            Dictionary with analysis results or task information
        """
        # Get file
        file = AnalysisFile.query.get(file_id)
        if not file:
            return {'success': False, 'error': 'File not found'}

        # Check if analysis is already in progress
        if file.status == FileStatus.ANALYZING:
            return {
                'success': True,
                'message': 'Analysis already in progress',
                'status': file.status.value
            }

        # Check cache for existing analysis
        cached_analysis = get_cached_file_analysis(file.sha256_hash)
        if cached_analysis:
            logger.info(f"Using cached analysis for file {file.sha256_hash}")
            return {
                'success': True,
                'message': 'Analysis retrieved from cache',
                'analysis': cached_analysis
            }

        # Update file status
        file.status = FileStatus.ANALYZING
        db.session.commit()

        if async_mode:
            # Queue background task
            from crypto_hunter_web.tasks.analysis_tasks import analyze_file_task
            task = analyze_file_task.delay(file_id, user_id)

            return {
                'success': True,
                'message': 'Analysis queued',
                'task_id': task.id,
                'file_id': file_id
            }
        else:
            # Run analysis synchronously
            return AnalysisService._perform_analysis(file, user_id)

    @staticmethod
    def _perform_analysis(file: AnalysisFile, user_id: int) -> Dict[str, Any]:
        """
        Perform comprehensive analysis on a file

        Args:
            file: The file to analyze
            user_id: ID of the user requesting analysis

        Returns:
            Dictionary with analysis results
        """
        start_time = time.time()
        results = {
            'success': True,
            'file_id': file.id,
            'file_hash': file.sha256_hash,
            'findings': []
        }

        try:
            # Basic file analysis
            file_analysis = FileAnalyzer.analyze_file(file.filepath)
            results['file_analysis'] = file_analysis

            # Extract content if not already done
            if not file.content_entries.count():
                content_text = FileAnalyzer.extract_content(file.filepath, file.file_type)
                if content_text:
                    content = FileContent(
                        file_id=file.id,
                        content_type='extracted_text',
                        content_format='text',
                        extracted_by=user_id
                    )
                    content.set_content(content_text)
                    db.session.add(content)
                    db.session.commit()

            # Crypto pattern detection
            crypto_analysis = CryptoIntelligence.analyze_crypto_content(open(file.filepath, 'rb').read(), file.filename)
            results['crypto_analysis'] = crypto_analysis

            # Create findings from crypto analysis
            if crypto_analysis.get('patterns'):
                for pattern in crypto_analysis['patterns']:
                    finding = Finding(
                        file_id=file.id,
                        finding_type=pattern['type'],
                        category='crypto',
                        title=f"Found {pattern['type']}",
                        description=pattern.get('description', ''),
                        raw_data=pattern.get('value', ''),
                        confidence_level=int(pattern.get('confidence', 0.5) * 10),
                        created_by=user_id,
                        analysis_method='pattern_detection'
                    )
                    db.session.add(finding)
                    results['findings'].append({
                        'type': pattern['type'],
                        'value': pattern.get('value', ''),
                        'confidence': pattern.get('confidence', 0.5)
                    })

            # Run extraction if file is an image, archive, or other container
            if file.file_type and (file.file_type.startswith('image/') or file.is_archive):
                extraction_result = ExtractionService.extract_all_methods(
                    file_id=file.id,
                    user_id=user_id,
                    async_mode=False
                )
                results['extraction'] = extraction_result

            # Update file status
            file.mark_as_analyzed(
                user_id=user_id,
                duration=time.time() - start_time
            )
            db.session.commit()

            # Cache analysis results
            cache_file_analysis(file.sha256_hash, results)
            if 'crypto_analysis' in results:
                cache_crypto_analysis(file.sha256_hash, results['crypto_analysis'])

            return results

        except Exception as e:
            logger.error(f"Error analyzing file {file.id}: {str(e)}")
            file.status = FileStatus.ERROR
            db.session.commit()
            return {
                'success': False,
                'error': str(e),
                'file_id': file.id
            }

    @staticmethod
    def get_analysis_status(file_id: int) -> Dict[str, Any]:
        """
        Get the status of file analysis

        Args:
            file_id: ID of the file

        Returns:
            Dictionary with status information
        """
        file = AnalysisFile.query.get(file_id)
        if not file:
            return {'success': False, 'error': 'File not found'}

        return {
            'success': True,
            'file_id': file.id,
            'status': file.status.value,
            'findings_count': file.findings.count(),
            'content_count': file.content_entries.count(),
            'analyzed_at': file.analyzed_at.isoformat() if file.analyzed_at else None
        }

    @staticmethod
    def get_file_findings(file_id: int) -> Dict[str, Any]:
        """
        Get findings for a file

        Args:
            file_id: ID of the file

        Returns:
            Dictionary with findings
        """
        file = AnalysisFile.query.get(file_id)
        if not file:
            return {'success': False, 'error': 'File not found'}

        findings = []
        for finding in file.findings.all():
            findings.append(finding.to_dict())

        return {
            'success': True,
            'file_id': file.id,
            'findings': findings
        }

    @staticmethod
    def analyze_crypto_pattern(text: str, pattern_type: str = None) -> Dict[str, Any]:
        """
        Analyze text for cryptographic patterns

        Args:
            text: Text to analyze
            pattern_type: Specific pattern type to analyze for

        Returns:
            Dictionary with analysis results
        """
        if pattern_type:
            # Analyze for specific pattern
            if pattern_type == 'caesar':
                return CipherAnalyzer.analyze_caesar_cipher(text)
            elif pattern_type == 'hash':
                # Use brute_force_hash instead of identify_hash_type
                return AdvancedCryptoAnalyzer.brute_force_hash(text, 'md5')
            else:
                # Use CryptoIntelligence to detect patterns
                return CryptoIntelligence.analyze_crypto_content(text.encode(), f"pattern_{pattern_type}")
        else:
            # Analyze for all patterns
            return CryptoIntelligence.analyze_crypto_content(text.encode(), "all_patterns")

    @staticmethod
    def tag_region_of_interest(
        file_content_id: int,
        start_offset: int,
        end_offset: int,
        title: str,
        description: str = None,
        region_type: str = 'text',
        user_id: int = None,
        color: str = '#yellow',
        highlight_style: str = 'background'
    ) -> Optional[RegionOfInterest]:
        """
        Tag a region of interest in file content

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
            Created RegionOfInterest object or None if failed
        """
        try:
            content = FileContent.query.get(file_content_id)
            if not content:
                logger.error(f"File content not found: {file_content_id}")
                return None

            region = RegionOfInterest(
                file_content_id=file_content_id,
                start_offset=start_offset,
                end_offset=end_offset,
                title=title,
                description=description,
                region_type=region_type,
                created_by=user_id,
                color=color,
                highlight_style=highlight_style
            )

            db.session.add(region)
            db.session.commit()

            # Invalidate cache for the file
            file = content.file
            if file:
                invalidate_file_cache(file.sha256_hash)

            return region
        except Exception as e:
            logger.error(f"Error creating region of interest: {str(e)}")
            db.session.rollback()
            return None

    @staticmethod
    def get_regions_of_interest(file_id: int) -> Dict[str, Any]:
        """
        Get regions of interest for a file

        Args:
            file_id: ID of the file

        Returns:
            Dictionary with regions of interest
        """
        file = AnalysisFile.query.get(file_id)
        if not file:
            return {'success': False, 'error': 'File not found'}

        regions = []
        for content in file.content_entries.all():
            for region in content.regions_of_interest:
                regions.append({
                    'id': region.id,
                    'title': region.title,
                    'description': region.description,
                    'start_offset': region.start_offset,
                    'end_offset': region.end_offset,
                    'region_type': region.region_type,
                    'color': region.color,
                    'highlight_style': region.highlight_style,
                    'created_by': region.created_by,
                    'created_at': region.created_at.isoformat()
                })

        return {
            'success': True,
            'file_id': file.id,
            'regions': regions
        }

    @staticmethod
    def extract_from_file(file_id: int, extraction_method: str, user_id: int, async_mode: bool = True) -> Dict[str, Any]:
        """
        Extract content from a file using a specific method

        Args:
            file_id: ID of the file
            extraction_method: Method to use for extraction
            user_id: ID of the user requesting extraction
            async_mode: Whether to run extraction asynchronously

        Returns:
            Dictionary with extraction results or task information
        """
        return ExtractionService.extract_from_file(
            file_id=file_id,
            extraction_method=extraction_method,
            user_id=user_id,
            async_mode=async_mode
        )

    @staticmethod
    def get_recommended_tools(file_type: str) -> List[Dict[str, Any]]:
        """
        Get recommended tools for a file type

        Args:
            file_type: MIME type of the file

        Returns:
            List of recommended tools
        """
        tools = []

        # Basic tools for all file types
        tools.append({
            'id': 'basic_analysis',
            'name': 'Basic Analysis',
            'description': 'Extract metadata and basic information',
            'category': 'analysis'
        })

        tools.append({
            'id': 'crypto_detection',
            'name': 'Crypto Pattern Detection',
            'description': 'Detect cryptographic patterns in the file',
            'category': 'crypto'
        })

        # File type specific tools
        if file_type.startswith('image/'):
            tools.append({
                'id': 'steganography',
                'name': 'Steganography Analysis',
                'description': 'Detect and extract hidden data in images',
                'category': 'stegano'
            })

            tools.append({
                'id': 'zsteg',
                'name': 'zsteg',
                'description': 'Detect LSB steganography in PNG and BMP',
                'category': 'stegano'
            })

            if file_type == 'image/jpeg':
                tools.append({
                    'id': 'steghide',
                    'name': 'Steghide',
                    'description': 'Extract data hidden with Steghide',
                    'category': 'stegano'
                })

        elif file_type.startswith('application/'):
            tools.append({
                'id': 'binwalk',
                'name': 'Binwalk',
                'description': 'Extract embedded files and executable code',
                'category': 'carving'
            })

            tools.append({
                'id': 'strings',
                'name': 'Strings Analysis',
                'description': 'Extract readable strings from binary files',
                'category': 'analysis'
            })

        elif file_type.startswith('text/'):
            tools.append({
                'id': 'cipher_analysis',
                'name': 'Cipher Analysis',
                'description': 'Analyze text for common ciphers',
                'category': 'crypto'
            })

            tools.append({
                'id': 'frequency_analysis',
                'name': 'Frequency Analysis',
                'description': 'Analyze character frequency for cryptanalysis',
                'category': 'crypto'
            })

        return tools
