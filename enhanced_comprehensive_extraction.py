#!/usr/bin/env python3
"""
Enhanced Comprehensive Extraction Script

This script performs a recursive extraction from the base image with the following features:
1. Starts with the root image at uploads/image.png
2. Extracts any content using multiple extraction methods
3. Uncompresses compressed files
4. Tries to decrypt encrypted files with the passphrase 'Bodhi tree blossom'
5. XORs every bitplane with each other and combines them for new extractions
6. Performs exotic extractions
7. Respects a maximum depth of 15 levels
8. Avoids duplicate files (by SHA) and duplicate content
9. Writes everything to the database

Usage:
    python enhanced_comprehensive_extraction.py
"""

import sys
import os
import hashlib
import logging
import json
import tempfile
import shutil
from datetime import datetime
from typing import Dict, Any, List, Set, Optional, Tuple

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agent_framework import BaseAgent, AgentType, AgentTask, AgentResult
from crypto_hunter_web import create_app, db
from crypto_hunter_web.models import (
    AnalysisFile, FileContent, Finding, ExtractionRelationship,
    FileNode, GraphEdge, FileStatus, FileDerivation
)
from crypto_hunter_web.services.file_analyzer import FileAnalyzer
from crypto_hunter_web.services.extraction_engine import ExtractionEngine
from crypto_hunter_web.services.crypto_intelligence_service import CryptoIntelligenceService
from crypto_hunter_web.services.extractors import (
    get_extractor, get_recommended_extractors, list_extractors,
    XORBitplanesExtractor, CombinedBitplanesExtractor
)

# Constants
IMAGE_PATH = "uploads/image.png"
OUTPUT_DIR = "extraction"
MAX_DEPTH = 15  # Maximum recursion depth
PASSPHRASE = "Bodhi tree blossom"  # Passphrase for decryption
ADMIN_USER_ID = 1  # Admin user ID for attribution


class FileAnalysisAgent(BaseAgent):
    """Agent wrapper for your existing FileAnalyzer service"""

    def __init__(self):
        super().__init__()
        self.file_analyzer = FileAnalyzer()

    @property
    def agent_type(self) -> AgentType:
        return AgentType.FILE_ANALYSIS

    @property
    def supported_tasks(self) -> List[str]:
        return ['analyze_file', 'calculate_entropy', 'detect_file_type', 'extract_metadata']

    async def execute_task(self, task: AgentTask) -> AgentResult:
        """Execute file analysis using your existing FileAnalyzer"""
        try:
            if task.task_type == 'analyze_file':
                return await self._analyze_file(task)
            elif task.task_type == 'calculate_entropy':
                return await self._calculate_entropy(task)
            elif task.task_type == 'detect_file_type':
                return await self._detect_file_type(task)
            elif task.task_type == 'extract_metadata':
                return await self._extract_metadata(task)
            else:
                return AgentResult(
                    task_id=task.task_id,
                    agent_id=self.agent_id,
                    success=False,
                    error=f"Unsupported task type: {task.task_type}"
                )
        except Exception as e:
            return AgentResult(
                task_id=task.task_id,
                agent_id=self.agent_id,
                success=False,
                error=f"File analysis error: {str(e)}"
            )

    async def _analyze_file(self, task: AgentTask) -> AgentResult:
        """Perform complete file analysis"""
        file_id = task.payload.get('file_id')

        with self.app.app_context():
            file_record = AnalysisFile.query.get(file_id)
            if not file_record:
                return AgentResult(
                    task_id=task.task_id,
                    agent_id=self.agent_id,
                    success=False,
                    error=f"File not found: {file_id}"
                )

            # Use existing FileAnalyzer
            analysis_result = self.file_analyzer.analyze_file(file_record.original_path)

            # Update file record with analysis results
            file_record.status = FileStatus.COMPLETE
            file_record.confidence_score = analysis_result.get('confidence', 0.0)
            file_record.contains_crypto = analysis_result.get('contains_crypto', False)
            file_record.analysis_extra_data = analysis_result.get('metadata', {})

            db.session.commit()

            return AgentResult(
                task_id=task.task_id,
                agent_id=self.agent_id,
                success=True,
                data={
                    'file_id': file_id,
                    'analysis': analysis_result,
                    'entropy': analysis_result.get('entropy'),
                    'file_type': analysis_result.get('file_type'),
                    'contains_crypto': analysis_result.get('contains_crypto')
                }
            )

    async def _calculate_entropy(self, task: AgentTask) -> AgentResult:
        """Calculate file entropy"""
        file_path = task.payload.get('file_path')

        entropy = self.file_analyzer.calculate_entropy(file_path)

        return AgentResult(
            task_id=task.task_id,
            agent_id=self.agent_id,
            success=True,
            data={'entropy': entropy, 'file_path': file_path}
        )

    async def _detect_file_type(self, task: AgentTask) -> AgentResult:
        """Detect file type"""
        file_path = task.payload.get('file_path')

        file_type = self.file_analyzer.detect_file_type(file_path)

        return AgentResult(
            task_id=task.task_id,
            agent_id=self.agent_id,
            success=True,
            data={'file_type': file_type, 'file_path': file_path}
        )

    async def _extract_metadata(self, task: AgentTask) -> AgentResult:
        """Extract file metadata"""
        file_path = task.payload.get('file_path')

        metadata = self.file_analyzer.extract_metadata(file_path)

        return AgentResult(
            task_id=task.task_id,
            agent_id=self.agent_id,
            success=True,
            data={'metadata': metadata, 'file_path': file_path}
        )


class SteganographyAgent(BaseAgent):
    """Agent wrapper for your existing ExtractionEngine"""

    def __init__(self):
        super().__init__()
        self.extraction_engine = ExtractionEngine()

    @property
    def agent_type(self) -> AgentType:
        return AgentType.STEGANOGRAPHY

    @property
    def supported_tasks(self) -> List[str]:
        return ['extract_hidden_data', 'run_zsteg', 'run_steghide', 'run_binwalk', 'detect_steganography']

    async def execute_task(self, task: AgentTask) -> AgentResult:
        """Execute steganography analysis using your existing ExtractionEngine"""
        try:
            if task.task_type == 'extract_hidden_data':
                return await self._extract_hidden_data(task)
            elif task.task_type == 'run_zsteg':
                return await self._run_zsteg(task)
            elif task.task_type == 'run_steghide':
                return await self._run_steghide(task)
            elif task.task_type == 'run_binwalk':
                return await self._run_binwalk(task)
            elif task.task_type == 'detect_steganography':
                return await self._detect_steganography(task)
            else:
                return AgentResult(
                    task_id=task.task_id,
                    agent_id=self.agent_id,
                    success=False,
                    error=f"Unsupported task type: {task.task_type}"
                )
        except Exception as e:
            return AgentResult(
                task_id=task.task_id,
                agent_id=self.agent_id,
                success=False,
                error=f"Steganography analysis error: {str(e)}"
            )

    async def _extract_hidden_data(self, task: AgentTask) -> AgentResult:
        """Run comprehensive steganography extraction"""
        file_id = task.payload.get('file_id')
        methods = task.payload.get('methods', ['zsteg', 'steghide', 'binwalk'])

        with self.app.app_context():
            file_record = AnalysisFile.query.get(file_id)
            if not file_record:
                return AgentResult(
                    task_id=task.task_id,
                    agent_id=self.agent_id,
                    success=False,
                    error=f"File not found: {file_id}"
                )

            extraction_results = {}

            # Run each extraction method
            for method in methods:
                try:
                    result = self.extraction_engine.extract(
                        source_file=file_record,
                        extraction_method=method,
                        user_id=1  # Admin user
                    )
                    extraction_results[method] = result
                except Exception as e:
                    extraction_results[method] = {'success': False, 'error': str(e)}

            # Count successful extractions
            successful_extractions = sum(1 for r in extraction_results.values() if r.get('success'))

            return AgentResult(
                task_id=task.task_id,
                agent_id=self.agent_id,
                success=True,
                data={
                    'file_id': file_id,
                    'methods_run': methods,
                    'successful_extractions': successful_extractions,
                    'results': extraction_results
                }
            )

    async def _run_zsteg(self, task: AgentTask) -> AgentResult:
        """Run zsteg extraction specifically"""
        file_path = task.payload.get('file_path')

        # Use your existing zsteg extractor
        zsteg_extractor = get_extractor('zsteg')
        result = zsteg_extractor.extract(file_path, {})

        return AgentResult(
            task_id=task.task_id,
            agent_id=self.agent_id,
            success=result['success'],
            data=result,
            error=result.get('error')
        )

    async def _run_steghide(self, task: AgentTask) -> AgentResult:
        """Run steghide extraction specifically"""
        file_path = task.payload.get('file_path')
        password = task.payload.get('password', '')

        steghide_extractor = get_extractor('steghide')
        result = steghide_extractor.extract(file_path, {'password': password})

        return AgentResult(
            task_id=task.task_id,
            agent_id=self.agent_id,
            success=result['success'],
            data=result,
            error=result.get('error')
        )

    async def _run_binwalk(self, task: AgentTask) -> AgentResult:
        """Run binwalk extraction specifically"""
        file_path = task.payload.get('file_path')

        binwalk_extractor = get_extractor('binwalk')
        result = binwalk_extractor.extract(file_path, {})

        return AgentResult(
            task_id=task.task_id,
            agent_id=self.agent_id,
            success=result['success'],
            data=result,
            error=result.get('error')
        )

    async def _detect_steganography(self, task: AgentTask) -> AgentResult:
        """Detect potential steganography without extraction"""
        file_id = task.payload.get('file_id')

        # This would use pattern detection to identify potential steganography
        # For now, return a placeholder
        return AgentResult(
            task_id=task.task_id,
            agent_id=self.agent_id,
            success=True,
            data={
                'file_id': file_id,
                'steganography_detected': False,  # Placeholder
                'confidence': 0.5,
                'indicators': []
            }
        )


class CryptographyAgent(BaseAgent):
    """Agent wrapper for your existing CryptoIntelligenceService"""

    def __init__(self):
        super().__init__()
        self.crypto_service = CryptoIntelligenceService()

    @property
    def agent_type(self) -> AgentType:
        return AgentType.CRYPTOGRAPHY

    @property
    def supported_tasks(self) -> List[str]:
        return ['analyze_crypto_patterns', 'detect_ciphers', 'analyze_frequency', 'decrypt_content']

    async def execute_task(self, task: AgentTask) -> AgentResult:
        """Execute cryptography analysis using your existing CryptoIntelligenceService"""
        try:
            if task.task_type == 'analyze_crypto_patterns':
                return await self._analyze_crypto_patterns(task)
            elif task.task_type == 'detect_ciphers':
                return await self._detect_ciphers(task)
            elif task.task_type == 'analyze_frequency':
                return await self._analyze_frequency(task)
            elif task.task_type == 'decrypt_content':
                return await self._decrypt_content(task)
            else:
                return AgentResult(
                    task_id=task.task_id,
                    agent_id=self.agent_id,
                    success=False,
                    error=f"Unsupported task type: {task.task_type}"
                )
        except Exception as e:
            return AgentResult(
                task_id=task.task_id,
                agent_id=self.agent_id,
                success=False,
                error=f"Cryptography analysis error: {str(e)}"
            )

    async def _analyze_crypto_patterns(self, task: AgentTask) -> AgentResult:
        """Analyze cryptographic patterns in file content"""
        file_id = task.payload.get('file_id')

        with self.app.app_context():
            file_record = AnalysisFile.query.get(file_id)
            if not file_record:
                return AgentResult(
                    task_id=task.task_id,
                    agent_id=self.agent_id,
                    success=False,
                    error=f"File not found: {file_id}"
                )

            # Use your existing crypto intelligence service
            analysis = self.crypto_service.analyze_patterns(file_record.original_path)

            return AgentResult(
                task_id=task.task_id,
                agent_id=self.agent_id,
                success=True,
                data={
                    'file_id': file_id,
                    'crypto_analysis': analysis,
                    'patterns_found': analysis.get('patterns', []),
                    'confidence': analysis.get('confidence', 0.0)
                }
            )

    async def _detect_ciphers(self, task: AgentTask) -> AgentResult:
        """Detect potential cipher types"""
        content = task.payload.get('content', '')

        cipher_analysis = self.crypto_service.detect_ciphers(content)

        return AgentResult(
            task_id=task.task_id,
            agent_id=self.agent_id,
            success=True,
            data={
                'content_length': len(content),
                'detected_ciphers': cipher_analysis.get('ciphers', []),
                'confidence_scores': cipher_analysis.get('scores', {})
            }
        )

    async def _analyze_frequency(self, task: AgentTask) -> AgentResult:
        """Perform frequency analysis"""
        content = task.payload.get('content', '')

        frequency_analysis = self.crypto_service.frequency_analysis(content)

        return AgentResult(
            task_id=task.task_id,
            agent_id=self.agent_id,
            success=True,
            data={
                'frequency_distribution': frequency_analysis,
                'content_length': len(content)
            }
        )

    async def _decrypt_content(self, task: AgentTask) -> AgentResult:
        """Attempt to decrypt content"""
        content = task.payload.get('content', '')
        cipher_type = task.payload.get('cipher_type', 'auto')
        key = task.payload.get('key', '')

        decryption_result = self.crypto_service.decrypt(content, cipher_type, key)

        return AgentResult(
            task_id=task.task_id,
            agent_id=self.agent_id,
            success=decryption_result.get('success', False),
            data=decryption_result,
            error=decryption_result.get('error')
        )


class IntelligenceAgent(BaseAgent):
    """Agent for synthesizing findings across other agents"""

    @property
    def agent_type(self) -> AgentType:
        return AgentType.INTELLIGENCE

    @property
    def supported_tasks(self) -> List[str]:
        return ['synthesize_findings', 'correlate_results', 'generate_hypothesis', 'assess_confidence']

    async def execute_task(self, task: AgentTask) -> AgentResult:
        """Execute intelligence synthesis tasks"""
        try:
            if task.task_type == 'synthesize_findings':
                return await self._synthesize_findings(task)
            elif task.task_type == 'correlate_results':
                return await self._correlate_results(task)
            elif task.task_type == 'generate_hypothesis':
                return await self._generate_hypothesis(task)
            elif task.task_type == 'assess_confidence':
                return await self._assess_confidence(task)
            else:
                return AgentResult(
                    task_id=task.task_id,
                    agent_id=self.agent_id,
                    success=False,
                    error=f"Unsupported task type: {task.task_type}"
                )
        except Exception as e:
            return AgentResult(
                task_id=task.task_id,
                agent_id=self.agent_id,
                success=False,
                error=f"Intelligence synthesis error: {str(e)}"
            )

    async def _synthesize_findings(self, task: AgentTask) -> AgentResult:
        """Synthesize findings from multiple agents"""
        file_id = task.payload.get('file_id')

        with self.app.app_context():
            # Get all agent execution results for this file
            executions = db.session.execute(text("""
                                                 SELECT agent_type, task_type, success, metadata
                                                 FROM agent_executions
                                                 WHERE metadata::jsonb @> :file_filter
                                                 ORDER BY created_at DESC
                                                 """), {'file_filter': json.dumps({'file_id': file_id})}).fetchall()

            synthesis = {
                'file_id': file_id,
                'total_analyses': len(executions),
                'successful_analyses': sum(1 for e in executions if e.success),
                'agent_results': {},
                'confidence_score': 0.0,
                'recommendations': []
            }

            # Organize results by agent type
            for execution in executions:
                agent_type = execution.agent_type
                if agent_type not in synthesis['agent_results']:
                    synthesis['agent_results'][agent_type] = []

                synthesis['agent_results'][agent_type].append({
                    'task_type': execution.task_type,
                    'success': execution.success,
                    'metadata': json.loads(execution.metadata) if execution.metadata else {}
                })

            # Calculate overall confidence
            if synthesis['total_analyses'] > 0:
                synthesis['confidence_score'] = synthesis['successful_analyses'] / synthesis['total_analyses']

            # Generate recommendations based on results
            if 'steganography' in synthesis['agent_results']:
                synthesis['recommendations'].append('Steganography analysis completed')
            if 'cryptography' in synthesis['agent_results']:
                synthesis['recommendations'].append('Cryptographic patterns analyzed')

            return AgentResult(
                task_id=task.task_id,
                agent_id=self.agent_id,
                success=True,
                data=synthesis
            )


# Example of how to set up the complete system
async def setup_complete_agent_system():
    """Set up the complete agent system with all services integrated"""
    from agent_framework import OrchestrationAgent

    # Create orchestration agent
    orchestrator = OrchestrationAgent()

    # Create and register all agents
    file_agent = FileAnalysisAgent()
    steg_agent = SteganographyAgent()
    crypto_agent = CryptographyAgent()
    intel_agent = IntelligenceAgent()

    orchestrator.register_agent(file_agent)
    orchestrator.register_agent(steg_agent)
    orchestrator.register_agent(crypto_agent)
    orchestrator.register_agent(intel_agent)

    print("🤖 Multi-Agent System Ready!")
    print(f"📊 Registered {len(orchestrator.registry.agents)} agents")

    # Example: Process a file through the complete pipeline
    file_analysis_task = AgentTask(
        task_id=f"analyze_file_{uuid.uuid4().hex[:8]}",
        agent_type=AgentType.ORCHESTRATION,
        task_type='orchestrate',
        payload={'file_id': 1},  # Your file ID
        priority=TaskPriority.HIGH
    )

    orchestrator.task_queue.add_task(file_analysis_task)

    return orchestrator


class RecursiveExtractionAgent(BaseAgent):
    """
    Agent for performing comprehensive recursive extraction

    This agent implements a recursive extraction process that:
    1. Extracts content from files using multiple methods
    2. Uncompresses compressed files
    3. Decrypts encrypted files with a passphrase
    4. Performs XOR bitplane operations
    5. Avoids duplicate files and content
    6. Respects a maximum recursion depth
    7. Writes everything to the database
    """

    def __init__(self):
        super().__init__()
        self.processed_files = set()  # Track processed files by SHA256 hash
        self.processed_content = set()  # Track processed content by hash
        self.db_file_records = {}  # Cache of file records by hash

        # Create Flask app and application context
        self.app = create_app()
        self.app_context = self.app.app_context()
        self.app_context.push()

        # Create output directory
        os.makedirs(OUTPUT_DIR, exist_ok=True)

        # Initialize database connection
        try:
            # Test database connection
            db.session.execute(db.text('SELECT 1'))
            logger.info("Database connection successful")
            self.db_available = True
        except Exception as e:
            logger.error(f"Database connection failed: {e}")
            logger.warning("Continuing without database support - some features will be limited")
            self.db_available = False

    def __del__(self):
        """Clean up resources"""
        try:
            self.app_context.pop()
        except:
            pass

    @property
    def agent_type(self) -> AgentType:
        return AgentType.STEGANOGRAPHY

    @property
    def supported_tasks(self) -> List[str]:
        return ['recursive_extract', 'extract_with_method', 'xor_bitplanes', 'decrypt_with_passphrase']

    async def execute_task(self, task: AgentTask) -> AgentResult:
        """Execute recursive extraction tasks"""
        try:
            if task.task_type == 'recursive_extract':
                return await self._recursive_extract(task)
            elif task.task_type == 'extract_with_method':
                return await self._extract_with_method(task)
            elif task.task_type == 'xor_bitplanes':
                return await self._xor_bitplanes(task)
            elif task.task_type == 'decrypt_with_passphrase':
                return await self._decrypt_with_passphrase(task)
            else:
                return AgentResult(
                    task_id=task.task_id,
                    agent_id=self.agent_id,
                    success=False,
                    error=f"Unsupported task type: {task.task_type}"
                )
        except Exception as e:
            return AgentResult(
                task_id=task.task_id,
                agent_id=self.agent_id,
                success=False,
                error=f"Recursive extraction error: {str(e)}"
            )

    async def _recursive_extract(self, task: AgentTask) -> AgentResult:
        """Perform recursive extraction from a file"""
        file_path = task.payload.get('file_path', IMAGE_PATH)
        depth = task.payload.get('depth', 0)

        logger.info(f"Starting recursive extraction from {file_path} at depth {depth}")

        # Verify the file exists
        if not os.path.exists(file_path):
            return AgentResult(
                task_id=task.task_id,
                agent_id=self.agent_id,
                success=False,
                error=f"File not found: {file_path}"
            )

        # Check maximum depth
        if depth > MAX_DEPTH:
            return AgentResult(
                task_id=task.task_id,
                agent_id=self.agent_id,
                success=False,
                error=f"Maximum recursion depth reached: {depth}"
            )

        # Calculate file hash
        file_hash = self.calculate_file_hash(file_path)

        # Skip if already processed
        if file_hash in self.processed_files:
            return AgentResult(
                task_id=task.task_id,
                agent_id=self.agent_id,
                success=True,
                data={
                    'file_path': file_path,
                    'file_hash': file_hash,
                    'status': 'skipped',
                    'reason': 'already_processed'
                }
            )

        # Mark as processed
        self.processed_files.add(file_hash)

        # Get or create file record
        file_record = self.get_or_create_file_record(file_path)

        # Create file-specific output directory
        basename = os.path.basename(file_path)
        short_name = basename[:20] if len(basename) > 20 else basename
        file_output_dir = os.path.join(OUTPUT_DIR, f"{file_hash[:8]}_{short_name}")
        os.makedirs(file_output_dir, exist_ok=True)

        # Determine extraction methods
        extraction_methods = self.determine_extraction_methods(file_record)

        # Track extracted files
        all_extracted_files = []

        # Apply each extraction method
        for method in extraction_methods:
            extracted_files = self.extract_with_method(file_record, file_path, method, file_output_dir, depth)
            all_extracted_files.extend(extracted_files)

        # Special handling for XOR bitplane operations
        xor_extracted_files = self.perform_xor_bitplane_operations(file_record, file_path, file_output_dir, depth)
        all_extracted_files.extend(xor_extracted_files)

        # Special handling for encrypted files
        decrypted_files = self.try_decrypt_with_passphrase(file_record, file_path, file_output_dir, depth)
        all_extracted_files.extend(decrypted_files)

        # Special handling for compressed files
        decompressed_files = self.try_decompress_file(file_record, file_path, file_output_dir, depth)
        all_extracted_files.extend(decompressed_files)

        # Process each extracted file recursively
        for extracted_file in all_extracted_files:
            # Create a new task for recursive extraction
            subtask = AgentTask(
                task_id=f"recursive_extract_{os.path.basename(extracted_file)}",
                agent_type=self.agent_type,
                task_type='recursive_extract',
                payload={
                    'file_path': extracted_file,
                    'depth': depth + 1
                }
            )

            # Execute the subtask
            await self.execute_task(subtask)

        # Mark file as analyzed
        if file_record and self.db_available:
            file_record.status = FileStatus.ANALYZED
            file_record.analyzed_at = datetime.utcnow()
            db.session.commit()

        return AgentResult(
            task_id=task.task_id,
            agent_id=self.agent_id,
            success=True,
            data={
                'file_path': file_path,
                'file_hash': file_hash,
                'extracted_files': len(all_extracted_files),
                'extraction_methods': extraction_methods,
                'depth': depth
            }
        )

    async def _extract_with_method(self, task: AgentTask) -> AgentResult:
        """Extract content using a specific method"""
        file_path = task.payload.get('file_path')
        method = task.payload.get('method')
        depth = task.payload.get('depth', 0)

        # Get or create file record
        file_record = self.get_or_create_file_record(file_path)

        # Create output directory
        basename = os.path.basename(file_path)
        short_name = basename[:20] if len(basename) > 20 else basename
        file_hash = self.calculate_file_hash(file_path)
        file_output_dir = os.path.join(OUTPUT_DIR, f"{file_hash[:8]}_{short_name}")
        os.makedirs(file_output_dir, exist_ok=True)

        # Perform extraction
        extracted_files = self.extract_with_method(file_record, file_path, method, file_output_dir, depth)

        return AgentResult(
            task_id=task.task_id,
            agent_id=self.agent_id,
            success=True,
            data={
                'file_path': file_path,
                'method': method,
                'extracted_files': len(extracted_files),
                'extracted_paths': extracted_files
            }
        )

    async def _xor_bitplanes(self, task: AgentTask) -> AgentResult:
        """Perform XOR bitplane operations"""
        file_path = task.payload.get('file_path')
        depth = task.payload.get('depth', 0)

        # Get or create file record
        file_record = self.get_or_create_file_record(file_path)

        # Create output directory
        basename = os.path.basename(file_path)
        short_name = basename[:20] if len(basename) > 20 else basename
        file_hash = self.calculate_file_hash(file_path)
        file_output_dir = os.path.join(OUTPUT_DIR, f"{file_hash[:8]}_{short_name}")
        os.makedirs(file_output_dir, exist_ok=True)

        # Perform XOR bitplane operations
        extracted_files = self.perform_xor_bitplane_operations(file_record, file_path, file_output_dir, depth)

        return AgentResult(
            task_id=task.task_id,
            agent_id=self.agent_id,
            success=True,
            data={
                'file_path': file_path,
                'extracted_files': len(extracted_files),
                'extracted_paths': extracted_files
            }
        )

    async def _decrypt_with_passphrase(self, task: AgentTask) -> AgentResult:
        """Try to decrypt with passphrase"""
        file_path = task.payload.get('file_path')
        depth = task.payload.get('depth', 0)

        # Get or create file record
        file_record = self.get_or_create_file_record(file_path)

        # Create output directory
        basename = os.path.basename(file_path)
        short_name = basename[:20] if len(basename) > 20 else basename
        file_hash = self.calculate_file_hash(file_path)
        file_output_dir = os.path.join(OUTPUT_DIR, f"{file_hash[:8]}_{short_name}")
        os.makedirs(file_output_dir, exist_ok=True)

        # Try decryption
        extracted_files = self.try_decrypt_with_passphrase(file_record, file_path, file_output_dir, depth)

        return AgentResult(
            task_id=task.task_id,
            agent_id=self.agent_id,
            success=True,
            data={
                'file_path': file_path,
                'extracted_files': len(extracted_files),
                'extracted_paths': extracted_files
            }
        )

    def determine_extraction_methods(self, file_record: AnalysisFile) -> List[str]:
        """Determine appropriate extraction methods for the file"""
        # Get file type
        file_type = file_record.file_type.lower() if file_record.file_type else ""

        # Get recommended extractors for this file type
        recommended = get_recommended_extractors(file_type)

        # Add special extractors for comprehensive extraction
        all_extractors = list(set(recommended + [
            'binwalk',          # For general file carving
            'strings',          # For text extraction
            'exiftool',         # For metadata extraction
            'xor_bitplanes',    # For XOR bitplane operations
            'combined_bitplanes', # For combined bitplane operations
            'xor_decrypt',      # For XOR decryption
            'aes_decrypt',      # For AES decryption
            'base64',           # For base64 encoded content
            'hex'               # For hex encoded content
        ]))

        logger.info(f"Using extraction methods: {all_extractors}")
        return all_extractors

    def extract_with_method(self, file_record: AnalysisFile, file_path: str, 
                           method: str, output_dir: str, depth: int) -> List[str]:
        """Extract content using a specific method"""
        logger.info(f"Extracting from {os.path.basename(file_path)} using {method}")

        extracted_files = []

        try:
            # Get the extractor
            extractor = get_extractor(method)
            if not extractor:
                logger.warning(f"Extractor not found for method: {method}")
                return extracted_files

            # Set up parameters with passphrase for methods that support it
            parameters = {}
            if method in ['steghide', 'aes_decrypt', 'xor_decrypt']:
                parameters['password'] = PASSPHRASE

            # Perform extraction
            result = extractor.extract(file_path, parameters)

            if result.get('success'):
                # Handle extracted data
                if result.get('data') and len(result.get('data')) > 0:
                    # Check for duplicate content
                    content_hash = hashlib.sha256(result['data']).hexdigest()
                    if content_hash in self.processed_content:
                        logger.info(f"Skipping duplicate content from {method}")
                        return extracted_files

                    # Mark content as processed
                    self.processed_content.add(content_hash)

                    # Create output file
                    timestamp = datetime.now().strftime("%H%M%S")
                    output_filename = f"{method}_{content_hash[:8]}_{timestamp}.bin"
                    output_path = os.path.join(output_dir, output_filename)

                    with open(output_path, 'wb') as f:
                        f.write(result['data'])

                    logger.info(f"Extracted data saved to {output_path}")
                    extracted_files.append(output_path)

                    # Create extraction relationship
                    if self.db_available:
                        self.create_extraction_relationship(
                            file_record,
                            output_path,
                            method,
                            result.get('command_line', ''),
                            depth
                        )

                # Handle extracted files (if extractor returns file paths)
                if result.get('extracted_files'):
                    for ext_file in result.get('extracted_files', []):
                        if os.path.exists(ext_file):
                            # Check for duplicate file
                            ext_file_hash = self.calculate_file_hash(ext_file)
                            if ext_file_hash in self.processed_files:
                                logger.info(f"Skipping duplicate extracted file: {ext_file}")
                                continue

                            logger.info(f"Found extracted file: {ext_file}")
                            extracted_files.append(ext_file)

                            # Create extraction relationship
                            if self.db_available:
                                self.create_extraction_relationship(
                                    file_record,
                                    ext_file,
                                    method,
                                    result.get('command_line', ''),
                                    depth
                                )
            else:
                logger.warning(f"Extraction failed with {method}: {result.get('error', 'Unknown error')}")

        except Exception as e:
            logger.error(f"Error during extraction with {method}: {e}")

        return extracted_files

    def perform_xor_bitplane_operations(self, file_record: AnalysisFile, file_path: str, 
                                       output_dir: str, depth: int) -> List[str]:
        """Perform XOR bitplane operations on the file"""
        logger.info(f"Performing XOR bitplane operations on {os.path.basename(file_path)}")

        extracted_files = []

        try:
            # Check if file is an image
            file_type = file_record.file_type.lower() if file_record.file_type else ""
            if not ('image' in file_type or file_path.lower().endswith(('.png', '.bmp', '.jpg', '.jpeg', '.gif'))):
                logger.info(f"Skipping XOR bitplane operations for non-image file: {file_path}")
                return extracted_files

            # Get XOR bitplanes extractor
            xor_extractor = get_extractor('xor_bitplanes')
            if not xor_extractor:
                logger.warning("XOR bitplanes extractor not available")
                return extracted_files

            # Extract with XOR bitplanes
            result = xor_extractor.extract(file_path, {})

            if result.get('success') and result.get('data'):
                # Check for duplicate content
                content_hash = hashlib.sha256(result['data']).hexdigest()
                if content_hash in self.processed_content:
                    logger.info("Skipping duplicate XOR bitplane content")
                    return extracted_files

                # Mark content as processed
                self.processed_content.add(content_hash)

                # Save XOR bitplane result
                timestamp = datetime.now().strftime("%H%M%S")
                output_filename = f"xor_bitplanes_{content_hash[:8]}_{timestamp}.bin"
                output_path = os.path.join(output_dir, output_filename)

                with open(output_path, 'wb') as f:
                    f.write(result['data'])

                logger.info(f"XOR bitplane data saved to {output_path}")
                extracted_files.append(output_path)

                # Create extraction relationship
                if self.db_available:
                    self.create_extraction_relationship(
                        file_record,
                        output_path,
                        'xor_bitplanes',
                        result.get('command_line', ''),
                        depth
                    )

            # Get combined bitplanes extractor
            combined_extractor = get_extractor('combined_bitplanes')
            if not combined_extractor:
                logger.warning("Combined bitplanes extractor not available")
                return extracted_files

            # Extract with combined bitplanes
            result = combined_extractor.extract(file_path, {})

            if result.get('success') and result.get('data'):
                # Check for duplicate content
                content_hash = hashlib.sha256(result['data']).hexdigest()
                if content_hash in self.processed_content:
                    logger.info("Skipping duplicate combined bitplane content")
                    return extracted_files

                # Mark content as processed
                self.processed_content.add(content_hash)

                # Save combined bitplane result
                timestamp = datetime.now().strftime("%H%M%S")
                output_filename = f"combined_bitplanes_{content_hash[:8]}_{timestamp}.bin"
                output_path = os.path.join(output_dir, output_filename)

                with open(output_path, 'wb') as f:
                    f.write(result['data'])

                logger.info(f"Combined bitplane data saved to {output_path}")
                extracted_files.append(output_path)

                # Create extraction relationship
                if self.db_available:
                    self.create_extraction_relationship(
                        file_record,
                        output_path,
                        'combined_bitplanes',
                        result.get('command_line', ''),
                        depth
                    )

        except Exception as e:
            logger.error(f"Error during XOR bitplane operations: {e}")

        return extracted_files

    def try_decrypt_with_passphrase(self, file_record: AnalysisFile, file_path: str, 
                                   output_dir: str, depth: int) -> List[str]:
        """Try to decrypt the file with the passphrase"""
        logger.info(f"Trying to decrypt {os.path.basename(file_path)} with passphrase")

        extracted_files = []

        try:
            # Try with AES decryption
            aes_extractor = get_extractor('aes_decrypt')
            if aes_extractor:
                result = aes_extractor.extract(file_path, {'password': PASSPHRASE})

                if result.get('success') and result.get('data'):
                    # Check for duplicate content
                    content_hash = hashlib.sha256(result['data']).hexdigest()
                    if content_hash not in self.processed_content:
                        # Mark content as processed
                        self.processed_content.add(content_hash)

                        # Save decrypted result
                        timestamp = datetime.now().strftime("%H%M%S")
                        output_filename = f"aes_decrypted_{content_hash[:8]}_{timestamp}.bin"
                        output_path = os.path.join(output_dir, output_filename)

                        with open(output_path, 'wb') as f:
                            f.write(result['data'])

                        logger.info(f"AES decrypted data saved to {output_path}")
                        extracted_files.append(output_path)

                        # Create extraction relationship
                        if self.db_available:
                            self.create_extraction_relationship(
                                file_record,
                                output_path,
                                'aes_decrypt',
                                result.get('command_line', ''),
                                depth
                            )

            # Try with XOR decryption
            xor_extractor = get_extractor('xor_decrypt')
            if xor_extractor:
                result = xor_extractor.extract(file_path, {'password': PASSPHRASE})

                if result.get('success') and result.get('data'):
                    # Check for duplicate content
                    content_hash = hashlib.sha256(result['data']).hexdigest()
                    if content_hash not in self.processed_content:
                        # Mark content as processed
                        self.processed_content.add(content_hash)

                        # Save decrypted result
                        timestamp = datetime.now().strftime("%H%M%S")
                        output_filename = f"xor_decrypted_{content_hash[:8]}_{timestamp}.bin"
                        output_path = os.path.join(output_dir, output_filename)

                        with open(output_path, 'wb') as f:
                            f.write(result['data'])

                        logger.info(f"XOR decrypted data saved to {output_path}")
                        extracted_files.append(output_path)

                        # Create extraction relationship
                        if self.db_available:
                            self.create_extraction_relationship(
                                file_record,
                                output_path,
                                'xor_decrypt',
                                result.get('command_line', ''),
                                depth
                            )

            # Try with steghide (for JPEG and WAV files)
            file_type = file_record.file_type.lower() if file_record.file_type else ""
            if 'jpeg' in file_type or 'jpg' in file_type or 'wav' in file_type:
                steghide_extractor = get_extractor('steghide')
                if steghide_extractor:
                    result = steghide_extractor.extract(file_path, {'password': PASSPHRASE})

                    if result.get('success') and result.get('data'):
                        # Check for duplicate content
                        content_hash = hashlib.sha256(result['data']).hexdigest()
                        if content_hash not in self.processed_content:
                            # Mark content as processed
                            self.processed_content.add(content_hash)

                            # Save steghide result
                            timestamp = datetime.now().strftime("%H%M%S")
                            output_filename = f"steghide_{content_hash[:8]}_{timestamp}.bin"
                            output_path = os.path.join(output_dir, output_filename)

                            with open(output_path, 'wb') as f:
                                f.write(result['data'])

                            logger.info(f"Steghide extracted data saved to {output_path}")
                            extracted_files.append(output_path)

                            # Create extraction relationship
                            if self.db_available:
                                self.create_extraction_relationship(
                                    file_record,
                                    output_path,
                                    'steghide',
                                    result.get('command_line', ''),
                                    depth
                                )

        except Exception as e:
            logger.error(f"Error during decryption attempts: {e}")

        return extracted_files

    def try_decompress_file(self, file_record: AnalysisFile, file_path: str, 
                           output_dir: str, depth: int) -> List[str]:
        """Try to decompress the file"""
        logger.info(f"Trying to decompress {os.path.basename(file_path)}")

        extracted_files = []

        try:
            # Use binwalk for general decompression/extraction
            binwalk_extractor = get_extractor('binwalk')
            if binwalk_extractor:
                result = binwalk_extractor.extract(file_path, {'extract': True})

                if result.get('success'):
                    # Handle extracted files from binwalk
                    if result.get('metadata') and 'extracted_files' in result['metadata']:
                        for ext_file_info in result['metadata']['extracted_files']:
                            ext_file = ext_file_info.get('path')
                            if ext_file and os.path.exists(ext_file):
                                # Check for duplicate file
                                ext_file_hash = self.calculate_file_hash(ext_file)
                                if ext_file_hash in self.processed_files:
                                    logger.info(f"Skipping duplicate extracted file: {ext_file}")
                                    continue

                                # Copy the file to our output directory
                                filename = os.path.basename(ext_file)
                                output_path = os.path.join(output_dir, filename)
                                shutil.copy2(ext_file, output_path)

                                logger.info(f"Binwalk extracted file saved to {output_path}")
                                extracted_files.append(output_path)

                                # Create extraction relationship
                                if self.db_available:
                                    self.create_extraction_relationship(
                                        file_record,
                                        output_path,
                                        'binwalk',
                                        result.get('command_line', ''),
                                        depth
                                    )

        except Exception as e:
            logger.error(f"Error during decompression attempts: {e}")

        return extracted_files

    def create_extraction_relationship(self, source_file: AnalysisFile, 
                                      extracted_path: str, method: str, 
                                      command: str, depth: int):
        """Create extraction relationship in database"""
        # Skip if database is not available
        if not self.db_available:
            return

        # Get or create file record for extracted file
        extracted_file = self.get_or_create_file_record(extracted_path)

        if not extracted_file:
            logger.error(f"Failed to create file record for {extracted_path}")
            return

        try:
            # Create relationship
            relationship = ExtractionRelationship(
                source_file_id=source_file.id,
                source_file_sha=source_file.sha256_hash,
                extracted_file_id=extracted_file.id,
                extracted_file_sha=extracted_file.sha256_hash,
                extraction_method=method,
                extraction_command=command,
                extraction_depth=depth,
                created_at=datetime.utcnow()
            )

            db.session.add(relationship)
            db.session.commit()

            # Create file nodes and edge for visualization
            source_node = self.create_file_node(source_file, 'source', depth)
            target_node = self.create_file_node(extracted_file, 'extracted', depth + 1)

            if source_node and target_node:
                self.create_graph_edge(source_node, target_node, method)

            logger.info(f"Created extraction relationship: {source_file.filename} -> {extracted_file.filename} via {method}")

        except Exception as e:
            logger.error(f"Failed to create extraction relationship: {e}")
            db.session.rollback()

    def create_file_node(self, file: AnalysisFile, node_type: str, graph_level: int) -> Optional[FileNode]:
        """Create or get file node for visualization"""
        try:
            # Check if node already exists
            node = FileNode.query.filter_by(file_sha=file.sha256_hash).first()

            if not node:
                # Create new node
                node = FileNode(
                    file_id=file.id,
                    file_sha=file.sha256_hash,
                    node_type=node_type,
                    graph_level=graph_level,
                    node_color='#ff0000' if node_type == 'root' else '#0000ff',
                    node_size=15 if node_type == 'root' else 10,
                    extra_data={'extraction_depth': graph_level}
                )

                db.session.add(node)
                db.session.commit()

            return node

        except Exception as e:
            logger.error(f"Failed to create file node: {e}")
            db.session.rollback()
            return None

    def create_graph_edge(self, source_node: FileNode, target_node: FileNode, edge_type: str) -> Optional[GraphEdge]:
        """Create graph edge between nodes"""
        try:
            # Check if edge already exists
            edge = GraphEdge.query.filter_by(
                source_node_id=source_node.id,
                target_node_id=target_node.id
            ).first()

            if not edge:
                # Create new edge
                edge = GraphEdge(
                    source_node_id=source_node.id,
                    target_node_id=target_node.id,
                    edge_type=f"extracted_via_{edge_type}",
                    weight=1.0,
                    edge_color='#00ff00',
                    extra_data={'extraction_method': edge_type}
                )

                db.session.add(edge)
                db.session.commit()

            return edge

        except Exception as e:
            logger.error(f"Failed to create graph edge: {e}")
            db.session.rollback()
            return None

    def get_or_create_file_record(self, file_path: str) -> Optional[AnalysisFile]:
        """Get or create a file record in the database"""
        # Calculate file hash
        file_hash = self.calculate_file_hash(file_path)

        # Check if we already have this file in our cache
        if file_hash in self.db_file_records:
            return self.db_file_records[file_hash]

        # If database is not available, create a mock file record
        if not self.db_available:
            # Create a simple class to mimic AnalysisFile
            class MockFileRecord:
                def __init__(self, **kwargs):
                    for key, value in kwargs.items():
                        setattr(self, key, value)

            # Create a mock file record with a unique ID
            mock_id = len(self.db_file_records) + 1
            file_size = os.path.getsize(file_path)
            filename = os.path.basename(file_path)
            file_type = self.identify_file_type(file_path)

            file_record = MockFileRecord(
                id=mock_id,
                filename=filename,
                filepath=file_path,
                file_size=file_size,
                file_type=file_type,
                mime_type=file_type,
                sha256_hash=file_hash,
                status="PROCESSING",
                is_root_file=(file_path == IMAGE_PATH),
                created_at=datetime.utcnow()
            )

            logger.info(f"Created mock file record for {filename} with ID {mock_id} (no database)")
            self.db_file_records[file_hash] = file_record
            return file_record

        try:
            # Check if file exists in database
            file_record = AnalysisFile.query.filter_by(sha256_hash=file_hash).first()

            if not file_record:
                # Create new file record
                file_size = os.path.getsize(file_path)
                filename = os.path.basename(file_path)
                file_type = self.identify_file_type(file_path)

                file_record = AnalysisFile(
                    filename=filename,
                    filepath=file_path,
                    file_size=file_size,
                    file_type=file_type,
                    mime_type=file_type,
                    sha256_hash=file_hash,
                    status=FileStatus.PROCESSING,
                    is_root_file=(file_path == IMAGE_PATH),
                    created_by=ADMIN_USER_ID,
                    created_at=datetime.utcnow()
                )
                db.session.add(file_record)
                db.session.commit()
                logger.info(f"Created new file record for {filename} with ID {file_record.id}")
            else:
                logger.info(f"Found existing file record for {os.path.basename(file_path)} with ID {file_record.id}")

            # Cache the file record
            self.db_file_records[file_hash] = file_record

            return file_record

        except Exception as e:
            logger.error(f"Failed to get or create file record: {e}")
            if hasattr(db, 'session') and db.session:
                db.session.rollback()
            return None

    def calculate_file_hash(self, file_path: str) -> str:
        """Calculate SHA-256 hash of a file"""
        sha256_hash = hashlib.sha256()

        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)

        return sha256_hash.hexdigest()

    def identify_file_type(self, file_path: str) -> str:
        """Identify file type using magic"""
        try:
            import magic
            mime = magic.Magic(mime=True)
            return mime.from_file(file_path)
        except:
            # Fallback to extension-based identification
            ext = os.path.splitext(file_path)[1].lower()
            if ext == '.png':
                return 'image/png'
            elif ext in ['.jpg', '.jpeg']:
                return 'image/jpeg'
            elif ext == '.txt':
                return 'text/plain'
            elif ext == '.zip':
                return 'application/zip'
            else:
                return 'application/octet-stream'

if __name__ == '__main__':
    import asyncio

    async def run_recursive_extraction():
        """Run the recursive extraction process"""
        agent = RecursiveExtractionAgent()

        # Create initial task for recursive extraction
        task = AgentTask(
            task_id="recursive_extract_root",
            agent_type=agent.agent_type,
            task_type='recursive_extract',
            payload={
                'file_path': IMAGE_PATH,
                'depth': 0
            }
        )

        # Execute the task
        result = await agent.execute_task(task)

        logger.info("Recursive extraction completed")
        logger.info(f"Result: {result.success}")
        if result.data:
            logger.info(f"Extracted files: {result.data.get('extracted_files', 0)}")

    # Run the recursive extraction
    asyncio.run(run_recursive_extraction())
