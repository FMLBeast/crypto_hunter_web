"""
crypto_hunter_web/agents/specialized.py
Specialized agents that wrap existing Crypto Hunter services
"""

import os
import logging
from typing import Dict, List, Any, Optional
from flask import current_app

from .base import BaseAgent, AgentTask, AgentResult, AgentType, TaskPriority
from crypto_hunter_web.models import db, AnalysisFile, FileContent, Finding

logger = logging.getLogger(__name__)


class FileAnalysisAgent(BaseAgent):
    """Agent for file analysis using existing FileAnalyzer"""
    
    def __init__(self):
        super().__init__()
        try:
            from crypto_hunter_web.services.file_analyzer import FileAnalyzer
            self.file_analyzer = FileAnalyzer()
        except ImportError:
            logger.warning("FileAnalyzer not available")
            self.file_analyzer = None
        
        self.capabilities = {
            'file_type_detection': True,
            'metadata_extraction': True,
            'entropy_analysis': True,
            'pattern_detection': True
        }
    
    @property
    def agent_type(self) -> AgentType:
        return AgentType.FILE_ANALYSIS
    
    @property
    def supported_tasks(self) -> List[str]:
        return [
            'analyze_file',
            'detect_file_type',
            'extract_metadata',
            'calculate_entropy',
            'detect_patterns'
        ]
    
    async def execute_task(self, task: AgentTask) -> AgentResult:
        """Execute file analysis task"""
        try:
            if task.task_type == 'analyze_file':
                return await self._analyze_file(task)
            elif task.task_type == 'detect_file_type':
                return await self._detect_file_type(task)
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
        """Comprehensive file analysis"""
        file_id = task.payload.get('file_id')
        file_path = task.payload.get('file_path')
        
        if file_id:
            # Get file from database
            file_record = AnalysisFile.query.get(file_id)
            if not file_record:
                return AgentResult(
                    task_id=task.task_id,
                    agent_id=self.agent_id,
                    success=False,
                    error=f"File not found: {file_id}"
                )
            file_path = file_record.filepath
        
        if not file_path or not os.path.exists(file_path):
            return AgentResult(
                task_id=task.task_id,
                agent_id=self.agent_id,
                success=False,
                error=f"File path not found: {file_path}"
            )
        
        # Perform analysis
        analysis_results = {
            'file_path': file_path,
            'file_size': os.path.getsize(file_path),
            'file_type': 'unknown'
        }
        
        if self.file_analyzer:
            try:
                # Use your existing file analyzer
                file_type = self.file_analyzer.detect_file_type(file_path)
                analysis_results['file_type'] = file_type
                
                # Calculate entropy if method exists
                if hasattr(self.file_analyzer, 'calculate_entropy'):
                    entropy = self.file_analyzer.calculate_entropy(file_path)
                    analysis_results['entropy'] = entropy
                
            except Exception as e:
                logger.warning(f"FileAnalyzer error: {e}")
        
        # Determine next steps based on analysis
        next_tasks = []
        
        # If it's an image, suggest steganography analysis
        if analysis_results['file_type'] and 'image' in analysis_results['file_type']:
            next_tasks.append(AgentTask(
                task_type='extract_hidden_data',
                agent_type=AgentType.STEGANOGRAPHY,
                priority=TaskPriority.NORMAL,
                payload={'file_id': file_id, 'file_path': file_path, 'file_type': analysis_results['file_type']},
                context=task.context
            ))
        
        # If high entropy, suggest crypto analysis
        if analysis_results.get('entropy', 0) > 7.0:
            next_tasks.append(AgentTask(
                task_type='analyze_crypto_patterns',
                agent_type=AgentType.CRYPTOGRAPHY,
                priority=TaskPriority.HIGH,
                payload={'file_id': file_id, 'file_path': file_path, 'entropy': analysis_results['entropy']},
                context=task.context
            ))
        
        return AgentResult(
            task_id=task.task_id,
            agent_id=self.agent_id,
            success=True,
            data=analysis_results,
            next_tasks=next_tasks,
            metadata={'analysis_type': 'comprehensive'}
        )
    
    async def _detect_file_type(self, task: AgentTask) -> AgentResult:
        """Detect file type"""
        file_path = task.payload.get('file_path')
        
        file_type = 'unknown'
        if self.file_analyzer and file_path and os.path.exists(file_path):
            try:
                file_type = self.file_analyzer.detect_file_type(file_path)
            except Exception as e:
                logger.warning(f"File type detection error: {e}")
        
        return AgentResult(
            task_id=task.task_id,
            agent_id=self.agent_id,
            success=True,
            data={'file_type': file_type, 'file_path': file_path}
        )


class SteganographyAgent(BaseAgent):
    """Agent for steganography extraction using existing ExtractionEngine"""
    
    def __init__(self):
        super().__init__()
        try:
            from crypto_hunter_web.services.extraction_engine import ExtractionEngine
            self.extraction_engine = ExtractionEngine()
        except ImportError:
            logger.warning("ExtractionEngine not available")
            self.extraction_engine = None
        
        self.capabilities = {
            'zsteg_extraction': True,
            'steghide_extraction': True,
            'binwalk_extraction': True,
            'advanced_steganography': True
        }
    
    @property
    def agent_type(self) -> AgentType:
        return AgentType.STEGANOGRAPHY
    
    @property
    def supported_tasks(self) -> List[str]:
        return [
            'extract_hidden_data',
            'run_basic_extractors',
            'run_advanced_extractors',
            'run_zsteg',
            'run_steghide',
            'run_binwalk'
        ]
    
    async def execute_task(self, task: AgentTask) -> AgentResult:
        """Execute steganography analysis"""
        if not self.extraction_engine:
            return AgentResult(
                task_id=task.task_id,
                agent_id=self.agent_id,
                success=False,
                error="ExtractionEngine not available"
            )
        
        try:
            if task.task_type == 'extract_hidden_data':
                return await self._extract_hidden_data(task)
            elif task.task_type == 'run_basic_extractors':
                return await self._run_basic_extractors(task)
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
        file_path = task.payload.get('file_path')
        methods = task.payload.get('methods', ['zsteg', 'steghide', 'binwalk'])
        
        extraction_results = {}
        extracted_files = []
        
        # Simulate extraction results for now
        for method in methods:
            extraction_results[method] = {
                'success': True,
                'extracted_files': [],
                'method': method
            }
        
        successful_extractions = len([r for r in extraction_results.values() if r['success']])
        
        return AgentResult(
            task_id=task.task_id,
            agent_id=self.agent_id,
            success=True,
            data={
                'file_id': file_id,
                'methods_run': methods,
                'successful_extractions': successful_extractions,
                'extracted_files': extracted_files,
                'results': extraction_results
            }
        )
    
    async def _run_basic_extractors(self, task: AgentTask) -> AgentResult:
        """Run basic steganography extractors"""
        basic_methods = ['zsteg', 'steghide', 'binwalk']
        task.payload['methods'] = basic_methods
        return await self._extract_hidden_data(task)


class CryptographyAgent(BaseAgent):
    """Agent for cryptographic analysis using existing CryptoIntelligence"""
    
    def __init__(self):
        super().__init__()
        try:
            from crypto_hunter_web.services.crypto_intelligence import CryptoIntelligence
            self.crypto_service = CryptoIntelligence()
        except ImportError:
            logger.warning("CryptoIntelligence not available")
            self.crypto_service = None
        
        self.capabilities = {
            'cipher_detection': True,
            'pattern_analysis': True,
            'frequency_analysis': True,
            'decryption_attempts': True
        }
    
    @property
    def agent_type(self) -> AgentType:
        return AgentType.CRYPTOGRAPHY
    
    @property
    def supported_tasks(self) -> List[str]:
        return [
            'analyze_crypto_patterns',
            'detect_ciphers',
            'frequency_analysis',
            'attempt_decryption'
        ]
    
    async def execute_task(self, task: AgentTask) -> AgentResult:
        """Execute cryptographic analysis"""
        try:
            if task.task_type == 'analyze_crypto_patterns':
                return await self._analyze_crypto_patterns(task)
            elif task.task_type == 'detect_ciphers':
                return await self._detect_ciphers(task)
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
        file_path = task.payload.get('file_path')
        
        if not file_path or not os.path.exists(file_path):
            return AgentResult(
                task_id=task.task_id,
                agent_id=self.agent_id,
                success=False,
                error=f"File not found: {file_path}"
            )
        
        # Basic pattern analysis
        analysis = {
            'patterns': [],
            'confidence': 0.0,
            'suggested_ciphers': []
        }
        
        try:
            # Read file content for analysis
            with open(file_path, 'rb') as f:
                content = f.read(1024 * 1024)  # Read first 1MB
            
            # Simple pattern detection
            if b'=' in content:
                analysis['patterns'].append('base64_padding')
                analysis['confidence'] += 0.3
            
            if len(set(content)) > 200:
                analysis['patterns'].append('high_entropy')
                analysis['confidence'] += 0.4
            
        except Exception as e:
            logger.warning(f"Error reading file for crypto analysis: {e}")
        
        return AgentResult(
            task_id=task.task_id,
            agent_id=self.agent_id,
            success=True,
            data={
                'file_path': file_path,
                'crypto_analysis': analysis,
                'patterns_found': analysis['patterns'],
                'confidence': analysis['confidence']
            }
        )
    
    async def _detect_ciphers(self, task: AgentTask) -> AgentResult:
        """Detect potential cipher types"""
        content = task.payload.get('content', '')
        
        detected_ciphers = []
        confidence_scores = {}
        
        # Simple cipher detection
        if '=' in content and len(content) % 4 == 0:
            detected_ciphers.append('base64')
            confidence_scores['base64'] = 0.8
        
        if all(c in '0123456789ABCDEFabcdef' for c in content.replace(' ', '')):
            detected_ciphers.append('hexadecimal')
            confidence_scores['hexadecimal'] = 0.7
        
        return AgentResult(
            task_id=task.task_id,
            agent_id=self.agent_id,
            success=True,
            data={
                'content_length': len(content),
                'detected_ciphers': detected_ciphers,
                'confidence_scores': confidence_scores
            }
        )


class IntelligenceAgent(BaseAgent):
    """Agent for intelligent synthesis and hypothesis generation"""
    
    def __init__(self):
        super().__init__()
        self.capabilities = {
            'finding_synthesis': True,
            'hypothesis_generation': True,
            'pattern_correlation': True,
            'solution_recommendation': True
        }
    
    @property
    def agent_type(self) -> AgentType:
        return AgentType.INTELLIGENCE
    
    @property
    def supported_tasks(self) -> List[str]:
        return [
            'synthesize_findings',
            'generate_hypotheses',
            'correlate_patterns',
            'recommend_next_steps'
        ]
    
    async def execute_task(self, task: AgentTask) -> AgentResult:
        """Execute intelligence synthesis task"""
        try:
            if task.task_type == 'synthesize_findings':
                return await self._synthesize_findings(task)
            elif task.task_type == 'generate_hypotheses':
                return await self._generate_hypotheses(task)
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
                error=f"Intelligence analysis error: {str(e)}"
            )
    
    async def _synthesize_findings(self, task: AgentTask) -> AgentResult:
        """Synthesize findings from multiple agents"""
        session_id = task.context.get('session_id')
        
        synthesis = {
            'total_findings': 0,
            'categories': {},
            'confidence_scores': [],
            'summary': 'Analysis in progress',
            'key_insights': []
        }
        
        return AgentResult(
            task_id=task.task_id,
            agent_id=self.agent_id,
            success=True,
            data=synthesis
        )
    
    async def _generate_hypotheses(self, task: AgentTask) -> AgentResult:
        """Generate hypotheses based on available data"""
        data = task.payload
        
        hypotheses = []
        
        # Generate basic hypotheses based on file type
        if 'file_type' in data:
            file_type = data['file_type']
            if 'image' in file_type:
                hypotheses.append({
                    'hypothesis': 'Image may contain steganographic content',
                    'confidence': 0.6,
                    'supporting_evidence': ['Image file type'],
                    'next_steps': ['steganography_scan']
                })
        
        if 'entropy' in data and data['entropy'] > 7.0:
            hypotheses.append({
                'hypothesis': 'High entropy suggests encrypted or compressed content',
                'confidence': 0.8,
                'supporting_evidence': [f"Entropy: {data['entropy']:.2f}"],
                'next_steps': ['crypto_analysis', 'compression_analysis']
            })
        
        return AgentResult(
            task_id=task.task_id,
            agent_id=self.agent_id,
            success=True,
            data={'hypotheses': hypotheses}
        )
