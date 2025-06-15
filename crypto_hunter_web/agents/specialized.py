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
from crypto_hunter_web.services.file_analyzer import FileAnalyzer

logger = logging.getLogger(__name__)


class FileAnalysisAgent(BaseAgent):
    """Agent for file analysis using existing FileAnalyzer"""
    
    def __init__(self):
        super().__init__()
        self.file_analyzer = FileAnalyzer()
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
            elif task.task_type == 'extract_metadata':
                return await self._extract_metadata(task)
            elif task.task_type == 'calculate_entropy':
                return await self._calculate_entropy(task)
            elif task.task_type == 'detect_patterns':
                return await self._detect_patterns(task)
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
            with current_app.app_context():
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
        
        # Perform comprehensive analysis
        analysis_results = {}
        
        # File type detection
        file_type = self.file_analyzer.detect_file_type(file_path)
        analysis_results['file_type'] = file_type
        
        # Metadata extraction
        metadata = self.file_analyzer.extract_metadata(file_path)
        analysis_results['metadata'] = metadata
        
        # Entropy calculation
        entropy = self.file_analyzer.calculate_entropy(file_path)
        analysis_results['entropy'] = entropy
        
        # Pattern detection
        patterns = self.file_analyzer.detect_patterns(file_path)
        analysis_results['patterns'] = patterns
        
        # Determine next steps based on analysis
        next_tasks = []
        
        # If it's an image, suggest steganography analysis
        if file_type and file_type.startswith('image/'):
            next_tasks.append(AgentTask(
                task_type='extract_hidden_data',
                agent_type=AgentType.STEGANOGRAPHY,
                priority=TaskPriority.NORMAL,
                payload={'file_id': file_id, 'file_path': file_path, 'file_type': file_type},
                context=task.context
            ))
        
        # If high entropy, suggest crypto analysis
        if entropy and entropy > 7.0:
            next_tasks.append(AgentTask(
                task_type='analyze_crypto_patterns',
                agent_type=AgentType.CRYPTOGRAPHY,
                priority=TaskPriority.HIGH,
                payload={'file_id': file_id, 'file_path': file_path, 'entropy': entropy},
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
    
    async def _detect_patterns(self, task: AgentTask) -> AgentResult:
        """Detect patterns in file"""
        file_path = task.payload.get('file_path')
        patterns = self.file_analyzer.detect_patterns(file_path)
        
        return AgentResult(
            task_id=task.task_id,
            agent_id=self.agent_id,
            success=True,
            data={'patterns': patterns, 'file_path': file_path}
        )


class SteganographyAgent(BaseAgent):
    """Agent for steganography extraction using existing ExtractionEngine"""
    
    def __init__(self):
        super().__init__()
        # Import here to avoid circular imports
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
            'advanced_steganography': True,
            'frequency_domain_analysis': True
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
            'run_binwalk',
            'frequency_domain_analysis',
            'detect_steganography'
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
            elif task.task_type == 'run_advanced_extractors':
                return await self._run_advanced_extractors(task)
            elif task.task_type == 'run_zsteg':
                return await self._run_zsteg(task)
            elif task.task_type == 'run_steghide':
                return await self._run_steghide(task)
            elif task.task_type == 'run_binwalk':
                return await self._run_binwalk(task)
            elif task.task_type == 'frequency_domain_analysis':
                return await self._frequency_domain_analysis(task)
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
        file_path = task.payload.get('file_path')
        methods = task.payload.get('methods', ['zsteg', 'steghide', 'binwalk'])
        
        with current_app.app_context():
            if file_id:
                file_record = AnalysisFile.query.get(file_id)
                if not file_record:
                    return AgentResult(
                        task_id=task.task_id,
                        agent_id=self.agent_id,
                        success=False,
                        error=f"File not found: {file_id}"
                    )
                file_path = file_record.filepath
            
            extraction_results = {}
            extracted_files = []
            
            # Run each extraction method
            for method in methods:
                try:
                    if hasattr(self.extraction_engine, 'extract'):
                        result = self.extraction_engine.extract(
                            source_file=file_record if file_id else None,
                            file_path=file_path,
                            extraction_method=method,
                            user_id=1  # Admin user for agent tasks
                        )
                        extraction_results[method] = result
                        
                        # Collect extracted files
                        if result.get('success') and result.get('extracted_files'):
                            extracted_files.extend(result['extracted_files'])
                            
                except Exception as e:
                    extraction_results[method] = {'success': False, 'error': str(e)}
            
            # Count successful extractions
            successful_extractions = sum(1 for r in extraction_results.values() if r.get('success'))
            
            # Create next tasks for extracted files
            next_tasks = []
            for extracted_file in extracted_files:
                if os.path.exists(extracted_file):
                    next_tasks.append(AgentTask(
                        task_type='analyze_file',
                        agent_type=AgentType.FILE_ANALYSIS,
                        priority=TaskPriority.HIGH,
                        payload={'file_path': extracted_file},
                        context=task.context
                    ))
            
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
                },
                next_tasks=next_tasks
            )
    
    async def _run_basic_extractors(self, task: AgentTask) -> AgentResult:
        """Run basic steganography extractors"""
        basic_methods = ['zsteg', 'steghide', 'binwalk']
        task.payload['methods'] = basic_methods
        return await self._extract_hidden_data(task)
    
    async def _run_advanced_extractors(self, task: AgentTask) -> AgentResult:
        """Run advanced steganography extractors"""
        advanced_methods = [
            'zsteg_bitplane_1', 'zsteg_bitplane_2', 'zsteg_bitplane_3',
            'multilayer_stegano', 'frequency_domain', 'png_chunk_analyzer'
        ]
        task.payload['methods'] = advanced_methods
        return await self._extract_hidden_data(task)
    
    async def _run_zsteg(self, task: AgentTask) -> AgentResult:
        """Run zsteg specifically"""
        task.payload['methods'] = ['zsteg']
        return await self._extract_hidden_data(task)
    
    async def _run_steghide(self, task: AgentTask) -> AgentResult:
        """Run steghide specifically"""
        task.payload['methods'] = ['steghide']
        return await self._extract_hidden_data(task)
    
    async def _run_binwalk(self, task: AgentTask) -> AgentResult:
        """Run binwalk specifically"""
        task.payload['methods'] = ['binwalk']
        return await self._extract_hidden_data(task)
    
    async def _frequency_domain_analysis(self, task: AgentTask) -> AgentResult:
        """Perform frequency domain analysis"""
        task.payload['methods'] = ['frequency_domain']
        return await self._extract_hidden_data(task)
    
    async def _detect_steganography(self, task: AgentTask) -> AgentResult:
        """Detect potential steganography in file"""
        file_path = task.payload.get('file_path')
        
        # Run quick detection methods
        detection_results = {
            'has_steganography': False,
            'confidence': 0.0,
            'indicators': [],
            'recommended_extractors': []
        }
        
        # Use your existing detection logic here
        # This is a simplified version
        file_type = task.payload.get('file_type', '')
        
        if file_type.startswith('image/'):
            detection_results['recommended_extractors'] = ['zsteg', 'steghide']
            detection_results['indicators'].append('Image file type')
            detection_results['confidence'] = 0.6
        
        return AgentResult(
            task_id=task.task_id,
            agent_id=self.agent_id,
            success=True,
            data=detection_results
        )


class CryptographyAgent(BaseAgent):
    """Agent for cryptographic analysis using existing CryptoIntelligence"""
    
    def __init__(self):
        super().__init__()
        # Import here to avoid circular imports
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
            'entropy_analysis': True,
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
            'attempt_decryption',
            'analyze_entropy',
            'identify_encoding'
        ]
    
    async def execute_task(self, task: AgentTask) -> AgentResult:
        """Execute cryptographic analysis"""
        if not self.crypto_service:
            return AgentResult(
                task_id=task.task_id,
                agent_id=self.agent_id,
                success=False,
                error="CryptoIntelligence service not available"
            )
        
        try:
            if task.task_type == 'analyze_crypto_patterns':
                return await self._analyze_crypto_patterns(task)
            elif task.task_type == 'detect_ciphers':
                return await self._detect_ciphers(task)
            elif task.task_type == 'frequency_analysis':
                return await self._frequency_analysis(task)
            elif task.task_type == 'attempt_decryption':
                return await self._attempt_decryption(task)
            elif task.task_type == 'analyze_entropy':
                return await self._analyze_entropy(task)
            elif task.task_type == 'identify_encoding':
                return await self._identify_encoding(task)
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
        
        # Read file content
        with open(file_path, 'rb') as f:
            content = f.read(1024 * 1024)  # Read first 1MB
        
        # Use your existing crypto intelligence
        if hasattr(self.crypto_service, 'analyze_patterns'):
            analysis = self.crypto_service.analyze_patterns(content)
        else:
            # Fallback analysis
            analysis = {
                'patterns': [],
                'confidence': 0.0,
                'suggested_ciphers': []
            }
        
        return AgentResult(
            task_id=task.task_id,
            agent_id=self.agent_id,
            success=True,
            data={
                'file_path': file_path,
                'crypto_analysis': analysis,
                'patterns_found': analysis.get('patterns', []),
                'confidence': analysis.get('confidence', 0.0)
            }
        )
    
    async def _detect_ciphers(self, task: AgentTask) -> AgentResult:
        """Detect potential cipher types"""
        content = task.payload.get('content', '')
        file_path = task.payload.get('file_path', '')
        
        if file_path and not content:
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read(10000)  # Read first 10KB
            except:
                content = ''
        
        if hasattr(self.crypto_service, 'detect_ciphers'):
            cipher_analysis = self.crypto_service.detect_ciphers(content)
        else:
            # Fallback cipher detection
            cipher_analysis = {
                'ciphers': [],
                'scores': {}
            }
        
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
    
    async def _frequency_analysis(self, task: AgentTask) -> AgentResult:
        """Perform frequency analysis"""
        content = task.payload.get('content', '')
        file_path = task.payload.get('file_path', '')
        
        if file_path and not content:
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read(10000)
            except:
                content = ''
        
        if hasattr(self.crypto_service, 'frequency_analysis'):
            frequency_analysis = self.crypto_service.frequency_analysis(content)
        else:
            # Basic frequency analysis
            from collections import Counter
            frequency_analysis = dict(Counter(content.lower()))
        
        return AgentResult(
            task_id=task.task_id,
            agent_id=self.agent_id,
            success=True,
            data={
                'frequency_distribution': frequency_analysis,
                'content_length': len(content)
            }
        )
    
    async def _attempt_decryption(self, task: AgentTask) -> AgentResult:
        """Attempt to decrypt content"""
        content = task.payload.get('content', '')
        cipher_type = task.payload.get('cipher_type', 'auto')
        
        decryption_results = {
            'successful_decryptions': [],
            'attempted_methods': [],
            'best_result': None
        }
        
        # Use your existing decryption methods
        # This is a simplified version
        if hasattr(self.crypto_service, 'attempt_decryption'):
            results = self.crypto_service.attempt_decryption(content, cipher_type)
            decryption_results.update(results)
        
        return AgentResult(
            task_id=task.task_id,
            agent_id=self.agent_id,
            success=True,
            data=decryption_results
        )
    
    async def _analyze_entropy(self, task: AgentTask) -> AgentResult:
        """Analyze content entropy"""
        content = task.payload.get('content', b'')
        
        if isinstance(content, str):
            content = content.encode('utf-8')
        
        # Calculate entropy
        import math
        from collections import Counter
        
        if len(content) == 0:
            entropy = 0.0
        else:
            counts = Counter(content)
            entropy = -sum(count/len(content) * math.log2(count/len(content)) 
                          for count in counts.values())
        
        return AgentResult(
            task_id=task.task_id,
            agent_id=self.agent_id,
            success=True,
            data={
                'entropy': entropy,
                'content_length': len(content),
                'is_high_entropy': entropy > 7.0
            }
        )
    
    async def _identify_encoding(self, task: AgentTask) -> AgentResult:
        """Identify content encoding"""
        content = task.payload.get('content', '')
        
        encoding_results = {
            'detected_encodings': [],
            'confidence_scores': {}
        }
        
        # Basic encoding detection
        import base64
        import binascii
        
        # Check for base64
        try:
            decoded = base64.b64decode(content, validate=True)
            encoding_results['detected_encodings'].append('base64')
            encoding_results['confidence_scores']['base64'] = 0.8
        except:
            pass
        
        # Check for hex
        try:
            decoded = binascii.unhexlify(content.replace(' ', ''))
            encoding_results['detected_encodings'].append('hexadecimal')
            encoding_results['confidence_scores']['hexadecimal'] = 0.7
        except:
            pass
        
        return AgentResult(
            task_id=task.task_id,
            agent_id=self.agent_id,
            success=True,
            data=encoding_results
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
            'recommend_next_steps',
            'analyze_puzzle_state'
        ]
    
    async def execute_task(self, task: AgentTask) -> AgentResult:
        """Execute intelligence synthesis task"""
        try:
            if task.task_type == 'synthesize_findings':
                return await self._synthesize_findings(task)
            elif task.task_type == 'generate_hypotheses':
                return await self._generate_hypotheses(task)
            elif task.task_type == 'correlate_patterns':
                return await self._correlate_patterns(task)
            elif task.task_type == 'recommend_next_steps':
                return await self._recommend_next_steps(task)
            elif task.task_type == 'analyze_puzzle_state':
                return await self._analyze_puzzle_state(task)
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
        workflow_id = task.context.get('workflow_id')
        
        # Collect all findings from the workflow/session
        with current_app.app_context():
            findings = []
            if session_id:
                # Get findings from puzzle session
                from crypto_hunter_web.models import PuzzleSession
                session = PuzzleSession.query.filter_by(public_id=session_id).first()
                if session:
                    for step in session.steps:
                        findings.extend([sf.finding for sf in step.findings])
        
        # Analyze findings for patterns and connections
        synthesis = {
            'total_findings': len(findings),
            'categories': {},
            'confidence_scores': [],
            'connections': [],
            'summary': '',
            'key_insights': []
        }
        
        # Categorize findings
        for finding in findings:
            category = finding.category or 'uncategorized'
            if category not in synthesis['categories']:
                synthesis['categories'][category] = []
            synthesis['categories'][category].append({
                'title': finding.title,
                'confidence': finding.confidence_score or 0.0
            })
            
            if finding.confidence_score:
                synthesis['confidence_scores'].append(finding.confidence_score)
        
        # Generate insights
        if synthesis['confidence_scores']:
            avg_confidence = sum(synthesis['confidence_scores']) / len(synthesis['confidence_scores'])
            synthesis['summary'] = f"Analyzed {len(findings)} findings with average confidence {avg_confidence:.2f}"
            
            if avg_confidence > 0.8:
                synthesis['key_insights'].append("High confidence findings suggest clear patterns")
            elif avg_confidence < 0.3:
                synthesis['key_insights'].append("Low confidence findings require additional analysis")
        
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
        
        # Analyze available data to generate hypotheses
        if 'file_type' in data:
            file_type = data['file_type']
            if file_type.startswith('image/'):
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
    
    async def _correlate_patterns(self, task: AgentTask) -> AgentResult:
        """Correlate patterns across different analyses"""
        patterns = task.payload.get('patterns', [])
        
        correlations = []
        correlation_strength = 0.0
        
        # Simple pattern correlation logic
        # In a real implementation, this would be much more sophisticated
        pattern_types = [p.get('type', '') for p in patterns]
        
        if 'crypto' in pattern_types and 'steganography' in pattern_types:
            correlations.append({
                'type': 'crypto_steganography',
                'description': 'Both cryptographic and steganographic patterns detected',
                'strength': 0.8
            })
            correlation_strength = 0.8
        
        return AgentResult(
            task_id=task.task_id,
            agent_id=self.agent_id,
            success=True,
            data={
                'correlations': correlations,
                'correlation_strength': correlation_strength
            }
        )
    
    async def _recommend_next_steps(self, task: AgentTask) -> AgentResult:
        """Recommend next analysis steps"""
        current_state = task.payload
        
        recommendations = []
        
        # Based on current analysis state, recommend next steps
        if 'steganography_complete' not in current_state:
            recommendations.append({
                'action': 'steganography_analysis',
                'priority': 'high',
                'reason': 'Steganography analysis not yet performed'
            })
        
        if 'crypto_analysis_complete' not in current_state:
            recommendations.append({
                'action': 'cryptographic_analysis',
                'priority': 'medium',
                'reason': 'Cryptographic analysis recommended'
            })
        
        return AgentResult(
            task_id=task.task_id,
            agent_id=self.agent_id,
            success=True,
            data={'recommendations': recommendations}
        )
    
    async def _analyze_puzzle_state(self, task: AgentTask) -> AgentResult:
        """Analyze overall puzzle solving state"""
        session_id = task.context.get('session_id')
        
        puzzle_state = {
            'completion_percentage': 0.0,
            'active_leads': [],
            'dead_ends': [],
            'breakthrough_potential': 0.0,
            'recommended_focus': 'initial_analysis'
        }
        
        # Analyze puzzle session state
        if session_id:
            with current_app.app_context():
                from crypto_hunter_web.models import PuzzleSession
                session = PuzzleSession.query.filter_by(public_id=session_id).first()
                if session:
                    total_steps = len(session.steps)
                    completed_steps = len([s for s in session.steps if not s.is_active])
                    
                    if total_steps > 0:
                        puzzle_state['completion_percentage'] = (completed_steps / total_steps) * 100
        
        return AgentResult(
            task_id=task.task_id,
            agent_id=self.agent_id,
            success=True,
            data=puzzle_state
        )
