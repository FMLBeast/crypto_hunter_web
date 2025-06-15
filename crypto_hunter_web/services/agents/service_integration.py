#!/usr/bin/env python3
"""
Integration Guide: Converting Existing Services to Agent Pattern

This shows how to refactor your existing FileAnalyzer, ExtractionEngine, 
and CryptoIntelligenceService into the new agent framework.
"""

import sys
import os
import json
import uuid
import re
from typing import List, Dict, Any
from sqlalchemy import text

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from crypto_hunter_web.services.agents.agent_framework import BaseAgent, AgentType, AgentTask, AgentResult, TaskPriority, AgentCapability
from crypto_hunter_web import create_app, db
from crypto_hunter_web.models import AnalysisFile, FileStatus
from crypto_hunter_web.services.file_analyzer import FileAnalyzer
from crypto_hunter_web.services.extraction_engine import ExtractionEngine
from crypto_hunter_web.services.crypto_intelligence_service import CryptoIntelligenceService
from crypto_hunter_web.services.extractors import get_extractor


class FileAnalysisAgent(BaseAgent):
    """Agent wrapper for your existing FileAnalyzer service"""

    def __init__(self):
        agent_id = f"file_analysis_{uuid.uuid4().hex[:8]}"
        capabilities = [AgentCapability.FILE_ANALYSIS]
        super().__init__(agent_id, capabilities)
        self.file_analyzer = FileAnalyzer()
        self.app = create_app()

    @property
    def agent_type(self) -> AgentType:
        return AgentType.FILE_ANALYSIS

    @property
    def supported_tasks(self) -> List[str]:
        return ['analyze_file', 'calculate_entropy', 'detect_file_type', 'extract_metadata']

    async def execute(self, task: AgentTask) -> AgentResult:
        """Execute file analysis using your existing FileAnalyzer"""
        try:
            action = task.input_data.get('action', '')
            if action == 'analyze_file':
                return await self._analyze_file(task)
            elif action == 'calculate_entropy':
                return await self._calculate_entropy(task)
            elif action == 'detect_file_type':
                return await self._detect_file_type(task)
            elif action == 'extract_metadata':
                return await self._extract_metadata(task)
            else:
                return AgentResult(
                    task_id=task.task_id,
                    agent_id=self.agent_id,
                    success=False,
                    output_data={},
                    error_message=f"Unsupported action: {action}"
                )
        except Exception as e:
            return AgentResult(
                task_id=task.task_id,
                agent_id=self.agent_id,
                success=False,
                output_data={},
                error_message=f"File analysis error: {str(e)}"
            )

    async def _analyze_file(self, task: AgentTask) -> AgentResult:
        """Perform complete file analysis"""
        file_id = task.input_data.get('file_id')

        with self.app.app_context():
            file_record = AnalysisFile.query.get(file_id)
            if not file_record:
                return AgentResult(
                    task_id=task.task_id,
                    agent_id=self.agent_id,
                    success=False,
                    output_data={},
                    error_message=f"File not found: {file_id}"
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
                output_data={
                    'file_id': file_id,
                    'analysis': analysis_result,
                    'entropy': analysis_result.get('entropy'),
                    'file_type': analysis_result.get('file_type'),
                    'contains_crypto': analysis_result.get('contains_crypto')
                }
            )

    async def _calculate_entropy(self, task: AgentTask) -> AgentResult:
        """Calculate file entropy"""
        file_path = task.input_data.get('file_path')

        entropy = self.file_analyzer.calculate_entropy(file_path)

        return AgentResult(
            task_id=task.task_id,
            agent_id=self.agent_id,
            success=True,
            output_data={'entropy': entropy, 'file_path': file_path}
        )

    async def _detect_file_type(self, task: AgentTask) -> AgentResult:
        """Detect file type"""
        file_path = task.input_data.get('file_path')

        file_type = self.file_analyzer.detect_file_type(file_path)

        return AgentResult(
            task_id=task.task_id,
            agent_id=self.agent_id,
            success=True,
            output_data={'file_type': file_type, 'file_path': file_path}
        )

    async def _extract_metadata(self, task: AgentTask) -> AgentResult:
        """Extract file metadata"""
        file_path = task.input_data.get('file_path')

        metadata = self.file_analyzer.extract_metadata(file_path)

        return AgentResult(
            task_id=task.task_id,
            agent_id=self.agent_id,
            success=True,
            output_data={'metadata': metadata, 'file_path': file_path}
        )


class SteganographyAgent(BaseAgent):
    """Agent wrapper for your existing ExtractionEngine"""

    def __init__(self):
        agent_id = f"steganography_{uuid.uuid4().hex[:8]}"
        capabilities = [AgentCapability.STEGANOGRAPHY]
        super().__init__(agent_id, capabilities)
        self.extraction_engine = ExtractionEngine()
        self.app = create_app()

    @property
    def agent_type(self) -> AgentType:
        return AgentType.STEGANOGRAPHY

    @property
    def supported_tasks(self) -> List[str]:
        return ['extract_hidden_data', 'run_zsteg', 'run_steghide', 'run_binwalk', 'detect_steganography']

    async def execute(self, task: AgentTask) -> AgentResult:
        """Execute steganography analysis using your existing ExtractionEngine"""
        try:
            action = task.input_data.get('action', '')
            if action == 'extract_hidden_data':
                return await self._extract_hidden_data(task)
            elif action == 'run_zsteg':
                return await self._run_zsteg(task)
            elif action == 'run_steghide':
                return await self._run_steghide(task)
            elif action == 'run_binwalk':
                return await self._run_binwalk(task)
            elif action == 'detect_steganography':
                return await self._detect_steganography(task)
            else:
                return AgentResult(
                    task_id=task.task_id,
                    agent_id=self.agent_id,
                    success=False,
                    output_data={},
                    error_message=f"Unsupported action: {action}"
                )
        except Exception as e:
            return AgentResult(
                task_id=task.task_id,
                agent_id=self.agent_id,
                success=False,
                output_data={},
                error_message=f"Steganography analysis error: {str(e)}"
            )

    async def _extract_hidden_data(self, task: AgentTask) -> AgentResult:
        """Run comprehensive steganography extraction"""
        file_id = task.input_data.get('file_id')
        methods = task.input_data.get('methods', ['zsteg', 'steghide', 'binwalk'])

        with self.app.app_context():
            file_record = AnalysisFile.query.get(file_id)
            if not file_record:
                return AgentResult(
                    task_id=task.task_id,
                    agent_id=self.agent_id,
                    success=False,
                    output_data={},
                    error_message=f"File not found: {file_id}"
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
                output_data={
                    'file_id': file_id,
                    'methods_run': methods,
                    'successful_extractions': successful_extractions,
                    'results': extraction_results
                }
            )

    async def _run_zsteg(self, task: AgentTask) -> AgentResult:
        """Run zsteg extraction specifically"""
        file_path = task.input_data.get('file_path')

        # Use your existing zsteg extractor
        zsteg_extractor = get_extractor('zsteg')
        result = zsteg_extractor.extract(file_path, {})

        return AgentResult(
            task_id=task.task_id,
            agent_id=self.agent_id,
            success=result['success'],
            output_data=result,
            error_message=result.get('error')
        )

    async def _run_steghide(self, task: AgentTask) -> AgentResult:
        """Run steghide extraction specifically"""
        file_path = task.input_data.get('file_path')
        password = task.input_data.get('password', '')

        steghide_extractor = get_extractor('steghide')
        result = steghide_extractor.extract(file_path, {'password': password})

        return AgentResult(
            task_id=task.task_id,
            agent_id=self.agent_id,
            success=result['success'],
            output_data=result,
            error_message=result.get('error')
        )

    async def _run_binwalk(self, task: AgentTask) -> AgentResult:
        """Run binwalk extraction specifically"""
        file_path = task.input_data.get('file_path')

        binwalk_extractor = get_extractor('binwalk')
        result = binwalk_extractor.extract(file_path, {})

        return AgentResult(
            task_id=task.task_id,
            agent_id=self.agent_id,
            success=result['success'],
            output_data=result,
            error_message=result.get('error')
        )

    async def _detect_steganography(self, task: AgentTask) -> AgentResult:
        """Detect potential steganography without extraction"""
        file_id = task.input_data.get('file_id')

        # This would use pattern detection to identify potential steganography
        # For now, return a placeholder
        return AgentResult(
            task_id=task.task_id,
            agent_id=self.agent_id,
            success=True,
            output_data={
                'file_id': file_id,
                'steganography_detected': False,  # Placeholder
                'confidence': 0.5,
                'indicators': []
            }
        )


class CryptographyAgent(BaseAgent):
    """Agent wrapper for your existing CryptoIntelligenceService"""

    def __init__(self):
        agent_id = f"cryptography_{uuid.uuid4().hex[:8]}"
        capabilities = [AgentCapability.CRYPTOGRAPHY]
        super().__init__(agent_id, capabilities)
        self.crypto_service = CryptoIntelligenceService()
        self.app = create_app()

    @property
    def agent_type(self) -> AgentType:
        return AgentType.CRYPTOGRAPHY

    @property
    def supported_tasks(self) -> List[str]:
        return ['analyze_crypto_patterns', 'detect_ciphers', 'analyze_frequency', 'decrypt_content']

    async def execute(self, task: AgentTask) -> AgentResult:
        """Execute cryptography analysis using your existing CryptoIntelligenceService"""
        try:
            action = task.input_data.get('action', '')
            if action == 'analyze_crypto_patterns':
                return await self._analyze_crypto_patterns(task)
            elif action == 'detect_ciphers':
                return await self._detect_ciphers(task)
            elif action == 'analyze_frequency':
                return await self._analyze_frequency(task)
            elif action == 'decrypt_content':
                return await self._decrypt_content(task)
            else:
                return AgentResult(
                    task_id=task.task_id,
                    agent_id=self.agent_id,
                    success=False,
                    output_data={},
                    error_message=f"Unsupported action: {action}"
                )
        except Exception as e:
            return AgentResult(
                task_id=task.task_id,
                agent_id=self.agent_id,
                success=False,
                output_data={},
                error_message=f"Cryptography analysis error: {str(e)}"
            )

    async def _analyze_crypto_patterns(self, task: AgentTask) -> AgentResult:
        """Analyze cryptographic patterns in file content"""
        file_id = task.input_data.get('file_id')

        with self.app.app_context():
            file_record = AnalysisFile.query.get(file_id)
            if not file_record:
                return AgentResult(
                    task_id=task.task_id,
                    agent_id=self.agent_id,
                    success=False,
                    output_data={},
                    error_message=f"File not found: {file_id}"
                )

            # Use your existing crypto intelligence service
            analysis = self.crypto_service.analyze_patterns(file_record.original_path)

            return AgentResult(
                task_id=task.task_id,
                agent_id=self.agent_id,
                success=True,
                output_data={
                    'file_id': file_id,
                    'crypto_analysis': analysis,
                    'patterns_found': analysis.get('patterns', []),
                    'confidence': analysis.get('confidence', 0.0)
                }
            )

    async def _detect_ciphers(self, task: AgentTask) -> AgentResult:
        """Detect potential cipher types"""
        content = task.input_data.get('content', '')

        cipher_analysis = self.crypto_service.detect_ciphers(content)

        return AgentResult(
            task_id=task.task_id,
            agent_id=self.agent_id,
            success=True,
            output_data={
                'content_length': len(content),
                'detected_ciphers': cipher_analysis.get('ciphers', []),
                'confidence_scores': cipher_analysis.get('scores', {})
            }
        )

    async def _analyze_frequency(self, task: AgentTask) -> AgentResult:
        """Perform frequency analysis"""
        content = task.input_data.get('content', '')

        frequency_analysis = self.crypto_service.frequency_analysis(content)

        return AgentResult(
            task_id=task.task_id,
            agent_id=self.agent_id,
            success=True,
            output_data={
                'frequency_distribution': frequency_analysis,
                'content_length': len(content)
            }
        )

    async def _decrypt_content(self, task: AgentTask) -> AgentResult:
        """Attempt to decrypt content"""
        content = task.input_data.get('content', '')
        cipher_type = task.input_data.get('cipher_type', 'auto')
        key = task.input_data.get('key', '')

        decryption_result = self.crypto_service.decrypt(content, cipher_type, key)

        return AgentResult(
            task_id=task.task_id,
            agent_id=self.agent_id,
            success=decryption_result.get('success', False),
            output_data=decryption_result,
            error_message=decryption_result.get('error')
        )


class IntelligenceAgent(BaseAgent):
    """Agent for synthesizing findings across other agents"""

    def __init__(self):
        agent_id = f"intelligence_{uuid.uuid4().hex[:8]}"
        capabilities = [AgentCapability.INTELLIGENCE]
        super().__init__(agent_id, capabilities)
        self.app = create_app()

    @property
    def agent_type(self) -> AgentType:
        return AgentType.INTELLIGENCE

    @property
    def supported_tasks(self) -> List[str]:
        return ['synthesize_findings', 'correlate_results', 'generate_hypothesis', 'assess_confidence']

    async def execute(self, task: AgentTask) -> AgentResult:
        """Execute intelligence synthesis tasks"""
        try:
            action = task.input_data.get('action', '')
            if action == 'synthesize_findings':
                return await self._synthesize_findings(task)
            elif action == 'correlate_results':
                return await self._correlate_results(task)
            elif action == 'generate_hypothesis':
                return await self._generate_hypothesis(task)
            elif action == 'assess_confidence':
                return await self._assess_confidence(task)
            else:
                return AgentResult(
                    task_id=task.task_id,
                    agent_id=self.agent_id,
                    success=False,
                    output_data={},
                    error_message=f"Unsupported action: {action}"
                )
        except Exception as e:
            return AgentResult(
                task_id=task.task_id,
                agent_id=self.agent_id,
                success=False,
                output_data={},
                error_message=f"Intelligence synthesis error: {str(e)}"
            )

    async def _synthesize_findings(self, task: AgentTask) -> AgentResult:
        """Synthesize findings from multiple agents"""
        file_id = task.input_data.get('file_id')

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
                output_data=synthesis
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
        input_data={
            'file_id': 1,  # Your file ID
            'action': 'orchestrate'
        },
        priority=TaskPriority.HIGH
    )

    orchestrator.task_queue.add_task(file_analysis_task)

    return orchestrator


if __name__ == '__main__':
    import asyncio

    # Test the integrated system
    asyncio.run(setup_complete_agent_system())
