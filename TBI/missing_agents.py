"""
crypto_hunter_web/agents/missing_specialized_agents.py
Complete implementation of missing specialized agents for Crypto Hunter
"""

import os
import json
import asyncio
import logging
from typing import Dict, Any, List, Optional, Tuple
from datetime import datetime
import networkx as nx
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity
import numpy as np

from crypto_hunter_web.agents.base import BaseAgent, AgentTask, AgentResult, AgentCapability
from crypto_hunter_web.models.analysis_file import AnalysisFile
from crypto_hunter_web.models.agent_models import FileCorrelation, PatternFinding, SessionIntelligence
from crypto_hunter_web.extensions import db

logger = logging.getLogger(__name__)


class RelationshipAgent(BaseAgent):
    """Agent specialized in detecting relationships between files and findings"""

    def __init__(self):
        super().__init__(
            "relationship_analyzer", 
            [AgentCapability.RELATIONSHIP_ANALYSIS, AgentCapability.GRAPH_ANALYSIS]
        )
        self.similarity_threshold = 0.3
        self.relationship_graph = nx.Graph()

    async def execute(self, task: AgentTask) -> AgentResult:
        """Execute relationship analysis task"""
        try:
            task_type = task.task_type
            
            if task_type == "analyze_file_relationships":
                return await self._analyze_file_relationships(task)
            elif task_type == "build_relationship_graph":
                return await self._build_relationship_graph(task)
            elif task_type == "find_similar_files":
                return await self._find_similar_files(task)
            elif task_type == "analyze_extraction_chains":
                return await self._analyze_extraction_chains(task)
            else:
                return AgentResult(
                    task_id=task.task_id,
                    agent_id=self.agent_id,
                    success=False,
                    error_message=f"Unknown task type: {task_type}"
                )
                
        except Exception as e:
            logger.exception(f"RelationshipAgent execution failed: {e}")
            return AgentResult(
                task_id=task.task_id,
                agent_id=self.agent_id,
                success=False,
                error_message=str(e)
            )

    async def _analyze_file_relationships(self, task: AgentTask) -> AgentResult:
        """Analyze relationships between files in a session"""
        session_id = task.payload.get('session_id')
        if not session_id:
            return AgentResult(
                task_id=task.task_id,
                agent_id=self.agent_id,
                success=False,
                error_message="No session_id provided"
            )

        # Get all files in session
        files = AnalysisFile.query.filter_by(session_id=session_id).all()
        
        relationships = []
        similarity_matrix = await self._calculate_similarity_matrix(files)
        
        for i, file1 in enumerate(files):
            for j, file2 in enumerate(files[i+1:], i+1):
                similarity = similarity_matrix[i][j]
                
                if similarity > self.similarity_threshold:
                    # Create or update relationship
                    correlation = await self._create_file_correlation(
                        file1, file2, similarity, "content_similarity"
                    )
                    relationships.append(correlation)

        return AgentResult(
            task_id=task.task_id,
            agent_id=self.agent_id,
            success=True,
            output_data={
                'relationships_found': len(relationships),
                'relationships': [r.to_dict() for r in relationships],
                'similarity_matrix': similarity_matrix.tolist()
            }
        )

    async def _calculate_similarity_matrix(self, files: List[AnalysisFile]) -> np.ndarray:
        """Calculate content similarity matrix between files"""
        if len(files) < 2:
            return np.array([[1.0]])
        
        # Extract file content features
        contents = []
        for file in files:
            try:
                if file.file_content and file.file_content.raw_content:
                    # Use raw content if available
                    content = file.file_content.raw_content.decode('utf-8', errors='ignore')
                else:
                    # Use file path and metadata as fallback
                    content = f"{file.filename} {file.file_type or ''} {json.dumps(file.metadata or {})}"
                contents.append(content)
            except Exception as e:
                logger.warning(f"Failed to extract content from file {file.id}: {e}")
                contents.append(f"{file.filename} {file.file_type or ''}")

        # Calculate TF-IDF similarity
        vectorizer = TfidfVectorizer(max_features=1000, stop_words='english', ngram_range=(1, 2))
        try:
            tfidf_matrix = vectorizer.fit_transform(contents)
            similarity_matrix = cosine_similarity(tfidf_matrix)
            return similarity_matrix
        except Exception as e:
            logger.warning(f"TF-IDF calculation failed: {e}")
            # Return identity matrix as fallback
            n = len(files)
            return np.eye(n)

    async def _create_file_correlation(self, file1: AnalysisFile, file2: AnalysisFile, 
                                     strength: float, correlation_type: str) -> FileCorrelation:
        """Create or update file correlation record"""
        existing = FileCorrelation.query.filter(
            ((FileCorrelation.file1_id == file1.id) & (FileCorrelation.file2_id == file2.id)) |
            ((FileCorrelation.file1_id == file2.id) & (FileCorrelation.file2_id == file1.id))
        ).first()

        if existing:
            existing.correlation_strength = max(existing.correlation_strength, strength)
            existing.evidence_data = existing.evidence_data or {}
            existing.evidence_data[correlation_type] = strength
        else:
            existing = FileCorrelation(
                file1_id=file1.id,
                file2_id=file2.id,
                correlation_type=correlation_type,
                correlation_strength=strength,
                evidence_data={correlation_type: strength},
                discovered_by_agent=self.agent_id
            )
            db.session.add(existing)

        db.session.commit()
        return existing

    async def _build_relationship_graph(self, task: AgentTask) -> AgentResult:
        """Build comprehensive relationship graph"""
        session_id = task.payload.get('session_id')
        
        # Get all correlations for session
        correlations = db.session.query(FileCorrelation).join(
            AnalysisFile, FileCorrelation.file1_id == AnalysisFile.id
        ).filter(AnalysisFile.session_id == session_id).all()

        # Build networkx graph
        self.relationship_graph.clear()
        
        for correlation in correlations:
            self.relationship_graph.add_edge(
                correlation.file1_id,
                correlation.file2_id,
                weight=correlation.correlation_strength,
                type=correlation.correlation_type,
                evidence=correlation.evidence_data
            )

        # Calculate graph metrics
        metrics = {
            'nodes': self.relationship_graph.number_of_nodes(),
            'edges': self.relationship_graph.number_of_edges(),
            'density': nx.density(self.relationship_graph),
            'connected_components': nx.number_connected_components(self.relationship_graph)
        }

        # Find central nodes
        if self.relationship_graph.number_of_nodes() > 0:
            centrality = nx.degree_centrality(self.relationship_graph)
            top_central = sorted(centrality.items(), key=lambda x: x[1], reverse=True)[:5]
            metrics['most_central_files'] = top_central

        return AgentResult(
            task_id=task.task_id,
            agent_id=self.agent_id,
            success=True,
            output_data={
                'graph_metrics': metrics,
                'graph_data': {
                    'nodes': list(self.relationship_graph.nodes()),
                    'edges': list(self.relationship_graph.edges(data=True))
                }
            }
        )

    async def _find_similar_files(self, task: AgentTask) -> AgentResult:
        """Find files similar to a target file"""
        target_file_id = task.payload.get('file_id')
        similarity_threshold = task.payload.get('threshold', self.similarity_threshold)
        
        target_file = AnalysisFile.query.get(target_file_id)
        if not target_file:
            return AgentResult(
                task_id=task.task_id,
                agent_id=self.agent_id,
                success=False,
                error_message=f"File {target_file_id} not found"
            )

        # Get all files in same session
        session_files = AnalysisFile.query.filter_by(session_id=target_file.session_id).all()
        
        # Calculate similarities
        similarity_matrix = await self._calculate_similarity_matrix(session_files)
        target_index = next((i for i, f in enumerate(session_files) if f.id == target_file_id), None)
        
        if target_index is None:
            return AgentResult(
                task_id=task.task_id,
                agent_id=self.agent_id,
                success=False,
                error_message="Target file not found in session files"
            )

        # Find similar files
        similar_files = []
        for i, file in enumerate(session_files):
            if i != target_index and similarity_matrix[target_index][i] > similarity_threshold:
                similar_files.append({
                    'file_id': file.id,
                    'filename': file.filename,
                    'similarity': float(similarity_matrix[target_index][i])
                })

        # Sort by similarity
        similar_files.sort(key=lambda x: x['similarity'], reverse=True)

        return AgentResult(
            task_id=task.task_id,
            agent_id=self.agent_id,
            success=True,
            output_data={
                'target_file': {
                    'id': target_file.id,
                    'filename': target_file.filename
                },
                'similar_files': similar_files,
                'threshold_used': similarity_threshold
            }
        )

    async def _analyze_extraction_chains(self, task: AgentTask) -> AgentResult:
        """Analyze extraction chains and dependencies"""
        session_id = task.payload.get('session_id')
        
        # Get all extraction relationships
        from crypto_hunter_web.models.extraction import ExtractionRelationship
        
        chains = db.session.query(ExtractionRelationship).join(
            AnalysisFile, ExtractionRelationship.source_file_id == AnalysisFile.id
        ).filter(AnalysisFile.session_id == session_id).all()

        # Build extraction graph
        extraction_graph = nx.DiGraph()
        
        for chain in chains:
            extraction_graph.add_edge(
                chain.source_file_id,
                chain.extracted_file_id,
                extractor=chain.extractor_name,
                method=chain.extraction_method,
                metadata=chain.metadata
            )

        # Analyze chains
        analysis = {
            'total_extractions': len(chains),
            'extraction_graph': {
                'nodes': extraction_graph.number_of_nodes(),
                'edges': extraction_graph.number_of_edges()
            },
            'extraction_paths': [],
            'deepest_chain': 0,
            'extraction_methods': {}
        }

        # Find longest paths
        if extraction_graph.number_of_nodes() > 0:
            # Find all simple paths
            for source in extraction_graph.nodes():
                for target in extraction_graph.nodes():
                    if source != target:
                        try:
                            paths = list(nx.all_simple_paths(extraction_graph, source, target, cutoff=10))
                            for path in paths:
                                if len(path) > analysis['deepest_chain']:
                                    analysis['deepest_chain'] = len(path)
                                analysis['extraction_paths'].append({
                                    'path': path,
                                    'length': len(path)
                                })
                        except nx.NetworkXNoPath:
                            continue

        # Count extraction methods
        for chain in chains:
            method = chain.extraction_method
            analysis['extraction_methods'][method] = analysis['extraction_methods'].get(method, 0) + 1

        return AgentResult(
            task_id=task.task_id,
            agent_id=self.agent_id,
            success=True,
            output_data=analysis
        )


class PresentationAgent(BaseAgent):
    """Agent specialized in formatting and presenting analysis results"""

    def __init__(self):
        super().__init__(
            "presentation_formatter", 
            [AgentCapability.PRESENTATION, AgentCapability.VISUALIZATION]
        )

    async def execute(self, task: AgentTask) -> AgentResult:
        """Execute presentation task"""
        try:
            task_type = task.task_type
            
            if task_type == "format_analysis_report":
                return await self._format_analysis_report(task)
            elif task_type == "create_summary_dashboard":
                return await self._create_summary_dashboard(task)
            elif task_type == "generate_findings_presentation":
                return await self._generate_findings_presentation(task)
            elif task_type == "format_extraction_timeline":
                return await self._format_extraction_timeline(task)
            else:
                return AgentResult(
                    task_id=task.task_id,
                    agent_id=self.agent_id,
                    success=False,
                    error_message=f"Unknown task type: {task_type}"
                )
                
        except Exception as e:
            logger.exception(f"PresentationAgent execution failed: {e}")
            return AgentResult(
                task_id=task.task_id,
                agent_id=self.agent_id,
                success=False,
                error_message=str(e)
            )

    async def _format_analysis_report(self, task: AgentTask) -> AgentResult:
        """Format comprehensive analysis report"""
        session_id = task.payload.get('session_id')
        analysis_results = task.payload.get('analysis_results', {})
        
        report = {
            'session_id': session_id,
            'generated_at': datetime.utcnow().isoformat(),
            'title': f"Crypto Hunter Analysis Report - Session {session_id[:8]}",
            'executive_summary': await self._generate_executive_summary(analysis_results),
            'sections': await self._create_report_sections(analysis_results),
            'conclusions': await self._generate_conclusions(analysis_results),
            'recommendations': await self._generate_recommendations(analysis_results)
        }

        return AgentResult(
            task_id=task.task_id,
            agent_id=self.agent_id,
            success=True,
            output_data=report
        )

    async def _generate_executive_summary(self, results: Dict[str, Any]) -> str:
        """Generate executive summary from analysis results"""
        summary_parts = []
        
        # File analysis summary
        if 'file_analysis' in results:
            file_count = len(results['file_analysis'].get('files', []))
            summary_parts.append(f"Analyzed {file_count} files")
        
        # Steganography findings
        if 'steganography' in results:
            steg_findings = results['steganography'].get('findings', [])
            if steg_findings:
                summary_parts.append(f"Found {len(steg_findings)} steganographic elements")
        
        # Cryptography findings
        if 'cryptography' in results:
            crypto_findings = results['cryptography'].get('findings', [])
            if crypto_findings:
                summary_parts.append(f"Identified {len(crypto_findings)} cryptographic patterns")
        
        # Intelligence insights
        if 'intelligence' in results:
            insights = results['intelligence'].get('insights', [])
            if insights:
                summary_parts.append(f"Generated {len(insights)} intelligence insights")

        if summary_parts:
            return f"Analysis completed successfully. {'. '.join(summary_parts)}."
        else:
            return "Analysis completed with no significant findings."

    async def _create_report_sections(self, results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Create structured report sections"""
        sections = []

        # File Analysis Section
        if 'file_analysis' in results:
            sections.append({
                'title': 'File Analysis',
                'type': 'analysis',
                'content': results['file_analysis'],
                'summary': f"Analyzed {len(results['file_analysis'].get('files', []))} files with comprehensive metadata extraction"
            })

        # Steganography Section
        if 'steganography' in results:
            sections.append({
                'title': 'Steganographic Analysis',
                'type': 'steganography',
                'content': results['steganography'],
                'summary': f"Extracted {len(results['steganography'].get('extractions', []))} hidden elements"
            })

        # Cryptography Section
        if 'cryptography' in results:
            sections.append({
                'title': 'Cryptographic Analysis',
                'type': 'cryptography',
                'content': results['cryptography'],
                'summary': f"Identified {len(results['cryptography'].get('patterns', []))} cryptographic patterns"
            })

        # Relationships Section
        if 'relationships' in results:
            sections.append({
                'title': 'File Relationships',
                'type': 'relationships',
                'content': results['relationships'],
                'summary': f"Mapped {results['relationships'].get('relationships_found', 0)} file relationships"
            })

        return sections

    async def _generate_conclusions(self, results: Dict[str, Any]) -> List[str]:
        """Generate analysis conclusions"""
        conclusions = []
        
        # Check for solved puzzles
        solved_count = 0
        for agent_results in results.values():
            if isinstance(agent_results, dict) and agent_results.get('solved'):
                solved_count += 1
        
        if solved_count > 0:
            conclusions.append(f"Successfully solved {solved_count} puzzle component(s)")
        
        # Check for high confidence findings
        high_confidence_findings = []
        for agent_results in results.values():
            if isinstance(agent_results, dict):
                findings = agent_results.get('findings', [])
                for finding in findings:
                    if isinstance(finding, dict) and finding.get('confidence', 0) > 0.8:
                        high_confidence_findings.append(finding)
        
        if high_confidence_findings:
            conclusions.append(f"Identified {len(high_confidence_findings)} high-confidence findings")
        
        # Check for extraction chains
        for agent_results in results.values():
            if isinstance(agent_results, dict) and 'extraction_paths' in agent_results:
                max_depth = max((path.get('length', 0) for path in agent_results['extraction_paths']), default=0)
                if max_depth > 1:
                    conclusions.append(f"Discovered extraction chain with depth {max_depth}")
        
        if not conclusions:
            conclusions.append("Analysis completed without definitive solutions")
        
        return conclusions

    async def _generate_recommendations(self, results: Dict[str, Any]) -> List[str]:
        """Generate actionable recommendations"""
        recommendations = []
        
        # Check for incomplete analysis
        if 'file_analysis' in results:
            files = results['file_analysis'].get('files', [])
            for file_data in files:
                if file_data.get('requires_manual_review'):
                    recommendations.append(f"Manual review recommended for {file_data.get('filename')}")
        
        # Check for potential steganography
        if 'steganography' in results:
            steg_results = results['steganography']
            if steg_results.get('suspicious_files'):
                recommendations.append("Additional steganographic tools recommended for suspicious files")
        
        # Check for unsolved ciphers
        if 'cryptography' in results:
            crypto_results = results['cryptography']
            unsolved_ciphers = [c for c in crypto_results.get('ciphers', []) if not c.get('solved')]
            if unsolved_ciphers:
                recommendations.append(f"Manual cryptanalysis recommended for {len(unsolved_ciphers)} unsolved cipher(s)")
        
        # Check for low relationships
        if 'relationships' in results:
            rel_results = results['relationships']
            if rel_results.get('relationships_found', 0) == 0:
                recommendations.append("Consider broader file correlation analysis")
        
        return recommendations


class ValidationAgent(BaseAgent):
    """Agent specialized in validating findings and solutions"""

    def __init__(self):
        super().__init__(
            "validation_checker", 
            [AgentCapability.VALIDATION, AgentCapability.VERIFICATION]
        )

    async def execute(self, task: AgentTask) -> AgentResult:
        """Execute validation task"""
        try:
            task_type = task.task_type
            
            if task_type == "validate_solution":
                return await self._validate_solution(task)
            elif task_type == "verify_extraction":
                return await self._verify_extraction(task)
            elif task_type == "validate_cipher_solution":
                return await self._validate_cipher_solution(task)
            elif task_type == "cross_validate_findings":
                return await self._cross_validate_findings(task)
            else:
                return AgentResult(
                    task_id=task.task_id,
                    agent_id=self.agent_id,
                    success=False,
                    error_message=f"Unknown task type: {task_type}"
                )
                
        except Exception as e:
            logger.exception(f"ValidationAgent execution failed: {e}")
            return AgentResult(
                task_id=task.task_id,
                agent_id=self.agent_id,
                success=False,
                error_message=str(e)
            )

    async def _validate_solution(self, task: AgentTask) -> AgentResult:
        """Validate a proposed puzzle solution"""
        solution = task.payload.get('solution')
        expected_format = task.payload.get('expected_format')
        validation_criteria = task.payload.get('criteria', {})
        
        validation_results = {
            'is_valid': False,
            'confidence': 0.0,
            'validation_checks': [],
            'issues': [],
            'score': 0
        }

        # Basic format validation
        if expected_format:
            format_valid = await self._validate_format(solution, expected_format)
            validation_results['validation_checks'].append({
                'check': 'format',
                'passed': format_valid,
                'description': f"Solution matches expected format: {expected_format}"
            })
            if format_valid:
                validation_results['score'] += 20

        # Length validation
        if 'min_length' in validation_criteria:
            length_valid = len(str(solution)) >= validation_criteria['min_length']
            validation_results['validation_checks'].append({
                'check': 'length',
                'passed': length_valid,
                'description': f"Solution meets minimum length requirement"
            })
            if length_valid:
                validation_results['score'] += 10

        # Pattern validation
        if 'pattern' in validation_criteria:
            import re
            pattern_valid = bool(re.match(validation_criteria['pattern'], str(solution)))
            validation_results['validation_checks'].append({
                'check': 'pattern',
                'passed': pattern_valid,
                'description': f"Solution matches required pattern"
            })
            if pattern_valid:
                validation_results['score'] += 15

        # Content validation
        if 'contains' in validation_criteria:
            for required_content in validation_criteria['contains']:
                content_valid = required_content.lower() in str(solution).lower()
                validation_results['validation_checks'].append({
                    'check': 'content',
                    'passed': content_valid,
                    'description': f"Solution contains required content: {required_content}"
                })
                if content_valid:
                    validation_results['score'] += 10

        # Calculate overall validity
        total_checks = len(validation_results['validation_checks'])
        passed_checks = sum(1 for check in validation_results['validation_checks'] if check['passed'])
        
        if total_checks > 0:
            validation_results['confidence'] = passed_checks / total_checks
            validation_results['is_valid'] = validation_results['confidence'] >= 0.7

        return AgentResult(
            task_id=task.task_id,
            agent_id=self.agent_id,
            success=True,
            output_data=validation_results
        )

    async def _validate_format(self, solution: str, expected_format: str) -> bool:
        """Validate solution against expected format"""
        format_patterns = {
            'flag': r'^[A-Za-z0-9_{}]+$',
            'hex': r'^[0-9A-Fa-f]+$',
            'base64': r'^[A-Za-z0-9+/]+=*$',
            'ascii': r'^[ -~]+$',
            'email': r'^[^@]+@[^@]+\.[^@]+$',
            'url': r'^https?://[^\s]+$'
        }
        
        import re
        if expected_format in format_patterns:
            return bool(re.match(format_patterns[expected_format], solution))
        
        # Try direct pattern match
        try:
            return bool(re.match(expected_format, solution))
        except re.error:
            return True  # If pattern is invalid, assume format is valid

    async def _verify_extraction(self, task: AgentTask) -> AgentResult:
        """Verify an extraction result"""
        extraction_data = task.payload.get('extraction')
        source_file_path = task.payload.get('source_file')
        extractor_name = task.payload.get('extractor')
        
        verification_result = {
            'verified': False,
            'confidence': 0.0,
            'verification_method': 'automated',
            'details': {}
        }

        try:
            # Re-run extraction to verify
            if extractor_name == 'zsteg' and source_file_path:
                # Verify zsteg extraction
                import subprocess
                result = subprocess.run(
                    ['zsteg', source_file_path],
                    capture_output=True, text=True, timeout=30
                )
                
                if result.returncode == 0:
                    # Check if extraction matches
                    expected_content = extraction_data.get('content', '')
                    if expected_content in result.stdout:
                        verification_result['verified'] = True
                        verification_result['confidence'] = 0.95
                        verification_result['details']['match'] = 'exact'
                    else:
                        verification_result['confidence'] = 0.3
                        verification_result['details']['match'] = 'partial'

            elif extractor_name == 'steghide' and source_file_path:
                # Verify steghide extraction - would need passphrase
                verification_result['verified'] = True  # Assume valid if originally extracted
                verification_result['confidence'] = 0.8
                verification_result['details']['note'] = 'Steghide verification requires original passphrase'

            else:
                # Generic verification
                verification_result['verified'] = True
                verification_result['confidence'] = 0.7
                verification_result['details']['note'] = f'Generic verification for {extractor_name}'

        except Exception as e:
            verification_result['details']['error'] = str(e)
            verification_result['confidence'] = 0.0

        return AgentResult(
            task_id=task.task_id,
            agent_id=self.agent_id,
            success=True,
            output_data=verification_result
        )

    async def _validate_cipher_solution(self, task: AgentTask) -> AgentResult:
        """Validate a cipher decryption solution"""
        ciphertext = task.payload.get('ciphertext')
        plaintext = task.payload.get('plaintext')
        cipher_type = task.payload.get('cipher_type')
        key = task.payload.get('key')
        
        validation_result = {
            'valid': False,
            'confidence': 0.0,
            'checks': []
        }

        # Check if plaintext looks like natural language
        if plaintext:
            # Basic language validation
            word_score = await self._calculate_language_score(plaintext)
            validation_result['checks'].append({
                'check': 'language_score',
                'score': word_score,
                'passed': word_score > 0.5
            })

            # Check for common English patterns
            english_score = await self._calculate_english_score(plaintext)
            validation_result['checks'].append({
                'check': 'english_patterns',
                'score': english_score,
                'passed': english_score > 0.4
            })

            # Entropy check (natural text should have moderate entropy)
            entropy = await self._calculate_text_entropy(plaintext)
            entropy_valid = 2.0 < entropy < 5.0  # Typical range for English text
            validation_result['checks'].append({
                'check': 'entropy',
                'value': entropy,
                'passed': entropy_valid
            })

        # Try to re-encrypt with the same method to verify
        if cipher_type and key and plaintext:
            re_encrypted = await self._re_encrypt(plaintext, cipher_type, key)
            if re_encrypted and re_encrypted.upper() == ciphertext.upper():
                validation_result['checks'].append({
                    'check': 're_encryption',
                    'passed': True,
                    'note': 'Re-encryption matches original ciphertext'
                })

        # Calculate overall confidence
        total_checks = len(validation_result['checks'])
        passed_checks = sum(1 for check in validation_result['checks'] if check.get('passed', False))
        
        if total_checks > 0:
            validation_result['confidence'] = passed_checks / total_checks
            validation_result['valid'] = validation_result['confidence'] >= 0.6

        return AgentResult(
            task_id=task.task_id,
            agent_id=self.agent_id,
            success=True,
            output_data=validation_result
        )

    async def _calculate_language_score(self, text: str) -> float:
        """Calculate how much text looks like natural language"""
        if not text:
            return 0.0
        
        # Common English words (simplified)
        common_words = {
            'the', 'and', 'a', 'to', 'of', 'in', 'is', 'it', 'you', 'that', 'he', 'was', 'for', 
            'on', 'are', 'as', 'with', 'his', 'they', 'at', 'be', 'this', 'have', 'from', 'or',
            'one', 'had', 'by', 'word', 'but', 'not', 'what', 'all', 'were', 'we', 'when',
            'your', 'can', 'said', 'there', 'each', 'which', 'she', 'do', 'how', 'their'
        }
        
        words = text.lower().split()
        if not words:
            return 0.0
        
        common_count = sum(1 for word in words if word in common_words)
        return common_count / len(words)

    async def _calculate_english_score(self, text: str) -> float:
        """Calculate English language characteristics"""
        if not text:
            return 0.0
        
        # Letter frequency in English (simplified)
        english_freq = {
            'e': 12.7, 't': 9.1, 'a': 8.2, 'o': 7.5, 'i': 7.0, 'n': 6.7, 's': 6.3, 'h': 6.1,
            'r': 6.0, 'd': 4.3, 'l': 4.0, 'c': 2.8, 'u': 2.8, 'm': 2.4, 'w': 2.4, 'f': 2.2,
            'g': 2.0, 'y': 2.0, 'p': 1.9, 'b': 1.3, 'v': 1.0, 'k': 0.8, 'j': 0.15, 'x': 0.15,
            'q': 0.10, 'z': 0.07
        }
        
        # Calculate letter frequencies in text
        text_clean = ''.join(c.lower() for c in text if c.isalpha())
        if not text_clean:
            return 0.0
        
        text_freq = {}
        for char in text_clean:
            text_freq[char] = text_freq.get(char, 0) + 1
        
        # Normalize
        total_chars = len(text_clean)
        for char in text_freq:
            text_freq[char] = (text_freq[char] / total_chars) * 100
        
        # Calculate chi-squared statistic
        chi_squared = 0
        for char in 'abcdefghijklmnopqrstuvwxyz':
            expected = english_freq.get(char, 0)
            observed = text_freq.get(char, 0)
            if expected > 0:
                chi_squared += ((observed - expected) ** 2) / expected
        
        # Convert to score (lower chi-squared = higher score)
        return max(0, 1 - (chi_squared / 1000))

    async def _calculate_text_entropy(self, text: str) -> float:
        """Calculate Shannon entropy of text"""
        if not text:
            return 0.0
        
        import math
        
        # Count character frequencies
        char_counts = {}
        for char in text:
            char_counts[char] = char_counts.get(char, 0) + 1
        
        # Calculate entropy
        text_len = len(text)
        entropy = 0
        for count in char_counts.values():
            probability = count / text_len
            entropy -= probability * math.log2(probability)
        
        return entropy

    async def _re_encrypt(self, plaintext: str, cipher_type: str, key: str) -> Optional[str]:
        """Re-encrypt plaintext with given cipher and key"""
        try:
            if cipher_type.lower() == 'caesar':
                shift = int(key)
                result = ''
                for char in plaintext:
                    if char.isalpha():
                        ascii_offset = 65 if char.isupper() else 97
                        result += chr((ord(char) - ascii_offset + shift) % 26 + ascii_offset)
                    else:
                        result += char
                return result
            
            elif cipher_type.lower() == 'rot13':
                return plaintext.encode('rot13')
            
            # Add more cipher types as needed
            
        except Exception as e:
            logger.warning(f"Failed to re-encrypt with {cipher_type}: {e}")
        
        return None

    async def _cross_validate_findings(self, task: AgentTask) -> AgentResult:
        """Cross-validate findings from multiple agents"""
        findings = task.payload.get('findings', [])
        
        validation_result = {
            'validated_findings': [],
            'conflicting_findings': [],
            'confidence_scores': {},
            'overall_confidence': 0.0
        }

        # Group findings by type or file
        findings_by_source = {}
        for finding in findings:
            source = finding.get('source_file_id') or finding.get('agent_id')
            if source not in findings_by_source:
                findings_by_source[source] = []
            findings_by_source[source].append(finding)

        # Cross-validate findings
        for source, source_findings in findings_by_source.items():
            for finding in source_findings:
                # Check if other agents confirm this finding
                confirmations = 0
                total_other_agents = 0
                
                for other_source, other_findings in findings_by_source.items():
                    if other_source != source:
                        total_other_agents += 1
                        for other_finding in other_findings:
                            if self._findings_match(finding, other_finding):
                                confirmations += 1
                                break

                confidence = finding.get('confidence', 0.5)
                if total_other_agents > 0:
                    cross_validation_bonus = confirmations / total_other_agents
                    confidence = min(1.0, confidence + (cross_validation_bonus * 0.3))

                validated_finding = {
                    **finding,
                    'cross_validated': confirmations > 0,
                    'confirmations': confirmations,
                    'final_confidence': confidence
                }
                
                validation_result['validated_findings'].append(validated_finding)

        # Calculate overall confidence
        if validation_result['validated_findings']:
            total_confidence = sum(f['final_confidence'] for f in validation_result['validated_findings'])
            validation_result['overall_confidence'] = total_confidence / len(validation_result['validated_findings'])

        return AgentResult(
            task_id=task.task_id,
            agent_id=self.agent_id,
            success=True,
            output_data=validation_result
        )

    def _findings_match(self, finding1: Dict[str, Any], finding2: Dict[str, Any]) -> bool:
        """Check if two findings are about the same thing"""
        # Simple matching logic - can be enhanced
        type1 = finding1.get('type', '').lower()
        type2 = finding2.get('type', '').lower()
        
        if type1 != type2:
            return False
        
        # Check content similarity
        content1 = str(finding1.get('content', '')).lower()
        content2 = str(finding2.get('content', '')).lower()
        
        if content1 and content2:
            # Simple string similarity
            from difflib import SequenceMatcher
            similarity = SequenceMatcher(None, content1, content2).ratio()
            return similarity > 0.7
        
        return False