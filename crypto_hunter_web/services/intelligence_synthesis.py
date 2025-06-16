"""
crypto_hunter_web/services/intelligence_synthesis.py
AI-powered intelligence synthesis for cross-agent analysis and insights
"""

import re
import json
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple, Set
from dataclasses import dataclass, asdict
from collections import defaultdict, Counter
import statistics

from crypto_hunter_web.models import db, Finding, AnalysisFile, PuzzleSession
from crypto_hunter_web.agents.base import AgentResult

logger = logging.getLogger(__name__)


@dataclass
class PatternCorrelation:
    """Correlation between different patterns found by agents"""
    pattern_type: str
    confidence: float
    supporting_findings: List[int]  # Finding IDs
    agents_involved: List[str]
    description: str
    metadata: Dict[str, Any]


@dataclass
class Hypothesis:
    """AI-generated hypothesis about the puzzle"""
    hypothesis_id: str
    title: str
    description: str
    confidence: float
    supporting_evidence: List[str]
    contradicting_evidence: List[str]
    next_steps: List[str]
    priority: int  # 1-5, 1 being highest
    category: str  # 'steganography', 'cryptography', 'metadata', 'structural'


@dataclass
class Insight:
    """Actionable insight from cross-agent analysis"""
    insight_id: str
    title: str
    description: str
    action_type: str  # 'extract', 'analyze', 'decrypt', 'investigate'
    confidence: float
    urgency: int  # 1-5, 1 being most urgent
    estimated_effort: str  # 'low', 'medium', 'high'
    success_probability: float


class IntelligenceSynthesisEngine:
    """AI engine for synthesizing insights from multi-agent analysis"""
    
    def __init__(self):
        self.pattern_database = {}  # Known patterns and their signatures
        self.correlation_history = []  # Historical correlations for learning
        self.hypothesis_cache = {}  # session_id -> List[Hypothesis]
        self.insight_cache = {}  # session_id -> List[Insight]
        
        # Initialize pattern recognition database
        self._initialize_pattern_database()
    
    def _initialize_pattern_database(self):
        """Initialize the pattern recognition database"""
        self.pattern_database = {
            'steganography_indicators': {
                'lsb_patterns': ['regular_bit_patterns', 'unusual_noise', 'entropy_variations'],
                'frequency_anomalies': ['dct_coefficients', 'spectral_analysis', 'statistical_tests'],
                'structural_indicators': ['file_size_anomalies', 'header_modifications', 'padding_patterns']
            },
            'cryptography_indicators': {
                'cipher_patterns': ['base64_sequences', 'hex_patterns', 'alphabet_substitution'],
                'key_indicators': ['repeating_sequences', 'length_patterns', 'format_clues'],
                'encryption_markers': ['high_entropy', 'random_distribution', 'compression_resistance']
            },
            'metadata_clues': {
                'hidden_fields': ['custom_properties', 'extended_attributes', 'comment_fields'],
                'timestamp_patterns': ['creation_sequences', 'modification_chains', 'access_correlations'],
                'creator_information': ['software_signatures', 'user_traces', 'device_fingerprints']
            }
        }
    
    def synthesize_findings(self, session_id: str, agent_results: List[AgentResult]) -> Dict[str, Any]:
        """Synthesize findings from multiple agents into actionable insights"""
        try:
            # Collect all findings data
            findings_data = self._collect_findings_data(session_id, agent_results)
            
            # Detect patterns and correlations
            correlations = self._detect_pattern_correlations(findings_data)
            
            # Generate hypotheses
            hypotheses = self._generate_hypotheses(findings_data, correlations)
            
            # Create actionable insights
            insights = self._generate_insights(findings_data, correlations, hypotheses)
            
            # Calculate overall confidence and progress
            synthesis_score = self._calculate_synthesis_score(findings_data, correlations)
            
            # Cache results
            self.hypothesis_cache[session_id] = hypotheses
            self.insight_cache[session_id] = insights
            
            synthesis_result = {
                'session_id': session_id,
                'synthesis_timestamp': datetime.utcnow().isoformat(),
                'total_findings': len(findings_data),
                'agent_coverage': self._calculate_agent_coverage(agent_results),
                'pattern_correlations': [asdict(c) for c in correlations],
                'hypotheses': [asdict(h) for h in hypotheses],
                'insights': [asdict(i) for i in insights],
                'synthesis_score': synthesis_score,
                'next_recommended_actions': self._get_recommended_actions(insights),
                'breakthrough_probability': self._estimate_breakthrough_probability(correlations, hypotheses)
            }
            
            logger.info(f"Intelligence synthesis completed for session {session_id}: {len(correlations)} correlations, {len(hypotheses)} hypotheses, {len(insights)} insights")
            
            return synthesis_result
            
        except Exception as e:
            logger.error(f"Error in intelligence synthesis: {e}")
            return {'error': str(e), 'session_id': session_id}
    
    def _collect_findings_data(self, session_id: str, agent_results: List[AgentResult]) -> List[Dict[str, Any]]:
        """Collect and normalize findings data from various sources"""
        findings_data = []
        
        # Add agent results
        for result in agent_results:
            findings_data.append({
                'source': 'agent_result',
                'agent_id': result.agent_id,
                'task_id': result.task_id,
                'success': result.success,
                'data': result.data,
                'metadata': result.metadata,
                'timestamp': result.completed_at
            })
        
        # Add database findings
        session = PuzzleSession.query.get(session_id)
        if session:
            findings = Finding.query.filter_by(session_id=session_id).all()
            for finding in findings:
                findings_data.append({
                    'source': 'database_finding',
                    'finding_id': finding.id,
                    'file_id': finding.file_id,
                    'content': finding.content,
                    'metadata': finding.metadata or {},
                    'confidence': finding.confidence,
                    'timestamp': finding.created_at
                })
        
        return findings_data
    
    def _detect_pattern_correlations(self, findings_data: List[Dict[str, Any]]) -> List[PatternCorrelation]:
        """Detect correlations between patterns found by different agents"""
        correlations = []
        
        # Group findings by type
        file_analysis_findings = [f for f in findings_data if 'file_type' in str(f.get('data', {})) or 'entropy' in str(f.get('data', {}))]
        stego_findings = [f for f in findings_data if 'steganography' in str(f.get('data', {})) or 'hidden' in str(f.get('data', {}))]
        crypto_findings = [f for f in findings_data if 'crypto' in str(f.get('data', {})) or 'cipher' in str(f.get('data', {}))]
        
        # Detect high entropy + steganography correlation
        if file_analysis_findings and stego_findings:
            high_entropy_files = []
            for finding in file_analysis_findings:
                entropy = finding.get('data', {}).get('entropy', 0)
                if entropy > 7.0:
                    high_entropy_files.append(finding)
            
            if high_entropy_files and len(stego_findings) > 0:
                correlations.append(PatternCorrelation(
                    pattern_type='high_entropy_steganography',
                    confidence=0.8,
                    supporting_findings=[f.get('finding_id', f.get('task_id', '')) for f in high_entropy_files + stego_findings],
                    agents_involved=['file_analysis', 'steganography'],
                    description='High entropy files detected with steganography indicators',
                    metadata={'entropy_threshold': 7.0, 'files_count': len(high_entropy_files)}
                ))
        
        # Detect crypto + metadata correlation
        if crypto_findings:
            for finding in crypto_findings:
                crypto_data = finding.get('data', {})
                if 'base64' in str(crypto_data) or 'hex' in str(crypto_data):
                    correlations.append(PatternCorrelation(
                        pattern_type='encoded_data_pattern',
                        confidence=0.7,
                        supporting_findings=[finding.get('finding_id', finding.get('task_id', ''))],
                        agents_involved=['cryptography'],
                        description='Encoded data patterns detected (Base64/Hex)',
                        metadata={'encoding_types': ['base64', 'hex']}
                    ))
        
        # Detect multi-file relationships
        file_groups = defaultdict(list)
        for finding in findings_data:
            file_id = finding.get('file_id')
            if file_id:
                file_groups[file_id].append(finding)
        
        multi_file_sessions = [group for group in file_groups.values() if len(group) > 2]
        if multi_file_sessions:
            correlations.append(PatternCorrelation(
                pattern_type='multi_file_relationship',
                confidence=0.6,
                supporting_findings=[f.get('finding_id', f.get('task_id', '')) for group in multi_file_sessions for f in group],
                agents_involved=['file_analysis', 'steganography', 'cryptography'],
                description=f'Multiple files with related findings detected ({len(multi_file_sessions)} groups)',
                metadata={'file_groups': len(multi_file_sessions)}
            ))
        
        return correlations
    
    def _generate_hypotheses(self, findings_data: List[Dict[str, Any]], correlations: List[PatternCorrelation]) -> List[Hypothesis]:
        """Generate hypotheses based on findings and correlations"""
        hypotheses = []
        
        # Hypothesis 1: Steganography-based puzzle
        stego_indicators = sum(1 for c in correlations if 'steganography' in c.pattern_type)
        if stego_indicators > 0:
            confidence = min(0.9, 0.5 + (stego_indicators * 0.2))
            hypotheses.append(Hypothesis(
                hypothesis_id=f"stego_puzzle_{datetime.utcnow().timestamp()}",
                title="Steganography-based Challenge",
                description="The puzzle appears to involve hidden data embedded in media files using steganographic techniques.",
                confidence=confidence,
                supporting_evidence=[
                    f"Steganography indicators detected in {stego_indicators} correlations",
                    "High entropy patterns in image/audio files",
                    "Multiple extraction methods yielding results"
                ],
                contradicting_evidence=[],
                next_steps=[
                    "Run