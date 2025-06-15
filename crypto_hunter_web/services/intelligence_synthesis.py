"""
crypto_hunter_web/services/intelligence_synthesis.py
AI-powered intelligence synthesis engine for advanced puzzle analysis
"""

import json
import logging
import re
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple, Set
from dataclasses import dataclass, field
from collections import defaultdict, Counter
import hashlib

from flask import current_app
from sqlalchemy import and_, or_, desc, func

from crypto_hunter_web.extensions import db
from crypto_hunter_web.models import (
    AnalysisFile, Finding, PuzzleSession, PuzzleStep, FileContent,
    ExtractionRelationship
)
from crypto_hunter_web.models.agent_models import (
    PatternFinding, CipherAnalysis, FileCorrelation, SessionIntelligence
)

logger = logging.getLogger(__name__)


@dataclass
class Hypothesis:
    """Data structure for puzzle-solving hypotheses"""
    id: str = field(default_factory=lambda: hashlib.md5(str(datetime.utcnow()).encode()).hexdigest()[:8])
    title: str = ""
    description: str = ""
    confidence: float = 0.0
    supporting_evidence: List[Dict[str, Any]] = field(default_factory=list)
    contradicting_evidence: List[Dict[str, Any]] = field(default_factory=list)
    next_steps: List[str] = field(default_factory=list)
    category: str = "general"
    created_at: datetime = field(default_factory=datetime.utcnow)
    validated: bool = False
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'id': self.id,
            'title': self.title,
            'description': self.description,
            'confidence': self.confidence,
            'supporting_evidence': self.supporting_evidence,
            'contradicting_evidence': self.contradicting_evidence,
            'next_steps': self.next_steps,
            'category': self.category,
            'created_at': self.created_at.isoformat(),
            'validated': self.validated
        }


@dataclass
class Insight:
    """Data structure for analysis insights"""
    type: str = "pattern"  # pattern, correlation, breakthrough, recommendation
    title: str = ""
    description: str = ""
    confidence: float = 0.0
    impact_level: str = "medium"  # low, medium, high, critical
    data: Dict[str, Any] = field(default_factory=dict)
    related_files: List[int] = field(default_factory=list)
    related_findings: List[int] = field(default_factory=list)
    actionable_steps: List[str] = field(default_factory=list)
    timestamp: datetime = field(default_factory=datetime.utcnow)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'type': self.type,
            'title': self.title,
            'description': self.description,
            'confidence': self.confidence,
            'impact_level': self.impact_level,
            'data': self.data,
            'related_files': self.related_files,
            'related_findings': self.related_findings,
            'actionable_steps': self.actionable_steps,
            'timestamp': self.timestamp.isoformat()
        }


class PatternRecognitionEngine:
    """Advanced pattern recognition for puzzle elements"""
    
    def __init__(self):
        self.crypto_patterns = {
            'base64': re.compile(r'[A-Za-z0-9+/]{20,}={0,2}'),
            'hex': re.compile(r'[0-9a-fA-F]{32,}'),
            'caesar_shift': re.compile(r'\b[A-Z]{5,}\b'),
            'morse_code': re.compile(r'[\.\-\s]{10,}'),
            'binary': re.compile(r'[01]{16,}'),
            'url_encoded': re.compile(r'%[0-9a-fA-F]{2}'),
            'unicode_escape': re.compile(r'\\u[0-9a-fA-F]{4}'),
            'rot13': re.compile(r'\b[N-ZA-Mn-za-m]{5,}\b')
        }
        
        self.file_patterns = {
            'magic_bytes': {
                'pdf': b'%PDF',
                'zip': b'PK\x03\x04',
                'png': b'\x89PNG',
                'jpeg': b'\xff\xd8\xff',
                'elf': b'\x7fELF',
                'pe': b'MZ'
            },
            'embedded_file_indicators': [
                b'PK\x03\x04',  # ZIP
                b'\x7fELF',     # ELF binary
                b'MZ',          # PE executable
                b'%PDF',        # PDF
                b'\x89PNG',     # PNG
                b'\xff\xd8\xff' # JPEG
            ]
        }
    
    def analyze_text_patterns(self, text: str) -> List[Dict[str, Any]]:
        """Analyze text for cryptographic patterns"""
        patterns_found = []
        
        for pattern_name, regex in self.crypto_patterns.items():
            matches = regex.findall(text)
            if matches:
                # Filter out short matches for some patterns
                if pattern_name in ['base64', 'hex'] and len(matches[0]) < 20:
                    continue
                
                patterns_found.append({
                    'type': pattern_name,
                    'matches': matches[:5],  # Limit to first 5 matches
                    'count': len(matches),
                    'confidence': self._calculate_pattern_confidence(pattern_name, matches, text)
                })
        
        return patterns_found
    
    def analyze_binary_patterns(self, binary_data: bytes) -> List[Dict[str, Any]]:
        """Analyze binary data for patterns"""
        patterns_found = []
        
        # Check for magic bytes
        for file_type, magic in self.file_patterns['magic_bytes'].items():
            if magic in binary_data:
                positions = []
                start = 0
                while True:
                    pos = binary_data.find(magic, start)
                    if pos == -1:
                        break
                    positions.append(pos)
                    start = pos + 1
                
                patterns_found.append({
                    'type': 'magic_bytes',
                    'subtype': file_type,
                    'positions': positions,
                    'count': len(positions),
                    'confidence': 0.9 if positions[0] == 0 else 0.7  # Higher confidence if at start
                })
        
        # Check for repetitive patterns
        repetitive_patterns = self._find_repetitive_patterns(binary_data)
        patterns_found.extend(repetitive_patterns)
        
        # Check entropy regions
        entropy_regions = self._analyze_entropy_regions(binary_data)
        patterns_found.extend(entropy_regions)
        
        return patterns_found
    
    def _calculate_pattern_confidence(self, pattern_type: str, matches: List[str], full_text: str) -> float:
        """Calculate confidence score for pattern detection"""
        base_confidence = {
            'base64': 0.8,
            'hex': 0.7,
            'morse_code': 0.9,
            'binary': 0.6,
            'url_encoded': 0.8,
            'unicode_escape': 0.9,
            'caesar_shift': 0.5,
            'rot13': 0.6
        }
        
        confidence = base_confidence.get(pattern_type, 0.5)
        
        # Adjust based on match length and context
        if matches:
            avg_length = sum(len(match) for match in matches) / len(matches)
            
            if pattern_type == 'base64' and avg_length > 50:
                confidence += 0.1
            elif pattern_type == 'hex' and avg_length > 64:
                confidence += 0.1
            
            # Reduce confidence if pattern appears in obvious contexts
            text_lower = full_text.lower()
            if any(word in text_lower for word in ['example', 'test', 'dummy', 'placeholder']):
                confidence -= 0.2
        
        return min(confidence, 1.0)
    
    def _find_repetitive_patterns(self, data: bytes) -> List[Dict[str, Any]]:
        """Find repetitive byte patterns"""
        patterns = []
        
        # Look for repeated 4-byte patterns
        for i in range(0, min(len(data) - 4, 1000), 4):  # Limit search for performance
            pattern = data[i:i+4]
            if pattern == b'\x00\x00\x00\x00':  # Skip null patterns
                continue
            
            count = 0
            positions = []
            for j in range(i, len(data) - 4, 4):
                if data[j:j+4] == pattern:
                    count += 1
                    positions.append(j)
                    if count > 10:  # Found enough repetitions
                        patterns.append({
                            'type': 'repetitive_pattern',
                            'pattern': pattern.hex(),
                            'positions': positions[:10],  # Limit stored positions
                            'count': count,
                            'confidence': min(count / 20.0, 0.9)
                        })
                        break
        
        return patterns
    
    def _analyze_entropy_regions(self, data: bytes) -> List[Dict[str, Any]]:
        """Analyze entropy in different regions of binary data"""
        regions = []
        chunk_size = 1024
        
        for i in range(0, len(data), chunk_size):
            chunk = data[i:i+chunk_size]
            if len(chunk) < 100:  # Skip small chunks
                continue
            
            entropy = self._calculate_entropy(chunk)
            
            if entropy > 7.8:  # High entropy - possibly encrypted/compressed
                regions.append({
                    'type': 'high_entropy_region',
                    'start_offset': i,
                    'end_offset': i + len(chunk),
                    'entropy': entropy,
                    'confidence': min((entropy - 7.5) / 0.5, 1.0)
                })
            elif entropy < 2.0:  # Very low entropy - possibly padding or structured data
                regions.append({
                    'type': 'low_entropy_region',
                    'start_offset': i,
                    'end_offset': i + len(chunk),
                    'entropy': entropy,
                    'confidence': min((2.5 - entropy) / 2.5, 1.0)
                })
        
        return regions
    
    def _calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy of binary data"""
        if not data:
            return 0.0
        
        # Count byte frequencies
        counts = Counter(data)
        length = len(data)
        
        # Calculate entropy
        entropy = 0.0
        for count in counts.values():
            probability = count / length
            if probability > 0:
                entropy -= probability * (probability.bit_length() - 1)
        
        return entropy


class CorrelationEngine:
    """Engine for finding correlations between different puzzle elements"""
    
    def __init__(self):
        self.similarity_threshold = 0.7
    
    def find_file_correlations(self, files: List[AnalysisFile]) -> List[Dict[str, Any]]:
        """Find correlations between files"""
        correlations = []
        
        for i, file1 in enumerate(files):
            for file2 in files[i+1:]:
                correlation = self._analyze_file_pair(file1, file2)
                if correlation and correlation['strength'] > self.similarity_threshold:
                    correlations.append(correlation)
        
        return correlations
    
    def _analyze_file_pair(self, file1: AnalysisFile, file2: AnalysisFile) -> Optional[Dict[str, Any]]:
        """Analyze correlation between two files"""
        correlation_factors = []
        total_strength = 0.0
        
        # Filename similarity
        name_similarity = self._calculate_string_similarity(file1.filename, file2.filename)
        if name_similarity > 0.5:
            correlation_factors.append({
                'type': 'filename_similarity',
                'strength': name_similarity,
                'details': f"Filenames '{file1.filename}' and '{file2.filename}' are similar"
            })
            total_strength += name_similarity * 0.3
        
        # File type correlation
        if file1.mime_type and file2.mime_type:
            if file1.mime_type == file2.mime_type:
                correlation_factors.append({
                    'type': 'same_file_type',
                    'strength': 0.8,
                    'details': f"Both files are {file1.mime_type}"
                })
                total_strength += 0.8 * 0.2
        
        # Size correlation (similar sizes might indicate related content)
        if file1.filesize and file2.filesize:
            size_ratio = min(file1.filesize, file2.filesize) / max(file1.filesize, file2.filesize)
            if size_ratio > 0.8:  # Similar sizes
                correlation_factors.append({
                    'type': 'similar_size',
                    'strength': size_ratio,
                    'details': f"Similar file sizes: {file1.filesize} and {file2.filesize} bytes"
                })
                total_strength += size_ratio * 0.1
        
        # Hash similarity (for detection of slightly modified files)
        if file1.sha256_hash and file2.sha256_hash:
            hash_similarity = self._calculate_hash_similarity(file1.sha256_hash, file2.sha256_hash)
            if hash_similarity > 0.1:  # Even small hash similarity is significant
                correlation_factors.append({
                    'type': 'hash_similarity',
                    'strength': hash_similarity,
                    'details': f"SHA256 hashes show {hash_similarity:.2%} similarity"
                })
                total_strength += hash_similarity * 0.4
        
        # Creation time correlation
        if file1.created_at and file2.created_at:
            time_diff = abs((file1.created_at - file2.created_at).total_seconds())
            if time_diff < 3600:  # Within 1 hour
                time_strength = max(0, 1 - (time_diff / 3600))
                correlation_factors.append({
                    'type': 'temporal_proximity',
                    'strength': time_strength,
                    'details': f"Files created within {time_diff/60:.1f} minutes of each other"
                })
                total_strength += time_strength * 0.1
        
        if total_strength > 0.3 and correlation_factors:
            return {
                'file1_id': file1.id,
                'file2_id': file2.id,
                'strength': min(total_strength, 1.0),
                'factors': correlation_factors,
                'correlation_type': self._determine_correlation_type(correlation_factors)
            }
        
        return None
    
    def _calculate_string_similarity(self, str1: str, str2: str) -> float:
        """Calculate similarity between two strings using Levenshtein distance"""
        if not str1 or not str2:
            return 0.0
        
        # Simple implementation of normalized Levenshtein distance
        len1, len2 = len(str1), len(str2)
        if len1 == 0:
            return 0.0 if len2 > 0 else 1.0
        if len2 == 0:
            return 0.0
        
        # Create matrix
        matrix = [[0] * (len2 + 1) for _ in range(len1 + 1)]
        
        # Initialize first row and column
        for i in range(len1 + 1):
            matrix[i][0] = i
        for j in range(len2 + 1):
            matrix[0][j] = j
        
        # Fill matrix
        for i in range(1, len1 + 1):
            for j in range(1, len2 + 1):
                cost = 0 if str1[i-1] == str2[j-1] else 1
                matrix[i][j] = min(
                    matrix[i-1][j] + 1,      # deletion
                    matrix[i][j-1] + 1,      # insertion
                    matrix[i-1][j-1] + cost  # substitution
                )
        
        # Calculate similarity (1 - normalized distance)
        max_len = max(len1, len2)
        return 1.0 - (matrix[len1][len2] / max_len)
    
    def _calculate_hash_similarity(self, hash1: str, hash2: str) -> float:
        """Calculate similarity between two hashes (simplified approach)"""
        if not hash1 or not hash2 or len(hash1) != len(hash2):
            return 0.0
        
        # Count matching characters at same positions
        matches = sum(1 for a, b in zip(hash1, hash2) if a == b)
        return matches / len(hash1)
    
    def _determine_correlation_type(self, factors: List[Dict[str, Any]]) -> str:
        """Determine the primary correlation type"""
        factor_types = [f['type'] for f in factors]
        
        if 'hash_similarity' in factor_types:
            return 'content_similarity'
        elif 'filename_similarity' in factor_types and 'same_file_type' in factor_types:
            return 'related_files'
        elif 'temporal_proximity' in factor_types:
            return 'temporal_correlation'
        else:
            return 'general_correlation'


class IntelligenceSynthesisEngine:
    """Main engine for AI-powered intelligence synthesis"""
    
    def __init__(self):
        self.pattern_engine = PatternRecognitionEngine()
        self.correlation_engine = CorrelationEngine()
        self.hypothesis_store: Dict[str, List[Hypothesis]] = defaultdict(list)
        self.insight_cache: Dict[str, List[Insight]] = {}
    
    def analyze_session(self, session_id: str) -> Dict[str, Any]:
        """Perform comprehensive intelligence analysis of a puzzle session"""
        session = PuzzleSession.query.filter_by(public_id=session_id).first()
        if not session:
            return {'error': 'Session not found'}
        
        # Gather all session data
        session_data = self._gather_session_data(session)
        
        # Generate insights
        insights = self._generate_insights(session_data)
        
        # Generate hypotheses
        hypotheses = self._generate_hypotheses(session_data, insights)
        
        # Create action plan
        action_plan = self._create_action_plan(session_data, insights, hypotheses)
        
        # Calculate overall progress score
        progress_score = self._calculate_progress_score(session_data, insights)
        
        # Store results
        self._store_session_intelligence(session, insights, hypotheses, progress_score)
        
        return {
            'session_id': session_id,
            'analysis_timestamp': datetime.utcnow().isoformat(),
            'progress_score': progress_score,
            'insights': [insight.to_dict() for insight in insights],
            'hypotheses': [hypothesis.to_dict() for hypothesis in hypotheses],
            'action_plan': action_plan,
            'session_summary': self._generate_session_summary(session_data, insights)
        }
    
    def _gather_session_data(self, session: PuzzleSession) -> Dict[str, Any]:
        """Gather all relevant data for a session"""
        # Get all files from session steps
        files = []
        findings = []
        
        for step in session.steps:
            step_files = [sf.file for sf in step.files]
            step_findings = [sf.finding for sf in step.findings]
            
            files.extend(step_files)
            findings.extend(step_findings)
        
        # Get pattern findings and cipher analyses
        file_ids = [f.id for f in files]
        pattern_findings = PatternFinding.query.filter(PatternFinding.file_id.in_(file_ids)).all()
        cipher_analyses = CipherAnalysis.query.filter(CipherAnalysis.file_id.in_(file_ids)).all()
        file_correlations = FileCorrelation.query.filter(
            or_(
                FileCorrelation.file1_id.in_(file_ids),
                FileCorrelation.file2_id.in_(file_ids)
            )
        ).all()
        
        # Get extraction relationships
        extraction_relationships = ExtractionRelationship.query.filter(
            or_(
                ExtractionRelationship.parent_file_id.in_(file_ids),
                ExtractionRelationship.extracted_file_id.in_(file_ids)
            )
        ).all()
        
        return {
            'session': session,
            'files': files,
            'findings': findings,
            'pattern_findings': pattern_findings,
            'cipher_analyses': cipher_analyses,
            'file_correlations': file_correlations,
            'extraction_relationships': extraction_relationships
        }
    
    def _generate_insights(self, session_data: Dict[str, Any]) -> List[Insight]:
        """Generate actionable insights from session data"""
        insights = []
        
        # Pattern analysis insights
        pattern_insights = self._analyze_patterns(session_data)
        insights.extend(pattern_insights)
        
        # File relationship insights
        relationship_insights = self._analyze_relationships(session_data)
        insights.extend(relationship_insights)
        
        # Crypto analysis insights
        crypto_insights = self._analyze_crypto_findings(session_data)
        insights.extend(crypto_insights)
        
        # Progress insights
        progress_insights = self._analyze_progress(session_data)
        insights.extend(progress_insights)
        
        # Sort by impact level and confidence
        insights.sort(key=lambda x: (
            {'critical': 4, 'high': 3, 'medium': 2, 'low': 1}[x.impact_level],
            x.confidence
        ), reverse=True)
        
        return insights
    
    def _analyze_patterns(self, session_data: Dict[str, Any]) -> List[Insight]:
        """Analyze patterns in session data"""
        insights = []
        
        # Analyze file type distribution
        file_types = [f.mime_type for f in session_data['files'] if f.mime_type]
        type_counter = Counter(file_types)
        
        if len(type_counter) > 5:
            insights.append(Insight(
                type='pattern',
                title='Diverse File Types Detected',
                description=f'Session contains {len(type_counter)} different file types, suggesting a complex puzzle structure.',
                confidence=0.8,
                impact_level='medium',
                data={'file_types': dict(type_counter)},
                actionable_steps=[
                    'Consider analyzing each file type with specialized tools',
                    'Look for hidden relationships between different file formats'
                ]
            ))
        
        # Analyze pattern findings
        pattern_types = [pf.pattern_type for pf in session_data['pattern_findings']]
        pattern_counter = Counter(pattern_types)
        
        for pattern_type, count in pattern_counter.items():
            if count >= 3:  # Multiple instances of same pattern
                insights.append(Insight(
                    type='pattern',
                    title=f'Recurring {pattern_type.title()} Pattern',
                    description=f'Found {count} instances of {pattern_type} patterns, indicating potential significance.',
                    confidence=min(0.9, 0.5 + (count * 0.1)),
                    impact_level='high' if count >= 5 else 'medium',
                    data={'pattern_type': pattern_type, 'count': count},
                    related_findings=[pf.id for pf in session_data['pattern_findings'] if pf.pattern_type == pattern_type],
                    actionable_steps=[
                        f'Focus analysis on {pattern_type} patterns',
                        'Look for connections between pattern instances'
                    ]
                ))
        
        return insights
    
    def _analyze_relationships(self, session_data: Dict[str, Any]) -> List[Insight]:
        """Analyze file relationships and extraction chains"""
        insights = []
        
        # Analyze extraction chains
        extraction_depth = defaultdict(int)
        for rel in session_data['extraction_relationships']:
            extraction_depth[rel.extraction_method] += 1
        
        if extraction_depth:
            most_successful_method = max(extraction_depth, key=extraction_depth.get)
            success_count = extraction_depth[most_successful_method]
            
            insights.append(Insight(
                type='correlation',
                title=f'Successful Extraction Method: {most_successful_method.title()}',
                description=f'{most_successful_method} has yielded {success_count} successful extractions.',
                confidence=0.8,
                impact_level='high' if success_count >= 3 else 'medium',
                data={'method': most_successful_method, 'success_count': success_count},
                actionable_steps=[
                    f'Continue using {most_successful_method} on similar files',
                    'Apply this method to unanalyzed files'
                ]
            ))
        
        # Analyze file correlations
        strong_correlations = [fc for fc in session_data['file_correlations'] if fc.correlation_strength > 0.8]
        
        if strong_correlations:
            insights.append(Insight(
                type='correlation',
                title='Strong File Correlations Detected',
                description=f'Found {len(strong_correlations)} strong correlations between files.',
                confidence=0.9,
                impact_level='high',
                data={'correlation_count': len(strong_correlations)},
                actionable_steps=[
                    'Investigate highly correlated files as a group',
                    'Look for shared patterns or hidden connections'
                ]
            ))
        
        return insights
    
    def _analyze_crypto_findings(self, session_data: Dict[str, Any]) -> List[Insight]:
        """Analyze cryptographic findings"""
        insights = []
        
        # Check for solved ciphers
        solved_ciphers = [ca for ca in session_data['cipher_analyses'] if ca.is_solved]
        unsolved_ciphers = [ca for ca in session_data['cipher_analyses'] if not ca.is_solved]
        
        if solved_ciphers:
            insights.append(Insight(
                type='breakthrough',
                title=f'Cipher Breakthrough: {len(solved_ciphers)} Solved',
                description=f'Successfully solved {len(solved_ciphers)} cipher(s). Solutions may contain keys or clues.',
                confidence=1.0,
                impact_level='critical',
                data={'solved_count': len(solved_ciphers), 'solutions': [c.solution_text for c in solved_ciphers if c.solution_text]},
                actionable_steps=[
                    'Analyze solved cipher solutions for additional clues',
                    'Use found keys/passwords on other encrypted content'
                ]
            ))
        
        if unsolved_ciphers:
            # Group by cipher type
            cipher_types = Counter([c.cipher_type for c in unsolved_ciphers])
            
            for cipher_type, count in cipher_types.items():
                insights.append(Insight(
                    type='recommendation',
                    title=f'Unsolved {cipher_type.title()} Ciphers',
                    description=f'{count} unsolved {cipher_type} cipher(s) require attention.',
                    confidence=0.7,
                    impact_level='medium',
                    data={'cipher_type': cipher_type, 'count': count},
                    actionable_steps=[
                        f'Try different {cipher_type} decryption approaches',
                        'Look for keys or clues in solved content'
                    ]
                ))
        
        return insights
    
    def _analyze_progress(self, session_data: Dict[str, Any]) -> List[Insight]:
        """Analyze overall progress and identify bottlenecks"""
        insights = []
        
        session = session_data['session']
        files = session_data['files']
        findings = session_data['findings']
        
        # Calculate analysis coverage
        analyzed_files = len([f for f in files if f.findings])
        total_files = len(files)
        
        if total_files > 0:
            coverage = analyzed_files / total_files
            
            if coverage < 0.5:
                insights.append(Insight(
                    type='recommendation',
                    title='Low Analysis Coverage',
                    description=f'Only {coverage:.1%} of files have been analyzed. Many files may contain undiscovered clues.',
                    confidence=0.8,
                    impact_level='high',
                    data={'coverage': coverage, 'unanalyzed_files': total_files - analyzed_files},
                    actionable_steps=[
                        'Run comprehensive analysis on remaining files',
                        'Prioritize files with unusual characteristics'
                    ]
                ))
        
        # Check for stagnation (no recent activity)
        if session.updated_at:
            days_since_update = (datetime.utcnow() - session.updated_at).days
            
            if days_since_update > 3:
                insights.append(Insight(
                    type='recommendation',
                    title='Session Stagnation Detected',
                    description=f'No activity for {days_since_update} days. Consider new analysis approaches.',
                    confidence=0.6,
                    impact_level='medium',
                    data={'days_inactive': days_since_update},
                    actionable_steps=[
                        'Try different extraction methods',
                        'Collaborate with other analysts',
                        'Use AI-powered analysis tools'
                    ]
                ))
        
        return insights
    
    def _generate_hypotheses(self, session_data: Dict[str, Any], insights: List[Insight]) -> List[Hypothesis]:
        """Generate puzzle-solving hypotheses based on data and insights"""
        hypotheses = []
        
        # Steganography hypothesis
        image_files = [f for f in session_data['files'] if f.mime_type and f.mime_type.startswith('image/')]
        if image_files and not any(pf.pattern_type == 'steganography' for pf in session_data['pattern_findings']):
            hypotheses.append(Hypothesis(
                title='Hidden Steganographic Content',
                description='Image files present but no steganographic content found yet. May contain hidden data.',
                confidence=0.6,
                supporting_evidence=[
                    {'type': 'file_presence', 'description': f'{len(image_files)} image file(s) available'}
                ],
                next_steps=[
                    'Run advanced steganography tools',
                    'Try different bit planes and color channels',
                    'Check for frequency domain hiding'
                ],
                category='steganography'
            ))
        
        # Multi-stage puzzle hypothesis
        if len(session_data['extraction_relationships']) > 2:
            hypotheses.append(Hypothesis(
                title='Multi-Stage Puzzle Structure',
                description='Multiple extraction layers suggest a complex, multi-stage puzzle design.',
                confidence=0.8,
                supporting_evidence=[
                    {'type': 'extraction_depth', 'description': f'{len(session_data["extraction_relationships"])} extraction relationships found'}
                ],
                next_steps=[
                    'Map complete extraction chain',
                    'Look for patterns in extraction sequence',
                    'Check if all stages lead to same endpoint'
                ],
                category='structure'
            ))
        
        # Key reuse hypothesis
        solved_ciphers = [ca for ca in session_data['cipher_analyses'] if ca.is_solved]
        unsolved_ciphers = [ca for ca in session_data['cipher_analyses'] if not ca.is_solved]
        
        if solved_ciphers and unsolved_ciphers:
            hypotheses.append(Hypothesis(
                title='Key Reuse Across Ciphers',
                description='Solved cipher keys might work on unsolved ciphers in the same puzzle.',
                confidence=0.7,
                supporting_evidence=[
                    {'type': 'cipher_presence', 'description': f'{len(solved_ciphers)} solved, {len(unsolved_ciphers)} unsolved ciphers'}
                ],
                next_steps=[
                    'Try solved cipher keys on unsolved ciphers',
                    'Look for key derivation patterns',
                    'Check for key fragments in solutions'
                ],
                category='cryptography'
            ))
        
        return hypotheses
    
    def _create_action_plan(self, session_data: Dict[str, Any], insights: List[Insight], hypotheses: List[Hypothesis]) -> Dict[str, Any]:
        """Create actionable plan based on analysis"""
        immediate_actions = []
        strategic_actions = []
        
        # Extract immediate actions from high-impact insights
        for insight in insights:
            if insight.impact_level in ['critical', 'high']:
                immediate_actions.extend(insight.actionable_steps)
        
        # Extract strategic actions from hypotheses
        for hypothesis in hypotheses:
            if hypothesis.confidence > 0.6:
                strategic_actions.extend(hypothesis.next_steps)
        
        # Remove duplicates while preserving order
        immediate_actions = list(dict.fromkeys(immediate_actions))
        strategic_actions = list(dict.fromkeys(strategic_actions))
        
        return {
            'immediate_actions': immediate_actions[:5],  # Top 5 immediate actions
            'strategic_actions': strategic_actions[:5],  # Top 5 strategic actions
            'priority_focus': self._determine_priority_focus(insights),
            'recommended_tools': self._recommend_tools(session_data, insights)
        }
    
    def _determine_priority_focus(self, insights: List[Insight]) -> str:
        """Determine the priority focus area"""
        focus_areas = Counter()
        
        for insight in insights:
            if insight.impact_level in ['critical', 'high']:
                if insight.type == 'breakthrough':
                    focus_areas['exploitation'] += 3
                elif insight.type == 'pattern':
                    focus_areas['pattern_analysis'] += 2
                elif insight.type == 'correlation':
                    focus_areas['relationship_mapping'] += 2
                elif insight.type == 'recommendation':
                    focus_areas['comprehensive_analysis'] += 1
        
        return focus_areas.most_common(1)[0][0] if focus_areas else 'comprehensive_analysis'
    
    def _recommend_tools(self, session_data: Dict[str, Any], insights: List[Insight]) -> List[str]:
        """Recommend specific tools based on analysis"""
        tools = set()
        
        # Based on file types
        file_types = [f.mime_type for f in session_data['files'] if f.mime_type]
        
        if any('image' in ft for ft in file_types):
            tools.update(['zsteg', 'steghide', 'stegsolve'])
        
        if any('text' in ft for ft in file_types):
            tools.update(['cryptanalysis_tools', 'frequency_analysis'])
        
        if any('application' in ft for ft in file_types):
            tools.update(['binwalk', 'foremost', 'hexeditor'])
        
        # Based on findings
        for cipher in session_data['cipher_analyses']:
            if cipher.cipher_type == 'base64':
                tools.add('base64_decoder')
            elif cipher.cipher_type == 'caesar':
                tools.add('caesar_cipher_solver')
        
        return list(tools)[:8]  # Limit to 8 recommendations
    
    def _calculate_progress_score(self, session_data: Dict[str, Any], insights: List[Insight]) -> float:
        """Calculate overall puzzle progress score (0-100)"""
        score = 0.0
        
        # Base score from analysis completion
        files = session_data['files']
        if files:
            analyzed_files = len([f for f in files if f.findings])
            score += (analyzed_files / len(files)) * 30  # Up to 30 points for analysis coverage
        
        # Score from solved ciphers
        solved_ciphers = len([ca for ca in session_data['cipher_analyses'] if ca.is_solved])
        total_ciphers = len(session_data['cipher_analyses'])
        if total_ciphers > 0:
            score += (solved_ciphers / total_ciphers) * 25  # Up to 25 points for cipher solving
        
        # Score from extraction success
        extractions = len(session_data['extraction_relationships'])
        score += min(extractions * 5, 20)  # Up to 20 points for extractions
        
        # Score from breakthroughs
        breakthroughs = len([i for i in insights if i.type == 'breakthrough'])
        score += min(breakthroughs * 10, 25)  # Up to 25 points for breakthroughs
        
        return min(score, 100.0)
    
    def _generate_session_summary(self, session_data: Dict[str, Any], insights: List[Insight]) -> str:
        """Generate human-readable session summary"""
        session = session_data['session']
        files = session_data['files']
        
        summary_parts = [
            f"Session '{session.name}' contains {len(files)} file(s) with {len(session_data['findings'])} finding(s)."
        ]
        
        # Add breakthrough information
        breakthroughs = [i for i in insights if i.type == 'breakthrough']
        if breakthroughs:
            summary_parts.append(f"Major breakthroughs: {', '.join([b.title for b in breakthroughs])}.")
        
        # Add progress information
        solved_ciphers = len([ca for ca in session_data['cipher_analyses'] if ca.is_solved])
        if solved_ciphers > 0:
            summary_parts.append(f"Successfully solved {solved_ciphers} cipher(s).")
        
        # Add recommendations
        high_impact_insights = [i for i in insights if i.impact_level in ['critical', 'high']]
        if high_impact_insights:
            summary_parts.append(f"Key focus areas: {', '.join([i.title for i in high_impact_insights[:3]])}.")
        
        return " ".join(summary_parts)
    
    def _store_session_intelligence(self, session: PuzzleSession, insights: List[Insight], 
                                  hypotheses: List[Hypothesis], progress_score: float):
        """Store intelligence results in database"""
        try:
            # Store insights as session intelligence
            for insight in insights:
                intelligence = SessionIntelligence(
                    session_id=session.id,
                    intelligence_type='insight',
                    title=insight.title,
                    description=insight.description,
                    confidence_score=insight.confidence,
                    intelligence_data=insight.to_dict(),
                    generated_by_agent='intelligence_synthesis_engine'
                )
                db.session.add(intelligence)
            
            # Store hypotheses
            for hypothesis in hypotheses:
                intelligence = SessionIntelligence(
                    session_id=session.id,
                    intelligence_type='hypothesis',
                    title=hypothesis.title,
                    description=hypothesis.description,
                    confidence_score=hypothesis.confidence,
                    intelligence_data=hypothesis.to_dict(),
                    generated_by_agent='intelligence_synthesis_engine'
                )
                db.session.add(intelligence)
            
            db.session.commit()
            logger.info(f"Stored {len(insights)} insights and {len(hypotheses)} hypotheses for session {session.public_id}")
            
        except Exception as e:
            logger.error(f"Error storing session intelligence: {e}")
            db.session.rollback()


# Global intelligence engine instance
intelligence_engine = IntelligenceSynthesisEngine()


def create_intelligence_api():
    """Create intelligence synthesis API endpoints"""
    from flask import Blueprint, jsonify, request
    from crypto_hunter_web.services.auth_service import AuthService
    
    intel_api = Blueprint('intelligence', __name__, url_prefix='/api/intelligence')
    
    @intel_api.route('/analyze/<session_id>', methods=['POST'])
    @AuthService.login_required
    def analyze_session(session_id):
        """Run intelligence analysis on session"""
        try:
            # Verify user has access to session
            session = PuzzleSession.query.filter_by(public_id=session_id).first()
            if not session:
                return jsonify({'success': False, 'error': 'Session not found'}), 404
            
            current_user = AuthService.get_current_user()
            if session.owner_id != current_user.id and not current_user.is_admin:
                collaborator = session.collaborators.filter_by(user_id=current_user.id).first()
                if not collaborator:
                    return jsonify({'success': False, 'error': 'Access denied'}), 403
            
            # Run analysis
            analysis_result = intelligence_engine.analyze_session(session_id)
            
            return jsonify({
                'success': True,
                'analysis': analysis_result
            })
            
        except Exception as e:
            logger.exception(f"Error analyzing session: {e}")
            return jsonify({'success': False, 'error': str(e)}), 500
    
    @intel_api.route('/insights/<session_id>', methods=['GET'])
    @AuthService.login_required
    def get_session_insights(session_id):
        """Get stored insights for session"""
        try:
            session = PuzzleSession.query.filter_by(public_id=session_id).first()
            if not session:
                return jsonify({'success': False, 'error': 'Session not found'}), 404
            
            # Get insights from database
            insights = SessionIntelligence.query.filter_by(
                session_id=session.id,
                intelligence_type='insight'
            ).order_by(desc(SessionIntelligence.created_at)).all()
            
            return jsonify({
                'success': True,
                'insights': [
                    {
                        'id': i.id,
                        'title': i.title,
                        'description': i.description,
                        'confidence': i.confidence_score,
                        'data': i.intelligence_data,
                        'created_at': i.created_at.isoformat()
                    }
                    for i in insights
                ]
            })
            
        except Exception as e:
            logger.exception(f"Error getting insights: {e}")
            return jsonify({'success': False, 'error': str(e)}), 500
    
    return intel_api
