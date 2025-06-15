#!/usr/bin/env python3
"""
Specialized Agents for Crypto Hunter Multi-Agent System
=======================================================

This module contains specialized agents that handle specific domains:
- FileAnalysisAgent: Analyzes file properties and metadata
- SteganographyAgent: Handles steganographic extraction
- CryptographyAgent: Analyzes cryptographic content
- IntelligenceAgent: Synthesizes findings across agents
- RelationshipAgent: Maps relationships between files
- PresentationAgent: Formats and presents results
"""

import os
import sys
import subprocess
import hashlib
import magic
import tempfile
import json
from pathlib import Path
from typing import Dict, Any, List, Optional
import logging

# Import the agent framework
from crypto_hunter_web.services.agents.agent_framework import (
    BaseAgent, AgentTask, AgentResult, AgentCapability, 
    TaskPriority, AgentStatus
)

logger = logging.getLogger(__name__)

try:
    from crypto_hunter_web.services.file_analyzer import FileAnalyzer
    from crypto_hunter_web.services.crypto_intelligence import CryptoIntelligenceService
    from crypto_hunter_web.services.llm_crypto_orchestrator import LLMCryptoOrchestrator
    SERVICES_AVAILABLE = True
except ImportError:
    SERVICES_AVAILABLE = False
    logger.warning("Some services not available for agents")


class FileAnalysisAgent(BaseAgent):
    """Agent specialized in file analysis and metadata extraction"""

    def __init__(self):
        super().__init__("file_analyzer", [AgentCapability.FILE_ANALYSIS])
        self.file_analyzer = FileAnalyzer() if SERVICES_AVAILABLE else None

    async def execute(self, task: AgentTask) -> AgentResult:
        """Execute file analysis task"""
        file_path = task.input_data.get('file_path')
        action = task.input_data.get('action', 'analyze')

        if not file_path or not os.path.exists(file_path):
            return AgentResult(
                task_id=task.task_id,
                agent_id=self.agent_id,
                success=False,
                output_data={},
                error_message=f"File not found: {file_path}"
            )

        try:
            analysis_result = {
                'file_path': file_path,
                'file_size': os.path.getsize(file_path),
                'file_type': self._detect_file_type(file_path),
                'sha256': self._calculate_sha256(file_path),
                'entropy': self._calculate_entropy(file_path),
                'metadata': self._extract_metadata(file_path)
            }

            # Use existing FileAnalyzer if available
            if self.file_analyzer and action == 'full_analysis':
                try:
                    detailed_analysis = self.file_analyzer.analyze_file(file_path)
                    analysis_result.update(detailed_analysis)
                except Exception as e:
                    logger.warning(f"FileAnalyzer integration failed: {e}")

            confidence = self._calculate_confidence(analysis_result)

            return AgentResult(
                task_id=task.task_id,
                agent_id=self.agent_id,
                success=True,
                output_data=analysis_result,
                confidence=confidence,
                metadata={
                    'analysis_type': action,
                    'file_type': analysis_result['file_type']
                }
            )

        except Exception as e:
            return AgentResult(
                task_id=task.task_id,
                agent_id=self.agent_id,
                success=False,
                output_data={},
                error_message=f"File analysis failed: {e}"
            )

    def _detect_file_type(self, file_path: str) -> str:
        """Detect file type using magic"""
        try:
            return magic.Magic(mime=True).from_file(file_path)
        except:
            return "application/octet-stream"

    def _calculate_sha256(self, file_path: str) -> str:
        """Calculate SHA256 hash"""
        try:
            with open(file_path, 'rb') as f:
                return hashlib.sha256(f.read()).hexdigest()
        except:
            return ""

    def _calculate_entropy(self, file_path: str) -> float:
        """Calculate file entropy"""
        try:
            with open(file_path, 'rb') as f:
                data = f.read(8192)  # Sample first 8KB
                if not data:
                    return 0.0

                # Calculate byte frequency
                freq = [0] * 256
                for byte in data:
                    freq[byte] += 1

                # Calculate entropy
                entropy = 0.0
                data_len = len(data)
                for count in freq:
                    if count > 0:
                        p = count / data_len
                        entropy -= p * (p.bit_length() - 1)

                return entropy
        except:
            return 0.0

    def _extract_metadata(self, file_path: str) -> Dict[str, Any]:
        """Extract metadata using exiftool"""
        try:
            result = subprocess.run(
                ['exiftool', '-json', file_path],
                capture_output=True, text=True, timeout=30
            )
            if result.returncode == 0:
                metadata = json.loads(result.stdout)
                return metadata[0] if metadata else {}
        except:
            pass
        return {}

    def _calculate_confidence(self, analysis_result: Dict[str, Any]) -> float:
        """Calculate confidence score for analysis"""
        confidence = 0.5  # Base confidence

        # Increase confidence based on available data
        if analysis_result.get('sha256'):
            confidence += 0.2
        if analysis_result.get('entropy', 0) > 0:
            confidence += 0.1
        if analysis_result.get('metadata'):
            confidence += 0.2

        return min(confidence, 1.0)


class SteganographyAgent(BaseAgent):
    """Agent specialized in steganographic extraction"""

    def __init__(self):
        super().__init__("steganography_extractor", [AgentCapability.STEGANOGRAPHY])
        self.extraction_methods = [
            'zsteg', 'steghide', 'binwalk', 'foremost', 'strings'
        ]

    async def execute(self, task: AgentTask) -> AgentResult:
        """Execute steganography extraction task"""
        file_path = task.input_data.get('file_path')
        methods = task.input_data.get('methods', self.extraction_methods)

        if not file_path or not os.path.exists(file_path):
            return AgentResult(
                task_id=task.task_id,
                agent_id=self.agent_id,
                success=False,
                output_data={},
                error_message=f"File not found: {file_path}"
            )

        try:
            extraction_results = []
            total_extracted = 0

            # Create output directory
            output_dir = Path(f"/tmp/stego_extraction_{task.task_id}")
            output_dir.mkdir(exist_ok=True)

            for method in methods:
                method_result = await self._run_extraction_method(
                    method, file_path, output_dir
                )
                extraction_results.append(method_result)
                if method_result['success']:
                    total_extracted += len(method_result.get('extracted_files', []))

            # Calculate overall confidence
            confidence = self._calculate_extraction_confidence(extraction_results, total_extracted)

            return AgentResult(
                task_id=task.task_id,
                agent_id=self.agent_id,
                success=total_extracted > 0,
                output_data={
                    'source_file': file_path,
                    'total_extracted_files': total_extracted,
                    'extraction_results': extraction_results,
                    'output_directory': str(output_dir)
                },
                confidence=confidence,
                metadata={
                    'methods_used': [r['method'] for r in extraction_results if r['success']],
                    'total_methods': len(methods)
                }
            )

        except Exception as e:
            return AgentResult(
                task_id=task.task_id,
                agent_id=self.agent_id,
                success=False,
                output_data={},
                error_message=f"Steganography extraction failed: {e}"
            )

    async def _run_extraction_method(self, method: str, file_path: str, 
                                   output_dir: Path) -> Dict[str, Any]:
        """Run specific extraction method"""
        method_dir = output_dir / method
        method_dir.mkdir(exist_ok=True)

        try:
            if method == 'zsteg':
                return await self._run_zsteg(file_path, method_dir)
            elif method == 'steghide':
                return await self._run_steghide(file_path, method_dir)
            elif method == 'binwalk':
                return await self._run_binwalk(file_path, method_dir)
            elif method == 'foremost':
                return await self._run_foremost(file_path, method_dir)
            elif method == 'strings':
                return await self._run_strings(file_path, method_dir)
            else:
                return {
                    'method': method,
                    'success': False,
                    'error': f"Unknown method: {method}",
                    'extracted_files': []
                }
        except Exception as e:
            return {
                'method': method,
                'success': False,
                'error': str(e),
                'extracted_files': []
            }

    async def _run_zsteg(self, file_path: str, output_dir: Path) -> Dict[str, Any]:
        """Run zsteg extraction"""
        extracted_files = []

        try:
            # Basic zsteg analysis
            result = subprocess.run(
                ['zsteg', '-a', file_path],
                capture_output=True, text=True, timeout=60
            )

            if result.returncode == 0 and result.stdout.strip():
                # Save analysis output
                analysis_file = output_dir / "zsteg_analysis.txt"
                with open(analysis_file, 'w') as f:
                    f.write(result.stdout)
                extracted_files.append(str(analysis_file))

                # Try to extract specific channels
                channels = ['b1,bgr,lsb,xy', 'b2,bgr,lsb,xy', 'b1,rgb,lsb,xy']
                for i, channel in enumerate(channels):
                    try:
                        extract_result = subprocess.run(
                            ['zsteg', '-E', channel, file_path],
                            capture_output=True, timeout=30
                        )
                        if extract_result.returncode == 0 and extract_result.stdout:
                            channel_file = output_dir / f"channel_{i:02d}_{channel.replace(',', '_')}.bin"
                            with open(channel_file, 'wb') as f:
                                f.write(extract_result.stdout)
                            extracted_files.append(str(channel_file))
                    except subprocess.TimeoutExpired:
                        continue

            return {
                'method': 'zsteg',
                'success': len(extracted_files) > 0,
                'extracted_files': extracted_files,
                'details': f"zsteg extracted {len(extracted_files)} files"
            }

        except Exception as e:
            return {
                'method': 'zsteg',
                'success': False,
                'error': str(e),
                'extracted_files': []
            }

    async def _run_steghide(self, file_path: str, output_dir: Path) -> Dict[str, Any]:
        """Run steghide extraction"""
        try:
            output_file = output_dir / "steghide_output.bin"
            result = subprocess.run(
                ['steghide', 'extract', '-sf', file_path, '-xf', str(output_file), '-p', ''],
                capture_output=True, timeout=30
            )

            extracted_files = []
            if result.returncode == 0 and output_file.exists() and output_file.stat().st_size > 0:
                extracted_files.append(str(output_file))

            return {
                'method': 'steghide',
                'success': len(extracted_files) > 0,
                'extracted_files': extracted_files,
                'details': f"steghide extracted {len(extracted_files)} files"
            }

        except Exception as e:
            return {
                'method': 'steghide',
                'success': False,
                'error': str(e),
                'extracted_files': []
            }

    async def _run_binwalk(self, file_path: str, output_dir: Path) -> Dict[str, Any]:
        """Run binwalk extraction"""
        try:
            with tempfile.TemporaryDirectory() as temp_dir:
                result = subprocess.run(
                    ['binwalk', '-e', '--directory', temp_dir, file_path],
                    capture_output=True, timeout=120
                )

                extracted_files = []
                # Copy extracted files to our output directory
                for root, dirs, files in os.walk(temp_dir):
                    for file in files:
                        temp_file_path = os.path.join(root, file)
                        if os.path.getsize(temp_file_path) > 0:
                            dest_file = output_dir / f"binwalk_{file}"
                            os.rename(temp_file_path, dest_file)
                            extracted_files.append(str(dest_file))

                return {
                    'method': 'binwalk',
                    'success': len(extracted_files) > 0,
                    'extracted_files': extracted_files,
                    'details': f"binwalk carved {len(extracted_files)} files"
                }

        except Exception as e:
            return {
                'method': 'binwalk',
                'success': False,
                'error': str(e),
                'extracted_files': []
            }

    async def _run_foremost(self, file_path: str, output_dir: Path) -> Dict[str, Any]:
        """Run foremost file carving"""
        try:
            with tempfile.TemporaryDirectory() as temp_dir:
                result = subprocess.run(
                    ['foremost', '-o', temp_dir, file_path],
                    capture_output=True, timeout=120
                )

                extracted_files = []
                # Copy extracted files to our output directory
                for root, dirs, files in os.walk(temp_dir):
                    for file in files:
                        temp_file_path = os.path.join(root, file)
                        if os.path.getsize(temp_file_path) > 0:
                            dest_file = output_dir / f"foremost_{file}"
                            os.rename(temp_file_path, dest_file)
                            extracted_files.append(str(dest_file))

                return {
                    'method': 'foremost',
                    'success': len(extracted_files) > 0,
                    'extracted_files': extracted_files,
                    'details': f"foremost carved {len(extracted_files)} files"
                }

        except Exception as e:
            return {
                'method': 'foremost',
                'success': False,
                'error': str(e),
                'extracted_files': []
            }

    async def _run_strings(self, file_path: str, output_dir: Path) -> Dict[str, Any]:
        """Run strings extraction"""
        try:
            result = subprocess.run(
                ['strings', file_path],
                capture_output=True, text=True, timeout=60
            )

            extracted_files = []
            if result.returncode == 0 and result.stdout.strip():
                strings_file = output_dir / "strings_output.txt"
                with open(strings_file, 'w') as f:
                    f.write(result.stdout)
                extracted_files.append(str(strings_file))

            return {
                'method': 'strings',
                'success': len(extracted_files) > 0,
                'extracted_files': extracted_files,
                'details': f"strings extracted {len(result.stdout.splitlines())} lines"
            }

        except Exception as e:
            return {
                'method': 'strings',
                'success': False,
                'error': str(e),
                'extracted_files': []
            }

    def _calculate_extraction_confidence(self, results: List[Dict], total_extracted: int) -> float:
        """Calculate confidence based on extraction results"""
        if total_extracted == 0:
            return 0.0

        base_confidence = 0.3

        # Increase confidence based on number of successful methods
        successful_methods = sum(1 for r in results if r['success'])
        confidence = base_confidence + (successful_methods * 0.15)

        # Increase confidence based on number of extracted files
        if total_extracted > 10:
            confidence += 0.2
        elif total_extracted > 5:
            confidence += 0.1

        return min(confidence, 1.0)


class CryptographyAgent(BaseAgent):
    """Agent specialized in cryptographic analysis"""

    def __init__(self):
        super().__init__("crypto_analyzer", [AgentCapability.CRYPTOGRAPHY])
        self.crypto_service = CryptoIntelligenceService() if SERVICES_AVAILABLE else None
        self.llm_orchestrator = LLMCryptoOrchestrator() if SERVICES_AVAILABLE else None

    async def execute(self, task: AgentTask) -> AgentResult:
        """Execute cryptographic analysis task"""
        file_path = task.input_data.get('file_path')
        content = task.input_data.get('content')

        if not file_path and not content:
            return AgentResult(
                task_id=task.task_id,
                agent_id=self.agent_id,
                success=False,
                output_data={},
                error_message="No file path or content provided for analysis"
            )

        try:
            # Read content if file path provided
            if file_path and os.path.exists(file_path):
                with open(file_path, 'rb') as f:
                    content = f.read()

            if not content:
                return AgentResult(
                    task_id=task.task_id,
                    agent_id=self.agent_id,
                    success=False,
                    output_data={},
                    error_message="No content to analyze"
                )

            analysis_result = {
                'file_path': file_path,
                'content_length': len(content),
                'crypto_patterns': self._detect_crypto_patterns(content),
                'hash_analysis': self._analyze_hashes(content),
                'cipher_analysis': self._analyze_ciphers(content),
                'key_patterns': self._detect_key_patterns(content)
            }

            # Use existing crypto services if available
            if self.crypto_service:
                try:
                    crypto_intelligence = self.crypto_service.analyze_content(content.decode('utf-8', errors='ignore'))
                    analysis_result['intelligence'] = crypto_intelligence
                except Exception as e:
                    logger.warning(f"CryptoIntelligenceService failed: {e}")

            if self.llm_orchestrator:
                try:
                    llm_analysis = self.llm_orchestrator.analyze_crypto_content(content.decode('utf-8', errors='ignore'))
                    analysis_result['llm_analysis'] = llm_analysis
                except Exception as e:
                    logger.warning(f"LLM analysis failed: {e}")

            confidence = self._calculate_crypto_confidence(analysis_result)

            return AgentResult(
                task_id=task.task_id,
                agent_id=self.agent_id,
                success=True,
                output_data=analysis_result,
                confidence=confidence,
                metadata={
                    'patterns_found': len(analysis_result['crypto_patterns']),
                    'has_intelligence': 'intelligence' in analysis_result
                }
            )

        except Exception as e:
            return AgentResult(
                task_id=task.task_id,
                agent_id=self.agent_id,
                success=False,
                output_data={},
                error_message=f"Cryptographic analysis failed: {e}"
            )

    def _detect_crypto_patterns(self, content: bytes) -> List[Dict[str, Any]]:
        """Detect cryptographic patterns in content"""
        patterns = []
        text_content = content.decode('utf-8', errors='ignore')

        # Bitcoin addresses
        import re
        btc_pattern = r'\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b'
        btc_matches = re.findall(btc_pattern, text_content)
        if btc_matches:
            patterns.append({
                'type': 'bitcoin_address',
                'count': len(btc_matches),
                'samples': btc_matches[:5]
            })

        # Ethereum addresses
        eth_pattern = r'\b0x[a-fA-F0-9]{40}\b'
        eth_matches = re.findall(eth_pattern, text_content)
        if eth_matches:
            patterns.append({
                'type': 'ethereum_address',
                'count': len(eth_matches),
                'samples': eth_matches[:5]
            })

        # Base64 patterns
        b64_pattern = r'[A-Za-z0-9+/]{20,}={0,2}'
        b64_matches = re.findall(b64_pattern, text_content)
        if b64_matches:
            patterns.append({
                'type': 'base64',
                'count': len(b64_matches),
                'samples': b64_matches[:5]
            })

        return patterns

    def _analyze_hashes(self, content: bytes) -> Dict[str, Any]:
        """Analyze hash patterns in content"""
        text_content = content.decode('utf-8', errors='ignore')

        # Common hash patterns
        import re
        hash_patterns = {
            'md5': r'\b[a-fA-F0-9]{32}\b',
            'sha1': r'\b[a-fA-F0-9]{40}\b',
            'sha256': r'\b[a-fA-F0-9]{64}\b',
            'sha512': r'\b[a-fA-F0-9]{128}\b'
        }

        hash_analysis = {}
        for hash_type, pattern in hash_patterns.items():
            matches = re.findall(pattern, text_content)
            if matches:
                hash_analysis[hash_type] = {
                    'count': len(matches),
                    'samples': matches[:3]
                }

        return hash_analysis

    def _analyze_ciphers(self, content: bytes) -> Dict[str, Any]:
        """Analyze potential cipher content"""
        text_content = content.decode('utf-8', errors='ignore')

        analysis = {
            'has_repeated_patterns': self._check_repeated_patterns(text_content),
            'character_frequency': self._analyze_character_frequency(text_content),
            'potential_substitution': self._check_substitution_cipher(text_content),
            'has_numbers_only': text_content.isdigit(),
            'mixed_case': any(c.isupper() for c in text_content) and any(c.islower() for c in text_content)
        }

        return analysis

    def _detect_key_patterns(self, content: bytes) -> List[str]:
        """Detect potential cryptographic keys"""
        patterns = []
        text_content = content.decode('utf-8', errors='ignore')

        # PEM format keys
        if '-----BEGIN' in text_content and '-----END' in text_content:
            patterns.append('pem_format_key')

        # SSH key patterns
        if text_content.startswith('ssh-'):
            patterns.append('ssh_key')

        # High entropy strings (potential keys)
        lines = text_content.split('\n')
        for line in lines:
            if len(line) > 40 and self._calculate_entropy(line.encode()) > 4.5:
                patterns.append('high_entropy_string')
                break

        return patterns

    def _check_repeated_patterns(self, text: str) -> bool:
        """Check for repeated patterns in text"""
        if len(text) < 20:
            return False

        # Look for repeated substrings
        for length in range(3, min(10, len(text) // 3)):
            for i in range(len(text) - length * 2):
                pattern = text[i:i+length]
                if text[i+length:].startswith(pattern):
                    return True
        return False

    def _analyze_character_frequency(self, text: str) -> Dict[str, float]:
        """Analyze character frequency distribution"""
        if not text:
            return {}

        freq = {}
        for char in text.lower():
            if char.isalpha():
                freq[char] = freq.get(char, 0) + 1

        total = sum(freq.values())
        if total == 0:
            return {}

        # Convert to percentages
        return {char: (count / total) * 100 for char, count in freq.items()}

    def _check_substitution_cipher(self, text: str) -> bool:
        """Check if text might be a substitution cipher"""
        if len(text) < 50:
            return False

        # Simple heuristic: check if character distribution is unusual
        freq = self._analyze_character_frequency(text)
        if not freq:
            return False

        # In English, 'e' should be most common
        most_common = max(freq.items(), key=lambda x: x[1])
        return most_common[1] < 8  # 'e' frequency should be around 12%

    def _calculate_entropy(self, data: bytes) -> float:
        """Calculate entropy of data"""
        if not data:
            return 0.0

        freq = [0] * 256
        for byte in data:
            freq[byte] += 1

        entropy = 0.0
        data_len = len(data)
        for count in freq:
            if count > 0:
                p = count / data_len
                entropy -= p * (p.bit_length() - 1)

        return entropy

    def _calculate_crypto_confidence(self, analysis: Dict[str, Any]) -> float:
        """Calculate confidence score for crypto analysis"""
        confidence = 0.1  # Base confidence

        # Increase based on patterns found
        if analysis.get('crypto_patterns'):
            confidence += len(analysis['crypto_patterns']) * 0.2

        if analysis.get('hash_analysis'):
            confidence += len(analysis['hash_analysis']) * 0.15

        if analysis.get('key_patterns'):
            confidence += len(analysis['key_patterns']) * 0.25

        if analysis.get('intelligence'):
            confidence += 0.3

        return min(confidence, 1.0)


class IntelligenceAgent(BaseAgent):
    """Agent that synthesizes findings from other agents"""

    def __init__(self):
        super().__init__("intelligence_synthesizer", [AgentCapability.INTELLIGENCE])
        self.findings_cache: Dict[str, Any] = {}

    async def execute(self, task: AgentTask) -> AgentResult:
        """Synthesize intelligence from multiple agent results"""
        agent_results = task.input_data.get('agent_results', [])
        synthesis_type = task.input_data.get('synthesis_type', 'comprehensive')

        if not agent_results:
            return AgentResult(
                task_id=task.task_id,
                agent_id=self.agent_id,
                success=False,
                output_data={},
                error_message="No agent results provided for synthesis"
            )

        try:
            synthesis = {
                'synthesis_type': synthesis_type,
                'agent_count': len(agent_results),
                'cross_agent_correlations': self._find_correlations(agent_results),
                'confidence_analysis': self._analyze_confidence(agent_results),
                'key_findings': self._extract_key_findings(agent_results),
                'recommendations': self._generate_recommendations(agent_results),
                'threat_assessment': self._assess_threats(agent_results)
            }

            # Generate overall confidence
            overall_confidence = self._calculate_synthesis_confidence(synthesis)

            return AgentResult(
                task_id=task.task_id,
                agent_id=self.agent_id,
                success=True,
                output_data=synthesis,
                confidence=overall_confidence,
                metadata={
                    'correlations_found': len(synthesis['cross_agent_correlations']),
                    'high_confidence_findings': len([f for f in synthesis['key_findings'] if f.get('confidence', 0) > 0.8])
                }
            )

        except Exception as e:
            return AgentResult(
                task_id=task.task_id,
                agent_id=self.agent_id,
                success=False,
                output_data={},
                error_message=f"Intelligence synthesis failed: {e}"
            )

    def _find_correlations(self, agent_results: List[Dict]) -> List[Dict[str, Any]]:
        """Find correlations between agent findings"""
        correlations = []

        # Look for common patterns across agents
        all_patterns = {}
        for result in agent_results:
            agent_id = result.get('agent_id', 'unknown')
            output_data = result.get('output_data', {})

            # Extract patterns from different agent types
            if 'crypto_patterns' in output_data:
                for pattern in output_data['crypto_patterns']:
                    pattern_key = f"{pattern['type']}"
                    if pattern_key not in all_patterns:
                        all_patterns[pattern_key] = []
                    all_patterns[pattern_key].append({
                        'agent': agent_id,
                        'details': pattern
                    })

        # Find patterns mentioned by multiple agents
        for pattern_key, mentions in all_patterns.items():
            if len(mentions) > 1:
                correlations.append({
                    'type': 'cross_agent_pattern',
                    'pattern': pattern_key,
                    'agents': [m['agent'] for m in mentions],
                    'confidence': 0.8 + (len(mentions) * 0.1)
                })

        return correlations

    def _analyze_confidence(self, agent_results: List[Dict]) -> Dict[str, Any]:
        """Analyze confidence levels across agents"""
        confidences = [r.get('confidence', 0.0) for r in agent_results]

        return {
            'average_confidence': sum(confidences) / len(confidences) if confidences else 0.0,
            'max_confidence': max(confidences) if confidences else 0.0,
            'min_confidence': min(confidences) if confidences else 0.0,
            'high_confidence_agents': len([c for c in confidences if c > 0.8]),
            'distribution': {
                'high': len([c for c in confidences if c > 0.7]),
                'medium': len([c for c in confidences if 0.4 <= c <= 0.7]),
                'low': len([c for c in confidences if c < 0.4])
            }
        }

    def _extract_key_findings(self, agent_results: List[Dict]) -> List[Dict[str, Any]]:
        """Extract the most important findings"""
        key_findings = []

        for result in agent_results:
            agent_id = result.get('agent_id', 'unknown')
            confidence = result.get('confidence', 0.0)
            output_data = result.get('output_data', {})

            # Extract significant findings based on agent type
            if 'crypto_patterns' in output_data and output_data['crypto_patterns']:
                key_findings.append({
                    'type': 'crypto_discovery',
                    'agent': agent_id,
                    'confidence': confidence,
                    'details': f"Found {len(output_data['crypto_patterns'])} crypto patterns",
                    'data': output_data['crypto_patterns']
                })

            if 'total_extracted_files' in output_data and output_data['total_extracted_files'] > 0:
                key_findings.append({
                    'type': 'extraction_success',
                    'agent': agent_id,
                    'confidence': confidence,
                    'details': f"Extracted {output_data['total_extracted_files']} files",
                    'data': {'file_count': output_data['total_extracted_files']}
                })

        # Sort by confidence
        key_findings.sort(key=lambda x: x['confidence'], reverse=True)
        return key_findings[:10]  # Top 10 findings

    def _generate_recommendations(self, agent_results: List[Dict]) -> List[str]:
        """Generate recommendations based on findings"""
        recommendations = []

        has_crypto = any('crypto_patterns' in r.get('output_data', {}) for r in agent_results)
        has_extractions = any('total_extracted_files' in r.get('output_data', {}) for r in agent_results)
        high_confidence_results = [r for r in agent_results if r.get('confidence', 0) > 0.8]

        if has_crypto:
            recommendations.append("Investigate cryptographic patterns for potential private keys or wallet addresses")

        if has_extractions:
            recommendations.append("Analyze extracted files for additional hidden content")

        if len(high_confidence_results) > 2:
            recommendations.append("Multiple high-confidence findings suggest significant hidden content")

        if not recommendations:
            recommendations.append("Consider additional analysis methods or manual inspection")

        return recommendations

    def _assess_threats(self, agent_results: List[Dict]) -> Dict[str, Any]:
        """Assess potential security threats"""
        threat_indicators = []

        for result in agent_results:
            output_data = result.get('output_data', {})

            # Check for potential threats
            if 'crypto_patterns' in output_data:
                for pattern in output_data['crypto_patterns']:
                    if pattern['type'] in ['bitcoin_address', 'ethereum_address']:
                        threat_indicators.append('cryptocurrency_content')

            if 'key_patterns' in output_data and output_data['key_patterns']:
                threat_indicators.append('cryptographic_keys')

        threat_level = 'low'
        if len(threat_indicators) > 3:
            threat_level = 'high'
        elif len(threat_indicators) > 1:
            threat_level = 'medium'

        return {
            'threat_level': threat_level,
            'indicators': list(set(threat_indicators)),
            'recommendation': 'Monitor for additional suspicious activity' if threat_level != 'low' else 'No immediate threats detected'
        }

    def _calculate_synthesis_confidence(self, synthesis: Dict[str, Any]) -> float:
        """Calculate overall synthesis confidence"""
        base_confidence = 0.5

        # Increase based on correlations found
        correlations = synthesis.get('cross_agent_correlations', [])
        if correlations:
            base_confidence += len(correlations) * 0.1

        # Increase based on confidence analysis
        conf_analysis = synthesis.get('confidence_analysis', {})
        avg_conf = conf_analysis.get('average_confidence', 0.0)
        base_confidence += avg_conf * 0.3

        return min(base_confidence, 1.0)
