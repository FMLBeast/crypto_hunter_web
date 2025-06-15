"""
Comprehensive file analyzer with crypto intelligence and metadata generation
"""

import json
import logging
import mimetypes
import magic
import os
import re
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any

from crypto_hunter_web.models import db, AnalysisFile, FileContent, FileStatus

logger = logging.getLogger(__name__)

class FileAnalyzer:
    """Comprehensive file analysis with crypto intelligence and metadata generation"""

    # Configuration constants
    MAX_CONTENT_SIZE = 100 * 1024 * 1024  # 100MB max for content analysis
    CHUNK_SIZE = 8192  # 8KB chunks for reading
    MAX_TEXT_PREVIEW = 10000  # Max characters for text preview

    # Crypto patterns (compiled for performance)
    CRYPTO_PATTERNS = {
        'bitcoin_address': re.compile(r'\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b'),
        'ethereum_address': re.compile(r'\b0x[a-fA-F0-9]{40}\b'),
        'private_key_hex': re.compile(r'\b[a-fA-F0-9]{64}\b'),
        'base64_key': re.compile(r'[A-Za-z0-9+/]{40,}={0,2}'),
        'pem_header': re.compile(r'-----BEGIN [A-Z ]+-----'),
        'pem_footer': re.compile(r'-----END [A-Z ]+-----'),
        'ssh_key': re.compile(r'ssh-[a-z0-9]+ [A-Za-z0-9+/=]+'),
        'pgp_block': re.compile(r'-----BEGIN PGP [A-Z ]+-----'),
        'certificate': re.compile(r'-----BEGIN CERTIFICATE-----'),
        'wallet_file': re.compile(r'"addresses":|"wallet":|"keystore":'),
        'mnemonic_words': re.compile(r'\b(?:abandon|ability|able|about|above|absent|absorb|abstract|absurd|abuse)\b'),
        'hash_md5': re.compile(r'\b[a-f0-9]{32}\b'),
        'hash_sha1': re.compile(r'\b[a-f0-9]{40}\b'),
        'hash_sha256': re.compile(r'\b[a-f0-9]{64}\b'),
    }

    @staticmethod
    def analyze_file_content(filepath: str, file_id: int) -> bool:
        """Comprehensive file content analysis with crypto intelligence"""
        try:
            if not os.path.exists(filepath):
                logger.warning(f"File not found for analysis: {filepath}")
                return False

            if not os.access(filepath, os.R_OK):
                logger.warning(f"Cannot read file for analysis: {filepath}")
                return False

            file_size = os.path.getsize(filepath)
            if file_size > FileAnalyzer.MAX_CONTENT_SIZE:
                logger.info(f"Skipping analysis of large file ({file_size} bytes): {filepath}")
                return FileAnalyzer._create_basic_analysis(file_id, filepath, file_size)

            # Perform comprehensive analysis
            analysis_result = FileAnalyzer._perform_comprehensive_analysis(filepath, file_size)

            # Save analysis results
            return FileAnalyzer._save_analysis_results(file_id, analysis_result)

        except Exception as e:
            logger.error(f"File analysis failed for {filepath}: {e}")
            return FileAnalyzer._create_error_analysis(file_id, str(e))

    @staticmethod
    def _perform_comprehensive_analysis(filepath: str, file_size: int) -> Dict[str, Any]:
        """Perform comprehensive file analysis with crypto intelligence"""
        analysis = {
            'file_info': {},
            'crypto_analysis': {},
            'content_analysis': {},
            'metadata': {},
            'intelligence_score': 0,
            'analysis_timestamp': datetime.now().isoformat()
        }

        try:
            # Basic file information
            analysis['file_info'] = FileAnalyzer._analyze_file_info(filepath, file_size)

            # Content-based analysis
            analysis['content_analysis'] = FileAnalyzer._analyze_content(filepath)

            # Comprehensive crypto analysis
            analysis['crypto_analysis'] = FileAnalyzer._analyze_crypto_indicators(
                filepath, analysis['content_analysis']
            )

            # Extract metadata with intelligence
            analysis['metadata'] = FileAnalyzer._extract_metadata(filepath)

            # Calculate intelligence score
            analysis['intelligence_score'] = FileAnalyzer._calculate_intelligence_score(analysis)

            # Generate actionable intelligence
            analysis['intelligence_summary'] = FileAnalyzer._generate_intelligence_summary(analysis)

        except Exception as e:
            logger.error(f"Error during comprehensive analysis: {e}")
            analysis['analysis_error'] = str(e)

        return analysis

    @staticmethod
    def _analyze_file_info(filepath: str, file_size: int) -> Dict[str, Any]:
        """Analyze basic file information with crypto indicators"""
        file_info = {
            'size': file_size,
            'extension': Path(filepath).suffix.lower(),
            'mime_type': None,
            'file_type_magic': None,
            'is_binary': False,
            'is_encrypted': False,
            'entropy': 0.0,
            'crypto_file_indicators': []
        }

        try:
            # MIME type detection
            file_info['mime_type'], _ = mimetypes.guess_type(filepath)

            # Magic number detection
            try:
                file_info['file_type_magic'] = magic.from_file(filepath, mime=True)
            except:
                pass  # magic library not available or failed

            # Binary detection and entropy calculation
            with open(filepath, 'rb') as f:
                sample = f.read(8192)  # Read first 8KB

                # Check if binary
                file_info['is_binary'] = b'\x00' in sample

                # Calculate entropy (simplified)
                if sample:
                    file_info['entropy'] = FileAnalyzer._calculate_entropy(sample)
                    file_info['is_encrypted'] = file_info['entropy'] > 7.5  # High entropy suggests encryption

            # Check for crypto file indicators in filename
            filename = Path(filepath).name.lower()
            crypto_indicators = [
                'wallet', 'private', 'key', 'keystore', 'utc', 'bitcoin', 'ethereum',
                'seed', 'mnemonic', 'pgp', 'gpg', 'ssh', 'cert', 'pem'
            ]

            for indicator in crypto_indicators:
                if indicator in filename:
                    file_info['crypto_file_indicators'].append(indicator)

        except Exception as e:
            logger.warning(f"Error analyzing file info: {e}")

        return file_info

    @staticmethod
    def _analyze_content(filepath: str) -> Dict[str, Any]:
        """Analyze file content for crypto patterns and structure"""
        content_analysis = {
            'text_content': None,
            'is_text': False,
            'encoding': None,
            'line_count': 0,
            'contains_crypto_keywords': False,
            'file_structure': {},
            'crypto_patterns_detected': []
        }

        try:
            # Try to read as text with encoding detection
            text_content = FileAnalyzer._read_text_safely(filepath)

            if text_content:
                content_analysis['is_text'] = True
                content_analysis['text_content'] = text_content[:FileAnalyzer.MAX_TEXT_PREVIEW]
                content_analysis['line_count'] = text_content.count('\n') + 1

                # Check for crypto keywords
                crypto_keywords = [
                    'bitcoin', 'ethereum', 'wallet', 'private key', 'public key',
                    'cryptocurrency', 'blockchain', 'mnemonic', 'seed phrase',
                    'keystore', 'address', 'signature', 'hash', 'satoshi',
                    'litecoin', 'dogecoin', 'monero', 'zcash', 'ripple'
                ]

                content_lower = text_content.lower()
                content_analysis['contains_crypto_keywords'] = any(
                    keyword in content_lower for keyword in crypto_keywords
                )

                # Detect crypto patterns in content
                for pattern_name, pattern in FileAnalyzer.CRYPTO_PATTERNS.items():
                    matches = pattern.findall(text_content)
                    if matches:
                        content_analysis['crypto_patterns_detected'].append({
                            'type': pattern_name,
                            'count': len(matches),
                            'samples': matches[:3]  # First 3 matches
                        })

                # Analyze file structure for specific formats
                content_analysis['file_structure'] = FileAnalyzer._analyze_file_structure(
                    text_content, filepath
                )

        except Exception as e:
            logger.warning(f"Error analyzing content: {e}")

        return content_analysis

    @staticmethod
    def _analyze_crypto_indicators(filepath: str, content_analysis: Dict) -> Dict[str, Any]:
        """Comprehensive crypto analysis with intelligence scoring"""
        crypto_analysis = {
            'crypto_patterns_found': {},
            'wallet_indicators': {},
            'key_indicators': {},
            'blockchain_indicators': {},
            'crypto_confidence_score': 0.0,
            'potential_crypto_type': None,
            'actionable_findings': []
        }

        try:
            text_content = content_analysis.get('text_content', '')

            if text_content:
                # Comprehensive pattern analysis
                for pattern_name, pattern in FileAnalyzer.CRYPTO_PATTERNS.items():
                    matches = pattern.findall(text_content)
                    if matches:
                        crypto_analysis['crypto_patterns_found'][pattern_name] = {
                            'count': len(matches),
                            'samples': matches[:5]  # First 5 matches
                        }

                # Analyze wallet-specific indicators
                crypto_analysis['wallet_indicators'] = FileAnalyzer._analyze_wallet_indicators(
                    text_content
                )

                # Analyze key-specific indicators
                crypto_analysis['key_indicators'] = FileAnalyzer._analyze_key_indicators(
                    text_content
                )

                # Analyze blockchain-specific indicators
                crypto_analysis['blockchain_indicators'] = FileAnalyzer._analyze_blockchain_indicators(
                    text_content
                )

                # Calculate confidence score
                crypto_analysis['crypto_confidence_score'] = FileAnalyzer._calculate_crypto_confidence(
                    crypto_analysis, content_analysis
                )

                # Determine potential crypto type
                crypto_analysis['potential_crypto_type'] = FileAnalyzer._determine_crypto_type(
                    crypto_analysis
                )

                # Generate actionable findings
                crypto_analysis['actionable_findings'] = FileAnalyzer._generate_actionable_findings(
                    crypto_analysis
                )

        except Exception as e:
            logger.warning(f"Error analyzing crypto indicators: {e}")

        return crypto_analysis

    @staticmethod
    def _read_text_safely(filepath: str) -> Optional[str]:
        """Safely read text file with encoding detection"""
        encodings = ['utf-8', 'utf-8-sig', 'latin1', 'cp1252', 'iso-8859-1']

        for encoding in encodings:
            try:
                with open(filepath, 'r', encoding=encoding, errors='ignore') as f:
                    return f.read(FileAnalyzer.MAX_TEXT_PREVIEW * 2)  # Read more than preview
            except (UnicodeError, UnicodeDecodeError):
                continue
            except Exception:
                break

        return None

    @staticmethod
    def _analyze_file_structure(text_content: str, filepath: str) -> Dict[str, Any]:
        """Analyze file structure for crypto-specific formats"""
        structure = {
            'is_json': False,
            'is_xml': False,
            'is_config': False,
            'is_key_file': False,
            'is_wallet_file': False,
            'json_structure': None,
            'crypto_structure_type': None
        }

        try:
            extension = Path(filepath).suffix.lower()

            # JSON analysis (common for wallet files)
            if extension in ['.json', '.jsonl'] or text_content.strip().startswith('{'):
                try:
                    json_data = json.loads(text_content)
                    structure['is_json'] = True
                    structure['json_structure'] = {
                        'top_level_keys': list(json_data.keys()) if isinstance(json_data, dict) else None,
                        'type': type(json_data).__name__
                    }

                    # Check for wallet-specific JSON structure
                    if isinstance(json_data, dict):
                        wallet_keys = ['address', 'crypto', 'cipher', 'ciphertext', 'kdf', 'kdfparams']
                        if any(key in json_data for key in wallet_keys):
                            structure['is_wallet_file'] = True
                            structure['crypto_structure_type'] = 'ethereum_keystore'

                except json.JSONDecodeError:
                    pass

            # XML analysis
            if extension in ['.xml', '.pem', '.crt'] or '<?xml' in text_content:
                structure['is_xml'] = True

            # Configuration file analysis
            if extension in ['.conf', '.config', '.ini', '.cfg']:
                structure['is_config'] = True

            # Key file analysis
            if any(indicator in text_content for indicator in ['-----BEGIN', '-----END', 'ssh-']):
                structure['is_key_file'] = True

                # Determine key type
                if 'PRIVATE KEY' in text_content:
                    structure['crypto_structure_type'] = 'private_key'
                elif 'PUBLIC KEY' in text_content:
                    structure['crypto_structure_type'] = 'public_key'
                elif 'CERTIFICATE' in text_content:
                    structure['crypto_structure_type'] = 'certificate'
                elif 'ssh-' in text_content:
                    structure['crypto_structure_type'] = 'ssh_key'

        except Exception as e:
            logger.warning(f"Error analyzing file structure: {e}")

        return structure

    @staticmethod
    def _analyze_wallet_indicators(text_content: str) -> Dict[str, Any]:
        """Analyze wallet-specific indicators"""
        indicators = {
            'has_wallet_structure': False,
            'wallet_type_hints': [],
            'address_count': 0,
            'key_count': 0,
            'mnemonic_indicators': [],
            'wallet_software_hints': []
        }

        try:
            # Check for wallet structure keywords
            wallet_keywords = [
                'addresses', 'accounts', 'keystore', 'mnemonic', 'seed',
                'hdwallet', 'derivation', 'xpub', 'xprv', 'master key'
            ]

            for keyword in wallet_keywords:
                if keyword in text_content.lower():
                    indicators['has_wallet_structure'] = True
                    indicators['wallet_type_hints'].append(keyword)

            # Count potential addresses and keys
            indicators['address_count'] = len(FileAnalyzer.CRYPTO_PATTERNS['bitcoin_address'].findall(text_content))
            indicators['address_count'] += len(FileAnalyzer.CRYPTO_PATTERNS['ethereum_address'].findall(text_content))

            indicators['key_count'] = len(FileAnalyzer.CRYPTO_PATTERNS['private_key_hex'].findall(text_content))
            indicators['key_count'] += len(FileAnalyzer.CRYPTO_PATTERNS['base64_key'].findall(text_content))

            # Check for mnemonic word indicators
            mnemonic_words = text_content.lower().split()
            common_mnemonic_words = [
                'abandon', 'ability', 'able', 'about', 'above', 'absent', 'absorb',
                'abstract', 'absurd', 'abuse', 'access', 'accident', 'account'
            ]

            for word in common_mnemonic_words:
                if word in mnemonic_words:
                    indicators['mnemonic_indicators'].append(word)

            # Check for wallet software hints
            wallet_software = ['electrum', 'exodus', 'myetherwallet', 'metamask', 'ledger', 'trezor']
            for software in wallet_software:
                if software in text_content.lower():
                    indicators['wallet_software_hints'].append(software)

        except Exception as e:
            logger.warning(f"Error analyzing wallet indicators: {e}")

        return indicators

    @staticmethod
    def _analyze_key_indicators(text_content: str) -> Dict[str, Any]:
        """Analyze cryptographic key indicators"""
        indicators = {
            'has_pem_structure': False,
            'key_types': [],
            'certificate_present': False,
            'ssh_key_present': False,
            'pgp_key_present': False,
            'key_strength_indicators': {}
        }

        try:
            # PEM structure
            if '-----BEGIN' in text_content and '-----END' in text_content:
                indicators['has_pem_structure'] = True

                # Extract key types from PEM headers
                pem_types = re.findall(r'-----BEGIN ([A-Z ]+)-----', text_content)
                indicators['key_types'] = list(set(pem_types))

            # Certificate detection
            if 'CERTIFICATE' in text_content:
                indicators['certificate_present'] = True

            # SSH key detection
            if text_content.startswith('ssh-') or 'ssh-rsa' in text_content or 'ssh-ed25519' in text_content:
                indicators['ssh_key_present'] = True

            # PGP key detection
            if 'BEGIN PGP' in text_content:
                indicators['pgp_key_present'] = True

            # Key strength analysis
            if indicators['has_pem_structure']:
                # Estimate key strength based on content length
                key_content = re.sub(r'-----[^-]+-----', '', text_content)
                key_content = re.sub(r'\s', '', key_content)

                if len(key_content) > 3000:
                    indicators['key_strength_indicators']['estimated_bits'] = '4096+'
                elif len(key_content) > 1500:
                    indicators['key_strength_indicators']['estimated_bits'] = '2048'
                else:
                    indicators['key_strength_indicators']['estimated_bits'] = '1024 or less'

        except Exception as e:
            logger.warning(f"Error analyzing key indicators: {e}")

        return indicators

    @staticmethod
    def _analyze_blockchain_indicators(text_content: str) -> Dict[str, Any]:
        """Analyze blockchain-specific indicators"""
        indicators = {
            'blockchain_types': [],
            'transaction_indicators': [],
            'smart_contract_indicators': [],
            'defi_indicators': []
        }

        try:
            content_lower = text_content.lower()

            # Blockchain type detection
            blockchain_keywords = {
                'bitcoin': ['bitcoin', 'btc', 'satoshi', 'block height'],
                'ethereum': ['ethereum', 'eth', 'gwei', 'gas', 'solidity'],
                'litecoin': ['litecoin', 'ltc'],
                'monero': ['monero', 'xmr'],
                'zcash': ['zcash', 'zec']
            }

            for blockchain, keywords in blockchain_keywords.items():
                if any(keyword in content_lower for keyword in keywords):
                    indicators['blockchain_types'].append(blockchain)

            # Transaction indicators
            tx_keywords = ['transaction', 'txid', 'hash', 'block', 'confirmation']
            for keyword in tx_keywords:
                if keyword in content_lower:
                    indicators['transaction_indicators'].append(keyword)

            # Smart contract indicators
            contract_keywords = ['contract', 'abi', 'bytecode', 'solidity', 'function']
            for keyword in contract_keywords:
                if keyword in content_lower:
                    indicators['smart_contract_indicators'].append(keyword)

            # DeFi indicators
            defi_keywords = ['uniswap', 'compound', 'aave', 'maker', 'defi', 'yield', 'liquidity']
            for keyword in defi_keywords:
                if keyword in content_lower:
                    indicators['defi_indicators'].append(keyword)

        except Exception as e:
            logger.warning(f"Error analyzing blockchain indicators: {e}")

        return indicators

    @staticmethod
    def _calculate_crypto_confidence(crypto_analysis: Dict, content_analysis: Dict) -> float:
        """Calculate confidence score for crypto-related content"""
        score = 0.0

        try:
            # Pattern matches
            pattern_count = len(crypto_analysis.get('crypto_patterns_found', {}))
            score += min(pattern_count * 0.15, 0.8)

            # Crypto keywords
            if content_analysis.get('contains_crypto_keywords', False):
                score += 0.2

            # Wallet indicators
            wallet_indicators = crypto_analysis.get('wallet_indicators', {})
            if wallet_indicators.get('has_wallet_structure', False):
                score += 0.25

            score += min(wallet_indicators.get('address_count', 0) * 0.1, 0.15)
            score += min(wallet_indicators.get('key_count', 0) * 0.1, 0.15)

            # Key indicators
            key_indicators = crypto_analysis.get('key_indicators', {})
            if key_indicators.get('has_pem_structure', False):
                score += 0.2

            if key_indicators.get('certificate_present', False):
                score += 0.1

            if key_indicators.get('ssh_key_present', False):
                score += 0.1

            # Blockchain indicators
            blockchain_indicators = crypto_analysis.get('blockchain_indicators', {})
            score += min(len(blockchain_indicators.get('blockchain_types', [])) * 0.1, 0.2)

        except Exception as e:
            logger.warning(f"Error calculating crypto confidence: {e}")

        return min(score, 1.0)

    @staticmethod
    def _determine_crypto_type(crypto_analysis: Dict) -> Optional[str]:
        """Determine the most likely cryptocurrency type"""
        patterns = crypto_analysis.get('crypto_patterns_found', {})
        blockchain_types = crypto_analysis.get('blockchain_indicators', {}).get('blockchain_types', [])

        if 'bitcoin_address' in patterns or 'bitcoin' in blockchain_types:
            return 'bitcoin'
        elif 'ethereum_address' in patterns or 'ethereum' in blockchain_types:
            return 'ethereum'
        elif 'ssh_key' in patterns:
            return 'ssh_key'
        elif 'certificate' in patterns:
            return 'certificate'
        elif 'pem_header' in patterns:
            return 'pem_key'
        elif 'wallet_file' in patterns:
            return 'wallet'
        elif blockchain_types:
            return blockchain_types[0]

        return None

    @staticmethod
    def _generate_actionable_findings(crypto_analysis: Dict) -> List[Dict[str, Any]]:
        """Generate actionable findings from crypto analysis"""
        findings = []

        try:
            patterns = crypto_analysis.get('crypto_patterns_found', {})

            # High-priority findings
            if 'private_key_hex' in patterns:
                findings.append({
                    'type': 'private_key_detected',
                    'priority': 'high',
                    'description': f"Detected {patterns['private_key_hex']['count']} potential private keys",
                    'action': 'Validate keys and check for associated balances'
                })

            if 'wallet_file' in patterns:
                findings.append({
                    'type': 'wallet_file_detected',
                    'priority': 'high',
                    'description': 'Wallet file structure detected',
                    'action': 'Extract and analyze wallet contents'
                })

            # Medium-priority findings
            if 'bitcoin_address' in patterns or 'ethereum_address' in patterns:
                addr_count = patterns.get('bitcoin_address', {}).get('count', 0)
                addr_count += patterns.get('ethereum_address', {}).get('count', 0)

                findings.append({
                    'type': 'crypto_addresses_detected',
                    'priority': 'medium',
                    'description': f"Detected {addr_count} cryptocurrency addresses",
                    'action': 'Check addresses for balances and transaction history'
                })

            # Security findings
            if 'ssh_key' in patterns:
                findings.append({
                    'type': 'ssh_key_detected',
                    'priority': 'medium',
                    'description': 'SSH key detected',
                    'action': 'Analyze for potential system access'
                })

        except Exception as e:
            logger.warning(f"Error generating actionable findings: {e}")

        return findings

    @staticmethod
    def _calculate_intelligence_score(analysis: Dict) -> int:
        """Calculate overall intelligence score for the file"""
        score = 0

        try:
            # Crypto confidence contributes heavily
            crypto_score = analysis.get('crypto_analysis', {}).get('crypto_confidence_score', 0)
            score += int(crypto_score * 40)  # 40 points max

            # File type and structure
            file_info = analysis.get('file_info', {})
            if file_info.get('crypto_file_indicators'):
                score += len(file_info['crypto_file_indicators']) * 5

            # Content analysis
            content_analysis = analysis.get('content_analysis', {})
            if content_analysis.get('contains_crypto_keywords'):
                score += 10

            if content_analysis.get('crypto_patterns_detected'):
                score += len(content_analysis['crypto_patterns_detected']) * 3

            # Actionable findings
            actionable_findings = analysis.get('crypto_analysis', {}).get('actionable_findings', [])
            high_priority_findings = [f for f in actionable_findings if f.get('priority') == 'high']
            score += len(high_priority_findings) * 15

        except Exception as e:
            logger.warning(f"Error calculating intelligence score: {e}")

        return min(score, 100)  # Cap at 100

    @staticmethod
    def _generate_intelligence_summary(analysis: Dict) -> Dict[str, Any]:
        """Generate intelligence summary from analysis"""
        summary = {
            'key_findings': [],
            'recommendations': [],
            'threat_level': 'low',
            'value_assessment': 'unknown'
        }

        try:
            crypto_analysis = analysis.get('crypto_analysis', {})
            confidence_score = crypto_analysis.get('crypto_confidence_score', 0)

            # Determine threat level and value
            if confidence_score > 0.8:
                summary['threat_level'] = 'high'
                summary['value_assessment'] = 'high'
            elif confidence_score > 0.5:
                summary['threat_level'] = 'medium'
                summary['value_assessment'] = 'medium'

            # Key findings
            if crypto_analysis.get('potential_crypto_type'):
                summary['key_findings'].append(
                    f"File contains {crypto_analysis['potential_crypto_type']} related content"
                )

            actionable_findings = crypto_analysis.get('actionable_findings', [])
            for finding in actionable_findings[:3]:  # Top 3 findings
                summary['key_findings'].append(finding['description'])

            # Recommendations
            if confidence_score > 0.7:
                summary['recommendations'].append("Queue for immediate comprehensive crypto analysis")
                summary['recommendations'].append("Check for live wallet balances")
            elif confidence_score > 0.4:
                summary['recommendations'].append("Schedule for detailed pattern analysis")

        except Exception as e:
            logger.warning(f"Error generating intelligence summary: {e}")

        return summary

    @staticmethod
    def _extract_metadata(filepath: str) -> Dict[str, Any]:
        """Extract file metadata safely"""
        metadata = {}

        try:
            stat = os.stat(filepath)
            metadata.update({
                'created': stat.st_ctime,
                'modified': stat.st_mtime,
                'accessed': stat.st_atime,
                'permissions': oct(stat.st_mode)[-3:],
                'inode': stat.st_ino
            })

        except Exception as e:
            logger.warning(f"Error extracting metadata: {e}")

        return metadata

    @staticmethod
    def _calculate_entropy(data: bytes) -> float:
        """Calculate Shannon entropy of data"""
        if not data:
            return 0.0

        try:
            # Count byte frequencies
            frequencies = {}
            for byte in data:
                frequencies[byte] = frequencies.get(byte, 0) + 1

            # Calculate entropy
            entropy = 0.0
            length = len(data)

            for count in frequencies.values():
                probability = count / length
                if probability > 0:
                    entropy -= probability * (probability.bit_length() - 1)

            return entropy

        except Exception as e:
            logger.warning(f"Error calculating entropy: {e}")
            return 0.0

    @staticmethod
    def _save_analysis_results(file_id: int, analysis_result: Dict) -> bool:
        """Save analysis results to database"""
        try:
            with FileAnalyzer._db_transaction():
                # Check if FileContent already exists
                content = FileContent.query.filter_by(file_id=file_id).first()

                if content:
                    # Update existing
                    content.content_text = json.dumps(analysis_result, indent=2)
                    content.updated_at = datetime.now()
                else:
                    # Create new
                    content = FileContent(
                        file_id=file_id,
                        content_text=json.dumps(analysis_result, indent=2),
                        content_type='comprehensive_analysis'
                    )
                    db.session.add(content)

                # Update file status
                analysis_file = AnalysisFile.query.get(file_id)
                if analysis_file:
                    analysis_file.status = FileStatus.ANALYZED
                    analysis_file.analysis_completed_at = datetime.now()

                    # Update priority based on intelligence score
                    intelligence_score = analysis_result.get('intelligence_score', 0)
                    if intelligence_score > 70:
                        analysis_file.priority = min(analysis_file.priority + 2, 10)

            return True

        except Exception as e:
            logger.error(f"Error saving analysis results: {e}")
            return False

    @staticmethod
    def _create_basic_analysis(file_id: int, filepath: str, file_size: int) -> bool:
        """Create basic analysis for files that can't be fully analyzed"""
        basic_analysis = {
            'analysis_type': 'basic',
            'file_size': file_size,
            'analysis_timestamp': datetime.now().isoformat(),
            'reason': 'File too large for full analysis',
            'intelligence_score': 0
        }

        return FileAnalyzer._save_analysis_results(file_id, basic_analysis)

    @staticmethod
    def _create_error_analysis(file_id: int, error_message: str) -> bool:
        """Create error analysis record"""
        error_analysis = {
            'analysis_type': 'error',
            'error_message': error_message,
            'analysis_timestamp': datetime.now().isoformat(),
            'intelligence_score': 0
        }

        return FileAnalyzer._save_analysis_results(file_id, error_analysis)

    @staticmethod
    @contextmanager
    def _db_transaction():
        """Context manager for database transactions"""
        try:
            yield
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            logger.error(f"Database transaction failed: {e}")
            raise
