"""
Comprehensive cryptographic intelligence and analysis service
"""

import re
import base64
import hashlib
import hmac
import binascii
import json
import requests
import os
from typing import Dict, List, Any, Optional, Tuple
from collections import Counter
try:
    from Crypto.Cipher import AES
    from Crypto.PublicKey import RSA
    from Crypto.Hash import SHA256
except ImportError:
    # Fallback if pycryptodome not available
    AES = RSA = SHA256 = None

try:
    import ecdsa
    from eth_hash.auto import keccak
except ImportError:
    # Fallback if eth dependencies not available
    ecdsa = keccak = None

import struct
import string
import itertools
from concurrent.futures import ThreadPoolExecutor
import time


class CryptoIntelligence:
    """Advanced cryptographic analysis and puzzle solving"""

    # Common crypto patterns
    CRYPTO_PATTERNS = {
        'base64': re.compile(r'[A-Za-z0-9+/]{20,}={0,2}'),
        'base32': re.compile(r'[A-Z2-7]{8,}={0,6}'),
        'hex': re.compile(r'[0-9a-fA-F]{16,}'),
        'pem_cert': re.compile(r'-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----', re.DOTALL),
        'pem_private': re.compile(r'-----BEGIN (RSA )?PRIVATE KEY-----.*?-----END (RSA )?PRIVATE KEY-----', re.DOTALL),
        'pem_public': re.compile(r'-----BEGIN PUBLIC KEY-----.*?-----END PUBLIC KEY-----', re.DOTALL),
        'pgp_block': re.compile(r'-----BEGIN PGP.*?-----.*?-----END PGP.*?-----', re.DOTALL),
        'eth_private': re.compile(r'\b[0-9a-fA-F]{64}\b'),
        'eth_address': re.compile(r'0x[a-fA-F0-9]{40}'),
        'bitcoin_address': re.compile(r'\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b'),
        'ssh_key': re.compile(r'ssh-rsa [A-Za-z0-9+/]+=*'),
        'jwt_token': re.compile(r'eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*'),
        'uuid': re.compile(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', re.IGNORECASE),
        'md5': re.compile(r'\b[a-fA-F0-9]{32}\b'),
        'sha1': re.compile(r'\b[a-fA-F0-9]{40}\b'),
        'sha256': re.compile(r'\b[a-fA-F0-9]{64}\b'),
        'sha512': re.compile(r'\b[a-fA-F0-9]{128}\b')
    }

    # Common cipher indicators
    CIPHER_INDICATORS = {
        'caesar': lambda text: all(c.isalpha() or c.isspace() for c in text),
        'vigenere': lambda text: len(set(text.upper())) < 15 and text.isalpha(),
        'substitution': lambda text: len(set(text)) == len(string.ascii_uppercase),
        'morse': lambda text: all(c in '.-/ \n' for c in text),
        'binary': lambda text: all(c in '01 \n' for c in text),
        'rot13': lambda text: text.isalpha() and len(text) > 10
    }

    @staticmethod
    def analyze_crypto_content(content: bytes, filename: str = '') -> Dict[str, Any]:
        """Comprehensive crypto analysis of file content"""
        analysis = {
            'crypto_patterns': [],
            'encoding_detection': [],
            'encryption_detection': {},
            'key_material': [],
            'ethereum_analysis': {},
            'puzzle_strategies': [],
            'recommendations': []
        }

        try:
            # Convert to text for pattern analysis
            text_content = content.decode('utf-8', errors='ignore')

            # Pattern detection
            analysis['crypto_patterns'] = CryptoIntelligence._detect_crypto_patterns(text_content)

            # Encoding detection
            analysis['encoding_detection'] = CryptoIntelligence._detect_encodings(content, text_content)

            # Encryption detection
            analysis['encryption_detection'] = CryptoIntelligence._detect_encryption(content)

            # Key material extraction
            analysis['key_material'] = CryptoIntelligence._extract_key_material(text_content)

            # Ethereum analysis
            analysis['ethereum_analysis'] = CryptoIntelligence._analyze_ethereum_content(text_content)

            # Puzzle strategy suggestions
            analysis['puzzle_strategies'] = CryptoIntelligence._suggest_puzzle_strategies(analysis, filename)

            # Generate recommendations
            analysis['recommendations'] = CryptoIntelligence._generate_recommendations(analysis)

        except Exception as e:
            analysis['error'] = str(e)

        return analysis

    @staticmethod
    def _detect_crypto_patterns(text: str) -> List[Dict[str, Any]]:
        """Detect cryptographic patterns in text"""
        patterns = []

        for pattern_name, regex in CryptoIntelligence.CRYPTO_PATTERNS.items():
            matches = regex.findall(text)
            if matches:
                patterns.append({
                    'type': pattern_name,
                    'count': len(matches),
                    'samples': matches[:3],  # First 3 matches
                    'confidence': CryptoIntelligence._calculate_pattern_confidence(pattern_name, matches)
                })

        return patterns

    @staticmethod
    def _calculate_pattern_confidence(pattern_type: str, matches: List[str]) -> float:
        """Calculate confidence score for detected patterns"""
        base_confidence = 0.5

        # Adjust based on pattern type and characteristics
        if pattern_type in ['eth_private', 'eth_address', 'bitcoin_address']:
            base_confidence = 0.9
        elif pattern_type in ['pem_cert', 'pem_private', 'pgp_block']:
            base_confidence = 0.95
        elif pattern_type in ['base64', 'hex']:
            avg_length = sum(len(m) for m in matches) / len(matches)
            if avg_length > 100:
                base_confidence = 0.8
            elif avg_length > 50:
                base_confidence = 0.6

        # Boost confidence with more matches
        confidence_boost = min(0.2, len(matches) * 0.05)

        return min(1.0, base_confidence + confidence_boost)

    @staticmethod
    def _detect_encodings(content: bytes, text: str) -> List[Dict[str, Any]]:
        """Detect various encodings and transformations"""
        encodings = []

        # Base64 detection and decoding
        base64_matches = CryptoIntelligence.CRYPTO_PATTERNS['base64'].findall(text)
        for match in base64_matches[:5]:  # Limit to 5 matches
            try:
                decoded = base64.b64decode(match)
                encodings.append({
                    'type': 'base64',
                    'original': match[:50] + '...' if len(match) > 50 else match,
                    'decoded_preview': decoded[:50].hex() if len(decoded) > 0 else '',
                    'decoded_length': len(decoded),
                    'is_text': CryptoIntelligence._is_likely_text(decoded)
                })
            except:
                continue

        # Hex detection and decoding
        hex_matches = CryptoIntelligence.CRYPTO_PATTERNS['hex'].findall(text)
        for match in hex_matches[:5]:
            if len(match) % 2 == 0:  # Valid hex length
                try:
                    decoded = bytes.fromhex(match)
                    encodings.append({
                        'type': 'hex',
                        'original': match[:50] + '...' if len(match) > 50 else match,
                        'decoded_preview': decoded[:50],
                        'decoded_length': len(decoded),
                        'is_text': CryptoIntelligence._is_likely_text(decoded)
                    })
                except:
                    continue

        return encodings

    @staticmethod
    def _is_likely_text(data: bytes) -> bool:
        """Determine if decoded data is likely text"""
        try:
            text = data.decode('utf-8')
            printable_ratio = sum(1 for c in text if c.isprintable()) / len(text)
            return printable_ratio > 0.7
        except:
            return False

    @staticmethod
    def _detect_encryption(content: bytes) -> Dict[str, Any]:
        """Detect encryption and analyze entropy"""
        detection = {
            'entropy': 0.0,
            'likely_encrypted': False,
            'cipher_indicators': [],
            'file_signatures': []
        }

        # Calculate entropy
        if len(content) > 0:
            byte_counts = Counter(content)
            entropy = 0.0
            for count in byte_counts.values():
                p = count / len(content)
                entropy -= p * (p.bit_length() - 1) if p > 0 else 0

            detection['entropy'] = entropy
            detection['likely_encrypted'] = entropy > 7.5  # High entropy threshold

        # Check for file signatures
        if content.startswith(b'\x50\x4b'):  # ZIP/encrypted archives
            detection['file_signatures'].append('zip_archive')
        elif content.startswith(b'\x7f\x45\x4c\x46'):  # ELF binary
            detection['file_signatures'].append('elf_binary')
        elif content.startswith(b'\x4d\x5a'):  # PE executable
            detection['file_signatures'].append('pe_executable')

        return detection

    @staticmethod
    def _extract_key_material(text: str) -> List[Dict[str, Any]]:
        """Extract potential cryptographic key material"""
        key_material = []

        # PEM certificates and keys
        for cert_match in CryptoIntelligence.CRYPTO_PATTERNS['pem_cert'].finditer(text):
            key_material.append({
                'type': 'x509_certificate',
                'content': cert_match.group(0),
                'confidence': 0.95
            })

        for key_match in CryptoIntelligence.CRYPTO_PATTERNS['pem_private'].finditer(text):
            key_material.append({
                'type': 'rsa_private_key',
                'content': key_match.group(0),
                'confidence': 0.95
            })

        return key_material

    @staticmethod
    def _analyze_ethereum_content(text: str) -> Dict[str, Any]:
        """Analyze Ethereum-related content"""
        ethereum = {
            'private_keys': [],
            'addresses': [],
            'validated_keys': [],
            'potential_wallets': []
        }

        # Only analyze if eth dependencies are available
        if not ecdsa or not keccak:
            return ethereum

        # Find potential private keys
        private_key_matches = CryptoIntelligence.CRYPTO_PATTERNS['eth_private'].findall(text)
        for key in private_key_matches[:10]:  # Limit to 10 keys
            validation = EthereumAnalyzer.validate_private_key(key)
            if validation['valid']:
                ethereum['private_keys'].append(key)
                ethereum['validated_keys'].append(validation)

        # Find Ethereum addresses
        address_matches = CryptoIntelligence.CRYPTO_PATTERNS['eth_address'].findall(text)
        for address in address_matches[:20]:  # Limit to 20 addresses
            if EthereumAnalyzer.validate_address(address):
                ethereum['addresses'].append(address)

        return ethereum

    @staticmethod
    def _suggest_puzzle_strategies(analysis: Dict[str, Any], filename: str) -> List[Dict[str, str]]:
        """Suggest strategies based on detected patterns"""
        strategies = []

        patterns = analysis.get('crypto_patterns', [])

        for pattern in patterns:
            if pattern['type'] == 'base64':
                strategies.append({
                    'strategy': 'base64_decoding',
                    'description': 'Decode base64 strings and analyze content recursively',
                    'priority': 'high' if pattern['confidence'] > 0.8 else 'medium'
                })

            elif pattern['type'] in ['eth_private', 'eth_address']:
                strategies.append({
                    'strategy': 'ethereum_analysis',
                    'description': 'Validate Ethereum keys and check balances',
                    'priority': 'high'
                })

        return strategies

    @staticmethod
    def _generate_recommendations(analysis: Dict[str, Any]) -> List[str]:
        """Generate actionable recommendations"""
        recommendations = []

        patterns = analysis.get('crypto_patterns', [])
        encodings = analysis.get('encoding_detection', [])

        if any(e['type'] == 'base64' for e in encodings):
            recommendations.append("Try recursive base64 decoding - data might be encoded multiple times")

        high_confidence_patterns = [p for p in patterns if p.get('confidence', 0) > 0.8]
        if high_confidence_patterns:
            recommendations.append("Focus on high-confidence crypto patterns first")

        return recommendations


class EthereumAnalyzer:
    """Ethereum-specific cryptographic analysis"""

    @staticmethod
    def validate_private_key(private_key_hex: str) -> Dict[str, Any]:
        """Validate and analyze Ethereum private key"""
        result = {
            'valid': False,
            'private_key': private_key_hex,
            'public_key': None,
            'address': None,
            'compressed_address': None
        }

        if not ecdsa or not keccak:
            result['error'] = 'Ethereum dependencies not available'
            return result

        try:
            # Remove 0x prefix if present
            if private_key_hex.startswith('0x'):
                private_key_hex = private_key_hex[2:]

            # Validate hex and length
            if len(private_key_hex) != 64:
                return result

            private_key_bytes = bytes.fromhex(private_key_hex)

            # Generate public key using secp256k1
            private_key_int = int.from_bytes(private_key_bytes, 'big')

            # Check if private key is in valid range
            if private_key_int >= 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141:
                return result

            if private_key_int == 0:
                return result

            # Generate public key
            sk = ecdsa.SigningKey.from_string(private_key_bytes, curve=ecdsa.SECP256k1)
            vk = sk.get_verifying_key()
            public_key_bytes = b'\x04' + vk.to_string()

            # Generate Ethereum address
            keccak_hash = keccak(public_key_bytes[1:])  # Remove 0x04 prefix
            address = '0x' + keccak_hash[-20:].hex()

            result.update({
                'valid': True,
                'public_key': public_key_bytes.hex(),
                'address': address,
                'checksum_address': EthereumAnalyzer.to_checksum_address(address)
            })

        except Exception as e:
            result['error'] = str(e)

        return result

    @staticmethod
    def validate_address(address: str) -> bool:
        """Validate Ethereum address format"""
        if not address.startswith('0x'):
            return False

        if len(address) != 42:
            return False

        try:
            int(address[2:], 16)
            return True
        except ValueError:
            return False

    @staticmethod
    def to_checksum_address(address: str) -> str:
        """Convert address to checksum format"""
        if not keccak:
            return address

        address = address.lower().replace('0x', '')
        address_hash = keccak(address.encode()).hex()

        checksum_address = '0x'
        for i, char in enumerate(address):
            if int(address_hash[i], 16) >= 8:
                checksum_address += char.upper()
            else:
                checksum_address += char

        return checksum_address

    @staticmethod
    def check_balance(address: str, api_key: str = None) -> Dict[str, Any]:
        """Check Ethereum balance using Etherscan API"""
        result = {
            'address': address,
            'balance_wei': '0',
            'balance_eth': '0',
            'transaction_count': 0,
            'success': False
        }

        try:
            base_url = 'https://api.etherscan.io/api'
            params = {
                'module': 'account',
                'action': 'balance',
                'address': address,
                'tag': 'latest',
                'apikey': api_key or 'YourApiKeyToken'
            }

            response = requests.get(base_url, params=params, timeout=10)
            data = response.json()

            if data.get('status') == '1':
                balance_wei = int(data.get('result', '0'))
                balance_eth = balance_wei / 10 ** 18

                result.update({
                    'balance_wei': str(balance_wei),
                    'balance_eth': str(balance_eth),
                    'success': True
                })

        except Exception as e:
            result['error'] = str(e)

        return result


class CipherAnalyzer:
    """Classical and modern cipher analysis"""

    @staticmethod
    def analyze_caesar_cipher(text: str) -> Dict[str, Any]:
        """Analyze potential Caesar cipher"""
        analysis = {
            'type': 'caesar_analysis',
            'all_shifts': {},
            'best_candidates': []
        }

        text_alpha = ''.join(c.upper() for c in text if c.isalpha())

        if not text_alpha:
            return analysis

        # Try all 26 shifts
        for shift in range(26):
            decoded = CipherAnalyzer._caesar_decrypt(text_alpha, shift)
            score = CipherAnalyzer._score_english_text(decoded)

            analysis['all_shifts'][shift] = {
                'text': decoded,
                'score': score
            }

        # Find best candidates
        sorted_shifts = sorted(
            analysis['all_shifts'].items(),
            key=lambda x: x[1]['score'],
            reverse=True
        )

        analysis['best_candidates'] = [
            {
                'shift': shift,
                'text': data['text'],
                'score': data['score']
            }
            for shift, data in sorted_shifts[:5]
        ]

        return analysis

    @staticmethod
    def _caesar_decrypt(text: str, shift: int) -> str:
        """Decrypt Caesar cipher with given shift"""
        result = []
        for char in text:
            if char.isalpha():
                shifted = (ord(char) - ord('A') - shift) % 26
                result.append(chr(shifted + ord('A')))
            else:
                result.append(char)
        return ''.join(result)

    @staticmethod
    def _score_english_text(text: str) -> float:
        """Score text based on English letter frequency"""
        english_freq = {
            'E': 12.7, 'T': 9.1, 'A': 8.2, 'O': 7.5, 'I': 7.0, 'N': 6.7,
            'S': 6.3, 'H': 6.1, 'R': 6.0, 'D': 4.3, 'L': 4.0, 'C': 2.8,
            'U': 2.8, 'M': 2.4, 'W': 2.4, 'F': 2.2, 'G': 2.0, 'Y': 2.0,
            'P': 1.9, 'B': 1.3, 'V': 1.0, 'K': 0.8, 'J': 0.15, 'X': 0.15,
            'Q': 0.10, 'Z': 0.07
        }

        if not text:
            return 0.0

        text_freq = Counter(c for c in text.upper() if c.isalpha())
        total_chars = sum(text_freq.values())

        if total_chars == 0:
            return 0.0

        score = 0.0
        for char, count in text_freq.items():
            expected_freq = english_freq.get(char, 0.01)
            actual_freq = (count / total_chars) * 100
            score += min(expected_freq, actual_freq)

        return score


class AdvancedCryptoAnalyzer:
    """Advanced cryptographic analysis for modern systems"""

    @staticmethod
    def brute_force_hash(target_hash: str, hash_type: str, wordlist: List[str] = None) -> Dict[str, Any]:
        """Attempt to brute force a hash with common passwords"""
        result = {
            'hash_type': hash_type,
            'target_hash': target_hash.lower(),
            'found': False,
            'plaintext': None,
            'attempts': 0
        }

        # Default wordlist
        if wordlist is None:
            wordlist = [
                'password', '123456', 'admin', 'root', 'flag', 'secret',
                'password123', 'admin123', 'qwerty', 'letmein', 'welcome',
                'monkey', 'dragon', 'master', 'shadow', 'superman'
            ]

        hash_func = None
        if hash_type.lower() == 'md5':
            hash_func = hashlib.md5
        elif hash_type.lower() == 'sha1':
            hash_func = hashlib.sha1
        elif hash_type.lower() == 'sha256':
            hash_func = hashlib.sha256
        else:
            result['error'] = f'Unsupported hash type: {hash_type}'
            return result

        for word in wordlist:
            result['attempts'] += 1
            word_hash = hash_func(word.encode()).hexdigest().lower()

            if word_hash == result['target_hash']:
                result['found'] = True
                result['plaintext'] = word
                break

        return result