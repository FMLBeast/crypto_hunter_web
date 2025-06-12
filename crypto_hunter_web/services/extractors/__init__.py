"""
crypto_hunter_web/services/extractors/__init__.py
Updated extractors system integrated with forensics toolkit
"""

from typing import Dict, List, Any, Optional
from .base import BaseExtractor
from .forensics_extractor import ForensicsExtractor
from .zsteg import ZStegExtractor
from .steghide import SteghideExtractor
from .binwalk import BinwalkExtractor
from .custom import CustomExtractor
from .pnganalyzer import analyze_png_file, extract_png_metadata

# Registry of available extractors
EXTRACTORS = {
    # Primary forensics extractor
    'forensics': ForensicsExtractor,

    # Steganography extractors
    'zsteg': ZStegExtractor,
    'zsteg_bitplane_1': ZStegExtractor,
    'zsteg_bitplane_2': ZStegExtractor,
    'zsteg_bitplane_3': ZStegExtractor,
    'zsteg_bitplane_4': ZStegExtractor,
    'steghide': SteghideExtractor,
    'stegseek': ForensicsExtractor,  # Use forensics extractor for advanced tools
    'outguess': ForensicsExtractor,

    # Binary analysis extractors
    'binwalk': BinwalkExtractor,
    'foremost': ForensicsExtractor,
    'bulk_extractor': ForensicsExtractor,
    'radare2': ForensicsExtractor,

    # String and hex extractors
    'strings': CustomExtractor,
    'hexdump': CustomExtractor,
    'exiftool': ForensicsExtractor,

    # Audio/video extractors
    'sox': ForensicsExtractor,
    'ffmpeg': ForensicsExtractor,

    # Network extractors
    'wireshark': ForensicsExtractor,
    'tcpdump': ForensicsExtractor,

    # Manual analysis
    'manual': CustomExtractor
}

def get_extractor(method_name):
    """Get extractor instance for specified method"""
    extractor_class = EXTRACTORS.get(method_name)
    if extractor_class:
        return extractor_class(method_name)
    return None

def list_extractors():
    """List all available extractors"""
    return list(EXTRACTORS.keys())

def get_extractors_by_category():
    """Get extractors grouped by category"""
    categories = {
        'steganography': ['zsteg', 'zsteg_bitplane_1', 'zsteg_bitplane_2', 'zsteg_bitplane_3',
                         'zsteg_bitplane_4', 'steghide', 'stegseek', 'outguess'],
        'binary_analysis': ['binwalk', 'foremost', 'bulk_extractor', 'radare2'],
        'string_analysis': ['strings', 'hexdump'],
        'metadata': ['exiftool'],
        'audio_video': ['sox', 'ffmpeg'],
        'network': ['wireshark', 'tcpdump'],
        'forensics': ['forensics'],
        'manual': ['manual']
    }
    return categories

def get_recommended_extractors(file_type: str):
    """Get recommended extractors for a file type"""
    recommendations = {
        'image/jpeg': ['steghide', 'stegseek', 'exiftool', 'binwalk', 'strings'],
        'image/png': ['zsteg', 'zsteg_bitplane_1', 'binwalk', 'strings'],
        'image/bmp': ['zsteg', 'binwalk', 'strings'],
        'image/gif': ['binwalk', 'strings', 'exiftool'],
        'audio/wav': ['steghide', 'sox', 'binwalk', 'strings'],
        'audio/mp3': ['binwalk', 'strings', 'exiftool'],
        'audio/ogg': ['binwalk', 'strings'],
        'video/mp4': ['ffmpeg', 'binwalk', 'strings', 'exiftool'],
        'video/avi': ['ffmpeg', 'binwalk', 'strings'],
        'application/pdf': ['binwalk', 'strings', 'exiftool'],
        'application/zip': ['binwalk', 'foremost', 'strings'],
        'application/x-executable': ['binwalk', 'radare2', 'strings'],
        'application/octet-stream': ['binwalk', 'strings', 'hexdump'],
        'text/plain': ['strings', 'manual'],
        'application/vnd.tcpdump.pcap': ['wireshark', 'tcpdump']
    }

    # Default recommendations for unknown types
    default = ['forensics', 'binwalk', 'strings']

    return recommendations.get(file_type, default)

__all__ = [
    'BaseExtractor',
    'ForensicsExtractor',
    'ZStegExtractor',
    'SteghideExtractor',
    'BinwalkExtractor',
    'CustomExtractor',
    'get_extractor',
    'list_extractors',
    'analyze_png_file',
    'extract_png_metadata',
    'get_extractors_by_category',
    'get_recommended_extractors',
    'EXTRACTORS'
]

# ===================================================================
# crypto_hunter_web/services/extractors/zsteg.py
# Updated ZSteg extractor
# ===================================================================

import os
import re
import subprocess
from .base import BaseExtractor

class ZStegExtractor(BaseExtractor):
    """Enhanced ZSteg extractor for image steganography"""

    def _get_tool_name(self):
        return 'zsteg'

    def extract(self, file_path: str, parameters: Dict = None):
        """Extract using zsteg with enhanced parameter handling"""
        if not os.path.exists(file_path):
            return {
                'success': False,
                'error': 'File not found',
                'data': b'',
                'details': '',
                'command_line': '',
                'confidence': 0
            }

        # Check if tool is available
        if not self._is_tool_available():
            return {
                'success': False,
                'error': 'ZSteg not available',
                'data': b'',
                'details': 'ZSteg is not installed. Install with: gem install zsteg',
                'command_line': '',
                'confidence': 0
            }

        # Determine zsteg parameters based on method
        zsteg_args = self._get_zsteg_args(parameters or {})
        command = ['zsteg'] + zsteg_args + [file_path]

        try:
            result = self._run_command(command, timeout=120)

            if result['returncode'] == 0 and result['stdout']:
                # Parse zsteg output
                extracted_data, confidence, findings = self._parse_zsteg_output(result['stdout'])

                return {
                    'success': True,
                    'data': extracted_data,
                    'error': '',
                    'details': f"ZSteg found {len(findings)} potential steganographic channels, extracted {len(extracted_data)} bytes",
                    'command_line': result['command_line'],
                    'confidence': confidence,
                    'metadata': {
                        'findings': findings,
                        'channels_analyzed': len(findings),
                        'stdout': result['stdout'].decode('utf-8', errors='ignore')
                    }
                }
            else:
                return {
                    'success': False,
                    'error': result['stderr'].decode('utf-8', errors='ignore'),
                    'data': b'',
                    'details': 'ZSteg found no steganographic content',
                    'command_line': result['command_line'],
                    'confidence': 0
                }

        except Exception as e:
            return {
                'success': False,
                'error': str(e),
                'data': b'',
                'details': 'ZSteg execution failed',
                'command_line': ' '.join(command),
                'confidence': 0
            }

    def _get_zsteg_args(self, parameters):
        """Get zsteg command arguments based on method and parameters"""
        args = []

        # Determine extraction method based on method name
        if 'bitplane_1' in self.method_name:
            args.extend(['-E', 'b1,bgr,lsb,xy'])
        elif 'bitplane_2' in self.method_name:
            args.extend(['-E', 'b2,bgr,lsb,xy'])
        elif 'bitplane_3' in self.method_name:
            args.extend(['-E', 'b3,bgr,lsb,xy'])
        elif 'bitplane_4' in self.method_name:
            args.extend(['-E', 'b4,bgr,lsb,xy'])
        else:
            # Default: scan all channels
            args.extend(['-a'])

        # Add custom parameters
        if 'channel' in parameters:
            args.extend(['-c', parameters['channel']])

        if 'limit' in parameters:
            args.extend(['-l', str(parameters['limit'])])

        if 'verbose' in parameters and parameters['verbose']:
            args.append('-v')

        return args

    def _parse_zsteg_output(self, output_bytes):
        """Parse zsteg output and extract meaningful data"""
        output_text = output_bytes.decode('utf-8', errors='ignore')
        lines = output_text.strip().split('\n')

        extracted_data = b''
        findings = []
        confidence = 0.2  # Base confidence

        for line in lines:
            line = line.strip()
            if not line or line.startswith('['):
                continue

            # Parse zsteg line format: "channel .. text"
            parts = line.split(' .. ', 1)
            if len(parts) == 2:
                channel, content = parts

                finding = {
                    'channel': channel.strip(),
                    'content': content.strip(),
                    'type': self._classify_content(content.strip())
                }
                findings.append(finding)

                # Extract binary data if it looks like meaningful content
                if self._is_meaningful_content(content.strip()):
                    extracted_data += content.encode('utf-8', errors='ignore')
                    confidence += 0.2

        # Cap confidence at 0.9
        confidence = min(0.9, confidence)

        return extracted_data, confidence, findings

    def _classify_content(self, content):
        """Classify the type of content found"""
        content_lower = content.lower()

        if any(keyword in content_lower for keyword in ['flag{', 'ctf{', 'password', 'key']):
            return 'sensitive'
        elif re.match(r'^[a-zA-Z0-9+/]{20,}={0,2}$', content):
            return 'base64'
        elif re.match(r'^[0-9a-fA-F]{32,}$', content):
            return 'hex'
        elif content.isprintable() and len(content) > 10:
            return 'text'
        else:
            return 'binary'

    def _is_meaningful_content(self, content):
        """Check if content appears to be meaningful (not random noise)"""
        if len(content) < 4:
            return False

        # Check for printable characters
        printable_ratio = sum(1 for c in content if c.isprintable()) / len(content)
        if printable_ratio < 0.7:
            return False

        # Check for common meaningful patterns
        meaningful_patterns = [
            r'flag{.*}', r'password.*', r'key.*', r'secret.*',
            r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',  # Email
            r'https?://[^\s]+',  # URL
            r'[A-Za-z0-9+/]{20,}={0,2}',  # Base64
        ]

        for pattern in meaningful_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                return True

        # Check for reasonable text (has spaces and common words)
        if ' ' in content and any(word in content.lower() for word in ['the', 'and', 'or', 'is', 'to', 'a']):
            return True

        return False

# ===================================================================
# crypto_hunter_web/services/extractors/steghide.py
# Updated Steghide extractor
# ===================================================================

import os
import tempfile
from .base import BaseExtractor

class SteghideExtractor(BaseExtractor):
    """Enhanced Steghide extractor with password cracking"""

    def _get_tool_name(self):
        return 'steghide'

    def extract(self, file_path: str, parameters: Dict = None):
        """Extract using steghide with enhanced password cracking"""
        if not os.path.exists(file_path):
            return {
                'success': False,
                'error': 'File not found',
                'data': b'',
                'details': '',
                'command_line': '',
                'confidence': 0
            }

        # Check if tool is available
        if not self._is_tool_available():
            return {
                'success': False,
                'error': 'Steghide not available',
                'data': b'',
                'details': 'Steghide is not installed',
                'command_line': '',
                'confidence': 0
            }

        parameters = parameters or {}

        # Get password list
        passwords = self._get_password_list(parameters)

        # Try each password
        for password in passwords:
            result = self._try_password(file_path, password)
            if result['success']:
                result['metadata'] = {
                    'password_used': password,
                    'passwords_tried': passwords.index(password) + 1,
                    'total_passwords': len(passwords)
                }
                return result

        # If no password worked, return failure
        return {
            'success': False,
            'error': 'No valid steghide data found with any password',
            'data': b'',
            'details': f'Tried {len(passwords)} passwords, no steganographic content found',
            'command_line': 'steghide extract (multiple attempts)',
            'confidence': 0,
            'metadata': {
                'passwords_tried': len(passwords),
                'password_list': passwords[:10]  # Show first 10 passwords tried
            }
        }

    def _get_password_list(self, parameters):
        """Get list of passwords to try"""
        passwords = ['']  # Start with empty password

        # Add custom password if provided
        if 'password' in parameters:
            passwords.insert(0, parameters['password'])

        # Add common passwords
        common_passwords = [
            'password', '123456', 'admin', 'root', 'steghide',
            'secret', 'hidden', 'flag', 'ctf', 'crypto',
            'test', 'guest', 'user', 'password123', 'admin123'
        ]

        passwords.extend(common_passwords)

        # Add wordlist if available
        wordlist_paths = [
            '/usr/share/wordlists/rockyou.txt',
            '/opt/wordlists/common.txt',
            parameters.get('wordlist_path')
        ]

        for wordlist_path in wordlist_paths:
            if wordlist_path and os.path.exists(wordlist_path):
                try:
                    with open(wordlist_path, 'r', encoding='utf-8', errors='ignore') as f:
                        wordlist_passwords = [line.strip() for line in f.readlines()[:1000]]  # Limit to 1000
                        passwords.extend(wordlist_passwords)
                    break
                except:
                    continue

        # Remove duplicates while preserving order
        seen = set()
        unique_passwords = []
        for pwd in passwords:
            if pwd not in seen:
                seen.add(pwd)
                unique_passwords.append(pwd)

        return unique_passwords

    def _try_password(self, file_path: str, password: str):
        """Try extracting with a specific password"""
        temp_output = None

        try:
            # Create temporary output file
            with tempfile.NamedTemporaryFile(delete=False) as temp_file:
                temp_output = temp_file.name

            # Build steghide command
            command = ['steghide', 'extract', '-sf', file_path, '-xf', temp_output, '-p', password]

            result = self._run_command(command, timeout=30)

            if result['returncode'] == 0 and os.path.exists(temp_output):
                # Read extracted data
                with open(temp_output, 'rb') as f:
                    extracted_data = f.read()

                if len(extracted_data) > 0:
                    confidence = 0.9 if password == '' else 0.95  # Higher confidence for password-protected

                    return {
                        'success': True,
                        'data': extracted_data,
                        'error': '',
                        'details': f"Steghide extraction successful with password: '{password}', extracted {len(extracted_data)} bytes",
                        'command_line': result['command_line'].replace(f'-p {password}', '-p [REDACTED]'),
                        'confidence': confidence
                    }

        except Exception as e:
            pass  # Continue trying other passwords

        finally:
            # Clean up temporary file
            if temp_output and os.path.exists(temp_output):
                try:
                    os.unlink(temp_output)
                except:
                    pass

        return {'success': False}

# ===================================================================
# crypto_hunter_web/services/extractors/binwalk.py
# Updated Binwalk extractor
# ===================================================================

import os
import tempfile
import shutil
import magic
from .base import BaseExtractor

class BinwalkExtractor(BaseExtractor):
    """Enhanced Binwalk extractor for file carving and analysis"""

    def _get_tool_name(self):
        return 'binwalk'

    def extract(self, file_path: str, parameters: Dict = None):
        """Extract using binwalk with enhanced file analysis"""
        if not os.path.exists(file_path):
            return {
                'success': False,
                'error': 'File not found',
                'data': b'',
                'details': '',
                'command_line': '',
                'confidence': 0
            }

        # Check if tool is available
        if not self._is_tool_available():
            return {
                'success': False,
                'error': 'Binwalk not available',
                'data': b'',
                'details': 'Binwalk is not installed. Install with: pip install binwalk',
                'command_line': '',
                'confidence': 0
            }

        # Create temporary directory for extraction
        temp_dir = tempfile.mkdtemp(prefix='binwalk_')

        try:
            parameters = parameters or {}

            # Build binwalk command
            command = ['binwalk']

            # Add extraction parameters
            if parameters.get('extract', True):
                command.extend(['-e', '--dd=.*'])

            # Add output directory
            command.extend(['-C', temp_dir])

            # Add signature scanning
            if parameters.get('signatures', True):
                command.append('--signature')

            # Add verbose output
            if parameters.get('verbose', False):
                command.append('-v')

            # Add file
            command.append(file_path)

            result = self._run_command(command, timeout=180)  # 3 minute timeout

            # Process results
            extracted_files = []
            extracted_data = b''
            signatures_found = []

            # Parse stdout for signatures
            if result['stdout']:
                stdout_text = result['stdout'].decode('utf-8', errors='ignore')
                signatures_found = self._parse_binwalk_signatures(stdout_text)

            # Collect extracted files
            for root, dirs, files in os.walk(temp_dir):
                for file in files:
                    file_full_path = os.path.join(root, file)
                    try:
                        with open(file_full_path, 'rb') as f:
                            file_data = f.read()

                        # Analyze file type
                        file_type = magic.from_file(file_full_path, mime=True)

                        extracted_files.append({
                            'name': file,
                            'size': len(file_data),
                            'path': file_full_path,
                            'type': file_type,
                            'offset': self._get_file_offset(file, stdout_text)
                        })

                        extracted_data += file_data

                    except Exception as e:
                        continue

            # Calculate confidence
            confidence = self._calculate_confidence(signatures_found, extracted_files)

            success = len(extracted_files) > 0 or len(signatures_found) > 0

            return {
                'success': success,
                'data': extracted_data,
                'error': result['stderr'].decode('utf-8', errors='ignore') if result['stderr'] else '',
                'details': f"Binwalk found {len(signatures_found)} signatures and extracted {len(extracted_files)} files, total {len(extracted_data)} bytes",
                'command_line': result['command_line'],
                'confidence': confidence,
                'metadata': {
                    'extracted_files': extracted_files,
                    'signatures_found': signatures_found,
                    'output_dir': temp_dir,
                    'stdout': stdout_text if result['stdout'] else ''
                }
            }

        except Exception as e:
            return {
                'success': False,
                'error': str(e),
                'data': b'',
                'details': 'Binwalk execution failed',
                'command_line': ' '.join(command) if 'command' in locals() else 'binwalk',
                'confidence': 0
            }

        finally:
            # Clean up temporary directory
            try:
                shutil.rmtree(temp_dir, ignore_errors=True)
            except:
                pass

    def _parse_binwalk_signatures(self, stdout_text):
        """Parse binwalk signature output"""
        signatures = []

        for line in stdout_text.split('\n'):
            line = line.strip()
            if not line or line.startswith('DECIMAL'):
                continue

            # Parse binwalk output format: "DECIMAL    HEX        DESCRIPTION"
            parts = line.split(None, 2)
            if len(parts) >= 3:
                try:
                    decimal_offset = int(parts[0])
                    hex_offset = parts[1]
                    description = parts[2]

                    signatures.append({
                        'offset': decimal_offset,
                        'hex_offset': hex_offset,
                        'description': description,
                        'type': self._classify_signature(description)
                    })
                except ValueError:
                    continue

        return signatures

    def _classify_signature(self, description):
        """Classify signature type"""
        description_lower = description.lower()

        if any(keyword in description_lower for keyword in ['zip', 'archive', 'compressed']):
            return 'archive'
        elif any(keyword in description_lower for keyword in ['jpeg', 'png', 'gif', 'image']):
            return 'image'
        elif any(keyword in description_lower for keyword in ['audio', 'wav', 'mp3']):
            return 'audio'
        elif any(keyword in description_lower for keyword in ['video', 'mp4', 'avi']):
            return 'video'
        elif any(keyword in description_lower for keyword in ['executable', 'elf', 'pe']):
            return 'executable'
        elif any(keyword in description_lower for keyword in ['certificate', 'key', 'crypto']):
            return 'crypto'
        else:
            return 'unknown'

    def _get_file_offset(self, filename, stdout_text):
        """Get the offset where a file was found"""
        # Try to match filename with offset from binwalk output
        for line in stdout_text.split('\n'):
            if filename in line:
                parts = line.split(None, 1)
                if parts:
                    try:
                        return int(parts[0])
                    except ValueError:
                        pass
        return 0

    def _calculate_confidence(self, signatures, extracted_files):
        """Calculate confidence based on findings"""
        base_confidence = 0.3

        # Boost confidence for signatures found
        signature_boost = min(0.4, len(signatures) * 0.1)

        # Boost confidence for files extracted
        file_boost = min(0.3, len(extracted_files) * 0.1)

        # Boost for interesting file types
        interesting_types = ['image', 'archive', 'crypto', 'executable']
        for sig in signatures:
            if sig['type'] in interesting_types:
                base_confidence += 0.05

        return min(0.9, base_confidence + signature_boost + file_boost)

# ===================================================================
# crypto_hunter_web/services/extractors/custom.py
# Updated Custom extractor
# ===================================================================

import os
import re
import subprocess
from .base import BaseExtractor

class CustomExtractor(BaseExtractor):
    """Enhanced custom extractors for strings, hexdump, and manual analysis"""

    def _get_tool_name(self):
        if 'strings' in self.method_name:
            return 'strings'
        elif 'hexdump' in self.method_name:
            return 'hexdump'
        else:
            return 'custom'

    def extract(self, file_path: str, parameters: Dict = None):
        """Extract using enhanced custom methods"""
        if not os.path.exists(file_path):
            return {
                'success': False,
                'error': 'File not found',
                'data': b'',
                'details': '',
                'command_line': '',
                'confidence': 0
            }

        parameters = parameters or {}

        if 'strings' in self.method_name:
            return self._extract_strings(file_path, parameters)
        elif 'hexdump' in self.method_name:
            return self._extract_hexdump(file_path, parameters)
        else:
            return self._manual_analysis(file_path, parameters)

    def _extract_strings(self, file_path: str, parameters: Dict):
        """Enhanced string extraction with pattern analysis"""
        min_length = parameters.get('min_length', 4)
        encoding = parameters.get('encoding', 'ascii')

        # Build strings command
        command = ['strings', '-n', str(min_length)]

        if encoding == 'unicode':
            command.append('-e')
            command.append('l')  # 16-bit little-endian

        command.append(file_path)

        try:
            result = self._run_command(command, timeout=60)

            if result['returncode'] == 0:
                strings_data = result['stdout']
                strings_text = strings_data.decode('utf-8', errors='ignore')

                # Analyze strings for patterns
                analysis = self._analyze_strings(strings_text)

                confidence = self._calculate_strings_confidence(analysis)

                return {
                    'success': True,
                    'data': strings_data,
                    'error': '',
                    'details': f"Extracted {analysis['total_strings']} strings, found {len(analysis['interesting_strings'])} interesting patterns",
                    'command_line': result['command_line'],
                    'confidence': confidence,
                    'metadata': {
                        'analysis': analysis,
                        'encoding': encoding,
                        'min_length': min_length
                    }
                }
            else:
                return {
                    'success': False,
                    'error': result['stderr'].decode('utf-8', errors='ignore'),
                    'data': b'',
                    'details': 'String extraction failed',
                    'command_line': result['command_line'],
                    'confidence': 0
                }

        except Exception as e:
            return {
                'success': False,
                'error': str(e),
                'data': b'',
                'details': 'String extraction exception',
                'command_line': ' '.join(command),
                'confidence': 0
            }

    def _analyze_strings(self, strings_text):
        """Analyze extracted strings for interesting patterns"""
        lines = strings_text.split('\n')

        analysis = {
            'total_strings': len(lines),
            'interesting_strings': [],
            'patterns': {
                'emails': [],
                'urls': [],
                'ips': [],
                'base64_candidates': [],
                'hex_strings': [],
                'flags': [],
                'passwords': [],
                'crypto_addresses': [],
                'file_paths': []
            }
        }

        # Pattern definitions
        patterns = {
            'emails': r'[\w\.-]+@[\w\.-]+\.\w+',
            'urls': r'https?://[\w\.-]+(?:/\S*)?',
            'ips': r'\b(?:\d{1,3}\.){3}\d{1,3}\b',
            'base64_candidates': r'^[A-Za-z0-9+/]{20,}={0,2}$',
            'hex_strings': r'^[0-9a-fA-F]{32,}$',
            'flags': r'flag\{[^}]+\}|CTF\{[^}]+\}|FLAG\{[^}]+\}',
            'passwords': r'(?:password|passwd|pwd)[\s:=]+\S+',
            'crypto_addresses': r'\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b|\b0x[a-fA-F0-9]{40}\b',
            'file_paths': r'(?:[a-zA-Z]:\\|/)(?:[^\\/:*?"<>|\r\n]+[\\\/])*[^\\/:*?"<>|\r\n]*'
        }

        # Keywords that make strings interesting
        interesting_keywords = [
            'flag', 'password', 'secret', 'key', 'token', 'auth', 'login',
            'admin', 'root', 'config', 'database', 'crypto', 'bitcoin',
            'wallet', 'private', 'public', 'certificate', 'ssh', 'rsa'
        ]

        for line in lines:
            line = line.strip()
            if len(line) < 4:
                continue

            # Check for interesting keywords
            line_lower = line.lower()
            if any(keyword in line_lower for keyword in interesting_keywords):
                analysis['interesting_strings'].append({
                    'string': line,
                    'type': 'keyword_match',
                    'keywords': [kw for kw in interesting_keywords if kw in line_lower]
                })

            # Check against patterns
            for pattern_name, pattern in patterns.items():
                matches = re.findall(pattern, line, re.IGNORECASE)
                if matches:
                    analysis['patterns'][pattern_name].extend(matches)
                    if line not in [item['string'] for item in analysis['interesting_strings']]:
                        analysis['interesting_strings'].append({
                            'string': line,
                            'type': pattern_name,
                            'matches': matches
                        })

        return analysis

    def _calculate_strings_confidence(self, analysis):
        """Calculate confidence based on string analysis"""
        base_confidence = 0.2

        # Boost for interesting strings
        interesting_boost = min(0.4, len(analysis['interesting_strings']) * 0.05)

        # Boost for specific patterns
        pattern_weights = {
            'flags': 0.3,
            'crypto_addresses': 0.2,
            'passwords': 0.2,
            'base64_candidates': 0.1,
            'emails': 0.05,
            'urls': 0.05
        }

        pattern_boost = 0
        for pattern_name, weight in pattern_weights.items():
            if analysis['patterns'][pattern_name]:
                pattern_boost += weight

        return min(0.9, base_confidence + interesting_boost + pattern_boost)

    def _extract_hexdump(self, file_path: str, parameters: Dict):
        """Enhanced hexdump with analysis"""
        length = parameters.get('length', 2048)
        offset = parameters.get('offset', 0)

        command = ['hexdump', '-C']

        if offset > 0:
            command.extend(['-s', str(offset)])

        if length > 0:
            command.extend(['-n', str(length)])

        command.append(file_path)

        try:
            result = self._run_command(command, timeout=30)

            if result['returncode'] == 0:
                hex_data = result['stdout']
                hex_text = hex_data.decode('utf-8', errors='ignore')

                # Analyze hex dump
                analysis = self._analyze_hexdump(hex_text)

                return {
                    'success': True,
                    'data': hex_data,
                    'error': '',
                    'details': f"Generated hexdump ({len(hex_data)} bytes), found {len(analysis['patterns'])} interesting patterns",
                    'command_line': result['command_line'],
                    'confidence': 0.5 if analysis['patterns'] else 0.3,
                    'metadata': {
                        'analysis': analysis,
                        'offset': offset,
                        'length': length
                    }
                }
            else:
                return {
                    'success': False,
                    'error': result['stderr'].decode('utf-8', errors='ignore'),
                    'data': b'',
                    'details': 'Hexdump failed',
                    'command_line': result['command_line'],
                    'confidence': 0
                }

        except Exception as e:
            return {
                'success': False,
                'error': str(e),
                'data': b'',
                'details': 'Hexdump exception',
                'command_line': ' '.join(command),
                'confidence': 0
            }

    def _analyze_hexdump(self, hex_text):
        """Analyze hexdump for patterns"""
        analysis = {
            'patterns': [],
            'file_signatures': [],
            'repeated_patterns': [],
            'ascii_strings': []
        }

        lines = hex_text.split('\n')

        # File signature patterns
        signatures = {
            'ffd8ff': 'JPEG image',
            '89504e47': 'PNG image',
            '474946': 'GIF image',
            '504b0304': 'ZIP archive',
            '7f454c46': 'ELF executable',
            '4d5a': 'Windows executable',
            '25504446': 'PDF document'
        }

        for line in lines:
            if not line.strip():
                continue

            # Parse hexdump line
            parts = line.split('|')
            if len(parts) >= 2:
                hex_part = parts[0]
                ascii_part = parts[1].rstrip('|').strip()

                # Check for file signatures
                hex_bytes = ''.join(hex_part.split()[1:])  # Remove offset
                for sig, desc in signatures.items():
                    if hex_bytes.startswith(sig):
                        analysis['file_signatures'].append({
                            'signature': sig,
                            'description': desc,
                            'offset': hex_part.split()[0] if hex_part.split() else '0'
                        })

                # Extract readable ASCII
                if ascii_part and len(ascii_part.replace('.', '').strip()) > 3:
                    analysis['ascii_strings'].append(ascii_part)

        return analysis

    def _manual_analysis(self, file_path: str, parameters: Dict):
        """Manual analysis - read file content with basic analysis"""
        try:
            max_size = parameters.get('max_size', 8192)  # 8KB default

            with open(file_path, 'rb') as f:
                file_data = f.read(max_size)

            # Basic analysis
            analysis = {
                'file_size': len(file_data),
                'entropy': self._calculate_entropy(file_data),
                'printable_ratio': sum(1 for b in file_data if 32 <= b <= 126) / len(file_data) if file_data else 0,
                'null_bytes': file_data.count(0),
                'has_magic_bytes': self._check_magic_bytes(file_data)
            }

            confidence = 0.3
            if analysis['entropy'] > 7.5:  # High entropy might indicate encryption/compression
                confidence += 0.2
            if analysis['printable_ratio'] > 0.8:  # Mostly text
                confidence += 0.1
            if analysis['has_magic_bytes']:  # Has file signature
                confidence += 0.2

            return {
                'success': True,
                'data': file_data,
                'error': '',
                'details': f"Manual analysis: {analysis['file_size']} bytes, entropy: {analysis['entropy']:.2f}",
                'command_line': f"manual analysis of {file_path}",
                'confidence': min(0.8, confidence),
                'metadata': analysis
            }

        except Exception as e:
            return {
                'success': False,
                'error': str(e),
                'data': b'',
                'details': 'Manual analysis failed',
                'command_line': f"manual analysis of {file_path}",
                'confidence': 0
            }

    def _calculate_entropy(self, data):
        """Calculate Shannon entropy of data"""
        if not data:
            return 0

        import math
        from collections import Counter

        # Count frequency of each byte
        counts = Counter(data)

        # Calculate entropy
        entropy = 0
        data_len = len(data)

        for count in counts.values():
            p = count / data_len
            if p > 0:
                entropy -= p * math.log2(p)

        return entropy

    def _check_magic_bytes(self, data):
        """Check if data starts with known magic bytes"""
        if len(data) < 4:
            return False

        magic_signatures = [
            b'\xff\xd8\xff',      # JPEG
            b'\x89\x50\x4e\x47',  # PNG
            b'\x47\x49\x46',      # GIF
            b'\x50\x4b\x03\x04',  # ZIP
            b'\x7f\x45\x4c\x46',  # ELF
            b'\x4d\x5a',          # PE/EXE
            b'\x25\x50\x44\x46'   # PDF
        ]

        for signature in magic_signatures:
            if data.startswith(signature):
                return True

        return False
