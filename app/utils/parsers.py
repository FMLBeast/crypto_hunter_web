"""
Content parsing utilities
"""

import re
import binascii
from typing import List, Dict, Any

def parse_hex_dump(hex_dump_text: str) -> Dict[str, Any]:
    """Parse hexdump output into structured data"""
    lines = hex_dump_text.strip().split('\n')
    parsed_data = {
        'entries': [],
        'total_bytes': 0,
        'ascii_strings': [],
        'patterns': []
    }
    
    for line in lines:
        if not line.strip():
            continue
            
        # Parse hexdump line format: "00000000  41 42 43 44 45 46 47 48  |ABCDEFGH|"
        match = re.match(r'^([0-9a-fA-F]{8})\s+([0-9a-fA-F\s]+)\s+\|(.*)\|', line)
        if match:
            offset = int(match.group(1), 16)
            hex_bytes = match.group(2).replace(' ', '')
            ascii_repr = match.group(3)

            parsed_data['entries'].append({
                'offset': offset,
                'hex_data': hex_bytes,
                'ascii': ascii_repr,
                'length': len(hex_bytes) // 2
            })

            parsed_data['total_bytes'] += len(hex_bytes) // 2

            # Extract readable ASCII strings
            if ascii_repr and len(ascii_repr.replace('.', '').strip()) > 3:
                parsed_data['ascii_strings'].append(ascii_repr)

    # Look for patterns
    parsed_data['patterns'] = find_hex_patterns(parsed_data['entries'])

    return parsed_data

def parse_strings_output(strings_text: str) -> Dict[str, Any]:
    """Parse strings command output"""
    lines = strings_text.strip().split('\n')
    parsed_data = {
        'strings': [],
        'interesting_strings': [],
        'patterns': {
            'urls': [],
            'emails': [],
            'base64_candidates': [],
            'hex_strings': [],
            'flags': []
        }
    }

    for line in lines:
        line = line.strip()
        if not line:
            continue

        parsed_data['strings'].append(line)

        # Check for interesting patterns
        if is_interesting_string(line):
            parsed_data['interesting_strings'].append(line)

        # URL pattern
        if re.search(r'https?://[\w\.-]+', line, re.IGNORECASE):
            parsed_data['patterns']['urls'].append(line)

        # Email pattern
        if re.search(r'[\w\.-]+@[\w\.-]+\.[a-zA-Z]{2,}', line):
            parsed_data['patterns']['emails'].append(line)

        # Base64 candidate (20+ chars, valid base64 chars)
        if re.match(r'^[A-Za-z0-9+/]{20,}={0,2}$', line):
            parsed_data['patterns']['base64_candidates'].append(line)

        # Hex string (32+ hex chars)
        if re.match(r'^[0-9a-fA-F]{32,}$', line):
            parsed_data['patterns']['hex_strings'].append(line)

        # Flag patterns
        if re.search(r'flag{.*}|FLAG{.*}|ctf{.*}|CTF{.*}', line, re.IGNORECASE):
            parsed_data['patterns']['flags'].append(line)

    return parsed_data

def find_hex_patterns(hex_entries: List[Dict]) -> List[Dict]:
    """Find interesting patterns in hex data"""
    patterns = []

    for entry in hex_entries:
        hex_data = entry['hex_data']

        # Look for repeated patterns
        if len(hex_data) >= 8:
            # Check for repeated 2-byte patterns
            for i in range(0, len(hex_data) - 6, 2):
                pattern = hex_data[i:i+4]
                if hex_data.count(pattern) >= 3:
                    patterns.append({
                        'type': 'repeated_bytes',
                        'pattern': pattern,
                        'count': hex_data.count(pattern),
                        'offset': entry['offset'] + i // 2
                    })

        # Look for file signatures
        file_sigs = {
            'ffd8ff': 'JPEG image',
            '89504e47': 'PNG image',
            '474946': 'GIF image',
            '504b0304': 'ZIP archive',
            '7f454c46': 'ELF executable',
            '4d5a': 'Windows executable'
        }

        for sig, desc in file_sigs.items():
            if hex_data.startswith(sig):
                patterns.append({
                    'type': 'file_signature',
                    'signature': sig,
                    'description': desc,
                    'offset': entry['offset']
                })

    return patterns

def is_interesting_string(string: str) -> bool:
    """Check if string is potentially interesting"""
    interesting_keywords = [
        'password', 'pass', 'pwd', 'key', 'secret', 'token', 'auth',
        'flag', 'ctf', 'admin', 'root', 'user', 'login', 'config',
        'database', 'db', 'sql', 'api', 'endpoint', 'url', 'path'
    ]

    string_lower = string.lower()

    # Check for keywords
    for keyword in interesting_keywords:
        if keyword in string_lower:
            return True

    # Check for long alphanumeric strings (potential tokens/hashes)
    if re.match(r'^[a-zA-Z0-9]{16,}$', string):
        return True

    # Check for base64-like strings
    if re.match(r'^[A-Za-z0-9+/]{20,}={0,2}$', string):
        return True

    return False

def extract_embedded_data(content: bytes, file_type: str) -> List[Dict]:
    """Extract potentially embedded data from file content"""
    embedded_data = []

    # Look for embedded files by magic bytes
    magic_signatures = {
        b'\xff\xd8\xff': {'type': 'JPEG', 'extension': '.jpg'},
        b'\x89PNG\r\n\x1a\n': {'type': 'PNG', 'extension': '.png'},
        b'GIF8': {'type': 'GIF', 'extension': '.gif'},
        b'PK\x03\x04': {'type': 'ZIP', 'extension': '.zip'},
        b'\x7fELF': {'type': 'ELF', 'extension': '.elf'},
        b'MZ': {'type': 'EXE', 'extension': '.exe'}
    }

    for sig, info in magic_signatures.items():
        offset = 0
        while True:
            pos = content.find(sig, offset)
            if pos == -1:
                break

            embedded_data.append({
                'type': 'embedded_file',
                'file_type': info['type'],
                'extension': info['extension'],
                'offset': pos,
                'signature': sig.hex()
            })

            offset = pos + 1

    # Look for base64 encoded data
    base64_pattern = re.compile(rb'[A-Za-z0-9+/]{20,}={0,2}')
    for match in base64_pattern.finditer(content):
        try:
            decoded = binascii.a2b_base64(match.group())
            if len(decoded) > 10:  # Significant amount of data
                embedded_data.append({
                    'type': 'base64_data',
                    'offset': match.start(),
                    'length': len(match.group()),
                    'decoded_length': len(decoded),
                    'data_preview': decoded[:50].hex()
                })
        except:
            continue

    return embedded_data