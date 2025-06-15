"""
Extractors for encoded data (base64, hex)
"""

import base64
import binascii
import re
from typing import Dict, List, Any

from .base import BaseExtractor


class Base64Extractor(BaseExtractor):
    """Extractor for base64-encoded data"""

    def _get_tool_name(self):
        return "base64"

    def extract(self, file_path: str, parameters: Dict = None):
        """
        Extract base64-encoded data from file
        
        Args:
            file_path: Path to the file to analyze
            parameters: Dictionary of extraction parameters
                - min_length: Minimum length of base64 string (default: 16)
                - decode_all: Try to decode all base64-like strings (default: True)
                
        Returns:
            Dictionary with extraction results
        """
        if parameters is None:
            parameters = {}
            
        min_length = parameters.get('min_length', 16)
        decode_all = parameters.get('decode_all', True)
        
        try:
            with open(file_path, 'rb') as f:
                content = f.read()
                
            # Try to decode the entire file as base64
            try:
                decoded_data = base64.b64decode(content, validate=True)
                return {
                    'success': True,
                    'data': decoded_data,
                    'details': f"Successfully decoded entire file as base64 ({len(decoded_data)} bytes)",
                    'command_line': f"base64 -d {file_path}",
                    'confidence': 9
                }
            except Exception as e:
                # If the entire file isn't base64, look for base64 strings
                if not decode_all:
                    return {
                        'success': False,
                        'error': f"Not valid base64: {str(e)}",
                        'data': b'',
                        'details': "File does not contain valid base64 data",
                        'command_line': f"base64 -d {file_path}",
                        'confidence': 0
                    }
            
            # Look for base64-like strings in the content
            text_content = content.decode('utf-8', errors='ignore')
            
            # Regex for base64 strings (allowing padding)
            base64_pattern = r'[A-Za-z0-9+/]{%d,}={0,2}' % min_length
            
            matches = re.finditer(base64_pattern, text_content)
            extracted_data = b''
            successful_decodes = 0
            
            for match in matches:
                b64_string = match.group(0)
                try:
                    decoded = base64.b64decode(b64_string, validate=True)
                    # Check if the decoded data looks like text or binary
                    if all(32 <= b <= 126 or b in (9, 10, 13) for b in decoded[:100]):
                        extracted_data += decoded + b'\n---\n'
                        successful_decodes += 1
                except:
                    # Skip invalid base64 strings
                    continue
            
            if successful_decodes > 0:
                return {
                    'success': True,
                    'data': extracted_data,
                    'details': f"Found {successful_decodes} base64-encoded strings",
                    'command_line': f"grep -oE '[A-Za-z0-9+/]{{16,}}={{0,2}}' {file_path} | base64 -d",
                    'confidence': 7
                }
            
            return {
                'success': False,
                'error': "No valid base64 data found",
                'data': b'',
                'details': "File does not contain valid base64 data",
                'command_line': f"base64 -d {file_path}",
                'confidence': 0
            }
            
        except Exception as e:
            return {
                'success': False,
                'error': str(e),
                'data': b'',
                'details': f"Error processing file: {str(e)}",
                'command_line': f"base64 -d {file_path}",
                'confidence': 0
            }
    
    def _is_tool_available(self):
        """Base64 is always available as it uses Python's built-in libraries"""
        return True


class HexExtractor(BaseExtractor):
    """Extractor for hex-encoded data"""

    def _get_tool_name(self):
        return "hex"

    def extract(self, file_path: str, parameters: Dict = None):
        """
        Extract hex-encoded data from file
        
        Args:
            file_path: Path to the file to analyze
            parameters: Dictionary of extraction parameters
                - min_length: Minimum length of hex string (default: 8)
                - decode_all: Try to decode all hex-like strings (default: True)
                
        Returns:
            Dictionary with extraction results
        """
        if parameters is None:
            parameters = {}
            
        min_length = parameters.get('min_length', 8)
        decode_all = parameters.get('decode_all', True)
        
        try:
            with open(file_path, 'rb') as f:
                content = f.read()
                
            # Try to decode the entire file as hex
            try:
                # Remove whitespace and convert to lowercase
                hex_content = content.decode('utf-8', errors='ignore').lower()
                hex_content = re.sub(r'\s', '', hex_content)
                
                # Check if it's a valid hex string
                if all(c in '0123456789abcdef' for c in hex_content):
                    decoded_data = binascii.unhexlify(hex_content)
                    return {
                        'success': True,
                        'data': decoded_data,
                        'details': f"Successfully decoded entire file as hex ({len(decoded_data)} bytes)",
                        'command_line': f"xxd -r -p {file_path}",
                        'confidence': 9
                    }
            except Exception as e:
                # If the entire file isn't hex, look for hex strings
                if not decode_all:
                    return {
                        'success': False,
                        'error': f"Not valid hex: {str(e)}",
                        'data': b'',
                        'details': "File does not contain valid hex data",
                        'command_line': f"xxd -r -p {file_path}",
                        'confidence': 0
                    }
            
            # Look for hex strings in the content
            text_content = content.decode('utf-8', errors='ignore')
            
            # Regex for hex strings (pairs of hex digits, optionally separated by spaces)
            hex_pattern = r'(?:[0-9a-fA-F]{2}[ \t]?){%d,}' % (min_length // 2)
            
            matches = re.finditer(hex_pattern, text_content)
            extracted_data = b''
            successful_decodes = 0
            
            for match in matches:
                hex_string = match.group(0)
                # Remove spaces
                hex_string = re.sub(r'\s', '', hex_string)
                
                try:
                    # Make sure we have an even number of digits
                    if len(hex_string) % 2 == 0:
                        decoded = binascii.unhexlify(hex_string)
                        # Check if the decoded data looks like text or binary
                        if all(32 <= b <= 126 or b in (9, 10, 13) for b in decoded[:100]):
                            extracted_data += decoded + b'\n---\n'
                            successful_decodes += 1
                except:
                    # Skip invalid hex strings
                    continue
            
            if successful_decodes > 0:
                return {
                    'success': True,
                    'data': extracted_data,
                    'details': f"Found {successful_decodes} hex-encoded strings",
                    'command_line': f"grep -oE '([0-9a-fA-F]{{2}}[ \\t]?){{4,}}' {file_path} | xxd -r -p",
                    'confidence': 7
                }
            
            return {
                'success': False,
                'error': "No valid hex data found",
                'data': b'',
                'details': "File does not contain valid hex data",
                'command_line': f"xxd -r -p {file_path}",
                'confidence': 0
            }
            
        except Exception as e:
            return {
                'success': False,
                'error': str(e),
                'data': b'',
                'details': f"Error processing file: {str(e)}",
                'command_line': f"xxd -r -p {file_path}",
                'confidence': 0
            }
    
    def _is_tool_available(self):
        """Hex decoding is always available as it uses Python's built-in libraries"""
        return True