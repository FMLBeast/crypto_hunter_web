"""
Custom extractors for simple analysis methods
"""

import os
import re
from .base import BaseExtractor

class CustomExtractor(BaseExtractor):
    """Custom extractors for strings, hexdump, and manual analysis"""
    
    def _get_tool_name(self):
        if 'strings' in self.method_name:
            return 'strings'
        elif 'hexdump' in self.method_name:
            return 'hexdump'
        else:
            return 'custom'
    
    def extract(self, file_path, parameters=None):
        """Extract using custom methods"""
        if not os.path.exists(file_path):
            return {
                'success': False,
                'error': 'File not found',
                'data': b'',
                'details': '',
                'command_line': '',
                'confidence': 0
            }
        
        if 'strings' in self.method_name:
            return self._extract_strings(file_path, parameters)
        elif 'hexdump' in self.method_name:
            return self._extract_hexdump(file_path, parameters)
        else:
            return self._manual_analysis(file_path, parameters)
    
    def _extract_strings(self, file_path, parameters):
        """Extract strings from file"""
        min_length = parameters.get('min_length', 4) if parameters else 4
        
        command = ['strings', '-n', str(min_length), file_path]
        result = self._run_command(command)
        
        if result['returncode'] == 0:
            strings_data = result['stdout']
            strings_text = strings_data.decode('utf-8', errors='ignore')
            
            # Look for interesting patterns
            confidence = 3
            interesting_patterns = [
                r'flag{.*}', r'password.*', r'key.*', r'secret.*',
                r'[a-zA-Z0-9+/]{20,}={0,2}',  # Base64-like
                r'[0-9a-fA-F]{32,}',  # Hex strings
            ]
            
            for pattern in interesting_patterns:
                if re.search(pattern, strings_text, re.IGNORECASE):
                    confidence = min(8, confidence + 2)
            
            return {
                'success': True,
                'data': strings_data,
                'error': '',
                'details': f"Extracted {len(strings_text.split())} strings",
                'command_line': result['command_line'],
                'confidence': confidence
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
    
    def _extract_hexdump(self, file_path, parameters):
        """Create hexdump of file"""
        length = parameters.get('length', 1024) if parameters else 1024
        
        command = ['hexdump', '-C', file_path]
        result = self._run_command(command)
        
        if result['returncode'] == 0:
            hex_data = result['stdout'][:length]  # Limit output
            
            return {
                'success': True,
                'data': hex_data,
                'error': '',
                'details': f"Generated hexdump ({len(hex_data)} bytes)",
                'command_line': result['command_line'],
                'confidence': 5
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
    
    def _manual_analysis(self, file_path, parameters):
        """Manual analysis - just read file content"""
        try:
            with open(file_path, 'rb') as f:
                file_data = f.read(4096)  # Read first 4KB
            
            return {
                'success': True,
                'data': file_data,
                'error': '',
                'details': f"Manual analysis: read {len(file_data)} bytes",
                'command_line': f"manual analysis of {file_path}",
                'confidence': 3
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
