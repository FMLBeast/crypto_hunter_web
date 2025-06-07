"""
ZSteg steganography extractor
"""

import os
import re
from .base import BaseExtractor

class ZStegExtractor(BaseExtractor):
    """ZSteg extractor for image steganography"""
    
    def _get_tool_name(self):
        return 'zsteg'
    
    def extract(self, file_path, parameters=None):
        """Extract using zsteg with specified parameters"""
        if not os.path.exists(file_path):
            return {
                'success': False,
                'error': 'File not found',
                'data': b'',
                'details': '',
                'command_line': '',
                'confidence': 0
            }
        
        # Determine zsteg parameters based on method
        zsteg_args = self._get_zsteg_args(parameters or {})
        command = ['zsteg'] + zsteg_args + [file_path]
        
        result = self._run_command(command)
        
        if result['returncode'] == 0 and result['stdout']:
            # Parse zsteg output
            extracted_data, confidence = self._parse_zsteg_output(result['stdout'])
            
            return {
                'success': True,
                'data': extracted_data,
                'error': '',
                'details': f"ZSteg extraction successful, found {len(extracted_data)} bytes",
                'command_line': result['command_line'],
                'confidence': confidence
            }
        else:
            return {
                'success': False,
                'error': result['stderr'].decode('utf-8', errors='ignore'),
                'data': b'',
                'details': 'ZSteg extraction failed',
                'command_line': result['command_line'],
                'confidence': 0
            }
    
    def _get_zsteg_args(self, parameters):
        """Get zsteg command arguments based on method and parameters"""
        args = []
        
        # Determine extraction method
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
        
        if 'order' in parameters:
            args.extend(['-o', parameters['order']])
        
        return args
    
    def _parse_zsteg_output(self, output):
        """Parse zsteg output and extract relevant data"""
        output_str = output.decode('utf-8', errors='ignore')
        
        # Look for potential data in output
        lines = output_str.split('\n')
        data_lines = []
        confidence = 3  # Default low confidence
        
        for line in lines:
            line = line.strip()
            if line and not line.startswith('['):
                # Skip metadata lines, look for actual data
                if len(line) > 10 and not line.startswith('imagedata'):
                    data_lines.append(line)
                    
                    # Increase confidence for certain patterns
                    if re.search(r'[a-zA-Z0-9+/=]{20,}', line):  # Base64-like
                        confidence = max(confidence, 7)
                    elif 'flag' in line.lower() or 'password' in line.lower():
                        confidence = 9
        
        # Join all data lines
        extracted_text = '\n'.join(data_lines)
        extracted_data = extracted_text.encode('utf-8')
        
        return extracted_data, confidence
