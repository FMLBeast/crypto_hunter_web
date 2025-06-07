"""
Steghide steganography extractor
"""

import os
import tempfile
from .base import BaseExtractor

class SteghideExtractor(BaseExtractor):
    """Steghide extractor for audio/image steganography"""
    
    def _get_tool_name(self):
        return 'steghide'
    
    def extract(self, file_path, parameters=None):
        """Extract using steghide"""
        if not os.path.exists(file_path):
            return {
                'success': False,
                'error': 'File not found',
                'data': b'',
                'details': '',
                'command_line': '',
                'confidence': 0
            }
        
        # Create temporary output file
        temp_output = tempfile.NamedTemporaryFile(delete=False)
        temp_output.close()
        
        try:
            # Get steghide parameters
            passphrase = parameters.get('passphrase', '') if parameters else ''
            
            # Build command
            command = ['steghide', 'extract', '-sf', file_path, '-xf', temp_output.name]
            
            if passphrase:
                command.extend(['-p', passphrase])
            else:
                command.extend(['-p', ''])  # Try empty passphrase
            
            result = self._run_command(command)
            
            if result['returncode'] == 0:
                # Read extracted data
                with open(temp_output.name, 'rb') as f:
                    extracted_data = f.read()
                
                confidence = 8 if len(extracted_data) > 0 else 3
                
                return {
                    'success': True,
                    'data': extracted_data,
                    'error': '',
                    'details': f"Steghide extraction successful, extracted {len(extracted_data)} bytes",
                    'command_line': result['command_line'],
                    'confidence': confidence
                }
            else:
                error_msg = result['stderr'].decode('utf-8', errors='ignore')
                return {
                    'success': False,
                    'error': error_msg,
                    'data': b'',
                    'details': 'Steghide extraction failed',
                    'command_line': result['command_line'],
                    'confidence': 0
                }
                
        finally:
            # Clean up temporary file
            self._cleanup_temp_file(temp_output.name)
