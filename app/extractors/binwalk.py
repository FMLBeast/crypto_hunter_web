"""
Binwalk file analysis extractor
"""

import os
import tempfile
import shutil
from .base import BaseExtractor

class BinwalkExtractor(BaseExtractor):
    """Binwalk extractor for file carving and analysis"""
    
    def _get_tool_name(self):
        return 'binwalk'
    
    def extract(self, file_path, parameters=None):
        """Extract using binwalk"""
        if not os.path.exists(file_path):
            return {
                'success': False,
                'error': 'File not found',
                'data': b'',
                'details': '',
                'command_line': '',
                'confidence': 0
            }
        
        # Create temporary directory for extraction
        temp_dir = tempfile.mkdtemp()
        
        try:
            # Build binwalk command
            command = ['binwalk', '-e', '--dd=.*', '-C', temp_dir, file_path]
            
            result = self._run_command(command, timeout=60)
            
            if result['returncode'] == 0:
                # Collect all extracted files
                extracted_data = b''
                extracted_files = []
                
                for root, dirs, files in os.walk(temp_dir):
                    for file in files:
                        file_path_full = os.path.join(root, file)
                        try:
                            with open(file_path_full, 'rb') as f:
                                file_data = f.read()
                                extracted_data += file_data
                                extracted_files.append({
                                    'name': file,
                                    'size': len(file_data),
                                    'path': file_path_full
                                })
                        except:
                            continue
                
                confidence = min(9, 3 + len(extracted_files))
                
                return {
                    'success': True,
                    'data': extracted_data,
                    'error': '',
                    'details': f"Binwalk found {len(extracted_files)} embedded files, total {len(extracted_data)} bytes",
                    'command_line': result['command_line'],
                    'confidence': confidence
                }
            else:
                error_msg = result['stderr'].decode('utf-8', errors='ignore')
                return {
                    'success': False,
                    'error': error_msg,
                    'data': b'',
                    'details': 'Binwalk extraction failed',
                    'command_line': result['command_line'],
                    'confidence': 0
                }
                
        finally:
            # Clean up temporary directory
            try:
                shutil.rmtree(temp_dir)
            except:
                pass
