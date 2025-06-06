"""
File content analysis service
"""

import os
import re
from datetime import datetime

from app.models import db
from app.models.file import FileContent
from app.utils.file_utils import calculate_file_entropy, get_file_magic

class FileAnalyzer:
    """Analyze file content and generate metadata"""
    
    @staticmethod
    def analyze_file_content(file_path, file_id):
        """Analyze file content and create content record"""
        if not os.path.exists(file_path):
            return None
        
        try:
            # Read file content
            with open(file_path, 'rb') as f:
                raw_content = f.read()
            
            content_size = len(raw_content)
            
            # Determine content type
            content_type = FileAnalyzer._determine_content_type(raw_content)
            
            # Generate appropriate content representation
            content_text, content_preview = FileAnalyzer._generate_content_text(
                raw_content, content_type, content_size
            )
            
            # Extract strings for binary files
            strings_extracted = False
            if content_type == 'binary':
                strings_content = FileAnalyzer.extract_strings(raw_content)
                strings_extracted = bool(strings_content)
            
            # Create content record
            file_content = FileContent(
                file_id=file_id,
                content_type=content_type,
                content_data=raw_content if content_size < 10*1024*1024 else None,  # Store up to 10MB
                content_text=content_text,
                content_preview=content_preview,
                content_size=content_size,
                strings_extracted=strings_extracted,
                hex_analyzed=content_type in ['binary', 'image'],
                entropy_calculated=True
            )
            
            db.session.add(file_content)
            db.session.commit()
            
            return file_content
            
        except Exception as e:
            print(f"Error analyzing file content: {e}")
            return None
    
    @staticmethod
    def _determine_content_type(raw_content):
        """Determine the content type of the file"""
        if len(raw_content) == 0:
            return 'empty'
        
        # Check if it's text
        try:
            text_content = raw_content.decode('utf-8')
            if all(ord(c) < 128 and (c.isprintable() or c.isspace()) for c in text_content[:1000]):
                return 'text'
        except UnicodeDecodeError:
            pass
        
        # Check if it's an image
        magic_bytes = raw_content[:16].hex()
        if magic_bytes.startswith(('ffd8ff', '89504e47', '47494638', '424d')):
            return 'image'
        
        return 'binary'
    
    @staticmethod
    def _generate_content_text(raw_content, content_type, content_size):
        """Generate text representation and preview"""
        if content_type == 'text':
            try:
                text_content = raw_content.decode('utf-8')
                preview = text_content[:2000]
                return text_content, preview
            except UnicodeDecodeError:
                pass
        
        # Generate hex dump for binary/image files
        hex_lines = []
        preview_size = min(content_size, 4096)  # First 4KB only
        
        for i in range(0, preview_size, 16):
            chunk = raw_content[i:i+16]
            hex_part = ' '.join(f'{b:02x}' for b in chunk)
            ascii_part = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in chunk)
            hex_lines.append(f'{i:08x}  {hex_part:<48} |{ascii_part}|')
        
        hex_content = '\n'.join(hex_lines)
        preview = hex_content[:2000]
        
        return hex_content, preview
    
    @staticmethod
    def extract_strings(content, min_length=4):
        """Extract printable strings from binary content"""
        try:
            if isinstance(content, str):
                content = content.encode()
            
            strings = re.findall(f'[ -~]{{{min_length},}}'.encode(), content)
            return [s.decode('ascii', errors='ignore') for s in strings]
        except Exception:
            return []
    
    @staticmethod
    def get_hex_dump(file_path, start_offset=0, length=1024):
        """Get hex dump of file section"""
        try:
            with open(file_path, 'rb') as f:
                f.seek(start_offset)
                data = f.read(length)
            
            hex_lines = []
            for i in range(0, len(data), 16):
                offset = start_offset + i
                chunk = data[i:i+16]
                hex_part = ' '.join(f'{b:02x}' for b in chunk)
                ascii_part = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in chunk)
                hex_lines.append(f'{offset:08x}  {hex_part:<48} |{ascii_part}|')
            
            return '\n'.join(hex_lines)
        except Exception:
            return "Error reading file"
