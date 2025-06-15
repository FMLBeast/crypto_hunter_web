"""
File type detection utilities
"""

import os
import subprocess
import re
from typing import Tuple

def detect_file_type(file_path: str) -> Tuple[str, str]:
    """
    Detect file type using the 'file' command
    
    Args:
        file_path: Path to the file to analyze
        
    Returns:
        Tuple of (mime_type, file_extension)
    """
    try:
        # Run the 'file' command with --mime-type flag
        mime_process = subprocess.run(
            ['file', '--mime-type', '-b', file_path],
            capture_output=True, text=True, check=True
        )
        mime_type = mime_process.stdout.strip()
        
        # Run the 'file' command to get detailed description
        desc_process = subprocess.run(
            ['file', '-b', file_path],
            capture_output=True, text=True, check=True
        )
        file_description = desc_process.stdout.strip()
        
        # Determine appropriate extension based on mime type and description
        extension = get_extension_from_type(mime_type, file_description)
        
        return mime_type, extension
    except Exception as e:
        print(f"Error detecting file type: {e}")
        return "application/octet-stream", "bin"

def get_extension_from_type(mime_type: str, description: str) -> str:
    """
    Determine file extension based on mime type and file description
    
    Args:
        mime_type: MIME type from file command
        description: File description from file command
        
    Returns:
        Appropriate file extension (without dot)
    """
    # Common mime type to extension mapping
    mime_map = {
        'image/jpeg': 'jpg',
        'image/png': 'png',
        'image/gif': 'gif',
        'image/bmp': 'bmp',
        'image/tiff': 'tiff',
        'image/webp': 'webp',
        'text/plain': 'txt',
        'text/html': 'html',
        'text/xml': 'xml',
        'text/csv': 'csv',
        'text/javascript': 'js',
        'application/json': 'json',
        'application/pdf': 'pdf',
        'application/zip': 'zip',
        'application/x-tar': 'tar',
        'application/x-gzip': 'gz',
        'application/x-bzip2': 'bz2',
        'application/x-7z-compressed': '7z',
        'application/x-rar-compressed': 'rar',
        'application/x-executable': 'exe',
        'application/x-sharedlib': 'so',
        'application/x-object': 'o',
        'application/x-dosexec': 'exe',
        'application/x-elf': 'elf',
        'application/octet-stream': 'bin',
        'audio/mpeg': 'mp3',
        'audio/wav': 'wav',
        'audio/ogg': 'ogg',
        'audio/flac': 'flac',
        'video/mp4': 'mp4',
        'video/mpeg': 'mpeg',
        'video/quicktime': 'mov',
        'video/x-msvideo': 'avi',
        'video/webm': 'webm'
    }
    
    # Check for specific patterns in the description
    if 'ASCII text' in description or 'Unicode text' in description:
        return 'txt'
    elif 'shell script' in description:
        return 'sh'
    elif 'Python script' in description:
        return 'py'
    elif 'JPEG image' in description:
        return 'jpg'
    elif 'PNG image' in description:
        return 'png'
    elif 'GIF image' in description:
        return 'gif'
    elif 'PDF document' in description:
        return 'pdf'
    elif 'Zip archive' in description:
        return 'zip'
    elif 'gzip compressed' in description:
        return 'gz'
    elif 'bzip2 compressed' in description:
        return 'bz2'
    elif 'tar archive' in description:
        return 'tar'
    elif 'ELF' in description and 'executable' in description:
        return 'elf'
    elif 'PE32' in description and 'executable' in description:
        return 'exe'
    elif 'PE32' in description and 'DLL' in description:
        return 'dll'
    elif 'data' in description or 'binary' in description:
        # Generic binary data
        return 'bin'
    
    # Fall back to mime type mapping
    return mime_map.get(mime_type, 'bin')