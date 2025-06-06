"""
File operation utilities
"""

import os
import hashlib
import mimetypes
from pathlib import Path

def calculate_file_entropy(file_path):
    """Calculate entropy of file for randomness analysis"""
    try:
        with open(file_path, 'rb') as f:
            data = f.read()
        
        if not data:
            return 0.0
        
        byte_counts = [0] * 256
        for byte in data:
            byte_counts[byte] += 1
        
        entropy = 0.0
        length = len(data)
        for count in byte_counts:
            if count > 0:
                p = count / length
                entropy -= p * (p.bit_length() - 1) if p > 0 else 0
        
        return entropy
    except Exception:
        return 0.0

def get_file_magic(file_path):
    """Get file magic signature (first 16 bytes as hex)"""
    try:
        with open(file_path, 'rb') as f:
            magic_bytes = f.read(16)
        return magic_bytes.hex()
    except Exception:
        return ""

def validate_file_path(file_path):
    """Validate that file path exists and is accessible"""
    try:
        path = Path(file_path)
        return path.exists() and path.is_file() and os.access(file_path, os.R_OK)
    except Exception:
        return False

def get_file_mime_type(file_path):
    """Get MIME type of file"""
    mime_type, _ = mimetypes.guess_type(file_path)
    return mime_type or 'application/octet-stream'

def safe_filename(filename):
    """Generate safe filename for storage"""
    # Remove or replace dangerous characters
    safe_chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_."
    safe_name = ''.join(c if c in safe_chars else '_' for c in filename)
    
    # Limit length
    if len(safe_name) > 255:
        name, ext = os.path.splitext(safe_name)
        safe_name = name[:250-len(ext)] + ext
    
    return safe_name

def get_file_size_formatted(file_path):
    """Get formatted file size string"""
    try:
        size = os.path.getsize(file_path)
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size < 1024.0:
                return f"{size:.1f} {unit}"
            size /= 1024.0
        return f"{size:.1f} TB"
    except Exception:
        return "Unknown"

def ensure_directory_exists(directory_path):
    """Ensure directory exists, create if necessary"""
    try:
        Path(directory_path).mkdir(parents=True, exist_ok=True)
        return True
    except Exception:
        return False
