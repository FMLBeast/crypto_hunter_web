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

def get_file_size_human(size_bytes):
    """
    Convert size in bytes to human-readable string

    Args:
        size_bytes: Size in bytes

    Returns:
        Human-readable size string (e.g., "1.5 MB")
    """
    try:
        size = float(size_bytes)
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if size < 1024.0:
                return f"{size:.1f} {unit}"
            size /= 1024.0
        return f"{size:.1f} PB"
    except Exception:
        return "Unknown"

def ensure_directory_exists(directory_path):
    """Ensure directory exists, create if necessary"""
    try:
        Path(directory_path).mkdir(parents=True, exist_ok=True)
        return True
    except Exception:
        return False


def calculate_file_hash(file_path, hash_algorithm='sha256', block_size=65536):
    """
    Calculate hash for a file using specified algorithm

    Args:
        file_path: Path to the file
        hash_algorithm: Hash algorithm to use (default: sha256)
        block_size: Size of blocks to read (default: 64KB)

    Returns:
        Hexadecimal hash string or empty string on error
    """
    try:
        if hash_algorithm == 'sha256':
            hasher = hashlib.sha256()
        elif hash_algorithm == 'md5':
            hasher = hashlib.md5()
        elif hash_algorithm == 'sha1':
            hasher = hashlib.sha1()
        else:
            hasher = hashlib.sha256()  # Default to SHA-256

        with open(file_path, 'rb') as f:
            buf = f.read(block_size)
            while len(buf) > 0:
                hasher.update(buf)
                buf = f.read(block_size)

        return hasher.hexdigest()
    except Exception as e:
        print(f"Error calculating file hash: {e}")
        return ""


def detect_file_type(file_path):
    """
    Detect file type based on content and extension

    Args:
        file_path: Path to the file

    Returns:
        Dictionary with file type information
    """
    try:
        # Get basic file information
        file_size = os.path.getsize(file_path)
        file_ext = os.path.splitext(file_path)[1].lower()
        mime_type = get_file_mime_type(file_path)

        # Read magic bytes for better identification
        magic_bytes = get_file_magic(file_path)

        # Determine file category
        category = "unknown"
        subtype = "unknown"

        # Image files
        if mime_type.startswith('image/'):
            category = "image"
            subtype = mime_type.split('/')[1]
        # Text files
        elif mime_type.startswith('text/'):
            category = "text"
            subtype = mime_type.split('/')[1]
        # Document files
        elif any(ext in file_ext for ext in ['.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx']):
            category = "document"
            subtype = file_ext.lstrip('.')
        # Archive files
        elif any(ext in file_ext for ext in ['.zip', '.rar', '.tar', '.gz', '.7z']):
            category = "archive"
            subtype = file_ext.lstrip('.')
        # Executable files
        elif file_ext in ['.exe', '.dll', '.so', '.bin']:
            category = "executable"
            subtype = file_ext.lstrip('.')
        # Crypto-related files
        elif file_ext in ['.key', '.pem', '.crt', '.cer', '.p12', '.pfx']:
            category = "crypto"
            subtype = file_ext.lstrip('.')

        # Calculate entropy for randomness detection
        entropy = calculate_file_entropy(file_path)
        is_encrypted = entropy > 7.8  # High entropy often indicates encryption

        return {
            'category': category,
            'subtype': subtype,
            'mime_type': mime_type,
            'extension': file_ext.lstrip('.'),
            'size': file_size,
            'size_formatted': get_file_size_formatted(file_path),
            'magic_bytes': magic_bytes[:16],
            'entropy': entropy,
            'possibly_encrypted': is_encrypted
        }
    except Exception as e:
        print(f"Error detecting file type: {e}")
        return {
            'category': 'unknown',
            'subtype': 'unknown',
            'error': str(e)
        }
