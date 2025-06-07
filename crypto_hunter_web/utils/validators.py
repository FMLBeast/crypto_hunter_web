"""
Input validation utilities
"""

import re
import os
from pathlib import Path
from typing import Union, List

def validate_sha256(sha_hash: str) -> bool:
    """Validate SHA256 hash format"""
    if not isinstance(sha_hash, str):
        return False
    return bool(re.match(r'^[a-fA-F0-9]{64}$', sha_hash))

def validate_md5(md5_hash: str) -> bool:
    """Validate MD5 hash format"""
    if not isinstance(md5_hash, str):
        return False
    return bool(re.match(r'^[a-fA-F0-9]{32}$', md5_hash))

def validate_filename(filename: str) -> bool:
    """Validate filename is safe and reasonable"""
    if not isinstance(filename, str) or not filename:
        return False

    # Check length
    if len(filename) > 255:
        return False

    # Check for dangerous characters
    dangerous_chars = ['..', '/', '\\', ':', '*', '?', '"', '<', '>', '|']
    for char in dangerous_chars:
        if char in filename:
            return False

    # Check for reserved names (Windows)
    reserved_names = [
        'CON', 'PRN', 'AUX', 'NUL', 'COM1', 'COM2', 'COM3', 'COM4', 'COM5',
        'COM6', 'COM7', 'COM8', 'COM9', 'LPT1', 'LPT2', 'LPT3', 'LPT4',
        'LPT5', 'LPT6', 'LPT7', 'LPT8', 'LPT9'
    ]

    name_without_ext = filename.split('.')[0].upper()
    if name_without_ext in reserved_names:
        return False

    return True

def validate_extraction_method(method: str) -> bool:
    """Validate extraction method name"""
    valid_methods = [
        'zsteg', 'zsteg_bitplane_1', 'zsteg_bitplane_2', 'zsteg_bitplane_3', 'zsteg_bitplane_4',
        'steghide', 'binwalk', 'strings', 'hexdump', 'exiftool', 'foremost', 'dd', 'manual'
    ]
    return method in valid_methods

def validate_file_path(file_path: str) -> bool:
    """Validate file path is safe and accessible"""
    if not isinstance(file_path, str) or not file_path:
        return False

    try:
        path = Path(file_path)

        # Check if path exists and is a file
        if not path.exists() or not path.is_file():
            return False

        # Check if readable
        if not os.access(file_path, os.R_OK):
            return False

        # Check for path traversal attempts
        if '..' in file_path or file_path.startswith('/'):
            return False

        return True
    except Exception:
        return False

def validate_file_size(file_path: str, max_size: int = 500 * 1024 * 1024) -> bool:
    """Validate file size is within limits"""
    try:
        size = os.path.getsize(file_path)
        return size <= max_size
    except Exception:
        return False

def validate_confidence_level(confidence: Union[int, str]) -> bool:
    """Validate confidence level is between 1-10"""
    try:
        conf_int = int(confidence)
        return 1 <= conf_int <= 10
    except (ValueError, TypeError):
        return False

def validate_user_role(role: str) -> bool:
    """Validate user role"""
    valid_roles = ['analyst', 'expert', 'admin']
    return role in valid_roles

def validate_region_coordinates(x_start: int, y_start: int, x_end: int, y_end: int) -> bool:
    """Validate region coordinates are logical"""
    try:
        return (x_start >= 0 and y_start >= 0 and
                x_end > x_start and y_end > y_start and
                x_end - x_start <= 10000 and y_end - y_start <= 10000)
    except (TypeError, ValueError):
        return False

def validate_offset_range(start_offset: int, end_offset: int, max_file_size: int = None) -> bool:
    """Validate byte offset range"""
    try:
        if start_offset < 0 or end_offset < 0:
            return False

        if end_offset <= start_offset:
            return False

        if max_file_size and end_offset > max_file_size:
            return False

        # Reasonable limit on region size
        if end_offset - start_offset > 100 * 1024 * 1024:  # 100MB
            return False

        return True
    except (TypeError, ValueError):
        return False

def sanitize_input(input_str: str, max_length: int = 1000) -> str:
    """Sanitize user input string"""
    if not isinstance(input_str, str):
        return ""

    # Remove null bytes and control characters
    sanitized = ''.join(char for char in input_str if ord(char) >= 32 or char in '\t\n\r')

    # Limit length
    if len(sanitized) > max_length:
        sanitized = sanitized[:max_length]

    return sanitized.strip()

def validate_color_hex(color: str) -> bool:
    """Validate hex color format"""
    if not isinstance(color, str):
        return False
    return bool(re.match(r'^#[0-9a-fA-F]{6}$', color))