"""
Complete validators for Crypto Hunter - BETA VERSION
"""
import re
import os
from typing import Any, Dict, List, Optional


def validate_sha256(sha: str) -> bool:
    """Validate SHA256 hash format"""
    if not sha or len(sha) != 64:
        return False
    try:
        int(sha, 16)
        return True
    except ValueError:
        return False


def validate_extraction_method(method: str) -> bool:
    """Validate extraction method"""
    valid_methods = ['zsteg', 'steghide', 'strings', 'binwalk', 'exiftool', 'hexdump', 'xxd']
    return method in valid_methods


def validate_filename(filename: str) -> bool:
    """Validate filename"""
    if not filename or len(filename) > 255:
        return False

    # Check for forbidden characters
    forbidden_chars = ['/', '\\', ':', '*', '?', '"', '<', '>', '|']
    if any(char in filename for char in forbidden_chars):
        return False

    # Check for reserved names (Windows)
    reserved_names = ['CON', 'PRN', 'AUX', 'NUL', 'COM1', 'COM2', 'COM3', 'COM4',
                      'COM5', 'COM6', 'COM7', 'COM8', 'COM9', 'LPT1', 'LPT2',
                      'LPT3', 'LPT4', 'LPT5', 'LPT6', 'LPT7', 'LPT8', 'LPT9']

    name_without_ext = filename.split('.')[0].upper()
    return name_without_ext not in reserved_names


def validate_email(email: str) -> bool:
    """Basic email validation"""
    if not email or '@' not in email:
        return False

    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None


def validate_json_input(data: Any) -> bool:
    """Basic JSON validation"""
    return isinstance(data, dict)


def validate_file_size(file_size: int, max_size: int = 1073741824) -> bool:
    """Validate file size (default 1GB max)"""
    return 0 < file_size <= max_size


def validate_file_extension(filename: str, allowed_extensions: List[str] = None) -> bool:
    """Validate file extension"""
    if not allowed_extensions:
        # Default allowed extensions
        allowed_extensions = [
            'txt', 'log', 'md', 'json', 'xml', 'csv', 'yaml', 'yml',
            'pdf', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx',
            'jpg', 'jpeg', 'png', 'gif', 'bmp', 'tiff', 'webp',
            'zip', 'rar', '7z', 'tar', 'gz', 'bz2', 'xz',
            'exe', 'dll', 'so', 'bin', 'img', 'iso',
            'py', 'js', 'html', 'css', 'cpp', 'c', 'java',
            'key', 'pem', 'crt', 'cer', 'p12', 'pfx',
            'pcap', 'pcapng', 'cap'
        ]

    if '.' not in filename:
        return False

    extension = filename.rsplit('.', 1)[1].lower()
    return extension in allowed_extensions


def validate_username(username: str) -> bool:
    """Validate username"""
    if not username or len(username) < 3 or len(username) > 50:
        return False

    # Only allow alphanumeric and underscore
    pattern = r'^[a-zA-Z0-9_]+$'
    return re.match(pattern, username) is not None


def validate_password(password: str) -> bool:
    """Validate password strength"""
    if not password or len(password) < 8:
        return False

    # Check for at least one uppercase, lowercase, digit
    has_upper = any(c.isupper() for c in password)
    has_lower = any(c.islower() for c in password)
    has_digit = any(c.isdigit() for c in password)

    return has_upper and has_lower and has_digit


def validate_priority(priority: int) -> bool:
    """Validate priority level (1-10)"""
    return isinstance(priority, int) and 1 <= priority <= 10


def validate_confidence(confidence: float) -> bool:
    """Validate confidence score (0.0-1.0)"""
    return isinstance(confidence, (int, float)) and 0.0 <= confidence <= 1.0


def validate_ip_address(ip: str) -> bool:
    """Basic IP address validation"""
    if not ip:
        return False

    parts = ip.split('.')
    if len(parts) != 4:
        return False

    try:
        return all(0 <= int(part) <= 255 for part in parts)
    except ValueError:
        return False


def validate_hex_string(hex_str: str) -> bool:
    """Validate hexadecimal string"""
    if not hex_str:
        return False

    try:
        int(hex_str, 16)
        return True
    except ValueError:
        return False


def sanitize_filename(filename: str) -> str:
    """Sanitize filename for safe storage"""
    if not filename:
        return 'untitled'

    # Remove or replace dangerous characters
    sanitized = re.sub(r'[<>:"/\\|?*]', '_', filename)

    # Limit length
    if len(sanitized) > 255:
        name, ext = os.path.splitext(sanitized)
        sanitized = name[:250] + ext

    return sanitized