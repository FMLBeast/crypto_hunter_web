# crypto_hunter_web/utils/validators.py - COMPLETE VALIDATION UTILITIES

import re
import os
import hashlib
import ipaddress
import email_validator
from typing import Dict, List, Optional, Any, Union, Tuple
from pathlib import Path
from urllib.parse import urlparse
import magic
import json

# Constants
MAX_FILENAME_LENGTH = 255
MAX_PATH_LENGTH = 4096
MAX_EMAIL_LENGTH = 254
MAX_USERNAME_LENGTH = 80
MIN_PASSWORD_LENGTH = 8
MAX_PASSWORD_LENGTH = 128
ALLOWED_FILENAME_CHARS = re.compile(r'^[a-zA-Z0-9._-]+$')
SHA256_PATTERN = re.compile(r'^[a-fA-F0-9]{64}$')
MD5_PATTERN = re.compile(r'^[a-fA-F0-9]{32}$')
UUID_PATTERN = re.compile(r'^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$', re.I)

# File type mappings
SAFE_FILE_EXTENSIONS = {
    'text': {'.txt', '.log', '.md', '.json', '.xml', '.csv', '.yaml', '.yml'},
    'document': {'.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx', '.odt', '.ods', '.odp'},
    'image': {'.jpg', '.jpeg', '.png', '.gif', '.bmp', '.tiff', '.webp', '.svg'},
    'archive': {'.zip', '.rar', '.7z', '.tar', '.gz', '.bz2', '.xz'},
    'code': {'.py', '.js', '.html', '.css', '.cpp', '.c', '.java', '.php', '.rb', '.go'},
    'crypto': {'.key', '.pem', '.crt', '.cer', '.p12', '.pfx', '.asc'},
    'binary': {'.exe', '.dll', '.so', '.bin', '.img', '.iso'},
    'network': {'.pcap', '.pcapng', '.cap'}
}

DANGEROUS_FILE_EXTENSIONS = {
    '.bat', '.cmd', '.com', '.exe', '.pif', '.scr', '.vbs', '.js', '.jar', '.app', '.deb', '.rpm'
}

MIME_TYPE_MAPPINGS = {
    'application/pdf': ['.pdf'],
    'application/zip': ['.zip'],
    'application/x-rar-compressed': ['.rar'],
    'application/x-7z-compressed': ['.7z'],
    'text/plain': ['.txt', '.log'],
    'application/json': ['.json'],
    'image/jpeg': ['.jpg', '.jpeg'],
    'image/png': ['.png'],
    'application/octet-stream': ['.bin', '.exe', '.dll']
}


class ValidationError(Exception):
    """Custom validation error with detailed information"""

    def __init__(self, message: str, field: str = None, code: str = None, details: Dict = None):
        super().__init__(message)
        self.message = message
        self.field = field
        self.code = code
        self.details = details or {}


class FileValidator:
    """Comprehensive file validation"""

    @staticmethod
    def validate_filename(filename: str, strict: bool = False) -> Tuple[bool, Optional[str]]:
        """
        Validate filename for security and compatibility

        Args:
            filename: The filename to validate
            strict: If True, only allow alphanumeric, dots, hyphens, underscores

        Returns:
            Tuple of (is_valid, error_message)
        """
        if not filename:
            return False, "Filename cannot be empty"

        if len(filename) > MAX_FILENAME_LENGTH:
            return False, f"Filename too long (max {MAX_FILENAME_LENGTH} characters)"

        # Check for null bytes
        if '\x00' in filename:
            return False, "Filename contains null bytes"

        # Check for directory traversal
        if '..' in filename or filename.startswith('/') or filename.startswith('\\'):
            return False, "Invalid filename: directory traversal detected"

        # Check for Windows reserved names
        windows_reserved = {
            'CON', 'PRN', 'AUX', 'NUL', 'COM1', 'COM2', 'COM3', 'COM4', 'COM5',
            'COM6', 'COM7', 'COM8', 'COM9', 'LPT1', 'LPT2', 'LPT3', 'LPT4',
            'LPT5', 'LPT6', 'LPT7', 'LPT8', 'LPT9'
        }

        base_name = Path(filename).stem.upper()
        if base_name in windows_reserved:
            return False, f"Reserved filename: {base_name}"

        # Check for invalid characters
        invalid_chars = '<>:"|?*\\'
        if any(char in filename for char in invalid_chars):
            return False, f"Filename contains invalid characters: {invalid_chars}"

        # Strict mode validation
        if strict and not ALLOWED_FILENAME_CHARS.match(filename):
            return False, "Filename contains non-alphanumeric characters"

        # Check file extension
        extension = Path(filename).suffix.lower()
        if extension in DANGEROUS_FILE_EXTENSIONS:
            return False, f"Dangerous file extension: {extension}"

        return True, None

    @staticmethod
    def validate_file_path(file_path: str, base_path: str = None) -> Tuple[bool, Optional[str]]:
        """
        Validate file path for security

        Args:
            file_path: The file path to validate
            base_path: Optional base path to restrict access to

        Returns:
            Tuple of (is_valid, error_message)
        """
        if not file_path:
            return False, "File path cannot be empty"

        if len(file_path) > MAX_PATH_LENGTH:
            return False, f"File path too long (max {MAX_PATH_LENGTH} characters)"

        try:
            # Resolve the path
            resolved_path = Path(file_path).resolve()

            # Check if path exists
            if not resolved_path.exists():
                return False, "File path does not exist"

            # Check if it's a file (not directory)
            if not resolved_path.is_file():
                return False, "Path is not a file"

            # Check base path restriction
            if base_path:
                base_resolved = Path(base_path).resolve()
                if not str(resolved_path).startswith(str(base_resolved)):
                    return False, "File path outside allowed directory"

            return True, None

        except Exception as e:
            return False, f"Invalid file path: {str(e)}"

    @staticmethod
    def validate_file_size(file_size: int, max_size: int = None, min_size: int = 0) -> Tuple[bool, Optional[str]]:
        """
        Validate file size

        Args:
            file_size: File size in bytes
            max_size: Maximum allowed size in bytes
            min_size: Minimum allowed size in bytes

        Returns:
            Tuple of (is_valid, error_message)
        """
        if file_size < 0:
            return False, "File size cannot be negative"

        if file_size < min_size:
            return False, f"File too small (minimum {min_size} bytes)"

        if max_size and file_size > max_size:
            size_mb = max_size / (1024 * 1024)
            return False, f"File too large (maximum {size_mb:.1f} MB)"

        return True, None

    @staticmethod
    def validate_file_type(file_path: str, allowed_extensions: set = None) -> Tuple[bool, Optional[str]]:
        """
        Validate file type using extension and MIME type

        Args:
            file_path: Path to the file
            allowed_extensions: Set of allowed extensions (with dots)

        Returns:
            Tuple of (is_valid, error_message)
        """
        if not os.path.exists(file_path):
            return False, "File does not exist"

        # Get file extension
        file_extension = Path(file_path).suffix.lower()

        # Check against allowed extensions
        if allowed_extensions and file_extension not in allowed_extensions:
            return False, f"File type not allowed: {file_extension}"

        # Check against dangerous extensions
        if file_extension in DANGEROUS_FILE_EXTENSIONS:
            return False, f"Dangerous file type: {file_extension}"

        try:
            # Validate MIME type
            mime_type = magic.from_file(file_path, mime=True)

            # Check MIME type consistency
            if file_extension in MIME_TYPE_MAPPINGS.get(mime_type, []):
                return True, None

            # Allow common mismatches
            text_extensions = {'.txt', '.log', '.md', '.json', '.xml', '.csv'}
            if file_extension in text_extensions and mime_type.startswith('text/'):
                return True, None

            # Warn about MIME type mismatch but don't fail
            return True, f"MIME type mismatch (file: {file_extension}, detected: {mime_type})"

        except Exception as e:
            return False, f"Could not determine file type: {str(e)}"

    @staticmethod
    def validate_file_content(file_path: str, max_scan_size: int = 1024 * 1024) -> Tuple[bool, Optional[str]]:
        """
        Validate file content for malicious patterns

        Args:
            file_path: Path to the file
            max_scan_size: Maximum bytes to scan

        Returns:
            Tuple of (is_valid, error_message)
        """
        if not os.path.exists(file_path):
            return False, "File does not exist"

        try:
            with open(file_path, 'rb') as f:
                content = f.read(max_scan_size)

            # Check for malicious patterns
            malicious_patterns = [
                b'\x4d\x5a\x90\x00',  # PE header
                b'<script',  # Script tags
                b'javascript:',  # JavaScript URLs
                b'data:text/html',  # Data URLs
                b'<?php',  # PHP tags
            ]

            for pattern in malicious_patterns:
                if pattern in content.lower():
                    return False, f"Potentially malicious content detected"

            return True, None

        except Exception as e:
            return False, f"Error reading file: {str(e)}"


class HashValidator:
    """Hash validation utilities"""

    @staticmethod
    def validate_sha256(hash_value: str) -> bool:
        """Validate SHA256 hash format"""
        if not hash_value or not isinstance(hash_value, str):
            return False
        return bool(SHA256_PATTERN.match(hash_value))

    @staticmethod
    def validate_md5(hash_value: str) -> bool:
        """Validate MD5 hash format"""
        if not hash_value or not isinstance(hash_value, str):
            return False
        return bool(MD5_PATTERN.match(hash_value))

    @staticmethod
    def calculate_file_hash(file_path: str, algorithm: str = 'sha256') -> Optional[str]:
        """Calculate file hash"""
        try:
            hash_func = getattr(hashlib, algorithm)()

            with open(file_path, 'rb') as f:
                for chunk in iter(lambda: f.read(65536), b""):
                    hash_func.update(chunk)

            return hash_func.hexdigest()

        except Exception:
            return None

    @staticmethod
    def verify_file_hash(file_path: str, expected_hash: str, algorithm: str = 'sha256') -> bool:
        """Verify file hash matches expected value"""
        calculated_hash = HashValidator.calculate_file_hash(file_path, algorithm)
        return calculated_hash and calculated_hash.lower() == expected_hash.lower()


class UserValidator:
    """User input validation"""

    @staticmethod
    def validate_username(username: str) -> Tuple[bool, Optional[str]]:
        """Validate username format"""
        if not username:
            return False, "Username is required"

        if len(username) < 3:
            return False, "Username must be at least 3 characters"

        if len(username) > MAX_USERNAME_LENGTH:
            return False, f"Username too long (max {MAX_USERNAME_LENGTH} characters)"

        # Only allow alphanumeric, underscore, hyphen
        if not re.match(r'^[a-zA-Z0-9_-]+$', username):
            return False, "Username can only contain letters, numbers, underscore, and hyphen"

        # Must start with letter or number
        if not username[0].isalnum():
            return False, "Username must start with a letter or number"

        # Check for reserved usernames
        reserved = {
            'admin', 'administrator', 'root', 'system', 'api', 'www', 'mail',
            'ftp', 'anonymous', 'guest', 'test', 'demo', 'null', 'undefined'
        }

        if username.lower() in reserved:
            return False, "Username is reserved"

        return True, None

    @staticmethod
    def validate_email(email: str) -> Tuple[bool, Optional[str]]:
        """Validate email address"""
        if not email:
            return False, "Email is required"

        if len(email) > MAX_EMAIL_LENGTH:
            return False, f"Email too long (max {MAX_EMAIL_LENGTH} characters)"

        try:
            # Use email-validator library for comprehensive validation
            valid = email_validator.validate_email(email)
            normalized_email = valid.email

            # Additional checks
            domain = email.split('@')[1]

            # Check for common typos in popular domains
            suspicious_domains = {
                'gmial.com': 'gmail.com',
                'gmai.com': 'gmail.com',
                'yahooo.com': 'yahoo.com',
                'hotmial.com': 'hotmail.com'
            }

            suggestion = suspicious_domains.get(domain.lower())
            if suggestion:
                return False, f"Did you mean {email.split('@')[0]}@{suggestion}?"

            return True, None

        except email_validator.EmailNotValidError as e:
            return False, str(e)

    @staticmethod
    def validate_password_strength(password: str) -> Dict[str, Any]:
        """
        Comprehensive password strength validation

        Returns:
            Dict with 'valid', 'score', 'errors', 'suggestions'
        """
        result = {
            'valid': False,
            'score': 0,
            'errors': [],
            'suggestions': [],
            'strength': 'weak'
        }

        if not password:
            result['errors'].append("Password is required")
            return result

        # Length checks
        if len(password) < MIN_PASSWORD_LENGTH:
            result['errors'].append(f"Password must be at least {MIN_PASSWORD_LENGTH} characters")

        if len(password) > MAX_PASSWORD_LENGTH:
            result['errors'].append(f"Password too long (max {MAX_PASSWORD_LENGTH} characters)")

        # Character requirements
        has_lower = bool(re.search(r'[a-z]', password))
        has_upper = bool(re.search(r'[A-Z]', password))
        has_digit = bool(re.search(r'\d', password))
        has_special = bool(re.search(r'[!@#$%^&*(),.?":{}|<>]', password))

        requirements = [
            (has_lower, "lowercase letter", "Add a lowercase letter"),
            (has_upper, "uppercase letter", "Add an uppercase letter"),
            (has_digit, "number", "Add a number"),
            (has_special, "special character", "Add a special character (!@#$%^&*)")
        ]

        missing_requirements = []
        for has_req, req_name, suggestion in requirements:
            if not has_req:
                missing_requirements.append(req_name)
                result['suggestions'].append(suggestion)

        if missing_requirements:
            result['errors'].append(f"Password must contain: {', '.join(missing_requirements)}")

        # Calculate score
        score = 0
        score += min(len(password) * 2, 20)  # Length (max 20 points)
        score += sum([has_lower, has_upper, has_digit, has_special]) * 10  # Character variety (max 40 points)

        # Bonus points
        if len(password) >= 12:
            score += 10
        if len(set(password)) >= 8:  # Character diversity
            score += 10
        if not re.search(r'(.)\1{2,}', password):  # No repeated characters
            score += 10

        # Penalty for common patterns
        if re.search(r'(123|abc|qwe|password)', password.lower()):
            score -= 20
            result['suggestions'].append("Avoid common patterns like '123' or 'password'")

        if re.search(r'(\d{4})', password):  # Years or simple numbers
            score -= 10
            result['suggestions'].append("Avoid using years or simple number sequences")

        result['score'] = max(0, min(100, score))

        # Determine strength
        if result['score'] >= 80:
            result['strength'] = 'very_strong'
        elif result['score'] >= 60:
            result['strength'] = 'strong'
        elif result['score'] >= 40:
            result['strength'] = 'moderate'
        elif result['score'] >= 20:
            result['strength'] = 'weak'
        else:
            result['strength'] = 'very_weak'

        # Check common passwords
        if UserValidator._is_common_password(password):
            result['errors'].append("Password is too common")
            result['score'] = min(result['score'], 30)
            result['strength'] = 'weak'

        result['valid'] = len(result['errors']) == 0 and result['score'] >= 40

        return result

    @staticmethod
    def _is_common_password(password: str) -> bool:
        """Check if password is in common passwords list"""
        # This would typically check against a database of common passwords
        # For now, just check obvious ones
        common_passwords = {
            'password', '123456', '12345678', 'qwerty', 'abc123',
            'password123', 'admin', 'letmein', 'welcome', 'monkey',
            'dragon', 'master', 'hello', 'freedom', 'whatever'
        }

        return password.lower() in common_passwords


class NetworkValidator:
    """Network-related validation"""

    @staticmethod
    def validate_ip_address(ip: str) -> Tuple[bool, Optional[str]]:
        """Validate IP address (IPv4 or IPv6)"""
        if not ip:
            return False, "IP address is required"

        try:
            ip_obj = ipaddress.ip_address(ip)

            # Check for private/loopback addresses in production
            if ip_obj.is_private:
                return True, "Private IP address"

            if ip_obj.is_loopback:
                return True, "Loopback IP address"

            return True, None

        except ValueError:
            return False, "Invalid IP address format"

    @staticmethod
    def validate_url(url: str, allowed_schemes: set = None) -> Tuple[bool, Optional[str]]:
        """Validate URL format and safety"""
        if not url:
            return False, "URL is required"

        if len(url) > 2048:
            return False, "URL too long"

        try:
            parsed = urlparse(url)

            if not parsed.scheme:
                return False, "URL must include scheme (http/https)"

            if allowed_schemes and parsed.scheme not in allowed_schemes:
                return False, f"Scheme not allowed: {parsed.scheme}"

            if not parsed.netloc:
                return False, "URL must include domain"

            # Check for suspicious patterns
            suspicious_patterns = ['..', '//', 'javascript:', 'data:', 'vbscript:']
            for pattern in suspicious_patterns:
                if pattern in url.lower():
                    return False, f"Suspicious URL pattern: {pattern}"

            return True, None

        except Exception as e:
            return False, f"Invalid URL: {str(e)}"


class JsonValidator:
    """JSON validation utilities"""

    @staticmethod
    def validate_json(json_string: str, max_size: int = 1024 * 1024) -> Tuple[bool, Optional[str], Optional[dict]]:
        """
        Validate JSON string

        Returns:
            Tuple of (is_valid, error_message, parsed_data)
        """
        if not json_string:
            return False, "JSON string is empty", None

        if len(json_string) > max_size:
            return False, f"JSON too large (max {max_size} bytes)", None

        try:
            parsed_data = json.loads(json_string)
            return True, None, parsed_data

        except json.JSONDecodeError as e:
            return False, f"Invalid JSON: {str(e)}", None
        except Exception as e:
            return False, f"JSON parsing error: {str(e)}", None

    @staticmethod
    def validate_json_schema(data: dict, required_fields: List[str] = None,
                             field_types: Dict[str, type] = None) -> Tuple[bool, Optional[str]]:
        """Validate JSON data against schema"""
        if not isinstance(data, dict):
            return False, "Data must be a dictionary"

        # Check required fields
        if required_fields:
            missing_fields = [field for field in required_fields if field not in data]
            if missing_fields:
                return False, f"Missing required fields: {', '.join(missing_fields)}"

        # Check field types
        if field_types:
            for field, expected_type in field_types.items():
                if field in data and not isinstance(data[field], expected_type):
                    return False, f"Field '{field}' must be of type {expected_type.__name__}"

        return True, None


class CryptoValidator:
    """Cryptocurrency-related validation"""

    @staticmethod
    def validate_bitcoin_address(address: str) -> Tuple[bool, Optional[str]]:
        """Validate Bitcoin address format"""
        if not address:
            return False, "Address is required"

        # Bitcoin legacy address (Base58Check)
        if re.match(r'^[13][a-km-zA-HJ-NP-Z1-9]{25,34}$', address):
            return True, "Bitcoin legacy address"

        # Bitcoin SegWit address (Bech32)
        if re.match(r'^bc1[a-z0-9]{39,59}$', address, re.I):
            return True, "Bitcoin SegWit address"

        return False, "Invalid Bitcoin address format"

    @staticmethod
    def validate_ethereum_address(address: str) -> Tuple[bool, Optional[str]]:
        """Validate Ethereum address format"""
        if not address:
            return False, "Address is required"

        # Remove 0x prefix if present
        if address.startswith('0x'):
            address = address[2:]

        # Check length and hex format
        if len(address) == 40 and re.match(r'^[a-fA-F0-9]{40}$', address):
            return True, "Ethereum address"

        return False, "Invalid Ethereum address format"

    @staticmethod
    def validate_private_key(key: str) -> Tuple[bool, Optional[str]]:
        """Validate private key format"""
        if not key:
            return False, "Private key is required"

        # Hex private key (256 bits)
        if len(key) == 64 and re.match(r'^[a-fA-F0-9]{64}$', key):
            return True, "Hex private key"

        # WIF private key
        if re.match(r'^[5KL][1-9A-HJ-NP-Za-km-z]{50,51}$', key):
            return True, "WIF private key"

        return False, "Invalid private key format"


class UUIDValidator:
    """UUID validation utilities"""

    @staticmethod
    def validate_uuid(uuid_string: str, version: int = None) -> Tuple[bool, Optional[str]]:
        """Validate UUID format"""
        if not uuid_string:
            return False, "UUID is required"

        if not UUID_PATTERN.match(uuid_string):
            return False, "Invalid UUID format"

        if version:
            try:
                import uuid
                uuid_obj = uuid.UUID(uuid_string)
                if uuid_obj.version != version:
                    return False, f"Expected UUID version {version}, got {uuid_obj.version}"
            except ValueError:
                return False, "Invalid UUID"

        return True, None


# Convenience functions
def validate_filename(filename: str, strict: bool = False) -> bool:
    """Quick filename validation"""
    valid, _ = FileValidator.validate_filename(filename, strict)
    return valid


def validate_file_size(file_size: int, max_size: int = None) -> bool:
    """Quick file size validation"""
    valid, _ = FileValidator.validate_file_size(file_size, max_size)
    return valid


def validate_sha256(hash_value: str) -> bool:
    """Quick SHA256 validation"""
    return HashValidator.validate_sha256(hash_value)


def validate_email(email: str) -> bool:
    """Quick email validation"""
    valid, _ = UserValidator.validate_email(email)
    return valid


def validate_password_strength(password: str) -> Dict[str, Any]:
    """Quick password strength check"""
    return UserValidator.validate_password_strength(password)


def validate_json_input(json_string: str) -> Tuple[bool, Optional[dict]]:
    """Quick JSON validation"""
    valid, _, data = JsonValidator.validate_json(json_string)
    return valid, data


def sanitize_filename(filename: str) -> str:
    """Sanitize filename for safe storage"""
    if not filename:
        return "unnamed_file"

    # Remove path components
    filename = os.path.basename(filename)

    # Replace unsafe characters
    safe_chars = re.sub(r'[<>:"|?*\\]', '_', filename)

    # Limit length
    if len(safe_chars) > MAX_FILENAME_LENGTH:
        name, ext = os.path.splitext(safe_chars)
        max_name_len = MAX_FILENAME_LENGTH - len(ext)
        safe_chars = name[:max_name_len] + ext

    return safe_chars or "unnamed_file"


# Export all validators
__all__ = [
    'ValidationError',
    'FileValidator',
    'HashValidator',
    'UserValidator',
    'NetworkValidator',
    'JsonValidator',
    'CryptoValidator',
    'UUIDValidator',
    'validate_filename',
    'validate_file_size',
    'validate_sha256',
    'validate_email',
    'validate_password_strength',
    'validate_json_input',
    'sanitize_filename'
]