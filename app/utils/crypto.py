"""
Cryptographic utilities
"""

import hashlib
import hmac
import secrets
from pathlib import Path

def calculate_sha256(file_path):
    """Calculate SHA256 hash of file"""
    sha256_hash = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                sha256_hash.update(chunk)
        return sha256_hash.hexdigest()
    except Exception:
        return None

def calculate_md5(file_path):
    """Calculate MD5 hash of file"""
    md5_hash = hashlib.md5()
    try:
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                md5_hash.update(chunk)
        return md5_hash.hexdigest()
    except Exception:
        return None

def calculate_sha256_data(data):
    """Calculate SHA256 hash of raw data"""
    if isinstance(data, str):
        data = data.encode('utf-8')
    return hashlib.sha256(data).hexdigest()

def calculate_md5_data(data):
    """Calculate MD5 hash of raw data"""
    if isinstance(data, str):
        data = data.encode('utf-8')
    return hashlib.md5(data).hexdigest()

def generate_secure_token(length=32):
    """Generate cryptographically secure random token"""
    return secrets.token_hex(length)

def verify_hmac_signature(data, signature, secret_key):
    """Verify HMAC signature"""
    if isinstance(data, str):
        data = data.encode('utf-8')
    if isinstance(secret_key, str):
        secret_key = secret_key.encode('utf-8')
    
    expected_signature = hmac.new(secret_key, data, hashlib.sha256).hexdigest()
    return hmac.compare_digest(signature, expected_signature)

def create_hmac_signature(data, secret_key):
    """Create HMAC signature"""
    if isinstance(data, str):
        data = data.encode('utf-8')
    if isinstance(secret_key, str):
        secret_key = secret_key.encode('utf-8')
    
    return hmac.new(secret_key, data, hashlib.sha256).hexdigest()
