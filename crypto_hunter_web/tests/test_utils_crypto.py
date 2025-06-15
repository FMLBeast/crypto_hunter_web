import os
import pytest
import tempfile
from unittest.mock import patch, mock_open

from crypto_hunter_web.utils.crypto import (
    calculate_sha256,
    calculate_md5,
    calculate_sha256_data,
    calculate_md5_data,
    generate_secure_token,
    verify_hmac_signature,
    create_hmac_signature
)


class TestCryptoUtils:
    """Test suite for cryptographic utility functions."""

    def test_calculate_sha256(self):
        """Test SHA256 hash calculation for a file."""
        # Create a temporary file with known content
        with tempfile.NamedTemporaryFile(delete=False) as temp_file:
            temp_file.write(b"test data for SHA256")
            temp_path = temp_file.name

        try:
            # Calculate hash
            result = calculate_sha256(temp_path)

            # Expected hash for "test data for SHA256"
            expected = "4acbca04dcb8ae07f067085528aa905a84ed41da9c397ba938f3ba5bccb80f82"

            # Verify result
            assert result == expected
        finally:
            # Clean up
            os.unlink(temp_path)

    def test_calculate_sha256_nonexistent_file(self):
        """Test SHA256 hash calculation for a nonexistent file."""
        result = calculate_sha256("/nonexistent/file/path")
        assert result is None

    def test_calculate_md5(self):
        """Test MD5 hash calculation for a file."""
        # Create a temporary file with known content
        with tempfile.NamedTemporaryFile(delete=False) as temp_file:
            temp_file.write(b"test data for MD5")
            temp_path = temp_file.name

        try:
            # Calculate hash
            result = calculate_md5(temp_path)

            # Expected hash for "test data for MD5"
            expected = "c1bc7745eda2e32a4c5b036f7ad33dc7"

            # Verify result
            assert result == expected
        finally:
            # Clean up
            os.unlink(temp_path)

    def test_calculate_md5_nonexistent_file(self):
        """Test MD5 hash calculation for a nonexistent file."""
        result = calculate_md5("/nonexistent/file/path")
        assert result is None

    def test_calculate_sha256_data_bytes(self):
        """Test SHA256 hash calculation for raw bytes data."""
        data = b"test data for SHA256"
        result = calculate_sha256_data(data)
        expected = "4acbca04dcb8ae07f067085528aa905a84ed41da9c397ba938f3ba5bccb80f82"
        assert result == expected

    def test_calculate_sha256_data_string(self):
        """Test SHA256 hash calculation for string data."""
        data = "test data for SHA256"
        result = calculate_sha256_data(data)
        expected = "4acbca04dcb8ae07f067085528aa905a84ed41da9c397ba938f3ba5bccb80f82"
        assert result == expected

    def test_calculate_md5_data_bytes(self):
        """Test MD5 hash calculation for raw bytes data."""
        data = b"test data for MD5"
        result = calculate_md5_data(data)
        expected = "c1bc7745eda2e32a4c5b036f7ad33dc7"
        assert result == expected

    def test_calculate_md5_data_string(self):
        """Test MD5 hash calculation for string data."""
        data = "test data for MD5"
        result = calculate_md5_data(data)
        expected = "c1bc7745eda2e32a4c5b036f7ad33dc7"
        assert result == expected

    def test_generate_secure_token_default_length(self):
        """Test generating a secure token with default length."""
        token = generate_secure_token()
        # Default length is 32 bytes, which produces a 64-character hex string
        assert len(token) == 64
        # Verify it's a valid hex string
        int(token, 16)  # This will raise ValueError if not a valid hex string

    def test_generate_secure_token_custom_length(self):
        """Test generating a secure token with custom length."""
        token = generate_secure_token(16)
        # 16 bytes produces a 32-character hex string
        assert len(token) == 32
        # Verify it's a valid hex string
        int(token, 16)  # This will raise ValueError if not a valid hex string

    def test_verify_hmac_signature_valid(self):
        """Test verifying a valid HMAC signature."""
        data = "test data"
        secret_key = "secret"
        # Create a valid signature
        signature = create_hmac_signature(data, secret_key)
        # Verify the signature
        result = verify_hmac_signature(data, signature, secret_key)
        assert result is True

    def test_verify_hmac_signature_invalid(self):
        """Test verifying an invalid HMAC signature."""
        data = "test data"
        secret_key = "secret"
        # Create an invalid signature
        signature = "invalid_signature"
        # Verify the signature
        result = verify_hmac_signature(data, signature, secret_key)
        assert result is False

    def test_create_hmac_signature_string_inputs(self):
        """Test creating an HMAC signature with string inputs."""
        data = "test data"
        secret_key = "secret"
        signature = create_hmac_signature(data, secret_key)
        # Verify it's a valid hex string
        assert len(signature) == 64  # SHA256 produces a 32-byte (64-char hex) digest
        int(signature, 16)  # This will raise ValueError if not a valid hex string

    def test_create_hmac_signature_bytes_inputs(self):
        """Test creating an HMAC signature with bytes inputs."""
        data = b"test data"
        secret_key = b"secret"
        signature = create_hmac_signature(data, secret_key)
        # Verify it's a valid hex string
        assert len(signature) == 64  # SHA256 produces a 32-byte (64-char hex) digest
        int(signature, 16)  # This will raise ValueError if not a valid hex string

    def test_create_and_verify_hmac_signature(self):
        """Test creating and verifying an HMAC signature."""
        data = "test data"
        secret_key = "secret"
        # Create a signature
        signature = create_hmac_signature(data, secret_key)
        # Verify the signature
        result = verify_hmac_signature(data, signature, secret_key)
        assert result is True

    def test_hmac_signature_different_data(self):
        """Test that signatures differ for different data."""
        secret_key = "secret"
        signature1 = create_hmac_signature("data1", secret_key)
        signature2 = create_hmac_signature("data2", secret_key)
        assert signature1 != signature2

    def test_hmac_signature_different_keys(self):
        """Test that signatures differ for different keys."""
        data = "test data"
        signature1 = create_hmac_signature(data, "key1")
        signature2 = create_hmac_signature(data, "key2")
        assert signature1 != signature2
