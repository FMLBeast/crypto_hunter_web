import os
import pytest
import tempfile
from unittest.mock import patch, mock_open
from pathlib import Path

from crypto_hunter_web.utils.file_utils import (
    calculate_file_entropy,
    get_file_magic,
    validate_file_path,
    get_file_mime_type,
    safe_filename,
    get_file_size_formatted,
    get_file_size_human,
    ensure_directory_exists,
    calculate_file_hash,
    detect_file_type
)


class TestFileUtils:
    """Test suite for file utility functions."""

    def test_calculate_file_entropy_normal_file(self):
        """Test entropy calculation for a normal file."""
        # Create a temporary file with known content
        with tempfile.NamedTemporaryFile(delete=False) as temp_file:
            temp_file.write(b"This is a test file with some content for entropy calculation.")
            temp_path = temp_file.name

        try:
            # Calculate entropy
            entropy = calculate_file_entropy(temp_path)
            
            # Entropy should be a float between 0 and 8
            assert isinstance(entropy, float)
            assert 0 <= entropy <= 8
        finally:
            # Clean up
            os.unlink(temp_path)

    def test_calculate_file_entropy_empty_file(self):
        """Test entropy calculation for an empty file."""
        # Create an empty temporary file
        with tempfile.NamedTemporaryFile(delete=False) as temp_file:
            temp_path = temp_file.name

        try:
            # Calculate entropy
            entropy = calculate_file_entropy(temp_path)
            
            # Entropy of an empty file should be 0
            assert entropy == 0.0
        finally:
            # Clean up
            os.unlink(temp_path)

    def test_calculate_file_entropy_nonexistent_file(self):
        """Test entropy calculation for a nonexistent file."""
        entropy = calculate_file_entropy("/nonexistent/file/path")
        assert entropy == 0.0

    def test_get_file_magic_normal_file(self):
        """Test getting magic bytes from a normal file."""
        # Create a temporary file with known content
        with tempfile.NamedTemporaryFile(delete=False) as temp_file:
            temp_file.write(b"Magic bytes test")
            temp_path = temp_file.name

        try:
            # Get magic bytes
            magic = get_file_magic(temp_path)
            
            # Magic bytes should be a hex string
            assert isinstance(magic, str)
            assert len(magic) > 0
            # Verify it's a valid hex string
            int(magic, 16)
        finally:
            # Clean up
            os.unlink(temp_path)

    def test_get_file_magic_nonexistent_file(self):
        """Test getting magic bytes from a nonexistent file."""
        magic = get_file_magic("/nonexistent/file/path")
        assert magic == ""

    def test_validate_file_path_valid(self):
        """Test validating a valid file path."""
        # Create a temporary file
        with tempfile.NamedTemporaryFile(delete=False) as temp_file:
            temp_path = temp_file.name

        try:
            # Validate path
            result = validate_file_path(temp_path)
            
            # Result should be True for a valid file
            assert result is True
        finally:
            # Clean up
            os.unlink(temp_path)

    def test_validate_file_path_nonexistent(self):
        """Test validating a nonexistent file path."""
        result = validate_file_path("/nonexistent/file/path")
        assert result is False

    def test_validate_file_path_directory(self):
        """Test validating a directory path."""
        # Use a temporary directory
        with tempfile.TemporaryDirectory() as temp_dir:
            # Validate path
            result = validate_file_path(temp_dir)
            
            # Result should be False for a directory
            assert result is False

    def test_get_file_mime_type(self):
        """Test getting MIME type for different file extensions."""
        # Test various file extensions
        assert get_file_mime_type("test.txt").startswith("text/")
        assert get_file_mime_type("test.jpg").startswith("image/")
        assert get_file_mime_type("test.png").startswith("image/")
        assert get_file_mime_type("test.pdf").startswith("application/")
        
        # Test unknown extension
        assert get_file_mime_type("test.unknown") == "application/octet-stream"

    def test_safe_filename_normal(self):
        """Test creating a safe filename from a normal filename."""
        result = safe_filename("test_file.txt")
        assert result == "test_file.txt"

    def test_safe_filename_with_unsafe_chars(self):
        """Test creating a safe filename from a filename with unsafe characters."""
        result = safe_filename("test/file:with?unsafe*chars.txt")
        assert result == "test_file_with_unsafe_chars.txt"
        
        # No unsafe characters should remain
        unsafe_chars = "/\\:*?\"<>|"
        for char in unsafe_chars:
            assert char not in result

    def test_safe_filename_very_long(self):
        """Test creating a safe filename from a very long filename."""
        long_name = "a" * 300 + ".txt"
        result = safe_filename(long_name)
        
        # Result should be truncated
        assert len(result) <= 255
        assert result.endswith(".txt")

    def test_get_file_size_formatted(self):
        """Test getting formatted file size."""
        # Create a temporary file with known size
        with tempfile.NamedTemporaryFile(delete=False) as temp_file:
            # Write 1024 bytes
            temp_file.write(b"0" * 1024)
            temp_path = temp_file.name

        try:
            # Get formatted size
            size = get_file_size_formatted(temp_path)
            
            # Size should be "1.0 KB"
            assert size == "1.0 KB"
        finally:
            # Clean up
            os.unlink(temp_path)

    def test_get_file_size_formatted_nonexistent(self):
        """Test getting formatted file size for a nonexistent file."""
        size = get_file_size_formatted("/nonexistent/file/path")
        assert size == "Unknown"

    def test_get_file_size_human(self):
        """Test converting byte sizes to human-readable format."""
        assert get_file_size_human(0) == "0.0 B"
        assert get_file_size_human(1023) == "1023.0 B"
        assert get_file_size_human(1024) == "1.0 KB"
        assert get_file_size_human(1024 * 1024) == "1.0 MB"
        assert get_file_size_human(1024 * 1024 * 1024) == "1.0 GB"
        assert get_file_size_human(1024 * 1024 * 1024 * 1024) == "1.0 TB"
        assert get_file_size_human(1024 * 1024 * 1024 * 1024 * 1024) == "1.0 PB"

    def test_get_file_size_human_invalid(self):
        """Test converting invalid byte sizes to human-readable format."""
        assert get_file_size_human("invalid") == "Unknown"
        assert get_file_size_human(None) == "Unknown"

    def test_ensure_directory_exists_new(self):
        """Test ensuring a new directory exists."""
        # Create a temporary directory
        with tempfile.TemporaryDirectory() as temp_dir:
            # Create a path for a new subdirectory
            new_dir = os.path.join(temp_dir, "new_subdir")
            
            # Ensure directory exists
            result = ensure_directory_exists(new_dir)
            
            # Result should be True
            assert result is True
            
            # Directory should exist
            assert os.path.exists(new_dir)
            assert os.path.isdir(new_dir)

    def test_ensure_directory_exists_existing(self):
        """Test ensuring an existing directory exists."""
        # Create a temporary directory
        with tempfile.TemporaryDirectory() as temp_dir:
            # Ensure directory exists
            result = ensure_directory_exists(temp_dir)
            
            # Result should be True
            assert result is True

    def test_ensure_directory_exists_invalid(self):
        """Test ensuring a directory exists with an invalid path."""
        # Use a path that can't be created (root-owned directory)
        result = ensure_directory_exists("/root/test_dir")
        
        # Result should be False
        assert result is False

    def test_calculate_file_hash_sha256(self):
        """Test calculating SHA256 hash for a file."""
        # Create a temporary file with known content
        with tempfile.NamedTemporaryFile(delete=False) as temp_file:
            temp_file.write(b"Test content for hash calculation")
            temp_path = temp_file.name

        try:
            # Calculate hash
            hash_value = calculate_file_hash(temp_path, 'sha256')
            
            # Hash should be a non-empty string
            assert isinstance(hash_value, str)
            assert len(hash_value) > 0
            
            # Verify it's a valid hex string
            int(hash_value, 16)
        finally:
            # Clean up
            os.unlink(temp_path)

    def test_calculate_file_hash_md5(self):
        """Test calculating MD5 hash for a file."""
        # Create a temporary file with known content
        with tempfile.NamedTemporaryFile(delete=False) as temp_file:
            temp_file.write(b"Test content for hash calculation")
            temp_path = temp_file.name

        try:
            # Calculate hash
            hash_value = calculate_file_hash(temp_path, 'md5')
            
            # Hash should be a non-empty string
            assert isinstance(hash_value, str)
            assert len(hash_value) > 0
            
            # Verify it's a valid hex string
            int(hash_value, 16)
        finally:
            # Clean up
            os.unlink(temp_path)

    def test_calculate_file_hash_invalid_algorithm(self):
        """Test calculating hash with an invalid algorithm."""
        # Create a temporary file
        with tempfile.NamedTemporaryFile(delete=False) as temp_file:
            temp_path = temp_file.name

        try:
            # Calculate hash with invalid algorithm
            hash_value = calculate_file_hash(temp_path, 'invalid_algorithm')
            
            # Should default to SHA256
            assert isinstance(hash_value, str)
            assert len(hash_value) > 0
        finally:
            # Clean up
            os.unlink(temp_path)

    def test_calculate_file_hash_nonexistent_file(self):
        """Test calculating hash for a nonexistent file."""
        hash_value = calculate_file_hash("/nonexistent/file/path")
        assert hash_value == ""

    def test_detect_file_type_text(self):
        """Test detecting file type for a text file."""
        # Create a temporary text file
        with tempfile.NamedTemporaryFile(delete=False, suffix=".txt") as temp_file:
            temp_file.write(b"This is a text file")
            temp_path = temp_file.name

        try:
            # Detect file type
            file_info = detect_file_type(temp_path)
            
            # Check file info
            assert file_info['category'] == 'text'
            assert file_info['extension'] == 'txt'
            assert file_info['mime_type'].startswith('text/')
            assert 'size' in file_info
            assert 'entropy' in file_info
        finally:
            # Clean up
            os.unlink(temp_path)

    def test_detect_file_type_image(self):
        """Test detecting file type for an image file."""
        # Create a temporary image file (just the extension, not real image data)
        with tempfile.NamedTemporaryFile(delete=False, suffix=".jpg") as temp_file:
            temp_file.write(b"Fake image data")
            temp_path = temp_file.name

        try:
            # Detect file type
            file_info = detect_file_type(temp_path)
            
            # Check file info
            assert file_info['category'] == 'image'
            assert file_info['extension'] == 'jpg'
            assert file_info['mime_type'].startswith('image/')
        finally:
            # Clean up
            os.unlink(temp_path)

    def test_detect_file_type_document(self):
        """Test detecting file type for a document file."""
        # Create a temporary document file
        with tempfile.NamedTemporaryFile(delete=False, suffix=".pdf") as temp_file:
            temp_file.write(b"Fake PDF data")
            temp_path = temp_file.name

        try:
            # Detect file type
            file_info = detect_file_type(temp_path)
            
            # Check file info
            assert file_info['category'] == 'document'
            assert file_info['extension'] == 'pdf'
        finally:
            # Clean up
            os.unlink(temp_path)

    def test_detect_file_type_archive(self):
        """Test detecting file type for an archive file."""
        # Create a temporary archive file
        with tempfile.NamedTemporaryFile(delete=False, suffix=".zip") as temp_file:
            temp_file.write(b"Fake ZIP data")
            temp_path = temp_file.name

        try:
            # Detect file type
            file_info = detect_file_type(temp_path)
            
            # Check file info
            assert file_info['category'] == 'archive'
            assert file_info['extension'] == 'zip'
        finally:
            # Clean up
            os.unlink(temp_path)

    def test_detect_file_type_executable(self):
        """Test detecting file type for an executable file."""
        # Create a temporary executable file
        with tempfile.NamedTemporaryFile(delete=False, suffix=".exe") as temp_file:
            temp_file.write(b"Fake EXE data")
            temp_path = temp_file.name

        try:
            # Detect file type
            file_info = detect_file_type(temp_path)
            
            # Check file info
            assert file_info['category'] == 'executable'
            assert file_info['extension'] == 'exe'
        finally:
            # Clean up
            os.unlink(temp_path)

    def test_detect_file_type_crypto(self):
        """Test detecting file type for a crypto file."""
        # Create a temporary crypto file
        with tempfile.NamedTemporaryFile(delete=False, suffix=".key") as temp_file:
            temp_file.write(b"Fake key data")
            temp_path = temp_file.name

        try:
            # Detect file type
            file_info = detect_file_type(temp_path)
            
            # Check file info
            assert file_info['category'] == 'crypto'
            assert file_info['extension'] == 'key'
        finally:
            # Clean up
            os.unlink(temp_path)

    def test_detect_file_type_unknown(self):
        """Test detecting file type for an unknown file type."""
        # Create a temporary file with unknown extension
        with tempfile.NamedTemporaryFile(delete=False, suffix=".unknown") as temp_file:
            temp_file.write(b"Unknown file type data")
            temp_path = temp_file.name

        try:
            # Detect file type
            file_info = detect_file_type(temp_path)
            
            # Check file info
            assert file_info['category'] == 'unknown'
            assert file_info['extension'] == 'unknown'
        finally:
            # Clean up
            os.unlink(temp_path)

    def test_detect_file_type_nonexistent_file(self):
        """Test detecting file type for a nonexistent file."""
        file_info = detect_file_type("/nonexistent/file/path")
        
        # Check file info
        assert file_info['category'] == 'unknown'
        assert file_info['subtype'] == 'unknown'
        assert 'error' in file_info