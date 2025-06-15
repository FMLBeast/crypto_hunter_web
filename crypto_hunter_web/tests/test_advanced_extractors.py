import pytest
import os
import numpy as np
from unittest.mock import patch, MagicMock, mock_open
from PIL import Image

from crypto_hunter_web.services.extractors.advanced_extractors import (
    XORBitplanesExtractor, CombinedBitplanesExtractor, DCTExtractor
)


@pytest.fixture
def mock_image_array():
    """Create a mock image array for testing."""
    # Create a 10x10 RGB image array with random values
    return np.random.randint(0, 256, (10, 10, 3), dtype=np.uint8)


class TestXORBitplanesExtractor:
    """Test suite for the XORBitplanesExtractor class."""

    def test_get_tool_name(self):
        """Test _get_tool_name method."""
        extractor = XORBitplanesExtractor('xor_bitplanes')
        assert extractor._get_tool_name() == 'xor_bitplanes'

    @patch('crypto_hunter_web.services.extractors.advanced_extractors.os.path.exists')
    def test_extract_file_not_found(self, mock_exists):
        """Test extract method when file is not found."""
        # Setup mocks
        mock_exists.return_value = False

        # Create extractor
        extractor = XORBitplanesExtractor('xor_bitplanes')

        # Call method
        result = extractor.extract('nonexistent_file.png')

        # Assertions
        assert result['success'] is False
        assert result['error'] == 'File not found'
        assert result['data'] == b''
        mock_exists.assert_called_once_with('nonexistent_file.png')

    @patch('crypto_hunter_web.services.extractors.advanced_extractors.os.path.exists')
    @patch('crypto_hunter_web.services.extractors.advanced_extractors.Image.open')
    @patch('crypto_hunter_web.services.extractors.advanced_extractors.np.array')
    @patch('crypto_hunter_web.services.extractors.advanced_extractors.XORBitplanesExtractor._extract_xor_bitplanes')
    def test_extract_success(self, mock_extract_xor, mock_array, mock_open, mock_exists):
        """Test extract method with successful extraction."""
        # Setup mocks
        mock_exists.return_value = True
        mock_img = MagicMock()
        mock_open.return_value = mock_img
        mock_img_array = MagicMock()
        mock_array.return_value = mock_img_array
        mock_extract_xor.return_value = b'extracted data'

        # Create extractor
        extractor = XORBitplanesExtractor('xor_bitplanes')

        # Call method
        result = extractor.extract('test_file.png', {'bitplane1': 1, 'bitplane2': 2, 'channel': 'r'})

        # Assertions
        assert result['success'] is True
        assert result['data'] == b'extracted data'
        assert 'XOR bitplanes extraction successful' in result['details']
        assert 'xor_bitplanes test_file.png' in result['command_line']
        mock_exists.assert_called_once_with('test_file.png')
        mock_open.assert_called_once_with('test_file.png')
        mock_array.assert_called_once_with(mock_img)
        mock_extract_xor.assert_called_once_with(mock_img_array, 1, 2, 'r')

    @patch('crypto_hunter_web.services.extractors.advanced_extractors.os.path.exists')
    @patch('crypto_hunter_web.services.extractors.advanced_extractors.Image.open')
    def test_extract_exception(self, mock_open, mock_exists):
        """Test extract method when an exception occurs."""
        # Setup mocks
        mock_exists.return_value = True
        mock_open.side_effect = Exception("Test error")

        # Create extractor
        extractor = XORBitplanesExtractor('xor_bitplanes')

        # Call method
        result = extractor.extract('test_file.png')

        # Assertions
        assert result['success'] is False
        assert result['error'] == 'Test error'
        assert result['data'] == b''
        mock_exists.assert_called_once_with('test_file.png')
        mock_open.assert_called_once_with('test_file.png')

    def test_extract_xor_bitplanes(self, mock_image_array):
        """Test _extract_xor_bitplanes method."""
        # Create extractor
        extractor = XORBitplanesExtractor('xor_bitplanes')

        # Call method
        result = extractor._extract_xor_bitplanes(mock_image_array, 1, 2, 'r')

        # Assertions
        assert isinstance(result, bytes)
        assert len(result) > 0


class TestCombinedBitplanesExtractor:
    """Test suite for the CombinedBitplanesExtractor class."""

    def test_get_tool_name(self):
        """Test _get_tool_name method."""
        extractor = CombinedBitplanesExtractor('combined_bitplanes')
        assert extractor._get_tool_name() == 'combined_bitplanes'

    @patch('crypto_hunter_web.services.extractors.advanced_extractors.os.path.exists')
    def test_extract_file_not_found(self, mock_exists):
        """Test extract method when file is not found."""
        # Setup mocks
        mock_exists.return_value = False

        # Create extractor
        extractor = CombinedBitplanesExtractor('combined_bitplanes')

        # Call method
        result = extractor.extract('nonexistent_file.png')

        # Assertions
        assert result['success'] is False
        assert result['error'] == 'File not found'
        assert result['data'] == b''
        mock_exists.assert_called_once_with('nonexistent_file.png')

    @patch('crypto_hunter_web.services.extractors.advanced_extractors.os.path.exists')
    @patch('crypto_hunter_web.services.extractors.advanced_extractors.Image.open')
    @patch('crypto_hunter_web.services.extractors.advanced_extractors.np.array')
    @patch('crypto_hunter_web.services.extractors.advanced_extractors.CombinedBitplanesExtractor._extract_combined_bitplanes')
    def test_extract_success(self, mock_extract_combined, mock_array, mock_open, mock_exists):
        """Test extract method with successful extraction."""
        # Setup mocks
        mock_exists.return_value = True
        mock_img = MagicMock()
        mock_open.return_value = mock_img
        mock_img_array = MagicMock()
        mock_array.return_value = mock_img_array
        mock_extract_combined.return_value = b'extracted data'

        # Create extractor
        extractor = CombinedBitplanesExtractor('combined_bitplanes')

        # Call method
        result = extractor.extract('test_file.png', {'bitplanes': [1, 2, 3], 'channel': 'r', 'combine_method': 'concat'})

        # Assertions
        assert result['success'] is True
        assert result['data'] == b'extracted data'
        assert 'Combined bitplanes extraction successful' in result['details']
        assert 'combined_bitplanes test_file.png' in result['command_line']
        mock_exists.assert_called_once_with('test_file.png')
        mock_open.assert_called_once_with('test_file.png')
        mock_array.assert_called_once_with(mock_img)
        mock_extract_combined.assert_called_once_with(mock_img_array, [1, 2, 3], 'r', 'concat')

    @patch('crypto_hunter_web.services.extractors.advanced_extractors.os.path.exists')
    @patch('crypto_hunter_web.services.extractors.advanced_extractors.Image.open')
    def test_extract_exception(self, mock_open, mock_exists):
        """Test extract method when an exception occurs."""
        # Setup mocks
        mock_exists.return_value = True
        mock_open.side_effect = Exception("Test error")

        # Create extractor
        extractor = CombinedBitplanesExtractor('combined_bitplanes')

        # Call method
        result = extractor.extract('test_file.png')

        # Assertions
        assert result['success'] is False
        assert result['error'] == 'Test error'
        assert result['data'] == b''
        mock_exists.assert_called_once_with('test_file.png')
        mock_open.assert_called_once_with('test_file.png')

    def test_extract_combined_bitplanes_concat(self, mock_image_array):
        """Test _extract_combined_bitplanes method with concat method."""
        # Create extractor
        extractor = CombinedBitplanesExtractor('combined_bitplanes')

        # Call method
        result = extractor._extract_combined_bitplanes(mock_image_array, [1, 2, 3], 'r', 'concat')

        # Assertions
        assert isinstance(result, bytes)
        assert len(result) > 0

    def test_extract_combined_bitplanes_interleave(self, mock_image_array):
        """Test _extract_combined_bitplanes method with interleave method."""
        # Create extractor
        extractor = CombinedBitplanesExtractor('combined_bitplanes')

        # Call method
        result = extractor._extract_combined_bitplanes(mock_image_array, [1, 2, 3], 'r', 'interleave')

        # Assertions
        assert isinstance(result, bytes)
        assert len(result) > 0

    def test_extract_combined_bitplanes_or(self, mock_image_array):
        """Test _extract_combined_bitplanes method with OR method."""
        # Create extractor
        extractor = CombinedBitplanesExtractor('combined_bitplanes')

        # Call method
        result = extractor._extract_combined_bitplanes(mock_image_array, [1, 2, 3], 'r', 'or')

        # Assertions
        assert isinstance(result, bytes)
        assert len(result) > 0


class TestDCTExtractor:
    """Test suite for the DCTExtractor class."""

    def test_get_tool_name(self):
        """Test _get_tool_name method."""
        extractor = DCTExtractor('dct_extract')
        assert extractor._get_tool_name() == 'dct_extract'

    @patch('crypto_hunter_web.services.extractors.advanced_extractors.os.path.exists')
    def test_extract_file_not_found(self, mock_exists):
        """Test extract method when file is not found."""
        # Setup mocks
        mock_exists.return_value = False

        # Create extractor
        extractor = DCTExtractor('dct_extract')

        # Call method
        result = extractor.extract('nonexistent_file.png')

        # Assertions
        assert result['success'] is False
        assert result['error'] == 'File not found'
        assert result['data'] == b''
        mock_exists.assert_called_once_with('nonexistent_file.png')

    @patch('crypto_hunter_web.services.extractors.advanced_extractors.os.path.exists')
    @patch('crypto_hunter_web.services.extractors.advanced_extractors.CV2_AVAILABLE', False)
    def test_extract_cv2_not_available(self, mock_exists):
        """Test extract method when cv2 is not available."""
        # Setup mocks
        mock_exists.return_value = True

        # Create extractor
        extractor = DCTExtractor('dct_extract')

        # Call method
        result = extractor.extract('test_file.png')

        # Assertions
        assert result['success'] is False
        assert result['error'] == 'OpenCV (cv2) is not available'
        assert result['data'] == b''
        mock_exists.assert_called_once_with('test_file.png')

    @patch('crypto_hunter_web.services.extractors.advanced_extractors.os.path.exists')
    @patch('crypto_hunter_web.services.extractors.advanced_extractors.CV2_AVAILABLE', True)
    @patch('crypto_hunter_web.services.extractors.advanced_extractors.cv2')
    @patch('crypto_hunter_web.services.extractors.advanced_extractors.DCTExtractor._extract_dct')
    def test_extract_success(self, mock_extract_dct, mock_cv2, mock_exists):
        """Test extract method with successful extraction."""
        # Setup mocks
        mock_exists.return_value = True
        mock_img = MagicMock()
        mock_cv2.imread.return_value = mock_img
        mock_cv2.IMREAD_GRAYSCALE = 0  # Set a dummy value for the constant
        mock_extract_dct.return_value = b'extracted data'

        # Create extractor
        extractor = DCTExtractor('dct_extract')

        # Call method
        result = extractor.extract('test_file.png', {'block_size': 8, 'coefficient': 'lsb'})

        # Assertions
        assert result['success'] is True
        assert result['data'] == b'extracted data'
        assert 'DCT extraction successful' in result['details']
        assert 'dct_extract test_file.png' in result['command_line']
        mock_exists.assert_called_once_with('test_file.png')
        mock_cv2.imread.assert_called_once_with('test_file.png', mock_cv2.IMREAD_GRAYSCALE)
        mock_extract_dct.assert_called_once_with(mock_img, 8, 'lsb')

    @patch('crypto_hunter_web.services.extractors.advanced_extractors.os.path.exists')
    @patch('crypto_hunter_web.services.extractors.advanced_extractors.CV2_AVAILABLE', True)
    @patch('crypto_hunter_web.services.extractors.advanced_extractors.cv2')
    def test_extract_image_load_failure(self, mock_cv2, mock_exists):
        """Test extract method when image loading fails."""
        # Setup mocks
        mock_exists.return_value = True
        mock_cv2.imread.return_value = None
        mock_cv2.IMREAD_GRAYSCALE = 0  # Set a dummy value for the constant

        # Create extractor
        extractor = DCTExtractor('dct_extract')

        # Call method
        result = extractor.extract('test_file.png')

        # Assertions
        assert result['success'] is False
        assert result['error'] == 'Failed to load image'
        assert result['data'] == b''
        mock_exists.assert_called_once_with('test_file.png')
        mock_cv2.imread.assert_called_once_with('test_file.png', mock_cv2.IMREAD_GRAYSCALE)

    @patch('crypto_hunter_web.services.extractors.advanced_extractors.os.path.exists')
    @patch('crypto_hunter_web.services.extractors.advanced_extractors.CV2_AVAILABLE', True)
    @patch('crypto_hunter_web.services.extractors.advanced_extractors.cv2')
    def test_extract_exception(self, mock_cv2, mock_exists):
        """Test extract method when an exception occurs."""
        # Setup mocks
        mock_exists.return_value = True
        mock_cv2.imread.side_effect = Exception("Test error")
        mock_cv2.IMREAD_GRAYSCALE = 0  # Set a dummy value for the constant

        # Create extractor
        extractor = DCTExtractor('dct_extract')

        # Call method
        result = extractor.extract('test_file.png')

        # Assertions
        assert result['success'] is False
        assert result['error'] == 'Test error'
        assert result['data'] == b''
        mock_exists.assert_called_once_with('test_file.png')
        mock_cv2.imread.assert_called_once_with('test_file.png', mock_cv2.IMREAD_GRAYSCALE)
