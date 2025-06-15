import pytest
import os
import tempfile
import subprocess
from unittest.mock import patch, MagicMock, call, mock_open

from crypto_hunter_web.services.extractors import (
    BaseExtractor, ZStegExtractor, SteghideExtractor, BinwalkExtractor, CustomExtractor,
    get_extractor, list_extractors, get_recommended_extractors
)

# Create concrete implementations for testing
class TestableBaseExtractor(BaseExtractor):
    """Concrete implementation of BaseExtractor for testing"""

    def _get_tool_name(self):
        return 'base'

    def extract(self, file_path, parameters=None):
        """Implement abstract method"""
        return {
            'success': True,
            'data': b'test data',
            'error': '',
            'details': 'Test extraction',
            'command_line': f'test {file_path}',
            'confidence': 0.5
        }

# Create a testable version of ZStegExtractor that includes _is_tool_available
class TestableZStegExtractor(ZStegExtractor):
    """Testable version of ZStegExtractor with _is_tool_available method"""

    def _is_tool_available(self):
        """Check if zsteg is available"""
        return self.is_available()


class TestBaseExtractor:
    """Test suite for the BaseExtractor class."""

    def test_init(self):
        """Test initialization of BaseExtractor."""
        extractor = TestableBaseExtractor('test_method')
        assert extractor.method_name == 'test_method'
        assert extractor.tool_name == 'base'  # Default value

    def test_get_tool_name(self):
        """Test _get_tool_name method."""
        extractor = TestableBaseExtractor('test_method')
        assert extractor._get_tool_name() == 'base'

    @patch('crypto_hunter_web.services.extractors.base.subprocess.run')
    def test_is_available_success(self, mock_run):
        """Test is_available method when tool is available."""
        # Setup mock
        mock_run.return_value = MagicMock(returncode=0)

        # Create extractor with mock
        extractor = TestableBaseExtractor('test_method')

        # Call method
        result = extractor.is_available()

        # Assertions
        assert result is True
        mock_run.assert_called_once()

    @patch('crypto_hunter_web.services.extractors.base.subprocess.run')
    def test_is_available_failure(self, mock_run):
        """Test is_available method when tool is not available."""
        # Setup mock
        mock_run.return_value = MagicMock(returncode=1)

        # Create extractor with mock
        extractor = TestableBaseExtractor('test_method')

        # Call method
        result = extractor.is_available()

        # Assertions
        assert result is False
        mock_run.assert_called_once()

    @patch('crypto_hunter_web.services.extractors.base.subprocess.run')
    def test_is_available_exception(self, mock_run):
        """Test is_available method when exception occurs."""
        # Setup mock
        mock_run.side_effect = Exception("Command not found")

        # Create extractor with mock
        extractor = TestableBaseExtractor('test_method')

        # Call method
        result = extractor.is_available()

        # Assertions
        assert result is False
        mock_run.assert_called_once()

    @patch('crypto_hunter_web.services.extractors.base.subprocess.run')
    def test_run_command_success(self, mock_run):
        """Test _run_command method with successful command."""
        # Setup mock
        mock_process = MagicMock()
        mock_process.returncode = 0
        mock_process.stdout = b'test output'
        mock_process.stderr = b''
        mock_run.return_value = mock_process

        # Create extractor with mock
        extractor = TestableBaseExtractor('test_method')

        # Call method
        result = extractor._run_command(['test', 'command'])

        # Assertions
        assert result['returncode'] == 0
        assert result['stdout'] == b'test output'
        assert result['stderr'] == b''
        assert result['command_line'] == 'test command'
        mock_run.assert_called_once()

    @patch('crypto_hunter_web.services.extractors.base.subprocess.run')
    def test_run_command_failure(self, mock_run):
        """Test _run_command method with failed command."""
        # Setup mock
        mock_process = MagicMock()
        mock_process.returncode = 1
        mock_process.stdout = b''
        mock_process.stderr = b'test error'
        mock_run.return_value = mock_process

        # Create extractor with mock
        extractor = TestableBaseExtractor('test_method')

        # Call method
        result = extractor._run_command(['test', 'command'])

        # Assertions
        assert result['returncode'] == 1
        assert result['stdout'] == b''
        assert result['stderr'] == b'test error'
        assert result['command_line'] == 'test command'
        mock_run.assert_called_once()

    @patch('crypto_hunter_web.services.extractors.base.subprocess.run')
    def test_run_command_timeout(self, mock_run):
        """Test _run_command method with timeout."""
        # Setup mock
        mock_run.side_effect = subprocess.TimeoutExpired(cmd=['test', 'command'], timeout=10)

        # Create extractor with mock
        extractor = TestableBaseExtractor('test_method')

        # Call method
        result = extractor._run_command(['test', 'command'], timeout=10)

        # Assertions
        assert result['returncode'] == -1
        assert result['stdout'] == b''
        assert result['stderr'] == b'Command timed out'
        assert result['command_line'] == 'test command'
        mock_run.assert_called_once()

    def test_extract_implementation(self):
        """Test extract method implementation."""
        extractor = TestableBaseExtractor('test_method')
        result = extractor.extract('test_file.txt')
        assert result['success'] is True
        assert result['data'] == b'test data'
        assert result['command_line'] == 'test test_file.txt'


class TestZStegExtractor:
    """Test suite for the ZStegExtractor class."""

    def test_get_tool_name(self):
        """Test _get_tool_name method."""
        extractor = TestableZStegExtractor('zsteg')
        assert extractor._get_tool_name() == 'zsteg'

    @patch('crypto_hunter_web.services.extractors.zsteg.os.path.exists')
    def test_extract_file_not_found(self, mock_exists):
        """Test extract method when file is not found."""
        # Setup mocks
        mock_exists.return_value = False

        # Create extractor
        extractor = TestableZStegExtractor('zsteg')

        # Call method
        result = extractor.extract('nonexistent_file.png')

        # Assertions
        assert result['success'] is False
        assert result['error'] == 'File not found'
        assert result['data'] == b''
        mock_exists.assert_called_once_with('nonexistent_file.png')

    @patch('crypto_hunter_web.services.extractors.zsteg.os.path.exists')
    def test_extract_tool_not_available(self, mock_exists):
        """Test extract method when tool is not available."""
        # Setup mocks
        mock_exists.return_value = True

        # Create extractor with mock
        extractor = TestableZStegExtractor('zsteg')

        # Mock _is_tool_available directly on the instance
        with patch.object(extractor, '_is_tool_available', return_value=False):
            # Call method
            with patch.object(extractor, '_run_command'):  # Prevent actual command execution
                result = extractor.extract('test_file.png')

        # Assertions
        assert result['success'] is False
        assert 'not available' in result['error'].lower()
        assert result['data'] == b''
        mock_exists.assert_called_once_with('test_file.png')

    @patch('crypto_hunter_web.services.extractors.zsteg.os.path.exists')
    def test_extract_success(self, mock_exists):
        """Test extract method with successful extraction."""
        # Setup mocks
        mock_exists.return_value = True

        # Create extractor
        extractor = TestableZStegExtractor('zsteg')

        # Mock methods directly on the instance
        with patch.object(extractor, '_is_tool_available', return_value=True):
            with patch.object(extractor, '_run_command', return_value={
                'returncode': 0,
                'stdout': b'test output',
                'stderr': b'',
                'command_line': 'zsteg test_file.png'
            }):
                # In the zsteg.py implementation, _parse_zsteg_output returns a tuple of (data, confidence)
                # In the __init__.py implementation, it returns a tuple of (data, confidence, findings)
                # Let's try both formats
                with patch.object(extractor, '_parse_zsteg_output', return_value=(b'extracted data', 0.8, [])):
                    # Call method
                    result = extractor.extract('test_file.png')

                    # Print result for debugging
                    print(f"Result: {result}")

        # Assertions
        assert result['success'] is True
        assert result['data'] == b'extracted data'
        assert result['confidence'] == 0.8
        mock_exists.assert_called_once_with('test_file.png')

    @patch('crypto_hunter_web.services.extractors.zsteg.os.path.exists')
    def test_extract_command_failure(self, mock_exists):
        """Test extract method with command failure."""
        # Setup mocks
        mock_exists.return_value = True

        # Create extractor
        extractor = TestableZStegExtractor('zsteg')

        # Mock methods directly on the instance
        with patch.object(extractor, '_is_tool_available', return_value=True):
            with patch.object(extractor, '_run_command', return_value={
                'returncode': 1,
                'stdout': b'',
                'stderr': b'test error',
                'command_line': 'zsteg test_file.png'
            }):
                # Call method
                result = extractor.extract('test_file.png')

        # Assertions
        assert result['success'] is False
        assert result['error'] == 'test error'
        assert result['data'] == b''
        mock_exists.assert_called_once_with('test_file.png')

    def test_get_zsteg_args_default(self):
        """Test _get_zsteg_args method with default parameters."""
        extractor = TestableZStegExtractor('zsteg')
        args = extractor._get_zsteg_args({})
        assert '-a' in args

    def test_get_zsteg_args_bitplane(self):
        """Test _get_zsteg_args method with bitplane method."""
        extractor = TestableZStegExtractor('zsteg_bitplane_1')
        args = extractor._get_zsteg_args({})
        assert '-E' in args
        assert 'b1,bgr,lsb,xy' in args

    def test_get_zsteg_args_custom_params(self):
        """Test _get_zsteg_args method with custom parameters."""
        extractor = TestableZStegExtractor('zsteg')
        args = extractor._get_zsteg_args({
            'channel': 'rgb',
            'limit': 100,
            'verbose': True
        })
        assert '-c' in args
        assert 'rgb' in args
        assert '-l' in args
        assert '100' in args
        assert '-v' in args


class TestGetExtractorFunctions:
    """Test suite for extractor utility functions."""

    @patch('crypto_hunter_web.services.extractors.EXTRACTORS')
    def test_get_extractor(self, mock_extractors):
        """Test get_extractor function."""
        # Setup mock
        mock_extractors.get.return_value = ZStegExtractor

        # Test getting a valid extractor
        extractor = get_extractor('zsteg')
        assert isinstance(extractor, ZStegExtractor)
        assert extractor.method_name == 'zsteg'
        mock_extractors.get.assert_called_with('zsteg')

        # Test getting a non-existent extractor
        mock_extractors.get.return_value = None
        extractor = get_extractor('nonexistent')
        assert extractor is None
        mock_extractors.get.assert_called_with('nonexistent')

    def test_list_extractors(self):
        """Test list_extractors function."""
        extractors = list_extractors()
        assert isinstance(extractors, list)
        assert len(extractors) > 0
        assert 'zsteg' in extractors
        assert 'steghide' in extractors
        assert 'binwalk' in extractors

    def test_get_recommended_extractors(self):
        """Test get_recommended_extractors function."""
        # Test with known file type
        extractors = get_recommended_extractors('image/png')
        assert isinstance(extractors, list)
        assert 'zsteg' in extractors
        assert 'binwalk' in extractors

        # Test with unknown file type
        extractors = get_recommended_extractors('unknown/type')
        assert isinstance(extractors, list)
        assert 'forensics' in extractors
        assert 'binwalk' in extractors
        assert 'strings' in extractors
