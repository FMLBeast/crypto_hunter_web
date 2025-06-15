import pytest
import os
import tempfile
from unittest.mock import patch, MagicMock

from crypto_hunter_web.models import AnalysisFile, ExtractionRelationship, db
from crypto_hunter_web.services.extraction import ExtractionService
from crypto_hunter_web.services.extraction_engine import ExtractionEngine
from crypto_hunter_web.services.extractors import BaseExtractor, ZStegExtractor


@pytest.fixture
def test_image_file(tmp_path):
    """Create a test image file for extraction testing."""
    # Create a simple PNG file with some embedded data
    file_path = tmp_path / "test_image.png"
    
    # Write a minimal valid PNG file
    with open(file_path, 'wb') as f:
        # PNG signature
        f.write(b'\x89PNG\r\n\x1a\n')
        # IHDR chunk
        f.write(b'\x00\x00\x00\x0d')  # Length
        f.write(b'IHDR')              # Type
        f.write(b'\x00\x00\x00\x10')  # Width
        f.write(b'\x00\x00\x00\x10')  # Height
        f.write(b'\x08\x02\x00\x00\x00')  # Bit depth, color type, etc.
        f.write(b'\x00\x00\x00\x00')  # CRC (invalid but ok for test)
        # Hidden data in a tEXt chunk
        secret_text = b'SECRET_DATA:test123'
        f.write(b'\x00\x00\x00' + bytes([len(secret_text)]))  # Length
        f.write(b'tEXt')              # Type
        f.write(secret_text)          # Data
        f.write(b'\x00\x00\x00\x00')  # CRC (invalid but ok for test)
        # IEND chunk
        f.write(b'\x00\x00\x00\x00')  # Length
        f.write(b'IEND')              # Type
        f.write(b'\xae\x42\x60\x82')  # CRC
    
    return str(file_path)


@pytest.fixture
def mock_analysis_file(test_image_file):
    """Create a mock AnalysisFile object for testing."""
    file_obj = MagicMock(spec=AnalysisFile)
    file_obj.id = 1
    file_obj.filename = os.path.basename(test_image_file)
    file_obj.filepath = test_image_file
    file_obj.file_type = 'image/png'
    file_obj.file_size = os.path.getsize(test_image_file)
    file_obj.sha256_hash = 'test_hash'
    file_obj.depth_level = 0
    return file_obj


class MockExtractor(BaseExtractor):
    """Mock extractor for testing."""
    
    def _get_tool_name(self):
        return 'mock_extractor'
    
    def extract(self, file_path, parameters=None):
        """Mock extraction that always succeeds."""
        return {
            'success': True,
            'data': b'EXTRACTED_DATA:mock_data',
            'details': 'Mock extraction successful',
            'command_line': f'mock_extract {file_path}',
            'confidence': 0.9
        }


class TestExtractionIntegration:
    """Integration tests for the extraction flow."""
    
    @patch('crypto_hunter_web.services.extractors.get_extractor')
    @patch('crypto_hunter_web.services.extraction_engine.db.session')
    def test_extraction_flow(self, mock_db_session, mock_get_extractor, mock_analysis_file):
        """Test the complete extraction flow."""
        # Setup mocks
        mock_extractor = MockExtractor('mock_method')
        mock_get_extractor.return_value = mock_extractor
        
        # Mock the database session
        mock_db_session.add = MagicMock()
        mock_db_session.commit = MagicMock()
        mock_db_session.flush = MagicMock()
        
        # Create a mock for the extracted file
        mock_extracted_file = MagicMock(spec=AnalysisFile)
        mock_extracted_file.id = 2
        mock_extracted_file.filename = f"{mock_analysis_file.filename}_mock_method_extracted"
        mock_extracted_file.filepath = f"{mock_analysis_file.filepath}_extracted"
        mock_extracted_file.sha256_hash = 'extracted_hash'
        
        # Mock the _create_extracted_file method
        with patch.object(ExtractionEngine, '_create_extracted_file', return_value=mock_extracted_file):
            # Call the extraction method
            result = ExtractionEngine.extract_from_file(
                source_file=mock_analysis_file,
                extraction_method='mock_method',
                parameters={'param': 'value'},
                user_id=1
            )
        
        # Assertions for ExtractionEngine
        assert result['success'] is True
        assert result['extracted_file'] == mock_extracted_file
        assert 'relationship' in result
        
        # Now test the ExtractionService layer
        with patch('crypto_hunter_web.services.extraction.extraction_service.AnalysisFile.query') as mock_query:
            mock_query.get.return_value = mock_analysis_file
            
            # Call the service method
            service_result = ExtractionService.extract_from_file(
                file_id=1,
                extraction_method='mock_method',
                parameters={'param': 'value'},
                user_id=1,
                async_mode=False  # Run synchronously for testing
            )
        
        # Assertions for ExtractionService
        assert service_result['success'] is True
        assert 'extracted_file_id' in service_result
        assert service_result['extracted_file_id'] == mock_extracted_file.id
    
    @patch('crypto_hunter_web.services.extractors.get_extractor')
    @patch('crypto_hunter_web.services.extraction_engine.db.session')
    def test_extraction_flow_failure(self, mock_db_session, mock_get_extractor, mock_analysis_file):
        """Test the extraction flow when extraction fails."""
        # Setup mocks
        mock_extractor = MagicMock(spec=BaseExtractor)
        mock_extractor.extract.return_value = {
            'success': False,
            'error': 'Mock extraction failed',
            'data': b'',
            'details': 'Error details',
            'command_line': 'mock_command',
            'confidence': 0
        }
        mock_get_extractor.return_value = mock_extractor
        
        # Call the extraction method
        result = ExtractionEngine.extract_from_file(
            source_file=mock_analysis_file,
            extraction_method='mock_method',
            parameters={'param': 'value'},
            user_id=1
        )
        
        # Assertions for ExtractionEngine
        assert result['success'] is False
        assert result['error'] == 'Mock extraction failed'
        assert 'details' in result
        
        # Now test the ExtractionService layer
        with patch('crypto_hunter_web.services.extraction.extraction_service.AnalysisFile.query') as mock_query:
            mock_query.get.return_value = mock_analysis_file
            
            # Call the service method
            service_result = ExtractionService.extract_from_file(
                file_id=1,
                extraction_method='mock_method',
                parameters={'param': 'value'},
                user_id=1,
                async_mode=False  # Run synchronously for testing
            )
        
        # Assertions for ExtractionService
        assert service_result['success'] is False
        assert 'error' in service_result
        assert service_result['error'] == 'Mock extraction failed'
    
    @patch('crypto_hunter_web.services.extraction.extraction_service.extract_from_file')
    @patch('crypto_hunter_web.services.extraction.extraction_service.AnalysisFile.query')
    def test_async_extraction(self, mock_query, mock_extract_task, mock_analysis_file):
        """Test asynchronous extraction."""
        # Setup mocks
        mock_query.get.return_value = mock_analysis_file
        
        mock_task = MagicMock()
        mock_task.id = 'test-task-id'
        mock_extract_task.delay.return_value = mock_task
        
        # Call the service method
        result = ExtractionService.extract_from_file(
            file_id=1,
            extraction_method='mock_method',
            parameters={'param': 'value'},
            user_id=1,
            async_mode=True  # Run asynchronously
        )
        
        # Assertions
        assert result['success'] is True
        assert result['task_id'] == 'test-task-id'
        assert result['is_async'] is True
        mock_query.get.assert_called_once_with(1)
        mock_extract_task.delay.assert_called_once_with(1, 'mock_method', {'param': 'value'}, 1, None)
    
    @patch('crypto_hunter_web.services.extraction.extraction_service.extract_all_methods')
    @patch('crypto_hunter_web.services.extraction.extraction_service.AnalysisFile.query')
    def test_extract_all_methods(self, mock_query, mock_extract_all_task, mock_analysis_file):
        """Test extracting with all methods."""
        # Setup mocks
        mock_query.get.return_value = mock_analysis_file
        
        mock_task = MagicMock()
        mock_task.id = 'test-task-id'
        mock_extract_all_task.delay.return_value = mock_task
        
        # Call the service method
        result = ExtractionService.extract_all_methods(
            file_id=1,
            user_id=1,
            async_mode=True  # Run asynchronously
        )
        
        # Assertions
        assert result['success'] is True
        assert result['task_id'] == 'test-task-id'
        assert result['is_async'] is True
        mock_query.get.assert_called_once_with(1)
        mock_extract_all_task.delay.assert_called_once_with(1, 1, None)
    
    @patch('crypto_hunter_web.services.extraction.extraction_service.BackgroundService.get_task_status')
    def test_get_task_status(self, mock_get_task_status):
        """Test getting task status."""
        # Setup mock
        mock_get_task_status.return_value = {
            'state': 'SUCCESS',
            'result': {'key': 'value'}
        }
        
        # Call the service method
        result = ExtractionService.get_task_status('test-task-id')
        
        # Assertions
        assert result['state'] == 'SUCCESS'
        assert result['result'] == {'key': 'value'}
        mock_get_task_status.assert_called_once_with('test-task-id')