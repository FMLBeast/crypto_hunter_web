import pytest
from unittest.mock import patch, MagicMock, call
import os
import subprocess
import re
from datetime import datetime
from flask import Flask

from crypto_hunter_web.models import AnalysisFile, ExtractionRelationship, db
from crypto_hunter_web.services.extraction_engine import ExtractionEngine
from crypto_hunter_web.services.extractors import BaseExtractor


@pytest.fixture
def app():
    """Create a Flask application for testing."""
    app = Flask('test')
    app.config['TESTING'] = True
    return app


@pytest.fixture
def app_context(app):
    """Create an application context for testing."""
    with app.app_context():
        yield


class TestExtractionEngine:
    """Test suite for the ExtractionEngine class."""

    @patch('crypto_hunter_web.services.extraction_engine.get_extractor')
    def test_extract_from_file_success(self, mock_get_extractor):
        """Test successful extraction from a file."""
        # Setup mocks
        mock_extractor = MagicMock(spec=BaseExtractor)
        mock_extractor.extract.return_value = {
            'success': True,
            'data': b'extracted data',
            'details': 'Extraction successful',
            'command_line': 'test command',
            'confidence': 0.8
        }
        mock_get_extractor.return_value = mock_extractor

        mock_source_file = MagicMock(spec=AnalysisFile)
        mock_source_file.id = 1
        mock_source_file.sha256_hash = 'test_hash'
        mock_source_file.filename = 'test_file.png'
        mock_source_file.filepath = '/path/to/test_file.png'
        mock_source_file.depth_level = 0

        # Mock the _create_extracted_file method
        mock_extracted_file = MagicMock(spec=AnalysisFile)
        mock_extracted_file.id = 2

        with patch.object(ExtractionEngine, '_create_extracted_file', return_value=mock_extracted_file):
            # Call the method
            result = ExtractionEngine.extract_from_file(
                source_file=mock_source_file,
                extraction_method='test_method',
                parameters={'param': 'value'},
                user_id=1
            )

        # Assertions
        assert result['success'] is True
        assert result['extracted_file'] == mock_extracted_file
        assert 'relationship' in result

        mock_get_extractor.assert_called_once_with('test_method')
        mock_extractor.extract.assert_called_once_with(mock_source_file.filepath, {'param': 'value'})

    @patch('crypto_hunter_web.services.extraction_engine.get_extractor')
    def test_extract_from_file_failure(self, mock_get_extractor):
        """Test extraction failure."""
        # Setup mocks
        mock_extractor = MagicMock(spec=BaseExtractor)
        mock_extractor.extract.return_value = {
            'success': False,
            'error': 'Extraction failed',
            'data': b'',
            'details': 'Error details',
            'command_line': 'test command',
            'confidence': 0
        }
        mock_get_extractor.return_value = mock_extractor

        mock_source_file = MagicMock(spec=AnalysisFile)
        mock_source_file.id = 1
        mock_source_file.sha256_hash = 'test_hash'
        mock_source_file.filename = 'test_file.png'
        mock_source_file.filepath = '/path/to/test_file.png'

        # Call the method
        result = ExtractionEngine.extract_from_file(
            source_file=mock_source_file,
            extraction_method='test_method',
            parameters=None,
            user_id=1
        )

        # Assertions
        assert result['success'] is False
        assert result['error'] == 'Extraction failed'
        assert 'details' in result

        mock_get_extractor.assert_called_once_with('test_method')
        mock_extractor.extract.assert_called_once_with(mock_source_file.filepath, {})

    @patch('crypto_hunter_web.services.extraction_engine.get_extractor')
    def test_extract_from_file_extractor_not_found(self, mock_get_extractor):
        """Test extraction with extractor not found."""
        # Setup mocks
        mock_get_extractor.return_value = None

        mock_source_file = MagicMock(spec=AnalysisFile)
        mock_source_file.id = 1
        mock_source_file.filename = 'test_file.png'

        # Call the method
        result = ExtractionEngine.extract_from_file(
            source_file=mock_source_file,
            extraction_method='nonexistent_method',
            parameters=None,
            user_id=1
        )

        # Assertions
        assert result['success'] is False
        assert 'Unknown extraction method' in result['error']

        mock_get_extractor.assert_called_once_with('nonexistent_method')

    @patch('crypto_hunter_web.services.extraction_engine.os')
    @patch('crypto_hunter_web.services.extraction_engine.current_app')
    def test_is_llm_mode_enabled_from_config(self, mock_current_app, mock_os, app_context):
        """Test is_llm_mode_enabled with config setting."""
        # Setup mocks
        mock_current_app.config.get.return_value = True

        # Call the method
        result = ExtractionEngine.is_llm_mode_enabled()

        # Assertions
        assert result is True
        mock_current_app.config.get.assert_called_once_with('USE_LLM_ORCHESTRATOR', False)
        mock_os.environ.get.assert_not_called()

    @patch('crypto_hunter_web.services.extraction_engine.os')
    @patch('crypto_hunter_web.services.extraction_engine.current_app')
    def test_is_llm_mode_enabled_from_env(self, mock_current_app, mock_os, app_context):
        """Test is_llm_mode_enabled with environment variable."""
        # Setup mocks
        mock_current_app.config.get.return_value = False
        mock_os.environ.get.return_value = 'true'

        # Call the method
        result = ExtractionEngine.is_llm_mode_enabled()

        # Assertions
        assert result is True
        mock_current_app.config.get.assert_called_once_with('USE_LLM_ORCHESTRATOR', False)
        mock_os.environ.get.assert_called_once_with('USE_LLM_ORCHESTRATOR', '')

    @patch('crypto_hunter_web.services.extraction_engine.os')
    @patch('crypto_hunter_web.services.extraction_engine.current_app')
    def test_is_llm_mode_disabled(self, mock_current_app, mock_os):
        """Test is_llm_mode_enabled when disabled."""
        # Setup mocks
        mock_current_app.config.get.return_value = False
        mock_os.environ.get.return_value = 'false'

        # Call the method
        result = ExtractionEngine.is_llm_mode_enabled()

        # Assertions
        assert result is False
        mock_current_app.config.get.assert_called_once_with('USE_LLM_ORCHESTRATOR', False)
        mock_os.environ.get.assert_called_once_with('USE_LLM_ORCHESTRATOR', '')

    @patch('crypto_hunter_web.services.extraction_engine.os.path.join')
    @patch('crypto_hunter_web.services.extraction_engine.open')
    @patch('crypto_hunter_web.services.extraction_engine.AnalysisFile.calculate_sha256')
    def test_create_extracted_file(self, mock_calculate_sha256, mock_open, mock_path_join):
        """Test _create_extracted_file method."""
        # Setup mocks
        mock_source_file = MagicMock(spec=AnalysisFile)
        mock_source_file.filename = 'test_file.png'
        mock_source_file.sha256_hash = 'source_hash'
        mock_source_file.depth_level = 1

        extraction_result = {
            'data': b'extracted data',
            'command_line': 'test command'
        }

        mock_path_join.return_value = '/path/to/extracted_file'
        mock_calculate_sha256.return_value = 'extracted_hash'

        # Mock file open context manager
        mock_file = MagicMock()
        mock_open.return_value.__enter__.return_value = mock_file

        # Mock db.session
        with patch('crypto_hunter_web.services.extraction_engine.db.session') as mock_session:
            # Call the method
            result = ExtractionEngine._create_extracted_file(
                mock_source_file,
                extraction_result,
                'test_method',
                1
            )

        # Assertions
        assert result is not None
        assert result.sha256_hash == 'extracted_hash'
        assert result.filename == 'test_file.png_test-method_extracted'
        assert result.parent_file_sha == 'source_hash'
        assert result.extraction_method == 'test_method'
        assert result.depth_level == 2  # source depth + 1

        mock_path_join.assert_called_once_with('bulk_uploads/discovered_files', 'test_file.png_test-method_extracted')
        mock_file.write.assert_called_once_with(b'extracted data')
        mock_calculate_sha256.assert_called_once_with('/path/to/extracted_file')
        mock_session.add.assert_called_once()
        mock_session.flush.assert_called_once()

    @patch('crypto_hunter_web.services.extraction_engine.llm_orchestrated_analysis')
    @patch('crypto_hunter_web.services.extraction_engine.BackgroundService')
    def test_extract_with_llm(self, mock_background_service, mock_llm_analysis):
        """Test _extract_with_llm method."""
        # Setup mocks
        mock_source_file = MagicMock(spec=AnalysisFile)
        mock_source_file.id = 1
        mock_source_file.file_size = 1024
        mock_source_file.file_type = 'image/png'

        mock_task = MagicMock()
        mock_task.id = 'test-task-id'
        mock_llm_analysis.delay.return_value = mock_task

        # Call the method
        with patch('crypto_hunter_web.services.extraction_engine.ExtractionEngine.is_llm_mode_enabled', return_value=True):
            result = ExtractionEngine._extract_with_llm(
                mock_source_file,
                'test_method',
                {'param': 'value'},
                1
            )

        # Assertions
        assert result['success'] is True
        assert result['task_id'] == 'test-task-id'
        assert result['is_async'] is True
        assert 'test_method' in result['message']

        mock_llm_analysis.delay.assert_called_once_with(
            mock_source_file.id,
            extraction_method='test_method',
            parameters={'param': 'value'}
        )

        mock_background_service.track_task.assert_called_once_with(
            'test-task-id',
            'llm_extraction',
            mock_source_file.id,
            1,
            {
                'extraction_method': 'test_method',
                'parameters': {'param': 'value'},
                'file_size': 1024,
                'file_type': 'image/png'
            }
        )

    def test_get_method_color(self):
        """Test _get_method_color method."""
        # Test known methods
        assert ExtractionEngine._get_method_color('zsteg') == '#ef4444'
        assert ExtractionEngine._get_method_color('steghide') == '#f97316'
        assert ExtractionEngine._get_method_color('binwalk') == '#eab308'

        # Test method with partial match
        assert ExtractionEngine._get_method_color('zsteg_bitplane_1') == '#ef4444'

        # Test unknown method
        assert ExtractionEngine._get_method_color('unknown_method') == '#64748b'  # manual color

        # Test None method
        assert ExtractionEngine._get_method_color(None) == '#64748b'  # manual color

    def test_get_file_type_color(self):
        """Test _get_file_type_color method."""
        # Test known file types
        assert ExtractionEngine._get_file_type_color('image') == '#ef4444'
        assert ExtractionEngine._get_file_type_color('audio') == '#f97316'
        assert ExtractionEngine._get_file_type_color('text') == '#22c55e'

        # Test file type with partial match
        assert ExtractionEngine._get_file_type_color('image/png') == '#ef4444'

        # Test unknown file type
        assert ExtractionEngine._get_file_type_color('unknown_type') == '#6b7280'

        # Test None file type
        assert ExtractionEngine._get_file_type_color(None) == '#6b7280'

    def test_suggest_extraction_methods(self):
        """Test suggest_extraction_methods method."""
        # Test known file types
        assert ExtractionEngine.suggest_extraction_methods('image/jpeg') == ['zsteg_bitplane_1', 'steghide', 'exiftool']
        assert ExtractionEngine.suggest_extraction_methods('image/png') == ['zsteg_bitplane_1', 'binwalk']
        assert ExtractionEngine.suggest_extraction_methods('audio/mp3') == ['binwalk', 'strings']

        # Test unknown file type
        assert ExtractionEngine.suggest_extraction_methods('unknown/type') == ['strings', 'hexdump']
