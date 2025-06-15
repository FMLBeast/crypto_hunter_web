import pytest
from unittest.mock import patch, MagicMock, call
from datetime import datetime

from crypto_hunter_web.services.extraction import ExtractionService
from crypto_hunter_web.models import AnalysisFile, FileContent, ExtractionRelationship


class TestExtractionService:
    """Test suite for the ExtractionService class."""

    @patch('crypto_hunter_web.services.extraction.extraction_service.extract_from_file')
    @patch('crypto_hunter_web.services.extraction.extraction_service.AnalysisFile.query')
    def test_extract_from_file_async(self, mock_query, mock_extract_task):
        """Test extract_from_file method in async mode."""
        # Setup mocks
        mock_file = MagicMock(spec=AnalysisFile)
        mock_file.id = 1
        mock_query.get.return_value = mock_file

        mock_task = MagicMock()
        mock_task.id = 'test-task-id'
        mock_extract_task.delay.return_value = mock_task

        # Call the method
        result = ExtractionService.extract_from_file(
            file_id=1,
            extraction_method='test_method',
            parameters={'param': 'value'},
            user_id=2,
            async_mode=True
        )

        # Assertions
        assert result['success'] is True
        assert result['task_id'] == 'test-task-id'
        assert result['is_async'] is True
        mock_query.get.assert_called_once_with(1)
        mock_extract_task.delay.assert_called_once_with(1, 'test_method', {'param': 'value'}, 2, None)

    @patch('crypto_hunter_web.services.extraction.extraction_service.extract_from_file')
    @patch('crypto_hunter_web.services.extraction.extraction_service.AnalysisFile.query')
    def test_extract_from_file_sync(self, mock_query, mock_extract_task):
        """Test extract_from_file method in sync mode."""
        # Setup mocks
        mock_file = MagicMock(spec=AnalysisFile)
        mock_file.id = 1
        mock_query.get.return_value = mock_file

        mock_extract_task.return_value = {'success': True, 'result': 'test_result'}

        # Call the method
        result = ExtractionService.extract_from_file(
            file_id=1,
            extraction_method='test_method',
            parameters={'param': 'value'},
            user_id=2,
            async_mode=False
        )

        # Assertions
        assert result['success'] is True
        assert result['result'] == 'test_result'
        mock_query.get.assert_called_once_with(1)
        mock_extract_task.assert_called_once_with(1, 'test_method', {'param': 'value'}, 2, None)

    @patch('crypto_hunter_web.services.extraction.extraction_service.AnalysisFile.query')
    def test_extract_from_file_file_not_found(self, mock_query):
        """Test extract_from_file method with file not found."""
        # Setup mocks
        mock_query.get.return_value = None

        # Call the method
        result = ExtractionService.extract_from_file(
            file_id=999,
            extraction_method='test_method'
        )

        # Assertions
        assert result['success'] is False
        assert 'not found' in result['error']
        mock_query.get.assert_called_once_with(999)

    @patch('crypto_hunter_web.services.extraction.extraction_service.extract_all_methods')
    @patch('crypto_hunter_web.services.extraction.extraction_service.AnalysisFile.query')
    def test_extract_all_methods_async(self, mock_query, mock_extract_task):
        """Test extract_all_methods method in async mode."""
        # Setup mocks
        mock_file = MagicMock(spec=AnalysisFile)
        mock_file.id = 1
        mock_query.get.return_value = mock_file

        mock_task = MagicMock()
        mock_task.id = 'test-task-id'
        mock_extract_task.delay.return_value = mock_task

        # Call the method
        result = ExtractionService.extract_all_methods(
            file_id=1,
            user_id=2,
            async_mode=True
        )

        # Assertions
        assert result['success'] is True
        assert result['task_id'] == 'test-task-id'
        assert result['is_async'] is True
        mock_query.get.assert_called_once_with(1)
        mock_extract_task.delay.assert_called_once_with(1, 2, None)

    @patch('crypto_hunter_web.services.extraction.extraction_service.BackgroundService.get_task_status')
    def test_get_task_status(self, mock_get_task_status):
        """Test get_task_status method."""
        # Setup mocks
        mock_get_task_status.return_value = {
            'status': 'SUCCESS',
            'result': {'key': 'value'}
        }

        # Call the method
        result = ExtractionService.get_task_status('test-task-id')

        # Assertions
        assert result['status'] == 'SUCCESS'
        assert result['result'] == {'key': 'value'}
        mock_get_task_status.assert_called_once_with('test-task-id')

    @patch('crypto_hunter_web.services.extraction.extraction_service.list_extractors')
    def test_get_available_extractors(self, mock_list_extractors):
        """Test get_available_extractors method."""
        # Setup mocks
        mock_list_extractors.return_value = ['extractor1', 'extractor2']

        # Call the method
        result = ExtractionService.get_available_extractors()

        # Assertions
        assert result == ['extractor1', 'extractor2']
        mock_list_extractors.assert_called_once()

    @patch('crypto_hunter_web.services.extraction.extraction_service.get_recommended_extractors')
    def test_get_recommended_extractors(self, mock_get_recommended):
        """Test get_recommended_extractors method."""
        # Setup mocks
        mock_get_recommended.return_value = ['extractor1', 'extractor3']

        # Call the method
        result = ExtractionService.get_recommended_extractors('image/png')

        # Assertions
        assert result == ['extractor1', 'extractor3']
        mock_get_recommended.assert_called_once_with('image/png')

    @patch('crypto_hunter_web.services.extraction.extraction_service.ExtractionRelationship.query')
    @patch('crypto_hunter_web.services.extraction.extraction_service.AnalysisFile.query')
    def test_get_extraction_history(self, mock_file_query, mock_relationship_query):
        """Test get_extraction_history method."""
        # Setup mocks
        mock_file = MagicMock(spec=AnalysisFile)
        mock_file.id = 1
        mock_file_query.get.return_value = mock_file

        mock_rel1 = MagicMock(spec=ExtractionRelationship)
        mock_rel1.id = 101
        mock_rel1.extraction_method = 'method1'
        mock_rel1.extraction_tool_version = '1.0'
        mock_rel1.extraction_command = 'command1'
        mock_rel1.confidence_score = 0.8
        mock_rel1.created_at = datetime(2023, 1, 1, 12, 0, 0)
        mock_rel1.extracted_file_id = 201
        mock_rel1.extracted_file_sha = 'sha1'
        mock_rel1.extra_data = {'key1': 'value1'}

        mock_rel2 = MagicMock(spec=ExtractionRelationship)
        mock_rel2.id = 102
        mock_rel2.extraction_method = 'method2'
        mock_rel2.extraction_tool_version = '2.0'
        mock_rel2.extraction_command = 'command2'
        mock_rel2.confidence_score = 0.9
        mock_rel2.created_at = datetime(2023, 1, 2, 12, 0, 0)
        mock_rel2.extracted_file_id = 202
        mock_rel2.extracted_file_sha = 'sha2'
        mock_rel2.extra_data = {'key2': 'value2'}

        mock_relationship_query.filter_by.return_value.all.return_value = [mock_rel1, mock_rel2]

        # Call the method
        result = ExtractionService.get_extraction_history(1)

        # Assertions
        assert len(result) == 2
        assert result[0]['id'] == 101
        assert result[0]['extraction_method'] == 'method1'
        assert result[0]['confidence_score'] == 0.8
        assert result[0]['created_at'] == '2023-01-01T12:00:00'
        assert result[1]['id'] == 102
        assert result[1]['extraction_method'] == 'method2'

        mock_file_query.get.assert_called_once_with(1)
        mock_relationship_query.filter_by.assert_called_once_with(source_file_id=1)

    @patch('crypto_hunter_web.services.extraction.extraction_service.FileContent.query')
    @patch('crypto_hunter_web.services.extraction.extraction_service.AnalysisFile.query')
    def test_get_file_content(self, mock_file_query, mock_content_query):
        """Test get_file_content method."""
        # Setup mocks
        mock_file = MagicMock(spec=AnalysisFile)
        mock_file.id = 1
        mock_file_query.get.return_value = mock_file

        mock_content1 = MagicMock(spec=FileContent)
        mock_content1.id = 301
        mock_content1.content_type = 'extracted_data'
        mock_content1.content_format = 'text'
        mock_content1.content_size = 100
        mock_content1.extracted_at = datetime(2023, 1, 1, 12, 0, 0)
        mock_content1.extraction_method = 'method1'
        mock_content1.extraction_extra_data = {'key1': 'value1'}

        mock_content2 = MagicMock(spec=FileContent)
        mock_content2.id = 302
        mock_content2.content_type = 'extracted_data'
        mock_content2.content_format = 'binary'
        mock_content2.content_size = 200
        mock_content2.extracted_at = datetime(2023, 1, 2, 12, 0, 0)
        mock_content2.extraction_method = 'method2'
        mock_content2.extraction_extra_data = {'key2': 'value2'}

        mock_content_query.filter_by.return_value.all.return_value = [mock_content1, mock_content2]

        # Call the method
        result = ExtractionService.get_file_content(1, 'extracted_data')

        # Assertions
        assert len(result) == 2
        assert result[0]['id'] == 301
        assert result[0]['content_type'] == 'extracted_data'
        assert result[0]['content_format'] == 'text'
        assert result[0]['content_size'] == 100
        assert result[0]['extracted_at'] == '2023-01-01T12:00:00'
        assert result[1]['id'] == 302
        assert result[1]['content_format'] == 'binary'

        mock_file_query.get.assert_called_once_with(1)
        mock_content_query.filter_by.assert_called_once_with(file_id=1, content_type='extracted_data')

    @patch('crypto_hunter_web.services.extraction.extraction_service.AnalysisFile.query')
    def test_get_extraction_history_file_not_found(self, mock_query):
        """Test get_extraction_history method with file not found."""
        # Setup mocks
        mock_query.get.return_value = None

        # Call the method
        result = ExtractionService.get_extraction_history(999)

        # Assertions
        assert result == []
        mock_query.get.assert_called_once_with(999)

    @patch('crypto_hunter_web.services.extraction.extraction_service.AnalysisFile.query')
    def test_get_file_content_file_not_found(self, mock_query):
        """Test get_file_content method with file not found."""
        # Setup mocks
        mock_query.get.return_value = None

        # Call the method
        result = ExtractionService.get_file_content(999)

        # Assertions
        assert result == []
        mock_query.get.assert_called_once_with(999)
