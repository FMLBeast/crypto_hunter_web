import pytest
from unittest.mock import patch, MagicMock, call
from flask import Flask, request

from crypto_hunter_web.services.auth_service import AuthService
from crypto_hunter_web.models import User, AuditLog


class TestAuthServiceMock:
    """Test suite for the AuthService class using mocks."""

    @pytest.fixture
    def app(self):
        """Create a Flask app for testing."""
        app = Flask('test_app')
        app.config['TESTING'] = True
        app.config['SECRET_KEY'] = 'test-secret-key'

        # Initialize Flask-Login
        from flask_login import LoginManager
        login_manager = LoginManager()
        login_manager.init_app(app)

        @login_manager.user_loader
        def load_user(user_id):
            # This is just a stub for testing
            return None

        return app

    @patch('crypto_hunter_web.services.auth_service.login_user')
    @patch('crypto_hunter_web.services.auth_service.User.query')
    @patch('crypto_hunter_web.services.auth_service.db.session')
    def test_login_user_success(self, mock_session, mock_user_query, mock_login_user, app):
        """Test successful user login."""
        # Setup mocks
        mock_user = MagicMock(spec=User)
        mock_user.id = 1
        mock_user.username = 'testuser'
        mock_user.check_password.return_value = True

        mock_user_query.filter_by.return_value.first.return_value = mock_user
        mock_login_user.return_value = True

        # Patch check_password_hash to return True
        with patch('crypto_hunter_web.services.auth_service.check_password_hash', return_value=True):
            # Call the method
            result = AuthService.login_user('testuser', 'password123')

        # Assertions
        assert result is mock_user
        mock_user_query.filter_by.assert_called_once_with(username='testuser')
        mock_login_user.assert_called_once_with(mock_user, remember=False, duration=None)

        # Check that AuditLog was created and session was committed
        mock_session.add.assert_called_once()
        mock_session.commit.assert_called_once()

    @patch('crypto_hunter_web.services.auth_service.login_user')
    @patch('crypto_hunter_web.services.auth_service.User.query')
    @patch('crypto_hunter_web.services.auth_service.db.session')
    def test_login_user_failure_wrong_password(self, mock_session, mock_user_query, mock_login_user, app):
        """Test login failure with wrong password."""
        # Setup mocks
        mock_user = MagicMock(spec=User)

        mock_user_query.filter_by.return_value.first.return_value = mock_user

        # Patch check_password_hash to return False
        with patch('crypto_hunter_web.services.auth_service.check_password_hash', return_value=False):
            # Call the method
            result = AuthService.login_user('testuser', 'wrong_password')

        # Assertions
        assert result is False
        mock_user_query.filter_by.assert_called_once_with(username='testuser')
        mock_login_user.assert_not_called()

        # Check that no AuditLog was created and session was not committed
        mock_session.add.assert_not_called()
        mock_session.commit.assert_not_called()

    @patch('crypto_hunter_web.services.auth_service.login_user')
    @patch('crypto_hunter_web.services.auth_service.User.query')
    @patch('crypto_hunter_web.services.auth_service.db.session')
    def test_login_user_failure_nonexistent_user(self, mock_session, mock_user_query, mock_login_user, app):
        """Test login failure with nonexistent user."""
        # Setup mocks
        mock_user_query.filter_by.return_value.first.return_value = None

        # Call the method
        result = AuthService.login_user('nonexistent', 'password123')

        # Assertions
        assert result is False
        mock_user_query.filter_by.assert_called_once_with(username='nonexistent')
        mock_login_user.assert_not_called()

        # Check that no AuditLog was created and session was not committed
        mock_session.add.assert_not_called()
        mock_session.commit.assert_not_called()

    @patch('crypto_hunter_web.services.auth_service.logout_user')
    @patch('crypto_hunter_web.services.auth_service.current_user')
    @patch('crypto_hunter_web.services.auth_service.db.session')
    def test_logout_user(self, mock_session, mock_current_user, mock_logout_user, app):
        """Test user logout."""
        # Setup mocks
        mock_current_user.is_authenticated = True
        mock_current_user.id = 1

        # Call the method within app context
        with app.app_context():
            AuthService.logout_user()

        # Assertions
        mock_logout_user.assert_called_once()

        # Check that AuditLog was created and session was committed
        mock_session.add.assert_called_once()
        mock_session.commit.assert_called_once()

    @patch('crypto_hunter_web.services.auth_service.current_user')
    @patch('crypto_hunter_web.services.auth_service.request')
    @patch('crypto_hunter_web.services.auth_service.AuditLog.log_action')
    @patch('crypto_hunter_web.services.auth_service.db.session')
    def test_log_action_success(self, mock_session, mock_log_action, mock_request, mock_current_user, app):
        """Test successful action logging."""
        # Setup mocks
        mock_current_user.is_authenticated = True
        mock_current_user.id = 1
        mock_request.remote_addr = '127.0.0.1'
        mock_log_entry = MagicMock(spec=AuditLog)
        mock_log_action.return_value = mock_log_entry

        # Call the method within app and request context
        with app.app_context():
            with app.test_request_context():
                result = AuthService.log_action(
                    action='test_action',
                    description='Test description',
                    metadata={'test_key': 'test_value'}
                )

        # Assertions
        assert result is mock_log_entry
        mock_log_action.assert_called_once_with(
            user_id=1,
            action='test_action',
            description='Test description',
            success=True,
            ip_address='127.0.0.1',
            metadata={'test_key': 'test_value'}
        )
        mock_session.commit.assert_called_once()

    @patch('crypto_hunter_web.services.auth_service.current_user')
    @patch('crypto_hunter_web.services.auth_service.request')
    @patch('crypto_hunter_web.services.auth_service.AuditLog.log_action')
    @patch('crypto_hunter_web.services.auth_service.db.session')
    @patch('crypto_hunter_web.services.auth_service.current_app')
    def test_log_action_exception_handling(self, mock_current_app, mock_session, mock_log_action, 
                                          mock_request, mock_current_user, app):
        """Test exception handling in log_action method."""
        # Setup mocks
        mock_current_user.is_authenticated = True
        mock_current_user.id = 1
        mock_request.remote_addr = '127.0.0.1'
        mock_log_entry = MagicMock(spec=AuditLog)
        mock_log_action.return_value = mock_log_entry
        mock_session.commit.side_effect = Exception('Test exception')
        mock_logger = MagicMock()
        mock_current_app.logger = mock_logger

        # Call the method within app and request context
        with app.app_context():
            with app.test_request_context():
                result = AuthService.log_action(
                    action='test_action',
                    description='Test description'
                )

        # Assertions
        assert result is None
        mock_logger.error.assert_called_once()
        mock_session.rollback.assert_called_once()
