import pytest
from unittest.mock import patch, MagicMock
from flask import url_for
from flask_login import current_user

from crypto_hunter_web.models import User, AuditLog
from crypto_hunter_web.services.auth_service import AuthService


class TestAuthService:
    """Test suite for the AuthService class."""

    def test_login_user_success(self, app, session, test_user):
        """Test successful user login."""
        with app.test_request_context():
            # Attempt to log in with correct credentials
            result = AuthService.login_user(test_user.username, 'password123')
            
            # Check that login was successful
            assert result is not False
            assert result.id == test_user.id
            
            # Check that an audit log entry was created
            audit_log = AuditLog.query.filter_by(
                user_id=test_user.id,
                action='login'
            ).first()
            assert audit_log is not None
            assert f'User {test_user.username} logged in' in audit_log.details

    def test_login_user_failure_wrong_password(self, app, session, test_user):
        """Test login failure with wrong password."""
        with app.test_request_context():
            # Attempt to log in with incorrect password
            result = AuthService.login_user(test_user.username, 'wrong_password')
            
            # Check that login failed
            assert result is False
            
            # Check that no audit log entry was created
            audit_log = AuditLog.query.filter_by(
                user_id=test_user.id,
                action='login'
            ).first()
            assert audit_log is None

    def test_login_user_failure_nonexistent_user(self, app, session):
        """Test login failure with nonexistent user."""
        with app.test_request_context():
            # Attempt to log in with nonexistent username
            result = AuthService.login_user('nonexistent_user', 'password123')
            
            # Check that login failed
            assert result is False
            
            # Check that no audit log entry was created
            audit_log = AuditLog.query.filter_by(action='login').first()
            assert audit_log is None

    def test_logout_user(self, app, session, test_user):
        """Test user logout."""
        with app.test_request_context():
            # First log in the user
            with patch('flask_login.utils._get_user', return_value=test_user):
                # Mock current_user to be authenticated
                test_user.is_authenticated = True
                
                # Call logout_user
                AuthService.logout_user()
                
                # Check that an audit log entry was created
                audit_log = AuditLog.query.filter_by(
                    user_id=test_user.id,
                    action='logout'
                ).first()
                assert audit_log is not None
                assert 'User logged out' in audit_log.details

    def test_login_required_decorator_authenticated(self, app, client, test_user):
        """Test login_required decorator with authenticated user."""
        with app.test_request_context():
            # Create a test route with login_required
            @app.route('/protected')
            @AuthService.login_required
            def protected_route():
                return 'Protected Content'
            
            # Register the route
            app.add_url_rule('/protected', 'protected', protected_route)
            
            # Mock current_user to be authenticated
            with patch('flask_login.utils._get_user', return_value=test_user):
                test_user.is_authenticated = True
                
                # Access the protected route
                response = client.get('/protected')
                
                # Check that access was granted
                assert response.status_code == 200
                assert b'Protected Content' in response.data

    def test_login_required_decorator_unauthenticated(self, app, client):
        """Test login_required decorator with unauthenticated user."""
        with app.test_request_context():
            # Create a test route with login_required
            @app.route('/protected')
            @AuthService.login_required
            def protected_route():
                return 'Protected Content'
            
            # Register the route
            app.add_url_rule('/protected', 'protected', protected_route)
            
            # Create login route for redirection
            @app.route('/login')
            def login():
                return 'Login Page'
            
            # Register the login route
            app.add_url_rule('/login', 'auth.login', login)
            
            # Access the protected route without authentication
            response = client.get('/protected', follow_redirects=True)
            
            # Check that user was redirected to login page
            assert b'Login Page' in response.data

    def test_admin_required_decorator_admin(self, app, client, admin_user):
        """Test admin_required decorator with admin user."""
        with app.test_request_context():
            # Create a test route with admin_required
            @app.route('/admin-only')
            @AuthService.admin_required
            def admin_route():
                return 'Admin Content'
            
            # Register the route
            app.add_url_rule('/admin-only', 'admin_only', admin_route)
            
            # Mock current_user to be authenticated admin
            with patch('flask_login.utils._get_user', return_value=admin_user):
                admin_user.is_authenticated = True
                
                # Access the admin route
                response = client.get('/admin-only')
                
                # Check that access was granted
                assert response.status_code == 200
                assert b'Admin Content' in response.data

    def test_admin_required_decorator_non_admin(self, app, client, test_user):
        """Test admin_required decorator with non-admin user."""
        with app.test_request_context():
            # Create a test route with admin_required
            @app.route('/admin-only')
            @AuthService.admin_required
            def admin_route():
                return 'Admin Content'
            
            # Register the route
            app.add_url_rule('/admin-only', 'admin_only', admin_route)
            
            # Create index route for redirection
            @app.route('/')
            def index():
                return 'Home Page'
            
            # Register the index route
            app.add_url_rule('/', 'main.index', index)
            
            # Mock current_user to be authenticated non-admin
            with patch('flask_login.utils._get_user', return_value=test_user):
                test_user.is_authenticated = True
                
                # Access the admin route
                response = client.get('/admin-only', follow_redirects=True)
                
                # Check that user was redirected to home page
                assert b'Home Page' in response.data

    def test_log_action_success(self, app, session, test_user):
        """Test successful action logging."""
        with app.test_request_context():
            # Mock current_user to be authenticated
            with patch('flask_login.utils._get_user', return_value=test_user):
                test_user.is_authenticated = True
                
                # Log an action
                log_entry = AuthService.log_action(
                    action='test_action',
                    description='Test description',
                    metadata={'test_key': 'test_value'}
                )
                
                # Check that log entry was created
                assert log_entry is not None
                
                # Check that log entry was added to database
                db_log = AuditLog.query.filter_by(
                    user_id=test_user.id,
                    action='test_action'
                ).first()
                assert db_log is not None
                assert db_log.description == 'Test description'
                assert db_log.details.get('test_key') == 'test_value'

    def test_log_action_exception_handling(self, app, session, test_user):
        """Test exception handling in log_action method."""
        with app.test_request_context():
            # Mock current_user to be authenticated
            with patch('flask_login.utils._get_user', return_value=test_user):
                test_user.is_authenticated = True
                
                # Mock db.session.commit to raise an exception
                with patch('crypto_hunter_web.models.db.session.commit', side_effect=Exception('Test exception')):
                    # Mock current_app.logger to capture error log
                    mock_logger = MagicMock()
                    with patch('crypto_hunter_web.services.auth_service.current_app') as mock_app:
                        mock_app.logger = mock_logger
                        
                        # Log an action that will trigger an exception
                        log_entry = AuthService.log_action(
                            action='test_action',
                            description='Test description'
                        )
                        
                        # Check that log entry is None due to exception
                        assert log_entry is None
                        
                        # Check that error was logged
                        mock_logger.error.assert_called_once()
                        
                        # Check that rollback was called
                        with patch('crypto_hunter_web.models.db.session.rollback') as mock_rollback:
                            AuthService.log_action('test_action')
                            mock_rollback.assert_called_once()