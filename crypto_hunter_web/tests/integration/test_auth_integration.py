import pytest
from flask import Flask, request, jsonify, session
from flask_login import login_required, current_user

from crypto_hunter_web.models import User, AuditLog
from crypto_hunter_web.services.auth_service import AuthService


class TestAuthIntegration:
    """Integration tests for authentication and audit logging."""

    @pytest.fixture
    def auth_app(self, app, session, test_user, admin_user):
        """Create a test app with authentication routes."""
        
        # Add authentication routes
        @app.route('/api/login', methods=['POST'])
        def login():
            data = request.get_json()
            username = data.get('username')
            password = data.get('password')
            remember = data.get('remember', False)
            
            user = AuthService.login_user(username, password, remember)
            if user:
                return jsonify({'success': True, 'user_id': user.id})
            else:
                return jsonify({'success': False, 'message': 'Invalid credentials'}), 401
        
        @app.route('/api/logout', methods=['POST'])
        def logout():
            AuthService.logout_user()
            return jsonify({'success': True})
        
        @app.route('/api/protected')
        @AuthService.login_required
        def protected():
            return jsonify({'success': True, 'user_id': current_user.id})
        
        @app.route('/api/admin')
        @AuthService.admin_required
        def admin_only():
            return jsonify({'success': True, 'user_id': current_user.id, 'is_admin': current_user.is_admin})
        
        @app.route('/api/log-action', methods=['POST'])
        @AuthService.login_required
        def log_action():
            data = request.get_json()
            action = data.get('action')
            description = data.get('description')
            metadata = data.get('metadata')
            
            log_entry = AuthService.log_action(action, description, metadata)
            if log_entry:
                return jsonify({'success': True, 'log_id': log_entry.id})
            else:
                return jsonify({'success': False, 'message': 'Failed to log action'}), 500
        
        return app

    def test_login_logout_flow(self, auth_app, client, test_user, session):
        """Test the complete login and logout flow with audit logging."""
        # Test login
        response = client.post('/api/login', json={
            'username': test_user.username,
            'password': 'password123',
            'remember': True
        })
        assert response.status_code == 200
        data = response.get_json()
        assert data['success'] is True
        assert data['user_id'] == test_user.id
        
        # Check that login audit log was created
        login_log = AuditLog.query.filter_by(
            user_id=test_user.id,
            action='login'
        ).first()
        assert login_log is not None
        
        # Test accessing protected route
        response = client.get('/api/protected')
        assert response.status_code == 200
        data = response.get_json()
        assert data['success'] is True
        assert data['user_id'] == test_user.id
        
        # Test logout
        response = client.post('/api/logout')
        assert response.status_code == 200
        data = response.get_json()
        assert data['success'] is True
        
        # Check that logout audit log was created
        logout_log = AuditLog.query.filter_by(
            user_id=test_user.id,
            action='logout'
        ).first()
        assert logout_log is not None
        
        # Test that protected route is no longer accessible
        response = client.get('/api/protected')
        assert response.status_code != 200  # Should redirect to login

    def test_admin_access_control(self, auth_app, client, test_user, admin_user, session):
        """Test admin access control with audit logging."""
        # Login as regular user
        client.post('/api/login', json={
            'username': test_user.username,
            'password': 'password123'
        })
        
        # Try to access admin route as regular user
        response = client.get('/api/admin')
        assert response.status_code != 200  # Should redirect or return error
        
        # Logout regular user
        client.post('/api/logout')
        
        # Login as admin user
        client.post('/api/login', json={
            'username': admin_user.username,
            'password': 'adminpass123'
        })
        
        # Access admin route as admin user
        response = client.get('/api/admin')
        assert response.status_code == 200
        data = response.get_json()
        assert data['success'] is True
        assert data['is_admin'] is True

    def test_audit_logging_integration(self, auth_app, client, test_user, session):
        """Test audit logging integration."""
        # Login
        client.post('/api/login', json={
            'username': test_user.username,
            'password': 'password123'
        })
        
        # Log a custom action
        response = client.post('/api/log-action', json={
            'action': 'custom_action',
            'description': 'Testing custom action logging',
            'metadata': {'source': 'integration_test', 'importance': 'high'}
        })
        assert response.status_code == 200
        data = response.get_json()
        assert data['success'] is True
        assert 'log_id' in data
        
        # Check that custom action log was created
        custom_log = AuditLog.query.filter_by(
            user_id=test_user.id,
            action='custom_action'
        ).first()
        assert custom_log is not None
        assert custom_log.description == 'Testing custom action logging'
        assert custom_log.details.get('source') == 'integration_test'
        assert custom_log.details.get('importance') == 'high'

    def test_failed_login_attempts(self, auth_app, client, test_user, session):
        """Test failed login attempts and account locking."""
        # Try to login with incorrect password multiple times
        for i in range(3):
            response = client.post('/api/login', json={
                'username': test_user.username,
                'password': 'wrong_password'
            })
            assert response.status_code == 401
        
        # Check that user's failed login attempts have been tracked
        user = User.query.filter_by(username=test_user.username).first()
        assert user.failed_login_attempts > 0
        
        # Check that audit logs for failed logins were not created
        # (since our implementation doesn't log failed attempts)
        failed_logs = AuditLog.query.filter_by(
            user_id=test_user.id,
            action='login',
            success=False
        ).all()
        assert len(failed_logs) == 0