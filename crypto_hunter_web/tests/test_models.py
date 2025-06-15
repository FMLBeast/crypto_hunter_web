import pytest
from datetime import datetime, timedelta
from werkzeug.security import check_password_hash

from crypto_hunter_web.models import User, AuditLog, UserLevel


class TestUserModel:
    """Test suite for the User model."""

    def test_user_creation(self, session):
        """Test creating a new user."""
        user = User(
            username='newuser',
            email='newuser@example.com',
            is_active=True,
            is_admin=False
        )
        user.set_password('securepass123')
        session.add(user)
        session.commit()

        # Retrieve the user from the database
        saved_user = User.query.filter_by(username='newuser').first()
        
        # Check that user was saved correctly
        assert saved_user is not None
        assert saved_user.username == 'newuser'
        assert saved_user.email == 'newuser@example.com'
        assert saved_user.is_active is True
        assert saved_user.is_admin is False
        assert saved_user.level == UserLevel.ANALYST  # Default level
        assert saved_user.points == 0  # Default points
        assert saved_user.check_password('securepass123') is True

    def test_user_password_hashing(self, session):
        """Test password hashing functionality."""
        user = User(username='passuser', email='pass@example.com')
        
        # Set password and check that it's hashed
        user.set_password('password123')
        assert user.password_hash is not None
        assert user.password_hash != 'password123'
        assert check_password_hash(user.password_hash, 'password123') is True
        
        # Check that password verification works
        assert user.check_password('password123') is True
        assert user.check_password('wrongpassword') is False

    def test_user_password_validation(self, session):
        """Test password validation."""
        user = User(username='validuser', email='valid@example.com')
        
        # Test password length validation
        with pytest.raises(ValueError, match="Password must be at least 8 characters"):
            user.set_password('short')

    def test_user_email_validation(self, session):
        """Test email validation."""
        # Test valid email
        user = User(username='emailuser', email='valid@example.com')
        assert user.email == 'valid@example.com'
        
        # Test invalid email
        with pytest.raises(ValueError, match="Invalid email format"):
            User(username='invalid', email='invalid-email')

    def test_user_username_validation(self, session):
        """Test username validation."""
        # Test valid username
        user = User(username='valid_user', email='valid@example.com')
        assert user.username == 'valid_user'
        
        # Test invalid username (too short)
        with pytest.raises(ValueError, match="Username must be 3-80 characters"):
            User(username='ab', email='short@example.com')
        
        # Test invalid username (invalid characters)
        with pytest.raises(ValueError, match="Username must be 3-80 characters"):
            User(username='invalid@user', email='invalid@example.com')

    def test_user_account_locking(self, session):
        """Test account locking functionality."""
        user = User(username='lockuser', email='lock@example.com')
        user.set_password('password123')
        session.add(user)
        session.commit()
        
        # Initially account should not be locked
        assert user.is_locked() is False
        
        # Lock the account
        user.lock_account(duration_minutes=30)
        session.commit()
        
        # Account should now be locked
        assert user.is_locked() is True
        assert user.failed_login_attempts == 1
        
        # Set locked_until to the past to simulate time passing
        user.locked_until = datetime.utcnow() - timedelta(minutes=1)
        session.commit()
        
        # Account should now be unlocked
        assert user.is_locked() is False


class TestAuditLogModel:
    """Test suite for the AuditLog model."""

    def test_audit_log_creation(self, session, test_user):
        """Test creating a new audit log entry."""
        # Create a new audit log entry
        audit_log = AuditLog(
            user_id=test_user.id,
            action='test_action',
            description='Test description',
            success=True,
            ip_address='127.0.0.1',
            details={'test_key': 'test_value'}
        )
        session.add(audit_log)
        session.commit()
        
        # Retrieve the audit log from the database
        saved_log = AuditLog.query.filter_by(action='test_action').first()
        
        # Check that audit log was saved correctly
        assert saved_log is not None
        assert saved_log.user_id == test_user.id
        assert saved_log.action == 'test_action'
        assert saved_log.description == 'Test description'
        assert saved_log.success is True
        assert saved_log.ip_address == '127.0.0.1'
        assert saved_log.details.get('test_key') == 'test_value'
        assert saved_log.timestamp is not None

    def test_log_action_class_method(self, session, test_user):
        """Test the log_action class method."""
        # Use the class method to create a log entry
        log_entry = AuditLog.log_action(
            user_id=test_user.id,
            action='class_method_test',
            description='Testing class method',
            resource_type='user',
            resource_id=str(test_user.id),
            success=True,
            error_message=None,
            ip_address='192.168.1.1',
            metadata={'source': 'test'}
        )
        
        # Check that log entry was created but not committed
        assert log_entry is not None
        assert log_entry.user_id == test_user.id
        assert log_entry.action == 'class_method_test'
        assert log_entry.description == 'Testing class method'
        assert log_entry.resource_type == 'user'
        assert log_entry.resource_id == str(test_user.id)
        assert log_entry.success is True
        assert log_entry.error_message is None
        assert log_entry.ip_address == '192.168.1.1'
        assert log_entry.details.get('source') == 'test'
        
        # Commit the session to save the log entry
        session.commit()
        
        # Retrieve the log entry from the database
        saved_log = AuditLog.query.filter_by(action='class_method_test').first()
        assert saved_log is not None
        assert saved_log.id == log_entry.id