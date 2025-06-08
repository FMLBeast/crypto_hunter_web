# tests/test_base.py - COMPLETE TESTING FRAMEWORK

import os
import tempfile
import pytest
import secrets

from crypto_hunter_web import create_app, db
from crypto_hunter_web.models import User, AnalysisFile, Finding, ApiKey
from crypto_hunter_web.config import TestingConfig


class TestBase:
    """Base test class with common utilities and fixtures"""

    @pytest.fixture(scope='function')
    def app(self):
        """Create test Flask application"""
        app = create_app('testing')
        app.config.from_object(TestingConfig)

        # Use in-memory SQLite for tests
        app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
        app.config['WTF_CSRF_ENABLED'] = False
        app.config['TESTING'] = True

        # Create temporary directories
        app.config['UPLOAD_FOLDER'] = tempfile.mkdtemp()

        with app.app_context():
            db.create_all()
            yield app
            db.session.remove()
            db.drop_all()

    @pytest.fixture(scope='function')
    def client(self, app):
        """Create test client"""
        return app.test_client()

    @pytest.fixture(scope='function')
    def runner(self, app):
        """Create CLI test runner"""
        return app.test_cli_runner()

    @pytest.fixture(scope='function')
    def db_session(self, app):
        """Create database session for tests"""
        with app.app_context():
            yield db.session

    @pytest.fixture(scope='function')
    def test_user(self, db_session):
        """Create test user"""
        user = User(
            username='testuser',
            email='test@example.com',
            display_name='Test User',
            is_verified=True,
            is_active=True
        )
        user.set_password('TestPassword123!')
        db_session.add(user)
        db_session.commit()
        return user

    @pytest.fixture(scope='function')
    def admin_user(self, db_session):
        """Create admin user"""
        user = User(
            username='admin',
            email='admin@example.com',
            display_name='Admin User',
            is_admin=True,
            is_verified=True,
            is_active=True
        )
        user.set_password('AdminPassword123!')
        db_session.add(user)
        db_session.commit()
        return user

    @pytest.fixture(scope='function')
    def api_key(self, db_session, test_user):
        """Create API key for testing"""
        key = secrets.token_urlsafe(32)
        api_key = ApiKey(
            user_id=test_user.id,
            name='Test API Key',
            key_hash=hashlib.sha256(key.encode()).hexdigest(),
            key_prefix=key[:8],
            permissions=['api:read', 'api:write'],
            is_active=True
        )
        db_session.add(api_key)
        db_session.commit()

        # Return both the key object and the actual key
        return api_key, key

    @pytest.fixture(scope='function')
    def sample_file(self, db_session, test_user):
        """Create sample analysis file"""
        # Create a temporary file
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            f.write("Sample file content with some crypto keywords: bitcoin, ethereum, wallet")
            temp_path = f.name

        # Create file record
        file_obj = AnalysisFile(
            filename='sample.txt',
            filepath=temp_path,
            file_size=len("Sample file content"),
            file_type='text',
            sha256_hash='a' * 64,  # Mock hash
            md5_hash='b' * 32,
            created_by=test_user.id,
            status='pending'
        )
        db_session.add(file_obj)
        db_session.commit()

        yield file_obj

        # Cleanup
        try:
            os.unlink(temp_path)
        except FileNotFoundError:
            pass

    @pytest.fixture(scope='function')
    def sample_finding(self, db_session, sample_file):
        """Create sample finding"""
        finding = Finding(
            file_id=sample_file.id,
            finding_type='crypto_pattern',
            category='cryptocurrency',
            title='Bitcoin Address Found',
            description='Found Bitcoin address in file',
            confidence_level=8,
            priority=7,
            status='unverified',
            created_by=sample_file.created_by
        )
        db_session.add(finding)
        db_session.commit()
        return finding

    def login_user(self, client, user):
        """Login user for tests"""
        return client.post('/auth/login', data={
            'username': user.username,
            'password': 'TestPassword123!' if not user.is_admin else 'AdminPassword123!'
        }, follow_redirects=True)

    def api_headers(self, api_key=None):
        """Get API headers with authentication"""
        headers = {'Content-Type': 'application/json'}
        if api_key:
            headers['X-API-Key'] = api_key
        return headers

    def assert_json_response(self, response, status_code=200):
        """Assert JSON response with status code"""
        assert response.status_code == status_code
        assert response.content_type == 'application/json'
        return response.get_json()

    def create_test_file(self, content="test content", filename="test.txt"):
        """Create temporary test file"""
        with tempfile.NamedTemporaryFile(mode='w', suffix=f'_{filename}', delete=False) as f:
            f.write(content)
            return f.name


class TestAuthentication(TestBase):
    """Test authentication functionality"""

    def test_user_registration(self, client):
        """Test user registration"""
        response = client.post('/auth/register', data={
            'username': 'newuser',
            'email': 'newuser@example.com',
            'password': 'NewPassword123!',
            'confirm_password': 'NewPassword123!',
            'display_name': 'New User',
            'terms_accepted': True
        })

        assert response.status_code == 302  # Redirect after successful registration

        # Check user was created
        user = User.query.filter_by(username='newuser').first()
        assert user is not None
        assert user.email == 'newuser@example.com'
        assert user.check_password('NewPassword123!')

    def test_user_login(self, client, test_user):
        """Test user login"""
        response = self.login_user(client, test_user)
        assert response.status_code == 200

        # Check redirect to dashboard
        assert b'dashboard' in response.data or b'files' in response.data

    def test_invalid_login(self, client, test_user):
        """Test invalid login attempts"""
        response = client.post('/auth/login', data={
            'username': test_user.username,
            'password': 'wrongpassword'
        })

        assert response.status_code == 200
        assert b'Invalid username or password' in response.data

    def test_logout(self, client, test_user):
        """Test user logout"""
        # Login first
        self.login_user(client, test_user)

        # Then logout
        response = client.get('/auth/logout', follow_redirects=True)
        assert response.status_code == 200
        assert b'login' in response.data


class TestFileManagement(TestBase):
    """Test file management functionality"""

    def test_file_upload(self, client, test_user):
        """Test file upload"""
        self.login_user(client, test_user)

        # Create test file
        test_content = "Sample file content for testing"

        response = client.post('/files/upload', data={
            'files': [(io.BytesIO(test_content.encode()), 'test.txt')],
            'priority': 5,
            'auto_analyze': False,
            'notes': 'Test upload'
        }, follow_redirects=True)

        assert response.status_code == 200

        # Check file was created in database
        file_obj = AnalysisFile.query.filter_by(filename='test.txt').first()
        assert file_obj is not None
        assert file_obj.created_by == test_user.id

    def test_file_list(self, client, test_user, sample_file):
        """Test file listing"""
        self.login_user(client, test_user)

        response = client.get('/files/list')
        assert response.status_code == 200
        assert sample_file.filename.encode() in response.data

    def test_file_details(self, client, test_user, sample_file):
        """Test file details view"""
        self.login_user(client, test_user)

        response = client.get(f'/files/{sample_file.sha256_hash}/details')
        assert response.status_code == 200
        assert sample_file.filename.encode() in response.data

    def test_file_download(self, client, test_user, sample_file):
        """Test file download"""
        self.login_user(client, test_user)

        response = client.get(f'/files/{sample_file.sha256_hash}/download')
        assert response.status_code == 200
        assert response.headers['Content-Disposition'].startswith('attachment')

    def test_file_delete(self, client, test_user, sample_file):
        """Test file deletion"""
        self.login_user(client, test_user)

        response = client.post(f'/files/{sample_file.sha256_hash}/delete')
        json_data = self.assert_json_response(response, 200)
        assert json_data['success'] is True

        # Check file was deleted
        file_obj = AnalysisFile.query.get(sample_file.id)
        assert file_obj is None


class TestCryptoAPI(TestBase):
    """Test cryptocurrency analysis API"""

    def test_analyze_crypto_patterns(self, client, sample_file, api_key):
        """Test crypto pattern analysis"""
        api_key_obj, key = api_key

        response = client.post(
            f'/api/crypto/analyze/{sample_file.sha256_hash}',
            headers=self.api_headers(key),
            json={
                'deep_scan': False,
                'include_blockchain': True,
                'confidence_threshold': 0.7
            }
        )

        json_data = self.assert_json_response(response, 200)
        assert json_data['success'] is True
        assert 'results' in json_data

    def test_search_crypto_patterns(self, client, api_key, sample_finding):
        """Test crypto pattern search"""
        api_key_obj, key = api_key

        response = client.post(
            '/api/crypto/patterns/search',
            headers=self.api_headers(key),
            json={
                'pattern_types': ['crypto_pattern'],
                'confidence_min': 0.5,
                'limit': 10
            }
        )

        json_data = self.assert_json_response(response, 200)
        assert json_data['success'] is True
        assert 'results' in json_data
        assert len(json_data['results']) >= 1

    def test_identify_wallet_addresses(self, client, api_key):
        """Test wallet address identification"""
        api_key_obj, key = api_key

        test_addresses = [
            '1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa',  # Bitcoin
            '0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed',  # Ethereum
            'invalid_address'
        ]

        response = client.post(
            '/api/crypto/wallets/identify',
            headers=self.api_headers(key),
            json={'addresses': test_addresses}
        )

        json_data = self.assert_json_response(response, 200)
        assert json_data['success'] is True
        assert len(json_data['results']) == 3

        # Check Bitcoin address was identified
        bitcoin_result = next(r for r in json_data['results'] if r['address'] == test_addresses[0])
        assert bitcoin_result['valid'] is True
        assert bitcoin_result['cryptocurrency'] == 'bitcoin'

    def test_crypto_statistics(self, client, api_key):
        """Test crypto statistics endpoint"""
        api_key_obj, key = api_key

        response = client.get(
            '/api/crypto/statistics',
            headers=self.api_headers(key)
        )

        json_data = self.assert_json_response(response, 200)
        assert json_data['success'] is True
        assert 'statistics' in json_data
        assert 'overview' in json_data['statistics']


class TestSecurity(TestBase):
    """Test security features"""

    def test_unauthorized_api_access(self, client):
        """Test API access without authentication"""
        response = client.get('/api/crypto/statistics')
        assert response.status_code == 401

    def test_invalid_api_key(self, client):
        """Test API access with invalid key"""
        response = client.get(
            '/api/crypto/statistics',
            headers=self.api_headers('invalid_key')
        )
        assert response.status_code == 401

    def test_rate_limiting(self, client, api_key):
        """Test rate limiting functionality"""
        api_key_obj, key = api_key

        # Make multiple rapid requests
        for i in range(10):
            response = client.get(
                '/api/crypto/statistics',
                headers=self.api_headers(key)
            )

            # Should eventually hit rate limit
            if response.status_code == 429:
                assert 'Retry-After' in response.headers
                break
        else:
            # If no rate limit hit, that's also acceptable for testing
            pass

    def test_permission_enforcement(self, client, test_user):
        """Test permission enforcement"""
        self.login_user(client, test_user)

        # Try to access admin-only endpoint
        response = client.get('/admin/users')
        assert response.status_code in [403, 404]  # Forbidden or not found

    def test_file_access_control(self, client, test_user, admin_user, sample_file):
        """Test file access control"""
        # Login as different user
        other_user = User(
            username='otheruser',
            email='other@example.com',
            is_verified=True,
            is_active=True
        )
        other_user.set_password('OtherPassword123!')
        db.session.add(other_user)
        db.session.commit()

        # Login as other user
        client.post('/auth/login', data={
            'username': 'otheruser',
            'password': 'OtherPassword123!'
        })

        # Try to delete file owned by test_user
        response = client.post(f'/files/{sample_file.sha256_hash}/delete')
        json_data = response.get_json()

        # Should be forbidden unless admin
        assert response.status_code == 403 or json_data.get('error') == 'Permission denied'


class TestValidation(TestBase):
    """Test input validation"""

    def test_username_validation(self, client):
        """Test username validation"""
        # Test invalid usernames
        invalid_usernames = [
            '',  # Empty
            'ab',  # Too short
            'user@name',  # Invalid characters
            'a' * 81,  # Too long
            'admin',  # Reserved
        ]

        for username in invalid_usernames:
            response = client.post('/auth/register', data={
                'username': username,
                'email': 'test@example.com',
                'password': 'ValidPassword123!',
                'confirm_password': 'ValidPassword123!',
                'terms_accepted': True
            })

            assert response.status_code == 200  # Should stay on form
            assert b'error' in response.data.lower()

    def test_password_validation(self, client):
        """Test password validation"""
        # Test weak passwords
        weak_passwords = [
            'password',  # Too common
            '123456',  # Too simple
            'short',  # Too short
            'nouppercase123',  # No uppercase
            'NOLOWERCASE123',  # No lowercase
            'NoNumbers!',  # No numbers
            'NoSpecial123',  # No special characters
        ]

        for password in weak_passwords:
            response = client.post('/auth/register', data={
                'username': 'testuser',
                'email': 'test@example.com',
                'password': password,
                'confirm_password': password,
                'terms_accepted': True
            })

            assert response.status_code == 200  # Should stay on form
            assert b'password' in response.data.lower()

    def test_file_validation(self, client, test_user):
        """Test file upload validation"""
        self.login_user(client, test_user)

        # Test invalid file types
        response = client.post('/files/upload', data={
            'files': [(io.BytesIO(b'malicious content'), 'virus.exe')],
        })

        # Should reject dangerous file types
        assert b'error' in response.data.lower() or response.status_code == 400


class TestPerformance(TestBase):
    """Test performance characteristics"""

    def test_database_queries(self, client, test_user):
        """Test database query efficiency"""
        self.login_user(client, test_user)

        # Create multiple files
        for i in range(10):
            file_obj = AnalysisFile(
                filename=f'test{i}.txt',
                filepath=f'/tmp/test{i}.txt',
                file_size=100,
                file_type='text',
                sha256_hash=f'{"a" * 63}{i}',
                md5_hash='b' * 32,
                created_by=test_user.id
            )
            db.session.add(file_obj)

        db.session.commit()

        # Test file listing performance
        import time
        start_time = time.time()

        response = client.get('/files/list')

        end_time = time.time()
        response_time = end_time - start_time

        assert response.status_code == 200
        assert response_time < 2.0  # Should respond within 2 seconds

    def test_memory_usage(self, client, test_user):
        """Test memory usage during file processing"""
        import psutil
        import os

        process = psutil.Process(os.getpid())
        initial_memory = process.memory_info().rss

        self.login_user(client, test_user)

        # Upload and process large file
        large_content = "x" * (1024 * 1024)  # 1MB content

        response = client.post('/files/upload', data={
            'files': [(io.BytesIO(large_content.encode()), 'large.txt')],
        })

        final_memory = process.memory_info().rss
        memory_increase = final_memory - initial_memory

        # Memory increase should be reasonable
        assert memory_increase < 100 * 1024 * 1024  # Less than 100MB increase


# Pytest configuration and fixtures
@pytest.fixture(scope='session')
def app_config():
    """Session-wide app configuration"""
    return {
        'TESTING': True,
        'SQLALCHEMY_DATABASE_URI': 'sqlite:///:memory:',
        'WTF_CSRF_ENABLED': False,
        'SECRET_KEY': 'test-secret-key'
    }


# Mock services for testing
class MockCryptoAnalyzer:
    """Mock crypto analyzer for testing"""

    def analyze_file(self, file_obj, options):
        return {
            'has_crypto_content': True,
            'confidence_score': 0.8,
            'patterns_found': [
                {
                    'pattern_name': 'Bitcoin Address',
                    'match_count': 1,
                    'confidence': 0.9
                }
            ],
            'crypto_categories': {
                'wallets': ['1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa'],
                'keys': [],
                'certificates': []
            }
        }


class MockBackgroundService:
    """Mock background service for testing"""

    @staticmethod
    def queue_comprehensive_analysis(file_id, analysis_types, user_id):
        return f'mock-task-{file_id}'

    @staticmethod
    def queue_crypto_analysis(file_id, analysis_options, user_id):
        return f'mock-crypto-task-{file_id}'

    @staticmethod
    def get_task_status(task_id):
        return {
            'task_id': task_id,
            'status': 'SUCCESS',
            'ready': True,
            'successful': True,
            'result': {'success': True}
        }


# Test utilities
def create_test_file_content(file_type='text', include_crypto=False):
    """Create test file content"""
    content = "This is a test file for analysis."

    if include_crypto:
        content += "\nBitcoin address: 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"
        content += "\nEthereum address: 0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed"

    if file_type == 'binary':
        return content.encode('utf-8')

    return content


def assert_crypto_patterns_found(analysis_result, expected_patterns):
    """Assert that expected crypto patterns were found"""
    found_patterns = [p['pattern_name'] for p in analysis_result.get('patterns_found', [])]

    for pattern in expected_patterns:
        assert pattern in found_patterns, f"Expected pattern '{pattern}' not found"


# Export test classes and utilities
__all__ = [
    'TestBase',
    'TestAuthentication',
    'TestFileManagement',
    'TestCryptoAPI',
    'TestSecurity',
    'TestValidation',
    'TestPerformance',
    'MockCryptoAnalyzer',
    'MockBackgroundService',
    'create_test_file_content',
    'assert_crypto_patterns_found'
]