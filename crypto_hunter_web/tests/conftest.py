import os
import uuid
import pytest
from flask import Flask
from flask_login import LoginManager
from sqlalchemy import create_engine, event, String, TypeDecorator
from sqlalchemy.dialects.postgresql import JSON, UUID, TIMESTAMP, DOUBLE_PRECISION
from sqlalchemy.orm import sessionmaker, scoped_session

from crypto_hunter_web.extensions import db as _db
from crypto_hunter_web.models import User, AuditLog
from crypto_hunter_web.services.auth_service import AuthService

# SQLite compatibility for PostgreSQL types
class SqliteUUID(TypeDecorator):
    """SQLite-compatible UUID type."""
    impl = String
    cache_ok = True

    def process_bind_param(self, value, dialect):
        if value is None:
            return None
        return str(value)

    def process_result_value(self, value, dialect):
        if value is None:
            return None
        return uuid.UUID(value)

class SqliteJSON(TypeDecorator):
    """SQLite-compatible JSON type."""
    impl = String
    cache_ok = True

    def process_bind_param(self, value, dialect):
        import json
        if value is None:
            return None
        return json.dumps(value)

    def process_result_value(self, value, dialect):
        import json
        if value is None:
            return None
        return json.loads(value)

# Test database URI
TEST_DATABASE_URI = os.environ.get(
    'TEST_DATABASE_URI',
    'sqlite:///:memory:'  # Use in-memory SQLite for tests by default
)

# Register type adapters for SQLite
from sqlalchemy.dialects import sqlite
sqlite.dialect.ischema_names['json'] = SqliteJSON
sqlite.dialect.ischema_names['uuid'] = SqliteUUID
sqlite.dialect.ischema_names['timestamp'] = sqlite.DATETIME


@pytest.fixture(scope='session')
def app():
    """Create and configure a Flask application for testing."""
    app = Flask('crypto_hunter_test')
    app.config.update({
        'TESTING': True,
        'DEBUG': False,
        'SQLALCHEMY_DATABASE_URI': TEST_DATABASE_URI,
        'SQLALCHEMY_TRACK_MODIFICATIONS': False,
        'SECRET_KEY': 'test-secret-key',
        'WTF_CSRF_ENABLED': False,  # Disable CSRF for testing
    })

    # Initialize extensions
    _db.init_app(app)

    # Initialize Flask-Login
    login_manager = LoginManager()
    login_manager.init_app(app)

    @login_manager.user_loader
    def load_user(user_id):
        return User.query.get(int(user_id))

    # Create a minimal application context
    with app.app_context():
        _db.create_all()  # Create all tables
        yield app
        _db.drop_all()  # Drop all tables after tests


@pytest.fixture(scope='function')
def db(app):
    """Create a fresh database for each test."""
    with app.app_context():
        _db.drop_all()
        _db.create_all()
        yield _db
        _db.session.remove()


@pytest.fixture(scope='function')
def session(db):
    """Create a new database session for a test."""
    connection = db.engine.connect()
    transaction = connection.begin()

    session = scoped_session(
        sessionmaker(autocommit=False, autoflush=False, bind=connection)
    )

    db.session = session

    yield session

    transaction.rollback()
    connection.close()
    session.remove()


@pytest.fixture(scope='function')
def client(app):
    """Create a test client for the app."""
    return app.test_client()


@pytest.fixture(scope='function')
def test_user(session):
    """Create a test user."""
    user = User(
        username='testuser',
        email='test@example.com',
        is_active=True,
        is_admin=False
    )
    user.set_password('password123')
    session.add(user)
    session.commit()
    return user


@pytest.fixture(scope='function')
def admin_user(session):
    """Create an admin user."""
    user = User(
        username='adminuser',
        email='admin@example.com',
        is_active=True,
        is_admin=True
    )
    user.set_password('adminpass123')
    session.add(user)
    session.commit()
    return user


@pytest.fixture(scope='function')
def auth_service():
    """Create an instance of the AuthService."""
    return AuthService()


@pytest.fixture(scope='function')
def authenticated_client(client, test_user):
    """Create a client with an authenticated user."""
    with client.session_transaction() as session:
        # Log in the user
        client.post('/login', data={
            'username': test_user.username,
            'password': 'password123'
        }, follow_redirects=True)
    return client
