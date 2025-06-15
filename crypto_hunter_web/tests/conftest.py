import os
import uuid
import pytest
from flask import Flask
from flask_login import LoginManager
from sqlalchemy import create_engine, event, String, TypeDecorator
from sqlalchemy.dialects.postgresql import JSON, UUID, TIMESTAMP, DOUBLE_PRECISION
from sqlalchemy.orm import sessionmaker, scoped_session
from sqlalchemy.dialects import sqlite

from crypto_hunter_web.extensions import db as _db
from crypto_hunter_web.models import User, AuditLog
from crypto_hunter_web.services.auth_service import AuthService

# SQLite compatibility for PostgreSQL types
# These type adapters allow SQLite to work with PostgreSQL-specific types
# by converting them to SQLite-compatible types at runtime.

class SqliteUUID(TypeDecorator):
    """SQLite-compatible UUID type.

    PostgreSQL has native UUID type support, but SQLite doesn't.
    This adapter stores UUIDs as strings in SQLite and converts them
    back to UUID objects when retrieving from the database.
    """
    impl = String
    cache_ok = True

    def process_bind_param(self, value, dialect):
        """Convert UUID to string when storing in SQLite."""
        if value is None:
            return None
        return str(value)

    def process_result_value(self, value, dialect):
        """Convert string back to UUID when retrieving from SQLite."""
        if value is None:
            return None
        return uuid.UUID(value)

class SqliteJSON(TypeDecorator):
    """SQLite-compatible JSON type.

    PostgreSQL has native JSON type support, but SQLite doesn't.
    This adapter serializes JSON data to strings in SQLite and
    deserializes them back to Python objects when retrieving.
    """
    impl = String
    cache_ok = True

    def process_bind_param(self, value, dialect):
        """Serialize JSON to string when storing in SQLite."""
        import json
        if value is None:
            return None
        return json.dumps(value)

    def process_result_value(self, value, dialect):
        """Deserialize string back to JSON when retrieving from SQLite."""
        import json
        if value is None:
            return None
        return json.loads(value)

class SqliteTimestamp(TypeDecorator):
    """SQLite-compatible TIMESTAMP type.

    PostgreSQL has a native TIMESTAMP type with timezone support,
    but SQLite only has DATETIME. This adapter ensures compatibility
    between the two types.
    """
    impl = sqlite.DATETIME
    cache_ok = True

    def process_bind_param(self, value, dialect):
        """Convert TIMESTAMP to DATETIME when storing in SQLite."""
        if value is None:
            return None
        return value

    def process_result_value(self, value, dialect):
        """Return DATETIME as is when retrieving from SQLite."""
        return value

# Test database URI
TEST_DATABASE_URI = os.environ.get(
    'TEST_DATABASE_URI',
    'sqlite:///:memory:'  # Use in-memory SQLite for tests by default
)

# Register type adapters for SQLite
sqlite.dialect.ischema_names['json'] = SqliteJSON
sqlite.dialect.ischema_names['uuid'] = SqliteUUID
sqlite.dialect.ischema_names['timestamp'] = sqlite.DATETIME

# Create a function to set SQLite pragmas and replace PostgreSQL types
def setup_sqlite_for_testing(engine):
    """Set up SQLite for testing with PostgreSQL models.

    This function performs two important tasks:
    1. Enables SQLite foreign key support (off by default in SQLite)
    2. Replaces PostgreSQL-specific column types with SQLite-compatible versions

    Args:
        engine: The SQLAlchemy engine to configure
    """
    # Set SQLite pragmas for better PostgreSQL compatibility
    @event.listens_for(engine, "connect")
    def _set_sqlite_pragma(dbapi_connection, connection_record):
        if engine.dialect.name == 'sqlite':
            cursor = dbapi_connection.cursor()
            # Enable foreign key support (required for relationship tests)
            cursor.execute("PRAGMA foreign_keys=ON")
            cursor.close()

    # Replace PostgreSQL types with SQLite-compatible versions
    # This is necessary because SQLite doesn't support PostgreSQL-specific types
    if engine.dialect.name == 'sqlite':
        for table in _db.metadata.tables.values():
            for column in table.columns:
                # Replace UUID columns with our custom SqliteUUID type
                if isinstance(column.type, UUID):
                    column.type = SqliteUUID()
                # Replace JSON columns with our custom SqliteJSON type
                elif isinstance(column.type, JSON):
                    column.type = SqliteJSON()
                # Replace TIMESTAMP columns with our custom SqliteTimestamp type
                elif isinstance(column.type, TIMESTAMP):
                    column.type = SqliteTimestamp()


@pytest.fixture(scope='session')
def app():
    """Create and configure a Flask application for testing.

    This fixture creates a Flask application with a test database,
    initializes Flask-Login, and sets up the database tables.

    If using SQLite (the default), it also configures the SQLite
    compatibility layer to handle PostgreSQL-specific types.

    Returns:
        Flask: A configured Flask application for testing
    """
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
        # Set up SQLite compatibility layer if using SQLite
        # This allows our PostgreSQL models to work with SQLite in tests
        if app.config['SQLALCHEMY_DATABASE_URI'].startswith('sqlite'):
            setup_sqlite_for_testing(_db.engine)

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
