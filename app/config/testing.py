"""
Testing configuration
"""

from .base import Config

class TestingConfig(Config):
    """Testing configuration"""
    TESTING = True
    DEBUG = True
    
    # In-memory database for tests
    SQLALCHEMY_DATABASE_URI = 'sqlite:///:memory:'
    
    # Disable CSRF for testing
    WTF_CSRF_ENABLED = False
    
    # Smaller limits for testing
    MAX_CONTENT_LENGTH = 1024 * 1024  # 1MB
