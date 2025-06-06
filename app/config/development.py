"""
Development configuration
"""

from .base import Config

class DevelopmentConfig(Config):
    """Development configuration"""
    DEBUG = True
    TESTING = False
    
    # Development database
    SQLALCHEMY_DATABASE_URI = 'sqlite:///arweave_tracker_dev.db'
    SQLALCHEMY_ECHO = True  # Log SQL queries
    
    # Looser security for development
    WTF_CSRF_ENABLED = False
