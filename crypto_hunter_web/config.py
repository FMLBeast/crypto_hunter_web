# crypto_hunter_web/config.py - COMPLETE CONFIGURATION MANAGEMENT

import json
import logging
import os
import secrets
from datetime import timedelta
from typing import Dict, List, Any
from urllib.parse import quote_plus

from sqlalchemy.sql.coercions import cls


class ConfigurationError(Exception):
    """Configuration related errors"""
    pass


class BaseConfig:
    """Base configuration with common settings"""

    # Application
    SECRET_KEY = os.getenv('SECRET_KEY') or secrets.token_hex(32)
    APPLICATION_NAME = 'Crypto Hunter'
    APPLICATION_VERSION = '2.0.0'
    APPLICATION_DESCRIPTION = 'Advanced Cryptocurrency and Cryptographic Analysis Platform'

    # Environment
    FLASK_ENV = os.getenv('FLASK_ENV', 'production')
    DEBUG = False
    TESTING = False

    # Database
    SQLALCHEMY_DATABASE_URI = os.getenv('DATABASE_URL', 'sqlite:///instance/crypto_hunter.db')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_RECORD_QUERIES = False
    SQLALCHEMY_ENGINE_OPTIONS = {
        'pool_pre_ping': True,
        'pool_recycle': 3600,
        'pool_timeout': 20,
        'max_overflow': 20,
        'pool_size': 10,
        'echo': False
    }

    # Security
    WTF_CSRF_ENABLED = True
    WTF_CSRF_TIME_LIMIT = 3600
    WTF_CSRF_SSL_STRICT = True
    SESSION_COOKIE_SECURE = True
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    PERMANENT_SESSION_LIFETIME = timedelta(hours=24)
    REMEMBER_COOKIE_DURATION = timedelta(days=30)
    REMEMBER_COOKIE_SECURE = True
    REMEMBER_COOKIE_HTTPONLY = True

    # File Upload
    UPLOAD_FOLDER = os.getenv('UPLOAD_FOLDER', '../uploads')
    MAX_CONTENT_LENGTH = int(os.getenv('MAX_CONTENT_LENGTH', 1073741824))  # 1GB
    ALLOWED_EXTENSIONS = {
        'txt', 'log', 'md', 'json', 'xml', 'csv', 'yaml', 'yml',
        'pdf', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx',
        'jpg', 'jpeg', 'png', 'gif', 'bmp', 'tiff', 'webp',
        'zip', 'rar', '7z', 'tar', 'gz', 'bz2', 'xz',
        'exe', 'dll', 'so', 'bin', 'img', 'iso',
        'py', 'js', 'html', 'css', 'cpp', 'c', 'java',
        'key', 'pem', 'crt', 'cer', 'p12', 'pfx',
        'pcap', 'pcapng', 'cap'
    }

    # Redis
    REDIS_URL = os.getenv('REDIS_URL', 'redis://localhost:6379/0')

    # Celery
    CELERY_BROKER_URL = os.getenv('CELERY_BROKER_URL', 'redis://localhost:6379/2')
    CELERY_RESULT_BACKEND = os.getenv('CELERY_RESULT_BACKEND', 'redis://localhost:6379/3')
    CELERY_TASK_SERIALIZER = 'json'
    CELERY_ACCEPT_CONTENT = ['json']
    CELERY_RESULT_SERIALIZER = 'json'
    CELERY_TIMEZONE = 'UTC'
    CELERY_ENABLE_UTC = True
    CELERY_TASK_ALWAYS_EAGER = False
    CELERY_WORKER_PREFETCH_MULTIPLIER = 1
    CELERY_TASK_ACKS_LATE = True
    CELERY_RESULT_EXPIRES = 86400  # 24 hours

    # Caching
    CACHE_TYPE = 'redis'
    CACHE_REDIS_URL = os.getenv('CACHE_REDIS_URL', 'redis://localhost:6379/1')
    CACHE_DEFAULT_TIMEOUT = 300
    CACHE_KEY_PREFIX = 'crypto_hunter:'

    # Rate Limiting
    RATELIMIT_STORAGE_URL = os.getenv('RATELIMIT_STORAGE_URL', 'redis://localhost:6379/4')
    RATELIMIT_DEFAULT = "1000 per hour, 10000 per day"
    RATELIMIT_HEADERS_ENABLED = True
    RATELIMIT_STRATEGY = "fixed-window"

    # Logging
    LOG_LEVEL = os.getenv('LOG_LEVEL', 'INFO')
    LOG_FILE = os.getenv('LOG_FILE', 'logs/crypto_hunter.log')
    LOG_MAX_BYTES = int(os.getenv('LOG_MAX_BYTES', 10485760))  # 10MB
    LOG_BACKUP_COUNT = int(os.getenv('LOG_BACKUP_COUNT', 5))
    LOG_FORMAT = '%(asctime)s %(levelname)s [%(name)s] %(message)s'

    # AI/LLM Services
    OPENAI_API_KEY = os.getenv('OPENAI_API_KEY')
    OPENAI_MODEL = os.getenv('OPENAI_MODEL', 'gpt-4')
    OPENAI_MAX_TOKENS = int(os.getenv('OPENAI_MAX_TOKENS', 4000))
    OPENAI_TEMPERATURE = float(os.getenv('OPENAI_TEMPERATURE', 0.1))

    ANTHROPIC_API_KEY = os.getenv('ANTHROPIC_API_KEY')
    ANTHROPIC_MODEL = os.getenv('ANTHROPIC_MODEL', 'claude-3-sonnet-20240229')
    ANTHROPIC_MAX_TOKENS = int(os.getenv('ANTHROPIC_MAX_TOKENS', 4000))

    # AI Budget Controls
    LLM_DAILY_BUDGET = float(os.getenv('LLM_DAILY_BUDGET', '100.0'))
    LLM_HOURLY_BUDGET = float(os.getenv('LLM_HOURLY_BUDGET', '20.0'))
    LLM_COST_PER_1K_TOKENS = float(os.getenv('LLM_COST_PER_1K_TOKENS', '0.03'))

    # Email (Optional)
    MAIL_SERVER = os.getenv('MAIL_SERVER')
    MAIL_PORT = int(os.getenv('MAIL_PORT', 587))
    MAIL_USE_TLS = os.getenv('MAIL_USE_TLS', 'true').lower() == 'true'
    MAIL_USE_SSL = os.getenv('MAIL_USE_SSL', 'false').lower() == 'true'
    MAIL_USERNAME = os.getenv('MAIL_USERNAME')
    MAIL_PASSWORD = os.getenv('MAIL_PASSWORD')
    MAIL_DEFAULT_SENDER = os.getenv('MAIL_DEFAULT_SENDER', 'noreply@cryptohunter.local')

    # Feature Flags
    ENABLE_REGISTRATION = os.getenv('ENABLE_REGISTRATION', 'true').lower() == 'true'
    ENABLE_API = os.getenv('ENABLE_API', 'true').lower() == 'true'
    ENABLE_BACKGROUND_TASKS = os.getenv('ENABLE_BACKGROUND_TASKS', 'true').lower() == 'true'
    ENABLE_AI_ANALYSIS = os.getenv('ENABLE_AI_ANALYSIS', 'true').lower() == 'true'
    ENABLE_CRYPTO_ANALYSIS = os.getenv('ENABLE_CRYPTO_ANALYSIS', 'true').lower() == 'true'
    ENABLE_FILE_UPLOAD = os.getenv('ENABLE_FILE_UPLOAD', 'true').lower() == 'true'
    ENABLE_GRAPH_VISUALIZATION = os.getenv('ENABLE_GRAPH_VISUALIZATION', 'true').lower() == 'true'

    # Monitoring and Metrics
    PROMETHEUS_METRICS = os.getenv('PROMETHEUS_METRICS', 'false').lower() == 'true'
    SENTRY_DSN = os.getenv('SENTRY_DSN')
    HEALTH_CHECK_TOKEN = os.getenv('HEALTH_CHECK_TOKEN', secrets.token_urlsafe(32))

    # CORS
    CORS_ORIGINS = os.getenv('CORS_ORIGINS', 'http://localhost:3000,http://localhost:8000').split(',')
    CORS_METHODS = ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS']
    CORS_ALLOW_HEADERS = ['Content-Type', 'Authorization', 'X-API-Key', 'X-Requested-With']

    # API Configuration
    API_TITLE = 'Crypto Hunter API'
    API_VERSION = 'v1'
    API_DESCRIPTION = 'Advanced Cryptocurrency and Cryptographic Analysis API'
    API_RATE_LIMIT = "1000 per hour"
    API_MAX_PAGE_SIZE = 1000
    API_DEFAULT_PAGE_SIZE = 50

    # Pagination
    PAGINATION_PER_PAGE = 50
    PAGINATION_MAX_PER_PAGE = 1000

    # Analysis Settings
    MAX_ANALYSIS_FILE_SIZE = int(os.getenv('MAX_ANALYSIS_FILE_SIZE', 536870912))  # 512MB
    MAX_CONCURRENT_ANALYSES = int(os.getenv('MAX_CONCURRENT_ANALYSES', 10))
    ANALYSIS_TIMEOUT = int(os.getenv('ANALYSIS_TIMEOUT', 3600))  # 1 hour
    AUTO_ANALYSIS_ENABLED = os.getenv('AUTO_ANALYSIS_ENABLED', 'true').lower() == 'true'

    # Crypto Pattern Detection
    CRYPTO_CONFIDENCE_THRESHOLD = float(os.getenv('CRYPTO_CONFIDENCE_THRESHOLD', 0.7))
    CRYPTO_SCAN_TIMEOUT = int(os.getenv('CRYPTO_SCAN_TIMEOUT', 300))  # 5 minutes

    # File Retention
    FILE_RETENTION_DAYS = int(os.getenv('FILE_RETENTION_DAYS', 90))
    CLEANUP_ORPHANED_FILES = os.getenv('CLEANUP_ORPHANED_FILES', 'true').lower() == 'true'

    # Internationalization
    LANGUAGES = {
        'en': 'English',
        'es': 'Español',
        'fr': 'Français',
        'de': 'Deutsch',
        'ja': '日本語',
        'zh': '中文'
    }
    BABEL_DEFAULT_LOCALE = 'en'
    BABEL_DEFAULT_TIMEZONE = 'UTC'

    # Performance
    SEND_FILE_MAX_AGE_DEFAULT = timedelta(hours=12)
    JSONIFY_PRETTYPRINT_REGULAR = False

    @classmethod
    def init_app(cls, app):
        """Initialize app with this configuration"""
        # Ensure required directories exist
        for directory in [cls.UPLOAD_FOLDER, 'instance', 'logs']:
            os.makedirs(directory, exist_ok=True)

        # Set up logging
        cls._setup_logging(app)

        # Validate configuration
        cls._validate_config(app)

    @classmethod
    def _setup_logging(cls, app):
        """Set up application logging"""
        import logging.handlers

        # Set log level
        log_level = getattr(logging, cls.LOG_LEVEL.upper(), logging.INFO)

        # Create formatter
        formatter = logging.Formatter(cls.LOG_FORMAT)

        # File handler
        if cls.LOG_FILE:
            file_handler = logging.handlers.RotatingFileHandler(
                cls.LOG_FILE,
                maxBytes=cls.LOG_MAX_BYTES,
                backupCount=cls.LOG_BACKUP_COUNT
            )
            file_handler.setFormatter(formatter)
            file_handler.setLevel(log_level)
            app.logger.addHandler(file_handler)

        # Console handler
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(formatter)
        console_handler.setLevel(log_level)
        app.logger.addHandler(console_handler)

        app.logger.setLevel(log_level)

    @classmethod
    def _validate_config(cls, app):
        """Validate configuration settings"""
        errors = []

        # Required settings
        if not cls.SECRET_KEY or cls.SECRET_KEY == 'dev-secret-key':
            errors.append("SECRET_KEY must be set to a secure random value")

        # Database URL
        if not hasattr(cls, 'SQLALCHEMY_DATABASE_URI') or not cls.SQLALCHEMY_DATABASE_URI:
            errors.append("Database URL must be configured")

        # Upload folder
        if not os.path.exists(cls.UPLOAD_FOLDER):
            try:
                os.makedirs(cls.UPLOAD_FOLDER, exist_ok=True)
            except Exception as e:
                errors.append(f"Cannot create upload folder: {e}")

        # AI configuration warnings
        if cls.ENABLE_AI_ANALYSIS and not (cls.OPENAI_API_KEY or cls.ANTHROPIC_API_KEY):
            app.logger.warning("AI analysis enabled but no API keys configured")

        if errors:
            raise ConfigurationError(f"Configuration errors: {'; '.join(errors)}")


class DevelopmentConfig(BaseConfig):
    """Development configuration"""

    DEBUG = True
    TESTING = False

    # Use SQLite for development
    SQLALCHEMY_DATABASE_URI = os.getenv(
        'DATABASE_URL',
        'sqlite:///instance/crypto_hunter_dev.db'
    )

    # Disable security features for development
    WTF_CSRF_ENABLED = False
    SESSION_COOKIE_SECURE = False
    REMEMBER_COOKIE_SECURE = False
    WTF_CSRF_SSL_STRICT = False

    # Enable SQL query logging
    SQLALCHEMY_ENGINE_OPTIONS = {
        **BaseConfig.SQLALCHEMY_ENGINE_OPTIONS,
        'echo': True
    }
    SQLALCHEMY_RECORD_QUERIES = True

    # Relaxed rate limits
    RATELIMIT_ENABLED = False
    API_RATE_LIMIT = "10000 per hour"

    # Enable all features
    ENABLE_REGISTRATION = True
    ENABLE_API = True
    ENABLE_BACKGROUND_TASKS = True
    ENABLE_AI_ANALYSIS = True

    # Development-specific settings
    MAIL_SUPPRESS_SEND = True
    EXPLAIN_TEMPLATE_LOADING = True

    # Smaller file size limits for testing
    MAX_CONTENT_LENGTH = 100 * 1024 * 1024  # 100MB
    MAX_ANALYSIS_FILE_SIZE = 50 * 1024 * 1024  # 50MB

    # Fast cache expiration for development
    CACHE_DEFAULT_TIMEOUT = 30

    @classmethod
    def init_app(cls, app):
        super().init_app(app)

        # Development-specific initialization
        app.logger.info("Running in DEVELOPMENT mode")
        app.logger.warning("Security features are disabled for development")


class TestingConfig(BaseConfig):
    """Testing configuration"""

    DEBUG = True
    TESTING = True

    # In-memory database for testing
    SQLALCHEMY_DATABASE_URI = 'sqlite:///:memory:'

    # Disable security features for testing
    WTF_CSRF_ENABLED = False
    LOGIN_DISABLED = True

    # Fast execution for tests
    CELERY_TASK_ALWAYS_EAGER = True
    CELERY_TASK_EAGER_PROPAGATES = True

    # Simple cache for testing
    CACHE_TYPE = 'simple'
    CACHE_DEFAULT_TIMEOUT = 1

    # Disable rate limiting
    RATELIMIT_ENABLED = False

    # Disable email
    MAIL_SUPPRESS_SEND = True

    # Smaller limits for faster tests
    MAX_CONTENT_LENGTH = 1024 * 1024  # 1MB
    MAX_ANALYSIS_FILE_SIZE = 512 * 1024  # 512KB

    # Enable all features for testing
    ENABLE_REGISTRATION = True
    ENABLE_API = True
    ENABLE_BACKGROUND_TASKS = False  # Synchronous for testing
    ENABLE_AI_ANALYSIS = False  # Mock in tests

    @classmethod
    def init_app(cls, app):
        super().init_app(app)
        app.logger.setLevel(logging.CRITICAL)  # Reduce noise in tests


class StagingConfig(BaseConfig):
    """Staging configuration"""

    DEBUG = False
    TESTING = False

    # PostgreSQL for staging
    SQLALCHEMY_DATABASE_URI = os.getenv('DATABASE_URL') or \
                              'postgresql://crypto_hunter:password@localhost/crypto_hunter_staging'

    # Moderate security
    WTF_CSRF_ENABLED = True
    SESSION_COOKIE_SECURE = False  # May not have HTTPS in staging

    # Staging-specific settings
    LOG_LEVEL = 'DEBUG'

    # Allow more generous limits for testing
    API_RATE_LIMIT = "2000 per hour"
    MAX_CONTENT_LENGTH = 500 * 1024 * 1024  # 500MB

    @classmethod
    def init_app(cls, app):
        super().init_app(app)
        app.logger.info("Running in STAGING mode")


class ProductionConfig(BaseConfig):
    """Production configuration"""

    DEBUG = False
    TESTING = False

    # PostgreSQL for production
    SQLALCHEMY_DATABASE_URI = os.getenv('DATABASE_URL') or \
                              cls._build_postgres_url()

    # Full security enabled
    WTF_CSRF_ENABLED = True
    SESSION_COOKIE_SECURE = True
    REMEMBER_COOKIE_SECURE = True
    WTF_CSRF_SSL_STRICT = True

    # Production logging
    LOG_LEVEL = 'INFO'

    # Strict rate limits
    API_RATE_LIMIT = "1000 per hour"
    RATELIMIT_DEFAULT = "500 per hour, 5000 per day"

    # Production file limits
    MAX_CONTENT_LENGTH = 1 * 1024 * 1024 * 1024  # 1GB
    MAX_ANALYSIS_FILE_SIZE = 512 * 1024 * 1024  # 512MB

    # Conservative feature flags (can be overridden by env vars)
    ENABLE_REGISTRATION = os.getenv('ENABLE_REGISTRATION', 'false').lower() == 'true'

    @classmethod
    def _build_postgres_url(cls):
        """Build PostgreSQL URL from components"""
        host = os.getenv('DB_HOST', 'localhost')
        port = os.getenv('DB_PORT', '5432')
        name = os.getenv('DB_NAME', 'crypto_hunter')
        user = os.getenv('DB_USER', 'crypto_hunter')
        password = os.getenv('DB_PASSWORD', 'password')

        # URL encode password to handle special characters
        password_encoded = quote_plus(password)

        return f'postgresql://{user}:{password_encoded}@{host}:{port}/{name}'

    @classmethod
    def init_app(cls, app):
        super().init_app(app)

        # Production-specific initialization
        app.logger.info("Running in PRODUCTION mode")

        # Initialize Sentry for error tracking
        if cls.SENTRY_DSN:
            cls._init_sentry(app)

        # Initialize Prometheus metrics
        if cls.PROMETHEUS_METRICS:
            cls._init_prometheus(app)

    @classmethod
    def _init_sentry(cls, app):
        """Initialize Sentry error tracking"""
        try:
            import sentry_sdk
            from sentry_sdk.integrations.flask import FlaskIntegration
            from sentry_sdk.integrations.sqlalchemy import SqlalchemyIntegration
            from sentry_sdk.integrations.redis import RedisIntegration
            from sentry_sdk.integrations.celery import CeleryIntegration

            sentry_sdk.init(
                dsn=cls.SENTRY_DSN,
                integrations=[
                    FlaskIntegration(transaction_style='endpoint'),
                    SqlalchemyIntegration(),
                    RedisIntegration(),
                    CeleryIntegration()
                ],
                traces_sample_rate=0.1,
                environment=cls.FLASK_ENV,
                release=cls.APPLICATION_VERSION
            )

            app.logger.info("Sentry error tracking initialized")

        except ImportError:
            app.logger.warning("Sentry SDK not installed")

    @classmethod
    def _init_prometheus(cls, app):
        """Initialize Prometheus metrics"""
        try:
            from prometheus_flask_exporter import PrometheusMetrics

            metrics = PrometheusMetrics(app)
            metrics.info('crypto_hunter_info', 'Crypto Hunter Application',
                         version=cls.APPLICATION_VERSION)

            app.logger.info("Prometheus metrics initialized")

        except ImportError:
            app.logger.warning("Prometheus Flask exporter not installed")


class DockerConfig(ProductionConfig):
    """Docker deployment configuration"""

    # Container-specific settings
    SQLALCHEMY_DATABASE_URI = os.getenv('DATABASE_URL', 'postgresql://postgres:password@db:5432/crypto_hunter')
    REDIS_URL = os.getenv('REDIS_URL', 'redis://redis:6379/0')
    CELERY_BROKER_URL = os.getenv('CELERY_BROKER_URL', 'redis://redis:6379/2')
    CELERY_RESULT_BACKEND = os.getenv('CELERY_RESULT_BACKEND', 'redis://redis:6379/3')

    # Docker-specific paths
    UPLOAD_FOLDER = '/app/uploads'
    LOG_FILE = '/app/logs/crypto_hunter.log'

    @classmethod
    def init_app(cls, app):
        super().init_app(app)
        app.logger.info("Running in DOCKER mode")


# Configuration registry
config = {
    'development': DevelopmentConfig,
    'testing': TestingConfig,
    'staging': StagingConfig,
    'production': ProductionConfig,
    'docker': DockerConfig,
    'default': DevelopmentConfig
}


def get_config(config_name: str = None) -> BaseConfig:
    """Get configuration class by name"""
    if config_name is None:
        config_name = os.getenv('FLASK_ENV', 'default')

    return config.get(config_name, config['default'])


def load_config_from_file(file_path: str) -> Dict[str, Any]:
    """Load configuration from JSON file"""
    try:
        with open(file_path, 'r') as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError) as e:
        raise ConfigurationError(f"Failed to load config from {file_path}: {e}")


def validate_environment() -> List[str]:
    """Validate environment configuration"""
    issues = []

    # Check required environment variables
    required_vars = [
        'SECRET_KEY',
        'DATABASE_URL'
    ]

    for var in required_vars:
        if not os.getenv(var):
            issues.append(f"Missing required environment variable: {var}")

    # Check optional but recommended variables
    recommended_vars = {
        'REDIS_URL': 'Redis is recommended for caching and rate limiting',
        'SENTRY_DSN': 'Sentry is recommended for error tracking in production',
        'MAIL_SERVER': 'Email server is recommended for user notifications'
    }

    for var, reason in recommended_vars.items():
        if not os.getenv(var):
            issues.append(f"Missing recommended environment variable {var}: {reason}")

    return issues


def get_database_url(config_name: str = None) -> str:
    """Get database URL for given configuration"""
    config_class = get_config(config_name)
    return config_class.SQLALCHEMY_DATABASE_URI


def get_redis_url(config_name: str = None) -> str:
    """Get Redis URL for given configuration"""
    config_class = get_config(config_name)
    return config_class.REDIS_URL


# Export main configuration function
__all__ = [
    'BaseConfig',
    'DevelopmentConfig',
    'TestingConfig',
    'StagingConfig',
    'ProductionConfig',
    'DockerConfig',
    'config',
    'get_config',
    'load_config_from_file',
    'validate_environment',
    'get_database_url',
    'get_redis_url',
    'ConfigurationError'
]
