# crypto_hunter_web/__init__.py - PRODUCTION-READY APP FACTORY WITH ROBUST LOGGING

import os
import logging
from datetime import timedelta
from pathlib import Path
from flask import Flask, request, jsonify, g
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import LoginManager
from flask_wtf.csrf import CSRFProtect
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_caching import Cache
import redis
from werkzeug.middleware.proxy_fix import ProxyFix

# Extensions
db = SQLAlchemy()
migrate = Migrate()
login_manager = LoginManager()
csrf = CSRFProtect()
cors = CORS()
limiter = Limiter(key_func=get_remote_address)
cache = Cache()


def setup_logging(app):
    """Setup robust logging configuration"""
    try:
        # Ensure logs directory exists
        logs_dir = Path('logs')
        logs_dir.mkdir(exist_ok=True)

        # Set permissions if directory was just created
        if logs_dir.exists():
            import stat
            os.chmod(logs_dir, stat.S_IRWXU | stat.S_IRGRP | stat.S_IXGRP)

        # Configure logging
        log_level = getattr(logging, app.config.get('LOG_LEVEL', 'INFO').upper())
        log_format = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'

        # Create handlers list
        handlers = []

        # Always add console handler
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(logging.Formatter(log_format))
        handlers.append(console_handler)

        # Try to add file handler
        log_file = logs_dir / 'crypto_hunter.log'
        try:
            # Test if we can write to the log file
            log_file.touch(exist_ok=True)

            file_handler = logging.FileHandler(str(log_file))
            file_handler.setFormatter(logging.Formatter(log_format))
            handlers.append(file_handler)

            app.logger.info(f"Logging to file: {log_file}")

        except (PermissionError, OSError) as e:
            # If file logging fails, just use console
            app.logger.warning(f"Cannot write to log file {log_file}: {e}")
            app.logger.warning("Using console logging only")

        # Configure root logger
        logging.basicConfig(
            level=log_level,
            format=log_format,
            handlers=handlers,
            force=True  # Override any existing configuration
        )

        # Set specific logger levels
        logging.getLogger('werkzeug').setLevel(logging.WARNING)
        logging.getLogger('sqlalchemy.engine').setLevel(logging.WARNING)

        app.logger.info("Logging configuration completed successfully")

    except Exception as e:
        # Fallback to basic console logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[logging.StreamHandler()]
        )
        print(f"Warning: Logging setup failed, using basic console logging: {e}")


logger = logging.getLogger(__name__)


def create_app(config_name='default'):
    """Create and configure the Flask application with security and performance optimizations"""
    app = Flask(__name__, instance_relative_config=True)

    # Trust proxy headers (for load balancers, reverse proxies)
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1)

    # Load configuration
    configure_app(app, config_name)

    # Setup logging first (before other operations)
    setup_logging(app)

    # Initialize extensions
    initialize_extensions(app)

    # Configure security
    configure_security(app)

    # Register blueprints
    register_blueprints(app)

    # Register error handlers
    register_error_handlers(app)

    # Register CLI commands
    register_cli_commands(app)

    # Setup monitoring and health checks
    setup_monitoring(app)

    # Application context processors
    setup_context_processors(app)

    # Initialize Sentry if configured
    init_sentry(app)

    logger.info(f"Crypto Hunter app created successfully in {config_name} mode")

    return app


def configure_app(app, config_name):
    """Configure Flask application with environment-specific settings"""

    # Base configuration
    app.config.update(
        # Core Flask settings
        SECRET_KEY=os.getenv('SECRET_KEY', 'dev-secret-key-change-in-production'),

        # Database configuration
        SQLALCHEMY_DATABASE_URI=os.getenv('DATABASE_URL',
                                          'postgresql://postgres:password@localhost:5432/crypto_hunter'),
        SQLALCHEMY_TRACK_MODIFICATIONS=False,
        SQLALCHEMY_ENGINE_OPTIONS={
            'pool_pre_ping': True,
            'pool_recycle': 300,
            'pool_timeout': 20,
            'max_overflow': 20
        },

        # File upload settings
        MAX_CONTENT_LENGTH=int(os.getenv('MAX_CONTENT_LENGTH', 1024 * 1024 * 1024)),  # 1GB default
        UPLOAD_FOLDER=os.getenv('UPLOAD_FOLDER', 'uploads'),

        # Session and security
        SESSION_COOKIE_SECURE=os.getenv('SESSION_COOKIE_SECURE', 'False').lower() == 'true',
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE='Lax',
        WTF_CSRF_TIME_LIMIT=3600,

        # Redis and caching
        CACHE_TYPE='redis',
        CACHE_REDIS_URL=os.getenv('REDIS_URL', 'redis://localhost:6379/1'),
        CACHE_DEFAULT_TIMEOUT=300,

        # Celery configuration
        CELERY_BROKER_URL=os.getenv('CELERY_BROKER_URL', 'redis://localhost:6379/2'),
        CELERY_RESULT_BACKEND=os.getenv('CELERY_RESULT_BACKEND', 'redis://localhost:6379/3'),
        CELERY_TASK_SERIALIZER='json',
        CELERY_ACCEPT_CONTENT=['json'],
        CELERY_RESULT_SERIALIZER='json',
        CELERY_TIMEZONE='UTC',

        # Rate limiting
        RATELIMIT_STORAGE_URL=os.getenv('REDIS_URL', 'redis://localhost:6379/4'),
        RATELIMIT_DEFAULT='1000 per hour, 10000 per day',
        RATELIMIT_HEADERS_ENABLED=True,

        # AI/LLM configuration
        OPENAI_API_KEY=os.getenv('OPENAI_API_KEY'),
        ANTHROPIC_API_KEY=os.getenv('ANTHROPIC_API_KEY'),
        LLM_MODEL=os.getenv('LLM_MODEL', 'gpt-4'),
        LLM_MAX_TOKENS=int(os.getenv('LLM_MAX_TOKENS', 4000)),
        LLM_TEMPERATURE=float(os.getenv('LLM_TEMPERATURE', 0.1)),

        # Performance settings
        SEND_FILE_MAX_AGE_DEFAULT=timedelta(hours=12),
        JSONIFY_PRETTYPRINT_REGULAR=False,

        # Logging configuration
        LOG_LEVEL=os.getenv('LOG_LEVEL', 'INFO'),
        LOG_FILE=os.getenv('LOG_FILE', 'logs/crypto_hunter.log'),
        LOG_MAX_BYTES=int(os.getenv('LOG_MAX_BYTES', 10485760)),
        LOG_BACKUP_COUNT=int(os.getenv('LOG_BACKUP_COUNT', 5)),

        # Feature flags
        ENABLE_REGISTRATION=os.getenv('ENABLE_REGISTRATION', 'True').lower() == 'true',
        ENABLE_API=os.getenv('ENABLE_API', 'True').lower() == 'true',
        ENABLE_BACKGROUND_TASKS=os.getenv('ENABLE_BACKGROUND_TASKS', 'True').lower() == 'true',
        ENABLE_AI_ANALYSIS=os.getenv('ENABLE_AI_ANALYSIS', 'True').lower() == 'true',

        # Monitoring and metrics
        PROMETHEUS_METRICS=os.getenv('PROMETHEUS_METRICS', 'False').lower() == 'true',
        SENTRY_DSN=os.getenv('SENTRY_DSN'),

        # CORS settings
        CORS_ORIGINS=os.getenv('CORS_ORIGINS', 'http://localhost:3000,http://localhost:8000').split(','),
    )

    # Environment-specific overrides
    if config_name == 'development':
        app.config.update(
            DEBUG=True,
            TESTING=False,
            WTF_CSRF_ENABLED=False,
            SESSION_COOKIE_SECURE=False,
            SQLALCHEMY_ENGINE_OPTIONS={**app.config['SQLALCHEMY_ENGINE_OPTIONS'], 'echo': False}
            # Don't echo SQL in dev
        )
    elif config_name == 'testing':
        app.config.update(
            TESTING=True,
            WTF_CSRF_ENABLED=False,
            LOGIN_DISABLED=True,
            SQLALCHEMY_DATABASE_URI='sqlite:///:memory:',
            CACHE_TYPE='simple',
            CELERY_TASK_ALWAYS_EAGER=True,
        )
    elif config_name == 'production':
        app.config.update(
            DEBUG=False,
            TESTING=False,
            WTF_CSRF_ENABLED=True,
            SESSION_COOKIE_SECURE=True,
            PREFERRED_URL_SCHEME='https'
        )

    # Ensure directories exist
    for directory in [app.config['UPLOAD_FOLDER'], 'instance', 'logs']:
        try:
            Path(directory).mkdir(exist_ok=True, parents=True)
        except PermissionError:
            # If we can't create the directory, log a warning but continue
            print(f"Warning: Cannot create directory {directory}")


def initialize_extensions(app):
    """Initialize Flask extensions with proper configuration"""

    # Database
    db.init_app(app)
    migrate.init_app(app, db)

    # Authentication
    login_manager.init_app(app)
    login_manager.login_view = 'auth.login'
    login_manager.login_message = 'Please log in to access this page.'
    login_manager.login_message_category = 'info'

    @login_manager.user_loader
    def load_user(user_id):
        from crypto_hunter_web.models import User
        return User.query.get(int(user_id))

    # CSRF Protection
    csrf.init_app(app)

    # CORS
    cors.init_app(app, origins=app.config['CORS_ORIGINS'])

    # Rate Limiting
    try:
        limiter.init_app(app)
    except Exception as e:
        app.logger.warning(f"Rate limiting not available: {e}")

    # Caching
    try:
        cache.init_app(app)
    except Exception as e:
        app.logger.warning(f"Caching not available: {e}")


def configure_security(app):
    """Configure security headers and policies"""

    @app.after_request
    def security_headers(response):
        # Security headers
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'DENY'
        response.headers['X-XSS-Protection'] = '1; mode=block'

        if app.config.get('SESSION_COOKIE_SECURE'):
            response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'

        return response


def register_blueprints(app):
    """Register application blueprints"""
    try:
        from crypto_hunter_web.routes.main import main_bp
        app.register_blueprint(main_bp)
    except ImportError as e:
        app.logger.warning(f"Main blueprint not available: {e}")

    try:
        from crypto_hunter_web.routes.auth import auth_bp
        app.register_blueprint(auth_bp, url_prefix='/auth')
    except ImportError as e:
        app.logger.warning(f"Auth blueprint not available: {e}")

    try:
        from crypto_hunter_web.routes.api import api_bp
        app.register_blueprint(api_bp, url_prefix='/api')
    except ImportError as e:
        app.logger.warning(f"API blueprint not available: {e}")

    try:
        from crypto_hunter_web.routes.files import files_bp
        app.register_blueprint(files_bp, url_prefix='/files')
    except ImportError as e:
        app.logger.warning(f"Files blueprint not available: {e}")


def register_error_handlers(app):
    """Register custom error handlers"""

    @app.errorhandler(404)
    def not_found_error(error):
        return jsonify({'error': 'Resource not found'}), 404

    @app.errorhandler(500)
    def internal_error(error):
        db.session.rollback()
        return jsonify({'error': 'Internal server error'}), 500


def register_cli_commands(app):
    """Register CLI commands"""
    try:
        from crypto_hunter_web.cli import cli
        app.cli.add_command(cli)
    except ImportError as e:
        app.logger.warning(f"CLI commands not available: {e}")


def setup_monitoring(app):
    """Setup health checks and monitoring endpoints"""

    @app.route('/health')
    def health_check():
        try:
            # Test database connection
            db.session.execute('SELECT 1')
            return jsonify({
                'status': 'healthy',
                'database': 'connected',
                'timestamp': '2025-06-08'
            })
        except Exception as e:
            return jsonify({
                'status': 'unhealthy',
                'database': 'error',
                'error': str(e)
            }), 500


def setup_context_processors(app):
    """Setup template context processors"""

    @app.context_processor
    def inject_config():
        return {
            'ENABLE_REGISTRATION': app.config.get('ENABLE_REGISTRATION', False),
            'ENABLE_AI_ANALYSIS': app.config.get('ENABLE_AI_ANALYSIS', False)
        }


def init_sentry(app):
    """Initialize Sentry error tracking"""
    sentry_dsn = app.config.get('SENTRY_DSN')
    if sentry_dsn:
        try:
            import sentry_sdk
            from sentry_sdk.integrations.flask import FlaskIntegration
            from sentry_sdk.integrations.sqlalchemy import SqlalchemyIntegration

            sentry_sdk.init(
                dsn=sentry_dsn,
                integrations=[
                    FlaskIntegration(transaction_style='endpoint'),
                    SqlalchemyIntegration(),
                ],
                traces_sample_rate=0.1,
                environment=app.config.get('ENV', 'production')
            )

            app.logger.info("Sentry error tracking initialized")
        except ImportError:
            app.logger.warning("Sentry SDK not installed, error tracking disabled")


# Export the create_app function and extensions
__all__ = ['create_app', 'db', 'migrate', 'login_manager', 'cache', 'limiter']