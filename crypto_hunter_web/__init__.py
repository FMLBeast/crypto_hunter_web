#!/usr/bin/env python3
from .extensions import db, login_manager, csrf, redis_client, cache, limiter, migrate
"""
Crypto Hunter Web Application
Flask application factory and configuration
"""

import os
import logging
from flask import Flask
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Version info
__version__ = '1.0.0'
__author__ = 'Crypto Hunter Team'


def create_app(config_name=None):
    """Application factory pattern"""

    # Create Flask application
    app = Flask(__name__)

    # Configure application
    configure_app(app, config_name)
    os.makedirs('instance', exist_ok=True)
    # Initialize extensions
    init_extensions(app)

    # Register blueprints
    register_blueprints(app)

    # Setup error handlers
    setup_error_handlers(app)

    # Setup logging
    setup_logging(app)

    return app


def configure_app(app, config_name=None):
    """Configure Flask application"""

    # Determine configuration
    config_name = config_name or os.getenv('FLASK_ENV', 'development')

    # Basic configuration
    app.config.update(
        SECRET_KEY=os.getenv('SECRET_KEY', 'dev-secret-key-change-in-production'),
        SQLALCHEMY_DATABASE_URI=os.getenv('DATABASE_URL', 'sqlite:///instance/crypto_hunter.db'),
        SQLALCHEMY_TRACK_MODIFICATIONS=False,
        MAX_CONTENT_LENGTH=int(os.getenv('MAX_CONTENT_LENGTH', 1024 * 1024 * 1024)),  # 1GB
        UPLOAD_FOLDER=os.getenv('UPLOAD_FOLDER', 'uploads'),

        # Redis configuration
        REDIS_URL=os.getenv('REDIS_URL', 'redis://localhost:6379/0'),
        # Celery (fall back to Redis if not explicitly set)
        CELERY_BROKER_URL = os.getenv('CELERY_BROKER_URL', os.getenv('REDIS_URL')),
        CELERY_RESULT_BACKEND = os.getenv('CELERY_RESULT_BACKEND', os.getenv('REDIS_URL')),
        # Security
        WTF_CSRF_ENABLED=True,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SECURE=os.getenv('SESSION_COOKIE_SECURE', 'False').lower() == 'true',

        # Features
        ENABLE_REGISTRATION=os.getenv('ENABLE_REGISTRATION', 'true').lower() == 'true',
        ENABLE_AI_ANALYSIS=os.getenv('ENABLE_AI_ANALYSIS', 'false').lower() == 'true',
    )

    # Environment-specific configuration
    if config_name == 'development':
        app.config.update(
            DEBUG=True,
            TESTING=False,
        )
    elif config_name == 'testing':
        app.config.update(
            DEBUG=False,
            TESTING=True,
            SQLALCHEMY_DATABASE_URI='sqlite:///instance/test.db',
            WTF_CSRF_ENABLED=False,
        )
    elif config_name == 'production':
        app.config.update(
            DEBUG=False,
            TESTING=False,
            SESSION_COOKIE_SECURE=True,
        )

    # Create upload folder
    upload_folder = app.config['UPLOAD_FOLDER']
    os.makedirs(upload_folder, exist_ok=True)


def init_extensions(app):
    """Initialize Flask extensions"""

    # SQLAlchemy
    try:
        db.init_app(app)
        try:
            with app.app_context():
                db.create_all()
        except Exception as e:
            app.logger.warning(f"DB initialization warning: {e}")
    except ImportError as e:
        app.logger.warning(f"Database extension not available: {e}")
    # Flask-Login
    try:
        from crypto_hunter_web.extensions import login_manager
        login_manager.init_app(app)
        login_manager.login_view = 'auth.login'
        login_manager.login_message = 'Please log in to access this page.'
    except ImportError as e:
        app.logger.warning(f"Login manager not available: {e}")

    # Flask-WTF CSRF
    try:
        from crypto_hunter_web.extensions import csrf
        csrf.init_app(app)
    except ImportError as e:
        app.logger.warning(f"CSRF protection not available: {e}")

    # Redis
    try:
        from crypto_hunter_web.extensions import redis_client
        redis_client.init_app(app)
    except ImportError as e:
        app.logger.warning(f"Redis not available: {e}")


def register_blueprints(app):
    """Register application blueprints"""

    # Main dashboard blueprint
    try:
        from crypto_hunter_web.routes.dashboard import dashboard_bp
        app.register_blueprint(dashboard_bp)
    except ImportError as e:
        app.logger.warning(f"Dashboard blueprint not available: {e}")

    # Other blueprints with graceful fallback
    blueprints = [
        ('crypto_hunter_web.routes.auth', 'auth_bp', None),
        ('crypto_hunter_web.routes.files', 'files_bp', None),
        ('crypto_hunter_web.routes.analysis', 'analysis_bp', None),
        ('crypto_hunter_web.routes.graph', 'graph_bp', None),
        ('crypto_hunter_web.routes.content', 'content_bp', None),
        ('crypto_hunter_web.routes.admin', 'admin_bp', None),
        ('crypto_hunter_web.routes.crypto_api', 'crypto_api_bp', '/api/crypto'),
        ('crypto_hunter_web.routes.search_api', 'search_api_bp', '/api/search'),
    ]

    for module_path, blueprint_name, url_prefix in blueprints:
        try:
            module = __import__(module_path, fromlist=[blueprint_name])
            blueprint = getattr(module, blueprint_name)
            if url_prefix:
                app.register_blueprint(blueprint, url_prefix=url_prefix)
            else:
                app.register_blueprint(blueprint)
            app.logger.info(f"Registered blueprint: {blueprint_name}")
        except (ImportError, AttributeError) as e:
            app.logger.warning(f"Blueprint {blueprint_name} not available: {e}")


def setup_error_handlers(app):
    """Setup error handlers"""

    @app.errorhandler(404)
    def not_found(error):
        return {'error': 'Resource not found'}, 404

    @app.errorhandler(500)
    def internal_error(error):
        return {'error': 'Internal server error'}, 500

    @app.errorhandler(403)
    def forbidden(error):
        return {'error': 'Access forbidden'}, 403


def setup_logging(app):
    """Setup application logging"""

    # Create logs directory
    os.makedirs('logs', exist_ok=True)

    # Configure logging
    log_level = getattr(logging, os.getenv('LOG_LEVEL', 'INFO').upper())
    logging.basicConfig(
        level=log_level,
        format='%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]',
        handlers=[
            logging.FileHandler('logs/crypto_hunter.log'),
            logging.StreamHandler()
        ]
    )

    app.logger.setLevel(log_level)
