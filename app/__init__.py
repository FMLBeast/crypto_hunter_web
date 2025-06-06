"""
Flask application factory for Arweave Puzzle #11 Tracker
"""

import os
import logging
from logging.handlers import RotatingFileHandler
from flask import Flask
from pathlib import Path

# Import extensions
from app.models import db

# Import blueprints
from app.routes.auth import auth_bp
from app.routes.files import files_bp
from app.routes.content import content_bp
from app.routes.graph import graph_bp
from app.routes.analysis import analysis_bp
from app.routes.api import api_bp
from app.routes.background_api import background_api_bp
from app.routes.crypto_api import crypto_api_bp
from app.routes.llm_crypto_api import llm_crypto_api_bp
from app.routes.search_api import search_api_bp


def create_app(config_name='development'):
    """Create and configure Flask application"""

    # Create Flask app with correct template/static paths
    app = Flask(__name__,
                template_folder='templates',
                static_folder='static')

    # Load configuration
    if config_name == 'development':
        app.config.update({
            'SECRET_KEY': 'dev-secret-key-change-in-production',
            'SQLALCHEMY_DATABASE_URI': 'sqlite:///arweave_puzzle.db',
            'SQLALCHEMY_TRACK_MODIFICATIONS': False,
            'UPLOAD_FOLDER': 'bulk_uploads',
            'MAX_CONTENT_LENGTH': 500 * 1024 * 1024  # 500MB max file size
        })
    elif config_name == 'production':
        app.config.update({
            'SECRET_KEY': os.environ.get('SECRET_KEY') or 'fallback-secret-key',
            'SQLALCHEMY_DATABASE_URI': os.environ.get('DATABASE_URL') or 'sqlite:///arweave_puzzle.db',
            'SQLALCHEMY_TRACK_MODIFICATIONS': False,
            'UPLOAD_FOLDER': os.environ.get('UPLOAD_FOLDER') or 'bulk_uploads',
            'MAX_CONTENT_LENGTH': 500 * 1024 * 1024
        })

    # Ensure upload directories exist
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    os.makedirs(os.path.join(app.config['UPLOAD_FOLDER'], 'discovered_files'), exist_ok=True)

    # Initialize extensions
    db.init_app(app)

    # Register blueprints
    app.register_blueprint(auth_bp, url_prefix='/auth')
    app.register_blueprint(files_bp, url_prefix='/')
    app.register_blueprint(content_bp, url_prefix='/content')
    app.register_blueprint(graph_bp, url_prefix='/graph')
    app.register_blueprint(analysis_bp, url_prefix='/analysis')
    app.register_blueprint(api_bp, url_prefix='/api')
    app.register_blueprint(background_api_bp, url_prefix='/background_api')
    app.register_blueprint(crypto_api_bp, url_prefix='/crypto_api')
    app.register_blueprint(llm_crypto_api_bp, url_prefix='/llm_crypto_api')
    app.register_blueprint(search_api_bp, url_prefix='/search_api')

    # Register main routes
    @app.route('/')
    def index():
        """Redirect to dashboard or login"""
        from flask import session, redirect, url_for
        if 'user_id' in session:
            return redirect(url_for('files.dashboard'))
        return redirect(url_for('auth.login'))

    # Setup logging
    if not app.debug and not app.testing:
        setup_logging(app)
    
    # Setup error handlers
    setup_error_handlers(app)
    
    # Setup template filters
    setup_template_filters(app)
    
    return app


def setup_logging(app):
    """Configure application logging"""
    if not os.path.exists('logs'):
        os.mkdir('logs')
    
    file_handler = RotatingFileHandler(
        'logs/arweave_tracker.log',
        maxBytes=10240000,  # 10MB
        backupCount=10
    )
    file_handler.setFormatter(logging.Formatter(
        '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
    ))
    file_handler.setLevel(logging.INFO)
    app.logger.addHandler(file_handler)
    
    app.logger.setLevel(logging.INFO)
    app.logger.info('Arweave Puzzle Tracker startup')


def setup_error_handlers(app):
    """Setup custom error handlers"""
    
    @app.errorhandler(404)
    def not_found_error(error):
        from flask import render_template
        return render_template('errors/404.html'), 404
    
    @app.errorhandler(500)
    def internal_error(error):
        from flask import render_template
        db.session.rollback()
        return render_template('errors/500.html'), 500
    
    @app.errorhandler(403)
    def forbidden_error(error):
        from flask import render_template
        return render_template('errors/403.html'), 403


def setup_template_filters(app):
    """Setup custom Jinja2 template filters"""
    
    @app.template_filter('filesizeformat')
    def filesizeformat(value):
        """Format file size in human readable format"""
        if not value:
            return "0 bytes"
        
        try:
            value = int(value)
        except (ValueError, TypeError):
            return "Unknown"
        
        for unit in ['bytes', 'KB', 'MB', 'GB', 'TB']:
            if value < 1024.0:
                if unit == 'bytes':
                    return f"{value} {unit}"
                return f"{value:.1f} {unit}"
            value /= 1024.0
        return f"{value:.1f} PB"
    
    @app.template_filter('timeago')
    def timeago(value):
        """Format datetime as time ago"""
        from datetime import datetime, timedelta
        
        if not value:
            return "Never"
        
        now = datetime.utcnow()
        diff = now - value
        
        if diff.days > 365:
            return f"{diff.days // 365} year{'s' if diff.days // 365 > 1 else ''} ago"
        elif diff.days > 30:
            return f"{diff.days // 30} month{'s' if diff.days // 30 > 1 else ''} ago"
        elif diff.days > 0:
            return f"{diff.days} day{'s' if diff.days > 1 else ''} ago"
        elif diff.seconds > 3600:
            hours = diff.seconds // 3600
            return f"{hours} hour{'s' if hours > 1 else ''} ago"
        elif diff.seconds > 60:
            minutes = diff.seconds // 60
            return f"{minutes} minute{'s' if minutes > 1 else ''} ago"
        else:
            return "Just now"
    
    @app.template_filter('truncate_sha')
    def truncate_sha(value, length=8):
        """Truncate SHA hash for display"""
        if not value:
            return ""
        return value[:length] + ('...' if len(value) > length else '')


# Make create_app importable
__all__ = ['create_app']