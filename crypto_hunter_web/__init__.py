"""
Crypto Hunter Web Application
"""
import os
import logging
from logging.handlers import RotatingFileHandler
from flask import Flask, render_template
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import LoginManager
from flask_wtf.csrf import CSRFProtect
from flask_caching import Cache

# Initialize extensions
db = SQLAlchemy()
migrate = Migrate()
login_manager = LoginManager()
csrf = CSRFProtect()
cache = Cache()

def create_app(config_name=None):
    """Create and configure the Flask application"""
    app = Flask(__name__)

    # Load configuration
    if config_name is None:
        config_name = os.getenv('FLASK_CONFIG', 'development')

    if config_name == 'production':
        app.config.from_object('crypto_hunter_web.config.ProductionConfig')
    elif config_name == 'testing':
        app.config.from_object('crypto_hunter_web.config.TestingConfig')
    else:
        app.config.from_object('crypto_hunter_web.config.DevelopmentConfig')

    # Override config from environment variables
    app.config.from_envvar('CRYPTO_HUNTER_SETTINGS', silent=True)

    # Initialize extensions
    db.init_app(app)
    migrate.init_app(app, db)
    login_manager.init_app(app)
    csrf.init_app(app)
    cache.init_app(app)

    # Configure login
    login_manager.login_view = 'auth.login'
    login_manager.login_message_category = 'info'

    # Register blueprints
    from crypto_hunter_web.routes.main import main_bp
    app.register_blueprint(main_bp)

    from crypto_hunter_web.routes.auth import auth_bp
    app.register_blueprint(auth_bp)

    from crypto_hunter_web.routes.files import files_bp
    app.register_blueprint(files_bp)

    from crypto_hunter_web.routes.analysis import analysis_bp
    app.register_blueprint(analysis_bp)

    from crypto_hunter_web.routes.content import content_bp
    app.register_blueprint(content_bp)

    from crypto_hunter_web.routes.dashboard import dashboard_bp
    app.register_blueprint(dashboard_bp)

    from crypto_hunter_web.routes.admin import admin_bp
    app.register_blueprint(admin_bp)

    from crypto_hunter_web.routes.graph import graph_bp
    app.register_blueprint(graph_bp)

    from crypto_hunter_web.routes.search import search_bp
    app.register_blueprint(search_bp)

    from crypto_hunter_web.routes.api.crypto import crypto_api_bp as modern_crypto_api_bp
    app.register_blueprint(modern_crypto_api_bp, url_prefix='/api/crypto')

    # Register puzzle blueprint
    from crypto_hunter_web.routes.puzzle_routes import puzzle_bp
    app.register_blueprint(puzzle_bp)

    # Configure logging
    if not app.debug and not app.testing:
        if not os.path.exists('logs'):
            os.mkdir('logs')
        file_handler = RotatingFileHandler('logs/crypto_hunter.log', maxBytes=10240, backupCount=10)
        file_handler.setFormatter(logging.Formatter(
            '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
        ))
        file_handler.setLevel(logging.INFO)
        app.logger.addHandler(file_handler)

        app.logger.setLevel(logging.INFO)
        app.logger.info('Crypto Hunter startup')

    # Error handlers
    @app.errorhandler(404)
    def not_found_error(error):
        return render_template('errors/404.html'), 404

    @app.errorhandler(500)
    def internal_error(error):
        db.session.rollback()
        return render_template('errors/500.html'), 500

    # Shell context
    @app.shell_context_processor
    def make_shell_context():
        from crypto_hunter_web.models import (
            User, AnalysisFile, Finding, FileContent,
            PuzzleSession, PuzzleStep, PuzzleCollaborator
        )
        return {
            'db': db, 
            'User': User, 
            'AnalysisFile': AnalysisFile, 
            'Finding': Finding, 
            'FileContent': FileContent,
            'PuzzleSession': PuzzleSession,
            'PuzzleStep': PuzzleStep,
            'PuzzleCollaborator': PuzzleCollaborator
        }

    return app
