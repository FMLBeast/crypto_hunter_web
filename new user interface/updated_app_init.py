"""
Crypto Hunter Web Application
Complete Flask application initialization with all components working
"""
import os
import logging
from logging.handlers import RotatingFileHandler
from flask import Flask, render_template, request, jsonify

# Import extensions from extensions.py
from crypto_hunter_web.extensions import (
    db, migrate, login_manager, csrf, cache, init_all_extensions
)

def create_app(config_name=None, database_url=None):
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

    # Override database URL if provided
    if database_url:
        app.config['SQLALCHEMY_DATABASE_URI'] = database_url
        app.logger.info(f"Using custom database URL: {database_url}")

    # Initialize all extensions
    init_all_extensions(app)

    # Add CSRF token to all templates
    @app.context_processor
    def inject_csrf_token():
        from flask_wtf.csrf import generate_csrf
        return dict(csrf_token=generate_csrf)

    # Register all blueprints
    register_blueprints(app)

    # Setup error handlers
    setup_error_handlers(app)

    # Setup database
    setup_database(app)

    # Configure logging
    setup_logging(app)

    # Add template filters
    setup_template_filters(app)

    # Add health check endpoint
    @app.route('/health')
    def health_check():
        """Health check endpoint"""
        try:
            # Test database connection
            db.session.execute('SELECT 1')
            return jsonify({
                'status': 'healthy',
                'message': 'Crypto Hunter is running',
                'version': '2.0.0'
            })
        except Exception as e:
            app.logger.error(f"Health check failed: {e}")
            return jsonify({
                'status': 'unhealthy',
                'message': str(e)
            }), 500

    return app


def register_blueprints(app):
    """Register all application blueprints"""
    try:
        # Import and register all blueprints
        from crypto_hunter_web.routes import register_all_blueprints
        register_all_blueprints(app)
        
    except Exception as e:
        app.logger.error(f"Error registering blueprints: {e}")
        # Fallback to manual registration
        register_blueprints_fallback(app)


def register_blueprints_fallback(app):
    """Fallback blueprint registration"""
    try:
        from crypto_hunter_web.routes.main import main_bp
        app.register_blueprint(main_bp)
    except ImportError:
        app.logger.warning("Could not import main blueprint")

    try:
        from crypto_hunter_web.routes.auth import auth_bp
        app.register_blueprint(auth_bp, url_prefix='/auth')
    except ImportError:
        app.logger.warning("Could not import auth blueprint")

    try:
        from crypto_hunter_web.routes.dashboard import dashboard_bp
        app.register_blueprint(dashboard_bp, url_prefix='/dashboard')
    except ImportError:
        app.logger.warning("Could not import dashboard blueprint")

    try:
        from crypto_hunter_web.routes.files import files_bp
        app.register_blueprint(files_bp, url_prefix='/files')
    except ImportError:
        app.logger.warning("Could not import files blueprint")

    try:
        from crypto_hunter_web.routes.analysis import analysis_bp
        app.register_blueprint(analysis_bp, url_prefix='/analysis')
    except ImportError:
        app.logger.warning("Could not import analysis blueprint")

    try:
        from crypto_hunter_web.routes.graph import graph_bp
        app.register_blueprint(graph_bp, url_prefix='/graph')
    except ImportError:
        app.logger.warning("Could not import graph blueprint")

    try:
        from crypto_hunter_web.routes.puzzle_routes import puzzle_bp
        app.register_blueprint(puzzle_bp, url_prefix='/puzzle')
    except ImportError:
        app.logger.warning("Could not import puzzle blueprint")


def setup_error_handlers(app):
    """Setup comprehensive error handlers"""
    
    @app.errorhandler(404)
    def not_found_error(error):
        return render_template('errors/404.html'), 404

    @app.errorhandler(500)
    def internal_error(error):
        db.session.rollback()
        return render_template('errors/500.html'), 500

    @app.errorhandler(403)
    def forbidden_error(error):
        return render_template('errors/403.html'), 403

    @app.errorhandler(400)
    def bad_request_error(error):
        return render_template('errors/400.html'), 400

    @app.errorhandler(413)
    def request_entity_too_large(error):
        return render_template('errors/413.html'), 413

    @app.errorhandler(429)
    def ratelimit_handler(error):
        return render_template('errors/429.html'), 429

    # API error handlers
    @app.errorhandler(404)
    def api_not_found(error):
        if request.path.startswith('/api/'):
            return jsonify({'error': 'Not found'}), 404
        return not_found_error(error)

    @app.errorhandler(500)
    def api_internal_error(error):
        if request.path.startswith('/api/'):
            return jsonify({'error': 'Internal server error'}), 500
        return internal_error(error)


def setup_database(app):
    """Setup database and create tables if needed"""
    with app.app_context():
        try:
            # Try to create tables
            db.create_all()
            
            # Initialize default data if needed
            init_default_data()
            
            app.logger.info("Database setup completed")
            
        except Exception as e:
            app.logger.error(f"Database setup error: {e}")


def init_default_data():
    """Initialize default data if database is empty"""
    try:
        from crypto_hunter_web.models import User, Vector
        
        # Check if we need to create default user
        if User.query.count() == 0:
            from werkzeug.security import generate_password_hash
            
            admin_user = User(
                username='admin',
                email='admin@cryptohunter.local',
                password_hash=generate_password_hash('admin123'),
                is_admin=True
            )
            db.session.add(admin_user)
            
        # Check if we need to create default vectors
        if Vector.query.count() == 0:
            default_vectors = [
                {
                    'name': 'LSB Steganography Detection',
                    'description': 'Detect LSB steganography in images',
                    'category': 'steganography',
                    'enabled': True,
                    'priority': 8,
                    'config': '{"tool": "zsteg", "options": ["-a"]}'
                },
                {
                    'name': 'String Analysis',
                    'description': 'Extract and analyze strings from files',
                    'category': 'forensics',
                    'enabled': True,
                    'priority': 5,
                    'config': '{"min_length": 4, "encoding": "utf-8"}'
                },
                {
                    'name': 'Entropy Analysis',
                    'description': 'Calculate file entropy to detect encryption/compression',
                    'category': 'cryptography',
                    'enabled': True,
                    'priority': 6,
                    'config': '{"block_size": 256}'
                }
            ]
            
            for vector_data in default_vectors:
                vector = Vector(**vector_data)
                db.session.add(vector)
        
        db.session.commit()
        
    except Exception as e:
        db.session.rollback()
        logging.error(f"Error initializing default data: {e}")


def setup_logging(app):
    """Setup application logging"""
    if not app.debug and not app.testing:
        if not os.path.exists('logs'):
            os.mkdir('logs')
            
        file_handler = RotatingFileHandler(
            'logs/crypto_hunter.log', 
            maxBytes=10240000, 
            backupCount=10
        )
        file_handler.setFormatter(logging.Formatter(
            '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
        ))
        file_handler.setLevel(logging.INFO)
        app.logger.addHandler(file_handler)
        
        app.logger.setLevel(logging.INFO)
        app.logger.info('Crypto Hunter startup')


def setup_template_filters(app):
    """Setup custom template filters"""
    
    @app.template_filter('filesizeformat')
    def filesizeformat(bytes_size):
        """Format file size in human readable format"""
        if bytes_size is None:
            return 'Unknown'
        
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if bytes_size < 1024.0:
                return f"{bytes_size:.1f} {unit}"
            bytes_size /= 1024.0
        return f"{bytes_size:.1f} PB"
    
    @app.template_filter('truncate')
    def truncate_filter(text, length=50):
        """Truncate text to specified length"""
        if not text:
            return ""
        if len(text) <= length:
            return text
        return text[:length-3] + "..."
    
    @app.template_filter('datetimeformat')
    def datetimeformat(value, format='%Y-%m-%d %H:%M'):
        """Format datetime objects"""
        if value is None:
            return ""
        return value.strftime(format)
    
    @app.template_filter('pluralize')
    def pluralize(count, singular='', plural='s'):
        """Pluralize words based on count"""
        if count == 1:
            return singular
        return plural
    
    @app.template_filter('highlight')
    def highlight_filter(text, term):
        """Highlight search terms in text"""
        if not term or not text:
            return text
        import re
        highlighted = re.sub(f'({re.escape(term)})', r'<mark>\1</mark>', text, flags=re.IGNORECASE)
        return highlighted
    
    @app.template_filter('status_color')
    def status_color(status):
        """Get color class for status"""
        colors = {
            'complete': 'green',
            'processing': 'blue', 
            'pending': 'yellow',
            'error': 'red',
            'cancelled': 'gray'
        }
        return colors.get(status, 'gray')


# Initialize the application
def init_app():
    """Initialize the application with default settings"""
    return create_app()


# For backwards compatibility
app = None

def get_app():
    """Get or create the application instance"""
    global app
    if app is None:
        app = create_app()
    return app