# crypto_hunter_web/__init__.py - COMPLETE PRODUCTION-READY APP FACTORY

import os
import logging
from datetime import timedelta
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

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('logs/crypto_hunter.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)


def create_app(config_name='default'):
    """Create and configure the Flask application with security and performance optimizations"""
    app = Flask(__name__, instance_relative_config=True)

    # Trust proxy headers (for load balancers, reverse proxies)
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1)

    # Load configuration
    configure_app(app, config_name)

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

    # Before/after request handlers
    setup_request_handlers(app)

    logger.info(f"Application created successfully in {config_name} mode")
    return app


def configure_app(app, config_name):
    """Configure application settings with environment-based configs"""

    # Base configuration
    app.config.update(
        # Core Flask settings
        SECRET_KEY=os.getenv("SECRET_KEY", "dev-secret-key-change-in-production-immediately"),

        # Database configuration
        SQLALCHEMY_DATABASE_URI=os.getenv(
            "DATABASE_URL",
            "sqlite:///instance/crypto_hunter.db"
        ),
        SQLALCHEMY_TRACK_MODIFICATIONS=False,
        SQLALCHEMY_ENGINE_OPTIONS={
            'pool_pre_ping': True,
            'pool_recycle': 3600,
            'pool_timeout': 20,
            'max_overflow': 20,
            'pool_size': 10,
            'echo': os.getenv('SQL_DEBUG', 'False').lower() == 'true'
        },

        # Security settings
        WTF_CSRF_TIME_LIMIT=3600,  # 1 hour CSRF token validity
        WTF_CSRF_SSL_STRICT=os.getenv('CSRF_SSL_STRICT', 'True').lower() == 'true',
        SESSION_COOKIE_SECURE=os.getenv('SESSION_COOKIE_SECURE', 'False').lower() == 'true',
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE='Lax',
        PERMANENT_SESSION_LIFETIME=timedelta(hours=24),

        # File handling
        UPLOAD_FOLDER=os.getenv("UPLOAD_FOLDER", "uploads"),
        MAX_CONTENT_LENGTH=int(os.getenv("MAX_CONTENT_LENGTH", 1073741824)),  # 1GB
        ALLOWED_EXTENSIONS={'txt', 'pdf', 'zip', 'rar', '7z', 'tar', 'gz', 'bz2', 'exe', 'dll', 'bin', 'img', 'iso'},

        # Redis and caching
        REDIS_URL=os.getenv("REDIS_URL", "redis://localhost:6379/0"),
        CACHE_TYPE="redis" if os.getenv("REDIS_URL") else "simple",
        CACHE_REDIS_URL=os.getenv("REDIS_URL", "redis://localhost:6379/1"),
        CACHE_DEFAULT_TIMEOUT=300,  # 5 minutes

        # Celery configuration
        CELERY_BROKER_URL=os.getenv("CELERY_BROKER_URL", "redis://localhost:6379/2"),
        CELERY_RESULT_BACKEND=os.getenv("CELERY_RESULT_BACKEND", "redis://localhost:6379/3"),
        CELERY_TASK_SERIALIZER='json',
        CELERY_ACCEPT_CONTENT=['json'],
        CELERY_RESULT_SERIALIZER='json',
        CELERY_TIMEZONE='UTC',

        # Rate limiting
        RATELIMIT_STORAGE_URL=os.getenv("REDIS_URL", "redis://localhost:6379/4"),
        RATELIMIT_DEFAULT="1000 per hour, 10000 per day",
        RATELIMIT_HEADERS_ENABLED=True,

        # AI/LLM configuration
        OPENAI_API_KEY=os.getenv("OPENAI_API_KEY"),
        ANTHROPIC_API_KEY=os.getenv("ANTHROPIC_API_KEY"),
        LLM_MODEL=os.getenv("LLM_MODEL", "gpt-4"),
        LLM_MAX_TOKENS=int(os.getenv("LLM_MAX_TOKENS", 4000)),
        LLM_TEMPERATURE=float(os.getenv("LLM_TEMPERATURE", 0.1)),
        LLM_DAILY_BUDGET=float(os.getenv("LLM_DAILY_BUDGET", "100.0")),
        LLM_HOURLY_BUDGET=float(os.getenv("LLM_HOURLY_BUDGET", "20.0")),

        # Performance settings
        SEND_FILE_MAX_AGE_DEFAULT=timedelta(hours=12),
        JSONIFY_PRETTYPRINT_REGULAR=False,

        # Logging configuration
        LOG_LEVEL=os.getenv("LOG_LEVEL", "INFO"),
        LOG_FILE=os.getenv("LOG_FILE", "logs/crypto_hunter.log"),
        LOG_MAX_BYTES=int(os.getenv("LOG_MAX_BYTES", 10485760)),  # 10MB
        LOG_BACKUP_COUNT=int(os.getenv("LOG_BACKUP_COUNT", 5)),

        # Feature flags
        ENABLE_REGISTRATION=os.getenv("ENABLE_REGISTRATION", "True").lower() == 'true',
        ENABLE_API=os.getenv("ENABLE_API", "True").lower() == 'true',
        ENABLE_BACKGROUND_TASKS=os.getenv("ENABLE_BACKGROUND_TASKS", "True").lower() == 'true',
        ENABLE_AI_ANALYSIS=os.getenv("ENABLE_AI_ANALYSIS", "True").lower() == 'true',

        # Monitoring and metrics
        PROMETHEUS_METRICS=os.getenv("PROMETHEUS_METRICS", "False").lower() == 'true',
        SENTRY_DSN=os.getenv("SENTRY_DSN"),

        # CORS settings
        CORS_ORIGINS=os.getenv("CORS_ORIGINS", "http://localhost:3000,http://localhost:8000").split(','),
    )

    # Environment-specific overrides
    if config_name == 'development':
        app.config.update(
            DEBUG=True,
            TESTING=False,
            WTF_CSRF_ENABLED=False,  # Easier for development
            SESSION_COOKIE_SECURE=False,
            SQLALCHEMY_ENGINE_OPTIONS={**app.config['SQLALCHEMY_ENGINE_OPTIONS'], 'echo': True}
        )
    elif config_name == 'testing':
        app.config.update(
            TESTING=True,
            WTF_CSRF_ENABLED=False,
            LOGIN_DISABLED=True,
            SQLALCHEMY_DATABASE_URI="sqlite:///:memory:",
            CACHE_TYPE="simple",
            CELERY_TASK_ALWAYS_EAGER=True,
        )
    elif config_name == 'production':
        app.config.update(
            DEBUG=False,
            TESTING=False,
            WTF_CSRF_ENABLED=True,
            SESSION_COOKIE_SECURE=True,
            # Force HTTPS in production
            PREFERRED_URL_SCHEME='https'
        )

    # Ensure directories exist
    for directory in [app.config['UPLOAD_FOLDER'], 'instance', 'logs']:
        os.makedirs(directory, exist_ok=True)


def initialize_extensions(app):
    """Initialize Flask extensions with proper configuration"""

    # Database
    db.init_app(app)
    migrate.init_app(app, db)

    # Authentication
    login_manager.init_app(app)
    login_manager.login_view = "auth.login"
    login_manager.login_message = "Please log in to access this page."
    login_manager.login_message_category = "info"
    login_manager.session_protection = "strong"
    login_manager.remember_cookie_duration = timedelta(days=30)
    login_manager.remember_cookie_secure = app.config.get('SESSION_COOKIE_SECURE', False)
    login_manager.remember_cookie_httponly = True

    # Security
    if app.config.get('WTF_CSRF_ENABLED', True):
        csrf.init_app(app)

    # CORS
    cors.init_app(app, origins=app.config['CORS_ORIGINS'])

    # Rate limiting
    limiter.init_app(app)

    # Caching
    cache.init_app(app)

    # Import models to ensure they're registered
    from crypto_hunter_web.models import User, AnalysisFile, FileContent, Finding, Vector, ApiKey, AuditLog

    @login_manager.user_loader
    def load_user(user_id):
        """Load user by ID for Flask-Login"""
        try:
            return User.query.get(int(user_id))
        except (ValueError, TypeError):
            return None


def configure_security(app):
    """Configure security headers and policies"""

    @app.after_request
    def security_headers(response):
        """Add security headers to all responses"""
        # Content Security Policy
        csp = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' 'unsafe-eval' https://cdnjs.cloudflare.com; "
            "style-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com; "
            "img-src 'self' data: https:; "
            "font-src 'self' https://cdnjs.cloudflare.com; "
            "connect-src 'self'; "
            "frame-ancestors 'none';"
        )

        response.headers.update({
            'Content-Security-Policy': csp,
            'X-Content-Type-Options': 'nosniff',
            'X-Frame-Options': 'DENY',
            'X-XSS-Protection': '1; mode=block',
            'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
            'Referrer-Policy': 'strict-origin-when-cross-origin',
            'Permissions-Policy': 'camera=(), microphone=(), geolocation=()'
        })

        return response


def register_blueprints(app):
    """Register all application blueprints"""

    # Import blueprints
    from crypto_hunter_web.routes.auth import auth_bp
    from crypto_hunter_web.routes.files import files_bp
    from crypto_hunter_web.routes.analysis import analysis_bp
    from crypto_hunter_web.routes.graph import graph_bp
    from crypto_hunter_web.routes.content import content_bp

    # API blueprints
    from crypto_hunter_web.routes.api.crypto import crypto_api_bp
    from crypto_hunter_web.routes.api.llm import llm_api_bp
    from crypto_hunter_web.routes.api.search import search_api_bp
    from crypto_hunter_web.routes.api.files import files_api_bp
    from crypto_hunter_web.routes.api.background import background_api_bp

    # Register UI blueprints
    app.register_blueprint(auth_bp, url_prefix='/auth')
    app.register_blueprint(files_bp, url_prefix='/files')
    app.register_blueprint(analysis_bp, url_prefix='/analysis')
    app.register_blueprint(graph_bp, url_prefix='/graph')
    app.register_blueprint(content_bp, url_prefix='/content')

    # Register API blueprints
    if app.config.get('ENABLE_API', True):
        app.register_blueprint(crypto_api_bp, url_prefix="/api/v1/crypto")
        app.register_blueprint(llm_api_bp, url_prefix="/api/v1/llm")
        app.register_blueprint(search_api_bp, url_prefix="/api/v1/search")
        app.register_blueprint(files_api_bp, url_prefix="/api/v1/files")
        app.register_blueprint(background_api_bp, url_prefix="/api/v1/background")

    # Main route
    @app.route('/')
    def index():
        """Main dashboard redirect"""
        from flask_login import current_user
        if current_user.is_authenticated:
            return redirect(url_for('files.dashboard'))
        return redirect(url_for('auth.login'))


def register_error_handlers(app):
    """Register error handlers for better user experience"""

    @app.errorhandler(400)
    def bad_request(error):
        """Handle bad request errors"""
        return jsonify({
            'error': 'Bad Request',
            'message': 'The request could not be understood by the server.',
            'status_code': 400
        }), 400

    @app.errorhandler(401)
    def unauthorized(error):
        """Handle unauthorized errors"""
        return jsonify({
            'error': 'Unauthorized',
            'message': 'Authentication required.',
            'status_code': 401
        }), 401

    @app.errorhandler(403)
    def forbidden(error):
        """Handle forbidden errors"""
        return jsonify({
            'error': 'Forbidden',
            'message': 'You do not have permission to access this resource.',
            'status_code': 403
        }), 403

    @app.errorhandler(404)
    def not_found(error):
        """Handle not found errors"""
        if request.path.startswith('/api/'):
            return jsonify({
                'error': 'Not Found',
                'message': 'The requested resource was not found.',
                'status_code': 404
            }), 404
        # For HTML requests, render a template
        return render_template('errors/404.html'), 404

    @app.errorhandler(429)
    def ratelimit_exceeded(error):
        """Handle rate limit exceeded"""
        return jsonify({
            'error': 'Rate Limit Exceeded',
            'message': f'Rate limit exceeded: {error.description}',
            'status_code': 429,
            'retry_after': getattr(error, 'retry_after', None)
        }), 429

    @app.errorhandler(500)
    def internal_error(error):
        """Handle internal server errors"""
        db.session.rollback()
        logger.error(f"Internal server error: {error}", exc_info=True)

        return jsonify({
            'error': 'Internal Server Error',
            'message': 'An unexpected error occurred.',
            'status_code': 500
        }), 500

    @app.errorhandler(Exception)
    def handle_exception(error):
        """Handle unexpected exceptions"""
        db.session.rollback()
        logger.error(f"Unhandled exception: {error}", exc_info=True)

        if app.debug:
            raise error

        return jsonify({
            'error': 'Internal Server Error',
            'message': 'An unexpected error occurred.',
            'status_code': 500
        }), 500


def register_cli_commands(app):
    """Register CLI commands for administration"""

    @app.cli.command()
    def init_db():
        """Initialize the database"""
        from crypto_hunter_web.models import create_indexes
        db.create_all()
        create_indexes()
        click.echo('Database initialized!')

    @app.cli.command()
    @click.option('--username', prompt=True)
    @click.option('--email', prompt=True)
    @click.option('--password', prompt=True, hide_input=True, confirmation_prompt=True)
    def create_admin(username, email, password):
        """Create an admin user"""
        from crypto_hunter_web.models import User

        user = User(
            username=username,
            email=email,
            is_admin=True,
            is_verified=True,
            display_name=f"Admin {username}"
        )
        user.set_password(password)

        db.session.add(user)
        db.session.commit()
        click.echo(f'Admin user {username} created!')

    @app.cli.command()
    def reset_db():
        """Reset the database (DANGER!)"""
        if click.confirm('This will delete all data. Are you sure?'):
            db.drop_all()
            db.create_all()
            click.echo('Database reset!')


def setup_monitoring(app):
    """Setup health checks and monitoring endpoints"""

    @app.route('/health')
    def health_check():
        """Health check endpoint"""
        try:
            # Check database
            db.session.execute('SELECT 1')

            # Check Redis if configured
            if app.config.get('REDIS_URL'):
                redis_client = redis.from_url(app.config['REDIS_URL'])
                redis_client.ping()

            return jsonify({
                'status': 'healthy',
                'timestamp': datetime.utcnow().isoformat(),
                'version': '1.0.0',
                'database': 'connected',
                'redis': 'connected' if app.config.get('REDIS_URL') else 'not_configured'
            }), 200

        except Exception as e:
            logger.error(f"Health check failed: {e}")
            return jsonify({
                'status': 'unhealthy',
                'timestamp': datetime.utcnow().isoformat(),
                'error': str(e)
            }), 503

    @app.route('/metrics')
    def metrics():
        """Basic metrics endpoint"""
        if not app.config.get('PROMETHEUS_METRICS'):
            return jsonify({'error': 'Metrics disabled'}), 404

        from crypto_hunter_web.models import User, AnalysisFile, Finding

        metrics = {
            'users_total': User.query.count(),
            'users_active': User.query.filter_by(is_active=True).count(),
            'files_total': AnalysisFile.query.count(),
            'files_analyzed': AnalysisFile.query.filter_by(status='complete').count(),
            'findings_total': Finding.query.count(),
            'findings_confirmed': Finding.query.filter_by(status='confirmed').count(),
        }

        return jsonify(metrics)


def setup_context_processors(app):
    """Setup template context processors"""

    @app.context_processor
    def inject_config():
        """Inject configuration into templates"""
        return {
            'app_name': 'Crypto Hunter',
            'app_version': '1.0.0',
            'enable_registration': app.config.get('ENABLE_REGISTRATION', True),
            'enable_api': app.config.get('ENABLE_API', True)
        }

    @app.template_filter('humanize_bytes')
    def humanize_bytes(bytes_value):
        """Convert bytes to human readable format"""
        if not bytes_value:
            return '0 B'

        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if bytes_value < 1024.0:
                return f"{bytes_value:.1f} {unit}"
            bytes_value /= 1024.0
        return f"{bytes_value:.1f} PB"

    @app.template_filter('time_ago')
    def time_ago(dt):
        """Convert datetime to time ago format"""
        if not dt:
            return 'Never'

        from datetime import datetime
        now = datetime.utcnow()
        diff = now - dt

        if diff.days > 0:
            return f"{diff.days} day{'s' if diff.days != 1 else ''} ago"
        elif diff.seconds > 3600:
            hours = diff.seconds // 3600
            return f"{hours} hour{'s' if hours != 1 else ''} ago"
        elif diff.seconds > 60:
            minutes = diff.seconds // 60
            return f"{minutes} minute{'s' if minutes != 1 else ''} ago"
        else:
            return "Just now"


def setup_request_handlers(app):
    """Setup before/after request handlers"""

    @app.before_request
    def before_request():
        """Before request handler"""
        # Track request start time for performance monitoring
        g.start_time = time.time()

        # Log API requests
        if request.path.startswith('/api/'):
            logger.info(f"API Request: {request.method} {request.path} from {request.remote_addr}")

    @app.after_request
    def after_request(response):
        """After request handler"""
        # Log request duration
        if hasattr(g, 'start_time'):
            duration = time.time() - g.start_time
            if duration > 1.0:  # Log slow requests
                logger.warning(f"Slow request: {request.method} {request.path} took {duration:.2f}s")

        return response

    @app.teardown_appcontext
    def shutdown_session(exception=None):
        """Clean up database session"""
        if exception:
            db.session.rollback()
        db.session.remove()


# Initialize Sentry for error tracking (if configured)
def init_sentry(app):
    """Initialize Sentry error tracking"""
    sentry_dsn = app.config.get('SENTRY_DSN')
    if sentry_dsn:
        try:
            import sentry_sdk
            from sentry_sdk.integrations.flask import FlaskIntegration
            from sentry_sdk.integrations.sqlalchemy import SqlalchemyIntegration
            from sentry_sdk.integrations.redis import RedisIntegration

            sentry_sdk.init(
                dsn=sentry_dsn,
                integrations=[
                    FlaskIntegration(transaction_style='endpoint'),
                    SqlalchemyIntegration(),
                    RedisIntegration(),
                ],
                traces_sample_rate=0.1,
                environment=app.config.get('ENV', 'production'),
                release=app.config.get('VERSION', '1.0.0')
            )

            logger.info("Sentry error tracking initialized")
        except ImportError:
            logger.warning("Sentry SDK not installed, error tracking disabled")


# Export the create_app function and extensions
__all__ = ['create_app', 'db', 'migrate', 'login_manager', 'cache', 'limiter']