# wsgi.py - COMPLETE WSGI ENTRY POINT FOR PRODUCTION

import os
from pathlib import Path

# Set up environment before importing app
os.environ.setdefault('FLASK_ENV', 'production')

from crypto_hunter_web import create_app, db
from crypto_hunter_web.services.background_service import init_celery

# Create Flask application
config_name = os.environ.get('FLASK_ENV', 'production')
app = create_app(config_name)

# Initialize Celery
celery = init_celery(app)

# Configure logging for production
if not app.debug:
    # Ensure log directory exists
    log_dir = Path(app.config.get('LOG_FILE', 'logs/crypto_hunter.log')).parent
    log_dir.mkdir(exist_ok=True)
    
    # Configure file logging
    import logging.handlers
    file_handler = logging.handlers.RotatingFileHandler(
        app.config.get('LOG_FILE', 'logs/crypto_hunter.log'),
        maxBytes=10485760,  # 10MB
        backupCount=10
    )
    file_handler.setFormatter(logging.Formatter(
        '[%(asctime)s] %(levelname)s in %(module)s: %(message)s'
    ))
    file_handler.setLevel(logging.INFO)
    app.logger.addHandler(file_handler)
    
    app.logger.setLevel(logging.INFO)
    app.logger.info('Crypto Hunter startup')

# Application context for database operations
with app.app_context():
    try:
        # Test database connection
        db.engine.execute('SELECT 1')
        app.logger.info('Database connection successful')
    except Exception as e:
        app.logger.error(f'Database connection failed: {e}')

# Health check endpoint for load balancers
@app.route('/health')
def health_check():
    """Health check endpoint for load balancers"""
    try:
        # Check database
        with app.app_context():
            db.engine.execute('SELECT 1')
        
        return {
            'status': 'healthy',
            'version': app.config.get('APPLICATION_VERSION', '2.0.0'),
            'environment': app.config.get('FLASK_ENV', 'production')
        }, 200
    except Exception as e:
        app.logger.error(f'Health check failed: {e}')
        return {'status': 'unhealthy', 'error': str(e)}, 503

# Readiness check for Kubernetes
@app.route('/ready')
def readiness_check():
    """Readiness check for Kubernetes deployments"""
    checks = {
        'database': False,
        'redis': False,
        'storage': False
    }
    
    try:
        # Database check
        with app.app_context():
            db.engine.execute('SELECT 1')
            checks['database'] = True
    except Exception:
        pass
    
    try:
        # Redis check
        import redis
        redis_client = redis.from_url(app.config.get('REDIS_URL'))
        redis_client.ping()
        checks['redis'] = True
    except Exception:
        pass
    
    try:
        # Storage check
        upload_dir = Path(app.config.get('UPLOAD_FOLDER', 'uploads'))
        upload_dir.mkdir(exist_ok=True)
        checks['storage'] = upload_dir.exists() and upload_dir.is_dir()
    except Exception:
        pass
    
    all_ready = all(checks.values())
    status_code = 200 if all_ready else 503
    
    return {
        'ready': all_ready,
        'checks': checks
    }, status_code

if __name__ == "__main__":
    # This should not be used in production
    # Use gunicorn or similar WSGI server
    app.logger.warning("Running with development server - not for production!")
    app.run(host='0.0.0.0', port=8000)

# Export for WSGI servers
application = app