#!/usr/bin/env python3
"""
Crypto Hunter Main Entry Point
Production-ready Flask application runner with comprehensive error handling
"""

import os
import sys
import logging
from pathlib import Path
from flask import Flask, jsonify

# Add project root to Python path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))


def create_application():
    """Create Flask application with all fixes applied"""

    try:
        # Import the fixed application factory
        from crypto_hunter_web import create_app

        # Create app with proper configuration
        config_name = os.getenv('FLASK_ENV', 'development')
        app = create_app(config_name)

        # Register all blueprints and initialize everything
        setup_application(app)

        return app

    except ImportError as e:
        print(f"❌ Failed to import application: {e}")
        # Create minimal Flask app as fallback
        return create_minimal_app()
    except Exception as e:
        print(f"❌ Application creation failed: {e}")
        return create_minimal_app()


def setup_application(app):
    """Setup the full application with all components"""

    # Initialize database if needed
    with app.app_context():
        from crypto_hunter_web.models import db, init_database
        from sqlalchemy import text, inspect

        # Check if database schema matches the models
        schema_matches = True
        try:
            # First check if users table exists at all
            db.session.execute(text("SELECT 1 FROM users LIMIT 1"))
            app.logger.info("Users table exists, checking schema...")

            # Check if schema matches the models
            inspector = inspect(db.engine)

            # Import all model classes we want to check
            from crypto_hunter_web.models import User, AnalysisFile, Finding, Vector, ApiKey, AuditLog

            # Check each model's table and columns
            for model_class in [User, AnalysisFile, Finding, Vector, ApiKey, AuditLog]:
                table_name = model_class.__tablename__

                # Get expected columns from the model
                model_columns = {column.name for column in model_class.__table__.columns}

                # Get actual columns from the database
                db_columns = {column['name'] for column in inspector.get_columns(table_name)}

                # Check for missing columns
                missing_columns = model_columns - db_columns
                if missing_columns:
                    app.logger.warning(f"Table '{table_name}' is missing columns: {missing_columns}")
                    schema_matches = False
                    break

            if schema_matches:
                app.logger.info("Database schema matches the models, skipping initialization")
            else:
                app.logger.warning("Database schema does not match the models")

                # Check if auto-reinitialization is enabled
                auto_reinit = os.getenv('AUTO_REINIT_DB', 'false').lower() == 'true'

                if auto_reinit:
                    app.logger.info("AUTO_REINIT_DB is set to true, reinitializing database...")
                    # Drop all tables
                    db.drop_all()
                    # Create tables
                    db.create_all()
                    # Initialize with default data
                    init_database()
                else:
                    app.logger.warning("AUTO_REINIT_DB is not set to true. Database schema mismatch remains.")
                    app.logger.warning("Set AUTO_REINIT_DB=true in your environment to automatically fix schema mismatches.")

        except Exception as e:
            app.logger.info(f"Database tables do not exist or cannot be accessed, creating tables: {e}")
            # Create tables if they don't exist
            db.create_all()
            # Initialize with default data
            init_database()

        app.logger.info("Database setup completed")

    # Register additional routes
    register_additional_routes(app)

    # Setup error handlers
    setup_comprehensive_error_handlers(app)


def register_additional_routes(app):
    """Register additional utility routes"""

    @app.route('/api/stats')
    def api_stats():
        """API endpoint for dashboard stats"""
        try:
            from crypto_hunter_web.models import AnalysisFile, Finding

            total_files = AnalysisFile.query.count()
            complete_files = AnalysisFile.query.filter_by(status='complete').count()
            total_findings = Finding.query.count()

            progress_percentage = (complete_files / total_files * 100) if total_files > 0 else 0

            return jsonify({
                'total_files': total_files,
                'complete_files': complete_files,
                'total_findings': total_findings,
                'active_tasks': 0,  # Placeholder
                'progress_percentage': progress_percentage
            })

        except Exception as e:
            app.logger.error(f"Stats API error: {e}")
            return jsonify({
                'total_files': 0,
                'complete_files': 0,
                'total_findings': 0,
                'active_tasks': 0,
                'progress_percentage': 0
            })

    @app.route('/api/activity')
    def api_activity():
        """API endpoint for recent activity"""
        try:
            from crypto_hunter_web.models import AnalysisFile

            recent_files = AnalysisFile.query.order_by(
                AnalysisFile.created_at.desc()
            ).limit(5).all()

            files_data = []
            for file in recent_files:
                files_data.append({
                    'id': file.id,
                    'filename': file.filename,
                    'status': file.status.value if hasattr(file.status, 'value') else str(file.status),
                    'created_at': file.created_at.isoformat() if file.created_at else None
                })

            return jsonify({'recent_files': files_data})

        except Exception as e:
            app.logger.error(f"Activity API error: {e}")
            return jsonify({'recent_files': []})

    @app.route('/api/background-status')
    def api_background_status():
        """API endpoint for background task status"""
        return jsonify({
            'user_tasks': [],
            'system_status': 'ok'
        })


def setup_comprehensive_error_handlers(app):
    """Setup comprehensive error handlers"""

    @app.errorhandler(400)
    def bad_request(error):
        return jsonify({'error': 'Bad request'}), 400

    @app.errorhandler(401)
    def unauthorized(error):
        return jsonify({'error': 'Unauthorized'}), 401

    @app.errorhandler(403)
    def forbidden(error):
        return jsonify({'error': 'Forbidden'}), 403

    @app.errorhandler(404)
    def not_found(error):
        return jsonify({'error': 'Not found'}), 404

    @app.errorhandler(429)
    def rate_limit_exceeded(error):
        response = jsonify({
            'error': 'Rate limit exceeded',
            'message': 'Maximum 5 requests per hour',
            'retry_after': getattr(error, 'retry_after', 60)
        }), 429
        response[0].headers['Retry-After'] = str(getattr(error, 'retry_after', 60))
        return response

    @app.errorhandler(500)
    def internal_error(error):
        return jsonify({'error': 'Internal server error'}), 500


def create_minimal_app():
    """Create minimal Flask app as fallback"""

    app = Flask(__name__)
    app.config.update({
        'SECRET_KEY': 'minimal-fallback-key',
        'DEBUG': True,
    })

    @app.route('/')
    def minimal_home():
        return '''
        <!DOCTYPE html>
        <html>
        <head>
            <title>Crypto Hunter - Minimal Mode</title>
            <script src="https://cdn.tailwindcss.com"></script>
        </head>
        <body class="bg-gray-100 min-h-screen flex items-center justify-center">
            <div class="max-w-md mx-auto bg-white rounded-lg shadow-lg p-8 text-center">
                <h1 class="text-2xl font-bold text-gray-900 mb-4">🔍 Crypto Hunter</h1>
                <div class="bg-yellow-50 border border-yellow-200 rounded-lg p-4 mb-4">
                    <p class="text-yellow-800 text-sm">
                        <strong>Minimal Mode:</strong> Running with basic functionality only.
                    </p>
                </div>
                <div class="space-y-3">
                    <p class="text-gray-600">Some features may not be available.</p>
                    <div class="text-left space-y-2">
                        <p class="text-sm"><strong>To fix:</strong></p>
                        <ol class="text-xs text-gray-600 ml-4 space-y-1">
                            <li>1. Run: <code class="bg-gray-100 px-1 rounded">python setup.py</code></li>
                            <li>2. Install: <code class="bg-gray-100 px-1 rounded">pip install -r requirements-minimal.txt</code></li>
                            <li>3. Restart: <code class="bg-gray-100 px-1 rounded">python run.py</code></li>
                        </ol>
                    </div>
                </div>
            </div>
        </body>
        </html>
        '''

    @app.route('/health')
    def minimal_health():
        return jsonify({'status': 'minimal', 'mode': 'fallback'})

    print("⚠️  Running in minimal mode - limited functionality")
    return app


def main():
    """Main entry point with comprehensive startup"""

    print("🔍 Starting Crypto Hunter...")

    # Check if setup is needed
    if not Path('.env').exists():
        print("⚠️  No .env file found. Running setup...")
        try:
            from setup import CryptoHunterSetup
            setup = CryptoHunterSetup()
            if not setup.run_setup():
                print("❌ Setup failed. Running in minimal mode.")
        except ImportError:
            print("⚠️  Setup script not found. Creating basic .env...")
            create_basic_env()

    # Create application
    app = create_application()

    # Print startup information
    print_startup_info(app)

    # Start server
    try:
        host = os.getenv('HOST', '0.0.0.0')
        port = int(os.getenv('PORT', 8000))
        debug = os.getenv('DEBUG', 'true').lower() == 'true'

        print(f"🚀 Starting server on http://{host}:{port}")
        app.run(host=host, port=port, debug=debug)

    except KeyboardInterrupt:
        print("\n👋 Crypto Hunter stopped by user")
    except Exception as e:
        print(f"❌ Server failed to start: {e}")
        sys.exit(1)


def create_basic_env():
    """Create basic .env file"""

    env_content = f"""# Basic Crypto Hunter Configuration
FLASK_APP=run.py
FLASK_ENV=development
SECRET_KEY={os.urandom(16).hex()}
DEBUG=true
DATABASE_URL=sqlite:///instance/crypto_hunter.db

# Database Management
# Set to 'true' to automatically reinitialize the database if the schema doesn't match the models
AUTO_REINIT_DB=false
"""

    with open('.env', 'w') as f:
        f.write(env_content)

    print("✅ Created basic .env file")


def print_startup_info(app):
    """Print startup information"""

    print(f"\n{'=' * 60}")
    print("🔍 CRYPTO HUNTER - CRYPTOCURRENCY ANALYSIS PLATFORM")
    print(f"{'=' * 60}")

    # Check application health
    try:
        with app.test_client() as client:
            health_response = client.get('/health')
            if health_response.status_code == 200:
                print("✅ Application: Healthy")
            else:
                print("⚠️  Application: Limited functionality")
    except:
        print("⚠️  Application: Minimal mode")

    # Check database
    try:
        with app.app_context():
            from crypto_hunter_web.models import db, User
            user_count = User.query.count()
            print(f"✅ Database: Connected ({user_count} users)")
    except:
        print("⚠️  Database: Using fallback")

    # Check Redis
    try:
        from crypto_hunter_web.extensions import redis_client
        if redis_client and redis_client.connected:
            print("✅ Redis: Connected")
        else:
            print("⚠️  Redis: Using memory fallback")
    except:
        print("⚠️  Redis: Not available")

    print(f"\n🌐 Access URLs:")
    print(f"   Web Interface: http://localhost:8000")
    print(f"   Health Check:  http://localhost:8000/health")
    print(f"   API Docs:      http://localhost:8000/api/stats")

    print(f"\n🔑 Default Login:")
    print(f"   Username: admin")
    print(f"   Password: admin123")

    print(f"\n📁 Important Paths:")
    print(f"   Logs:     logs/crypto_hunter.log")
    print(f"   Database: instance/crypto_hunter.db")
    print(f"   Uploads:  uploads/")

    print(f"\n⚡ Quick Commands:")
    print(f"   Setup:    python setup.py")
    print(f"   Workers:  celery -A crypto_hunter_web.services.background_service worker")
    print(f"   Shell:    flask shell")

    print(f"{'=' * 60}\n")


if __name__ == "__main__":
    main()
