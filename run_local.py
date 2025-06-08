# run_local.py - FIXED LOCAL DEVELOPMENT SERVER

"""
Local development server with unified Celery integration
Starts web server and background worker in development mode
"""

import os
import sys
import time
import signal
import threading
import subprocess
from pathlib import Path
from dotenv import load_dotenv

# Load environment variables
load_dotenv()


def create_directories():
    """Create necessary directories"""
    directories = ['logs', 'uploads', 'instance', 'temp']
    for directory in directories:
        Path(directory).mkdir(exist_ok=True)
    print("📁 Created necessary directories")


def setup_environment():
    """Setup development environment variables"""
    # Set development defaults
    env_vars = {
        'FLASK_ENV': 'development',
        'FLASK_DEBUG': 'True',
        'SECRET_KEY': 'dev-secret-key-change-in-production',
        'DATABASE_URL': 'postgresql://postgres:password@localhost:5432/crypto_hunter_dev',
        'REDIS_URL': 'redis://localhost:6379/0',
        'CELERY_BROKER_URL': 'redis://localhost:6379/2',
        'CELERY_RESULT_BACKEND': 'redis://localhost:6379/3',
        'WTF_CSRF_ENABLED': 'False',
        'ENABLE_REGISTRATION': 'True',
        'ENABLE_AI_ANALYSIS': 'True',
        'LOG_LEVEL': 'DEBUG'
    }

    for key, value in env_vars.items():
        if not os.getenv(key):
            os.environ[key] = value

    print("🔧 Environment configured for development")


def check_dependencies():
    """Check if required services are running"""
    dependencies = {
        'PostgreSQL': ('psql', ['-h', 'localhost', '-U', 'postgres', '-c', 'SELECT 1;']),
        'Redis': ('redis-cli', ['ping'])
    }

    print("🔍 Checking dependencies...")

    for service, (cmd, args) in dependencies.items():
        try:
            result = subprocess.run([cmd] + args,
                                    capture_output=True,
                                    text=True,
                                    timeout=5)
            if result.returncode == 0:
                print(f"✅ {service} is running")
            else:
                print(f"❌ {service} is not responding")
                return False
        except (subprocess.TimeoutExpired, FileNotFoundError):
            print(f"❌ {service} is not available")
            return False

    return True


def check_database():
    """Check database connection and tables"""
    try:
        from crypto_hunter_web import create_app
        from crypto_hunter_web.models import db

        app = create_app('development')
        with app.app_context():
            # Test connection
            db.session.execute('SELECT 1')

            # Check if tables exist
            tables = db.engine.table_names()
            if len(tables) < 5:  # Expecting several core tables
                print("⚠️  Database tables missing or incomplete")
                print("💡 Run: flask db upgrade")
                return False
            else:
                print(f"✅ Database ready with {len(tables)} tables")
                return True

    except Exception as e:
        print(f"❌ Database error: {e}")
        print("💡 Make sure PostgreSQL is running and database exists")
        return False


def start_background_worker():
    """Start Celery worker using unified configuration"""

    def run_worker():
        try:
            # Use the unified worker entrypoint
            subprocess.run([
                'python', 'celery_worker_entrypoint.py'
            ], check=False)
        except Exception as e:
            print(f"⚠️  Celery worker error: {e}")

    worker_thread = threading.Thread(target=run_worker, daemon=True)
    worker_thread.start()
    print("✅ Celery worker started with unified configuration")

    return worker_thread


def start_beat_scheduler():
    """Start Celery beat scheduler"""

    def run_beat():
        try:
            subprocess.run([
                'celery', '-A', 'celery_worker_entrypoint.celery_app',
                'beat', '--loglevel=info'
            ], check=False)
        except Exception as e:
            print(f"⚠️  Celery beat error: {e}")

    beat_thread = threading.Thread(target=run_beat, daemon=True)
    beat_thread.start()
    print("✅ Celery beat scheduler started")

    return beat_thread


def start_flask_app():
    """Start Flask development server"""
    try:
        from crypto_hunter_web import create_app

        app = create_app('development')

        print("🚀 Starting Flask development server...")
        app.run(
            host='0.0.0.0',
            port=8000,
            debug=True,
            use_reloader=True,
            threaded=True
        )
    except Exception as e:
        print(f"❌ Flask server error: {e}")
        sys.exit(1)


def print_startup_info():
    """Print startup information"""
    print("""
🔍 Crypto Hunter Development Server
===================================

🌐 Web Application: http://localhost:8000
📊 Health Check: http://localhost:8000/health
🛠️  Admin Panel: http://localhost:8000/admin (if available)

💡 Development Features:
   • Hot reload enabled - changes restart server automatically
   • Debug mode active - detailed error pages
   • CSRF protection disabled for easier API testing
   • Registration enabled for testing
   • Logs written to logs/development.log

🔧 Useful Commands:
   flask user create-admin     - Create admin user
   flask db upgrade           - Apply database migrations
   flask db init              - Initialize database
   curl http://localhost:8000/health  - Test health endpoint

📋 Celery Tasks:
   • Unified configuration using celery_worker_entrypoint.py
   • Background analysis tasks enabled
   • Beat scheduler for periodic tasks
   • Redis queues: analysis, crypto, ai, maintenance

Press Ctrl+C to stop all services
""")


def signal_handler(signum, frame):
    """Handle shutdown signals"""
    print("\n🛑 Shutting down development server...")
    sys.exit(0)


def main():
    """Main entry point for development server"""
    print("🚀 Starting Crypto Hunter Development Environment...")

    # Setup signal handlers
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    # Setup environment
    create_directories()
    setup_environment()

    # Check dependencies
    if not check_dependencies():
        print("❌ Dependencies not available. Please start required services:")
        print("   PostgreSQL: brew services start postgresql (macOS)")
        print("   Redis: brew services start redis (macOS)")
        print("   Or use Docker: docker-compose up postgres redis")
        sys.exit(1)

    # Check database
    if not check_database():
        print("❌ Database not ready. Please run database setup first.")
        sys.exit(1)

    # Test unified Celery configuration
    try:
        from crypto_hunter_web.services.celery_app import celery_app
        print(f"✅ Celery app loaded with {len(celery_app.tasks)} tasks")

        # List key tasks
        key_tasks = [t for t in celery_app.tasks.keys()
                     if 'crypto_hunter_web' in t and not t.startswith('celery.')]
        if key_tasks:
            print("📋 Key tasks registered:")
            for task in sorted(key_tasks)[:5]:  # Show first 5
                print(f"   • {task}")
            if len(key_tasks) > 5:
                print(f"   ... and {len(key_tasks) - 5} more")

    except ImportError as e:
        print(f"⚠️  Celery configuration issue: {e}")
        print("💡 Some background features may not work")

    # Start background services
    print("\n🔄 Starting background services...")
    worker_thread = start_background_worker()
    beat_thread = start_beat_scheduler()

    # Wait a moment for workers to start
    time.sleep(2)

    # Print startup info
    print_startup_info()

    # Start Flask app (this blocks)
    start_flask_app()


if __name__ == "__main__":
    main()