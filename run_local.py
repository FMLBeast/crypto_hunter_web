#!/usr/bin/env python3
"""
Local development server runner
Quick setup and run for development
"""

import os
import sys
import subprocess
from pathlib import Path


def setup_environment():
    """Setup basic environment for development"""
    print("🚀 Setting up Crypto Hunter for local development...")

    # Create necessary directories
    dirs = ['logs', 'uploads', 'instance', 'temp']
    for directory in dirs:
        Path(directory).mkdir(exist_ok=True)
        print(f"📁 Created directory: {directory}")

    # Create .env if it doesn't exist
    env_file = Path('.env')
    if not env_file.exists():
        print("📋 Creating .env file...")
        with open('.env', 'w') as f:
            f.write("""# Crypto Hunter Local Development Configuration
SECRET_KEY=dev-secret-key-change-in-production
FLASK_ENV=development
FLASK_DEBUG=1

# Database (SQLite for development)
DATABASE_URL=sqlite:///instance/crypto_hunter_dev.db

# Redis (use Docker or local installation)
REDIS_URL=redis://localhost:6379/0

# Features
ENABLE_REGISTRATION=true
ENABLE_AI_ANALYSIS=false

# Logging
LOG_LEVEL=DEBUG

# File Upload
MAX_CONTENT_LENGTH=1073741824
UPLOAD_FOLDER=uploads

# Optional AI APIs (uncomment and add keys if needed)
# OPENAI_API_KEY=sk-your-key-here
# ANTHROPIC_API_KEY=sk-ant-your-key-here
""")
        print("✅ Created .env file")

    print("✅ Environment setup complete!")


def check_dependencies():
    """Check if basic dependencies are available"""
    print("🔍 Checking dependencies...")

    try:
        import flask
        print(f"✅ Flask {flask.__version__}")
    except ImportError:
        print("❌ Flask not installed. Run: pip install -r requirements.txt")
        return False

    try:
        import sqlite3
        print("✅ SQLite available")
    except ImportError:
        print("❌ SQLite not available")
        return False

    return True


def run_server():
    """Run the development server"""
    print("🌟 Starting Crypto Hunter development server...")

    # Set environment variables
    os.environ['FLASK_ENV'] = 'development'
    os.environ['FLASK_DEBUG'] = '1'

    # Import and run the app
    try:
        from run import main
        main()
    except Exception as e:
        print(f"❌ Error starting server: {e}")
        print("💡 Try running: pip install -r requirements.txt")
        sys.exit(1)


def main():
    """Main function"""
    print("🔍 Crypto Hunter - Local Development Setup")
    print("=" * 45)

    # Setup environment
    setup_environment()

    # Install requirements
    if not install_requirements():
        print("\n❌ Failed to install requirements. You can try:")
        print("   pip install Flask Flask-SQLAlchemy Flask-Login python-dotenv")
        print("   Then run: python run.py")
        sys.exit(1)

    # Check dependencies
    if not check_dependencies():
        print("\n⚠️ Some dependencies missing, but trying to start anyway...")

    print("\n🚀 Starting development server...")
    print("📍 Server will be available at: http://localhost:8000")
    print("🛑 Press Ctrl+C to stop")
    print("-" * 45)

    # Run the server
    run_server()


if __name__ == "__main__":
    main()