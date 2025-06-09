#!/usr/bin/env python3
"""
Crypto Hunter Installation Script
Handles dependency installation with fallbacks
"""

import subprocess
import sys
from pathlib import Path


def run_command(cmd, description):
    """Run a command and return success status"""
    print(f"🔧 {description}...")
    try:
        result = subprocess.run(cmd, check=True, capture_output=True, text=True)
        print(f"✅ {description} completed")
        return True
    except subprocess.CalledProcessError as e:
        print(f"❌ {description} failed: {e.stderr.strip()}")
        return False


def install_core_packages():
    """Install core packages one by one"""
    core_packages = [
        "Flask>=2.3.0",
        "Flask-SQLAlchemy>=3.0.0",
        "Flask-Login>=0.6.0",
        "Flask-WTF>=1.1.0",
        "python-dotenv>=1.0.0",
        "Werkzeug>=2.3.0",
        "SQLAlchemy>=2.0.0",
        "cryptography>=41.0.0"
    ]

    print("📦 Installing core packages...")
    success_count = 0

    for package in core_packages:
        if run_command([sys.executable, "-m", "pip", "install", package],
                       f"Installing {package.split('>=')[0]}"):
            success_count += 1

    print(f"✅ Installed {success_count}/{len(core_packages)} core packages")
    return success_count >= len(core_packages) - 2  # Allow 2 failures


def install_optional_packages():
    """Install optional packages"""
    optional_packages = [
        "psycopg2-binary>=2.9.0",  # PostgreSQL
        "redis>=5.0.0",  # Redis
        "celery>=5.3.0",  # Background tasks
        "python-magic>=0.4.27",  # File type detection
        "gunicorn>=21.0.0"  # Production server
    ]

    print("📦 Installing optional packages...")

    for package in optional_packages:
        run_command([sys.executable, "-m", "pip", "install", package],
                    f"Installing {package.split('>=')[0]} (optional)")


def setup_directories():
    """Create necessary directories"""
    directories = ['logs', 'uploads', 'instance', 'temp']

    for directory in directories:
        Path(directory).mkdir(exist_ok=True)
        print(f"📁 Created directory: {directory}")


def create_env_file():
    """Create .env file if it doesn't exist"""
    env_file = Path('.env')
    if env_file.exists():
        print("📋 .env file already exists")
        return

    print("📋 Creating .env file...")
    with open('.env', 'w') as f:
        f.write("""# Crypto Hunter Configuration
SECRET_KEY=dev-secret-key-change-in-production
FLASK_ENV=development
FLASK_DEBUG=1

# Database (SQLite for development)
DATABASE_URL=sqlite:///instance/crypto_hunter_dev.db

# Features
ENABLE_REGISTRATION=true
ENABLE_AI_ANALYSIS=false

# Logging
LOG_LEVEL=DEBUG

# File Upload
MAX_CONTENT_LENGTH=1073741824
UPLOAD_FOLDER=uploads

# Optional services (uncomment if available)
# REDIS_URL=redis://localhost:6379/0
# OPENAI_API_KEY=sk-your-key-here
# ANTHROPIC_API_KEY=sk-ant-your-key-here
""")
    print("✅ Created .env file")


def main():
    """Main installation function"""
    print("🚀 Crypto Hunter Installation")
    print("=" * 40)

    # Upgrade pip first
    run_command([sys.executable, "-m", "pip", "install", "--upgrade", "pip"],
                "Upgrading pip")

    # Setup directories
    setup_directories()

    # Create environment file
    create_env_file()

    # Install packages
    if not install_core_packages():
        print("\n❌ Core package installation failed")
        print("You can try manually installing with:")
        print("pip install Flask Flask-SQLAlchemy Flask-Login python-dotenv")
        sys.exit(1)

    # Install optional packages
    install_optional_packages()

    print("\n🎉 Installation completed!")
    print("\nNext steps:")
    print("1. Run: python run_local.py")
    print("2. Open: http://localhost:8000")
    print("\nOr run directly with: python run.py")


if __name__ == "__main__":
    main()