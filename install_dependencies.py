# install_dependencies.py - INSTALL ALL REQUIRED DEPENDENCIES

"""
Install all required dependencies for Crypto Hunter
Handles both production and development requirements
"""

import subprocess
import sys
import os
from pathlib import Path


def run_command(cmd, description=""):
    """Run a command and check for success"""
    print(f"🔄 {description}...")
    try:
        result = subprocess.run(cmd, check=True, capture_output=True, text=True)
        print(f"✅ {description} completed successfully")
        return True
    except subprocess.CalledProcessError as e:
        print(f"❌ {description} failed:")
        print(f"   Command: {' '.join(cmd)}")
        print(f"   Error: {e.stderr}")
        return False


def check_virtual_environment():
    """Check if virtual environment is activated"""
    venv_active = hasattr(sys, 'real_prefix') or (
            hasattr(sys, 'base_prefix') and sys.base_prefix != sys.prefix
    )

    if venv_active:
        print(f"✅ Virtual environment active: {sys.prefix}")
        return True
    else:
        print("⚠️  No virtual environment detected")
        print("💡 Consider activating virtual environment: source .venv/bin/activate")
        return False


def upgrade_pip():
    """Upgrade pip to latest version"""
    return run_command([
        sys.executable, '-m', 'pip', 'install', '--upgrade', 'pip', 'setuptools', 'wheel'
    ], "Upgrading pip and build tools")


def install_core_dependencies():
    """Install core Flask and database dependencies"""
    core_packages = [
        'Flask==3.0.0',
        'Flask-SQLAlchemy==3.1.1',
        'Flask-Migrate==4.0.5',
        'Flask-Login==0.6.3',
        'Flask-WTF==1.2.1',
        'Flask-CORS==4.0.0',
        'Flask-Limiter==3.5.0',
        'Flask-Caching==2.1.0',
        'Werkzeug==3.0.1',
        'SQLAlchemy==2.0.23',
        'psycopg2-binary==2.9.9',
        'alembic==1.13.1'
    ]

    print("📦 Installing core Flask dependencies...")
    for package in core_packages:
        if not run_command([sys.executable, '-m', 'pip', 'install', package], f"Installing {package.split('==')[0]}"):
            return False

    print("✅ Core Flask dependencies installed")
    return True


def install_celery_dependencies():
    """Install Celery and Redis dependencies"""
    celery_packages = [
        'celery[redis]==5.3.4',
        'redis==5.0.1',
        'kombu==5.3.4'
    ]

    print("📦 Installing Celery dependencies...")
    for package in celery_packages:
        if not run_command([sys.executable, '-m', 'pip', 'install', package], f"Installing {package.split('==')[0]}"):
            return False

    print("✅ Celery dependencies installed")
    return True


def install_utility_dependencies():
    """Install utility and helper dependencies"""
    utility_packages = [
        'python-dotenv==1.0.0',
        'click==8.1.7',
        'bcrypt==4.1.2',
        'cryptography',
        'itsdangerous==2.1.2',
        'marshmallow==3.20.2',
        'WTForms==3.1.1',
        'python-magic==0.4.27',
        'chardet==5.2.0',
        'requests==2.31.0',
        'psutil==5.9.6'
    ]

    print("📦 Installing utility dependencies...")
    for package in utility_packages:
        if not run_command([sys.executable, '-m', 'pip', 'install', package], f"Installing {package.split('==')[0]}"):
            return False

    print("✅ Utility dependencies installed")
    return True


def install_from_requirements():
    """Install from requirements.txt if it exists"""
    requirements_file = Path('requirements.txt')

    if requirements_file.exists():
        print("📋 Found requirements.txt, installing all dependencies...")
        return run_command([
            sys.executable, '-m', 'pip', 'install', '-r', 'requirements.txt'
        ], "Installing from requirements.txt")
    else:
        print("⚠️  requirements.txt not found, installing core packages manually")
        return True


def verify_installations():
    """Verify that key packages are installed correctly"""
    print("\n🔍 Verifying installations...")

    test_imports = [
        ('Flask', 'import flask'),
        ('Flask-SQLAlchemy', 'import flask_sqlalchemy'),
        ('Celery', 'import celery'),
        ('Redis', 'import redis'),
        ('PostgreSQL driver', 'import psycopg2'),
        ('Cryptography', 'import cryptography'),
        ('Python-dotenv', 'import dotenv'),
    ]

    all_good = True

    for package_name, import_test in test_imports:
        try:
            exec(import_test)
            print(f"✅ {package_name} imported successfully")
        except ImportError as e:
            print(f"❌ {package_name} import failed: {e}")
            all_good = False

    return all_good


def install_development_dependencies():
    """Install development dependencies if requested"""
    dev_packages = [
        'pytest==7.4.3',
        'pytest-flask==1.3.0',
        'pytest-cov==4.1.0',
        'black==23.11.0',
        'flake8==6.1.0',
        'ipython',
        'ipdb'
    ]

    response = input("\n❓ Install development dependencies? (y/N): ").lower().strip()

    if response in ['y', 'yes']:
        print("📦 Installing development dependencies...")
        for package in dev_packages:
            run_command([sys.executable, '-m', 'pip', 'install', package], f"Installing {package.split('==')[0]}")
        print("✅ Development dependencies installed")
    else:
        print("⏭️  Skipping development dependencies")


def main():
    """Main dependency installation function"""
    print("📦 Crypto Hunter Dependency Installer")
    print("=" * 40)

    # Step 1: Check virtual environment
    venv_ok = check_virtual_environment()
    if not venv_ok:
        print("💡 Continuing anyway, but consider using a virtual environment")

    # Step 2: Upgrade pip
    if not upgrade_pip():
        print("⚠️  Pip upgrade failed, continuing anyway...")

    # Step 3: Try installing from requirements.txt first
    if not install_from_requirements():
        print("📦 Requirements.txt installation failed, trying manual installation...")

        # Step 4: Manual installation of core packages
        if not install_core_dependencies():
            print("❌ Core dependency installation failed")
            return False

        if not install_celery_dependencies():
            print("❌ Celery dependency installation failed")
            return False

        if not install_utility_dependencies():
            print("❌ Utility dependency installation failed")
            return False

    # Step 5: Verify installations
    if not verify_installations():
        print("❌ Some packages failed to install correctly")
        return False

    # Step 6: Optional development dependencies
    install_development_dependencies()

    print("\n🎉 All dependencies installed successfully!")
    print("\n📋 Next steps:")
    print("   1. Run: python fix_all_issues.py")
    print("   2. Test: python test_integration.py")
    print("   3. Start: python run_local.py")

    return True


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)