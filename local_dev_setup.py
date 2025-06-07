#!/usr/bin/env python3
"""
Local Development Setup Script
Runs the Flask app locally for the best development experience
Only uses Docker for Redis service
"""

import os
import sys
import subprocess
import time
import signal
from pathlib import Path

def setup_local_development():
    """Setup and run local development environment"""
    
    print("🚀 Setting up LOCAL development environment...")
    print("✅ No more Docker rebuilds!")
    print("✅ Real-time code changes!")
    print("✅ Native debugging with breakpoints!")
    print("✅ Fast startup!\n")
    
    # 1. Start only Redis in Docker
    print("1️⃣ Starting Redis service...")
    try:
        subprocess.run(['docker', 'compose', 'up', '-d', 'redis'], check=True)
        print("   ✅ Redis started on localhost:6379")
    except subprocess.CalledProcessError:
        print("   ❌ Failed to start Redis. Make sure Docker is running.")
        return False
    
    # 2. Wait for Redis to be ready
    print("2️⃣ Waiting for Redis to be ready...")
    time.sleep(2)
    
    # 3. Set environment variables for local development
    print("3️⃣ Setting up environment...")
    env = os.environ.copy()
    env.update({
        'FLASK_ENV': 'development',
        'FLASK_DEBUG': '1',
        'FLASK_APP': 'crypto_hunter_web',
        'DATABASE_URL': 'sqlite:///instance/arweave_tracker.db',
        'REDIS_URL': 'redis://localhost:6379/0',
        'CELERY_BROKER_URL': 'redis://localhost:6379/0', 
        'CELERY_RESULT_BACKEND': 'redis://localhost:6379/1',
        'SECRET_KEY': 'dev-secret-key-safe-for-development',
        'PYTHONUNBUFFERED': '1',
        'UPLOAD_FOLDER': 'uploads'
    })
    
    # 4. Create necessary directories
    print("4️⃣ Creating directories...")
    Path('instance').mkdir(exist_ok=True)
    Path('uploads').mkdir(exist_ok=True)
    Path('logs').mkdir(exist_ok=True)
    print("   ✅ Directories created")
    
    # 5. Install dependencies locally if needed
    print("5️⃣ Checking Python dependencies...")
    try:
        import flask
        print("   ✅ Flask already installed")
    except ImportError:
        print("   📦 Installing dependencies locally...")
        subprocess.run([sys.executable, '-m', 'pip', 'install', '-r', 'requirements.txt'], check=True)
        print("   ✅ Dependencies installed")
    
    # 6. Initialize database
    print("6️⃣ Initializing database...")
    try:
        subprocess.run([sys.executable, '-c', """
from crypto_hunter_web import create_app, db
app = create_app()
with app.app_context():
    db.create_all()
    print('Database initialized')
"""], env=env, check=True)
        print("   ✅ Database ready")
    except subprocess.CalledProcessError:
        print("   ⚠️ Database initialization had issues (may be normal)")
    
    # 7. Run database fixes
    print("7️⃣ Running database schema fixes...")
    run_database_fix(env)
    
    print("\n🎉 Local development environment ready!")
    print("📝 Development commands:")
    print("   🔧 Start app:    python run_local.py")
    print("   🧪 Run tests:    python -m pytest")
    print("   🐛 Debug mode:   python -m pdb run_local.py")
    print("   📊 Health check: curl http://localhost:8000/health")
    print("   📋 Shell:       python -c 'from crypto_hunter_web import create_app; app=create_app(); app.app_context().push()'")
    
    return True

def run_database_fix(env):
    """Run the database schema fixes"""
    fix_script = """
from crypto_hunter_web import create_app, db
from crypto_hunter_web.models import User
from sqlalchemy import text, inspect
import os

app = create_app()
with app.app_context():
    print('🔧 Applying database fixes...')
    
    inspector = inspect(db.engine)
    
    # Fix analysis_files if it exists
    if 'analysis_files' in inspector.get_table_names():
        columns = [col['name'] for col in inspector.get_columns('analysis_files')]
        
        # Rename columns if needed
        if 'sha256' in columns and 'sha256_hash' not in columns:
            try:
                db.session.execute(text('ALTER TABLE analysis_files RENAME COLUMN sha256 TO sha256_hash'))
                print('✅ Fixed sha256 → sha256_hash')
            except: pass
        
        if 'filesize' in columns and 'file_size' not in columns:
            try:
                db.session.execute(text('ALTER TABLE analysis_files RENAME COLUMN filesize TO file_size'))
                print('✅ Fixed filesize → file_size')
            except: pass
        
        # Add missing columns
        missing_cols = ['md5_hash', 'parent_file_sha', 'extraction_method', 'depth_level']
        for col in missing_cols:
            try:
                if col == 'md5_hash':
                    db.session.execute(text('ALTER TABLE analysis_files ADD COLUMN md5_hash VARCHAR(32)'))
                elif col == 'parent_file_sha':
                    db.session.execute(text('ALTER TABLE analysis_files ADD COLUMN parent_file_sha VARCHAR(64)'))
                elif col == 'extraction_method':
                    db.session.execute(text('ALTER TABLE analysis_files ADD COLUMN extraction_method VARCHAR(100)'))
                elif col == 'depth_level':
                    db.session.execute(text('ALTER TABLE analysis_files ADD COLUMN depth_level INTEGER DEFAULT 0'))
                print(f'✅ Added {col}')
            except: pass
    
    # Fix users table
    if 'users' in inspector.get_table_names():
        user_columns = [col['name'] for col in inspector.get_columns('users')]
        user_missing = ['display_name', 'points', 'level', 'contributions_count']
        for col in user_missing:
            try:
                if col == 'display_name':
                    db.session.execute(text('ALTER TABLE users ADD COLUMN display_name VARCHAR(128)'))
                elif col == 'points':
                    db.session.execute(text('ALTER TABLE users ADD COLUMN points INTEGER DEFAULT 0'))
                elif col == 'level':
                    db.session.execute(text('ALTER TABLE users ADD COLUMN level VARCHAR(50) DEFAULT "Analyst"'))
                elif col == 'contributions_count':
                    db.session.execute(text('ALTER TABLE users ADD COLUMN contributions_count INTEGER DEFAULT 0'))
                print(f'✅ Added user.{col}')
            except: pass
    
    db.session.commit()
    print('✅ Database fixes completed')
"""
    
    try:
        subprocess.run([sys.executable, '-c', fix_script], env=env, timeout=30)
    except Exception as e:
        print(f"   ⚠️ Database fix warning: {e}")

def create_run_script():
    """Create a simple run script for local development"""
    run_script = '''#!/usr/bin/env python3
"""
Local development server runner
Run with: python run_local.py
"""

import os
from crypto_hunter_web import create_app

if __name__ == '__main__':
    # Set development environment
    os.environ.update({
        'FLASK_ENV': 'development',
        'FLASK_DEBUG': '1',
        'DATABASE_URL': 'sqlite:///instance/arweave_tracker.db',
        'REDIS_URL': 'redis://localhost:6379/0',
        'CELERY_BROKER_URL': 'redis://localhost:6379/0',
        'CELERY_RESULT_BACKEND': 'redis://localhost:6379/1',
        'SECRET_KEY': 'dev-secret-key-safe-for-development',
        'PYTHONUNBUFFERED': '1'
    })
    
    app = create_app()
    
    print("🚀 Starting LOCAL development server...")
    print("📱 App running at: http://localhost:8000")
    print("🔧 Auto-reload enabled - just save your files!")
    print("🐛 Debugger enabled - exceptions will show interactive debugger")
    print("⏹️  Press Ctrl+C to stop\\n")
    
    # Run with development settings
    app.run(
        host='0.0.0.0',
        port=8000,
        debug=True,
        use_reloader=True,
        use_debugger=True,
        threaded=True
    )
'''
    
    with open('run_local.py', 'w') as f:
        f.write(run_script)
    os.chmod('run_local.py', 0o755)
    print("   ✅ Created run_local.py")

def cleanup_docker():
    """Clean up any existing Docker containers"""
    print("🧹 Cleaning up existing Docker containers...")
    try:
        subprocess.run(['docker', 'compose', 'down'], check=False)
        print("   ✅ Docker containers stopped")
    except:
        pass

if __name__ == '__main__':
    print("🎯 Crypto Hunter - Local Development Setup")
    print("=" * 50)
    
    # Handle Ctrl+C gracefully
    def signal_handler(sig, frame):
        print("\n\n🛑 Stopping development environment...")
        cleanup_docker()
        sys.exit(0)
    
    signal.signal(signal.SIGINT, signal_handler)
    
    # Create run script
    create_run_script()
    
    if len(sys.argv) > 1 and sys.argv[1] == 'cleanup':
        cleanup_docker()
        sys.exit(0)
    
    success = setup_local_development()
    
    if success:
        print("\n" + "=" * 50)
        print("🎉 Ready to develop! Run: python run_local.py")
        print("=" * 50)
    else:
        print("\n❌ Setup failed. Check the errors above.")
        sys.exit(1)
