#!/usr/bin/env python3
"""
🚀 LOCAL Development Server (No Docker Hell!)
- Instant startup
- Real-time code changes  
- Native debugging
- No rebuilds needed!
"""

import os
import sys
from pathlib import Path

def setup_environment():
    """Setup development environment"""
    os.environ.update({
        'FLASK_ENV': 'development',
        'FLASK_DEBUG': '1',
        'FLASK_APP': 'crypto_hunter_web',
        'DATABASE_URL': 'sqlite:///instance/arweave_tracker.db',
        'REDIS_URL': 'redis://localhost:6379/0',
        'CELERY_BROKER_URL': 'redis://localhost:6379/0',
        'CELERY_RESULT_BACKEND': 'redis://localhost:6379/1',
        'SECRET_KEY': 'dev-secret-key-fast-development',
        'PYTHONUNBUFFERED': '1'
    })
    
    # Create directories
    Path('instance').mkdir(exist_ok=True)
    Path('uploads').mkdir(exist_ok=True)
    Path('logs').mkdir(exist_ok=True)

if __name__ == '__main__':
    setup_environment()
    
    try:
        from crypto_hunter_web import create_app
    except ImportError as e:
        print(f"❌ Import error: {e}")
        print("💡 Make sure you've installed dependencies: pip install -r requirements.txt")
        sys.exit(1)
    
    app = create_app()
    
    print("🚀 Starting LOCAL development server...")
    print("📱 App: http://localhost:8000")
    print("🔧 Auto-reload: ON (just save files!)")
    print("🐛 Debugger: ON (interactive debugging!)")
    print("⚡ Speed: MAXIMUM (no Docker overhead!)")
    print("⏹️  Press Ctrl+C to stop\n")
    
    app.run(
        host='0.0.0.0',
        port=8000,
        debug=True,
        use_reloader=True,
        use_debugger=True
    )
