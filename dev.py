#!/usr/bin/env python3
"""🛠️ Development Tools - Makes debugging easy"""

import os, sys, subprocess, time
from pathlib import Path

def logs():
    """Stream real-time logs with colors"""
    print("📺 Real-time logs (Ctrl+C to stop)")
    try:
        cmd = ['docker', 'compose', '-f', 'docker-compose.dev.yml', 'logs', '-f', '--tail=50']
        subprocess.run(cmd)
    except KeyboardInterrupt:
        print("\n🛑 Stopped")

def restart():
    """Quick restart web service"""
    print("🔄 Quick restart...")
    subprocess.run(['docker', 'compose', '-f', 'docker-compose.dev.yml', 'restart', 'web'])
    print("✅ Restarted")

def health():
    """Health check"""
    try:
        import requests
        r = requests.get('http://localhost:8000/health', timeout=5)
        print(f"{'✅' if r.status_code == 200 else '❌'} Health: {r.status_code}")
    except:
        print("❌ Not responding")

def shell():
    """Flask shell"""
    os.environ.update({
        'FLASK_ENV': 'development',
        'DATABASE_URL': 'sqlite:///instance/arweave_tracker.db',
        'REDIS_URL': 'redis://localhost:6379/0'
    })
    
    shell_code = '''
from crypto_hunter_web import create_app, db
from crypto_hunter_web.models import *
app = create_app()
app.app_context().push()
print("🐍 Flask shell ready! Available: app, db, User, AnalysisFile")
'''
    
    with open('.temp_shell.py', 'w') as f:
        f.write(shell_code)
    subprocess.run([sys.executable, '-i', '.temp_shell.py'])
    os.remove('.temp_shell.py')

def local_setup():
    """Setup local development (Redis only in Docker)"""
    print("🚀 Setting up local development...")
    subprocess.run(['docker', 'run', '-d', '--name', 'redis-dev', '-p', '6379:6379', 'redis:7-alpine'])
    print("✅ Redis started on localhost:6379")
    print("💡 Now run: python run_local.py")

if __name__ == '__main__':
    cmd = sys.argv[1] if len(sys.argv) > 1 else 'menu'
    
    if cmd == 'logs': logs()
    elif cmd == 'restart': restart()
    elif cmd == 'health': health()
    elif cmd == 'shell': shell()
    elif cmd == 'local': local_setup()
    else:
        print("🛠️ Development Tools")
        print("Usage: python dev.py [command]")
        print("Commands:")
        print("  logs    - Real-time logs")
        print("  restart - Quick restart")
        print("  health  - Health check")
        print("  shell   - Flask shell")
        print("  local   - Setup local dev")
