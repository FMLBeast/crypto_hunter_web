#!/bin/bash

# 🚀 Escape Docker Hell - Instant Development Setup
# This script sets up a MUCH better development experience

set -e

echo "🔥 ESCAPING DOCKER DEVELOPMENT HELL!"
echo "=================================="
echo "✅ No more constant rebuilding"
echo "✅ Real-time code changes"
echo "✅ Instant logs in your terminal"
echo "✅ Native debugging with breakpoints"
echo "✅ 10x faster development cycle"
echo ""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

print_step() {
    echo -e "${BLUE}$1${NC}"
}

print_success() {
    echo -e "${GREEN}✅ $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠️ $1${NC}"
}

print_error() {
    echo -e "${RED}❌ $1${NC}"
}

# Step 1: Create development files
print_step "1️⃣ Creating development configuration files..."

# Create docker-compose.dev.yml (lightweight, volume-mounted)
cat > docker-compose.dev.yml << 'EOF'
version: '3.8'

services:
  redis:
    image: redis:7-alpine
    ports:
      - "6379:6379"
    command: redis-server --appendonly yes

  web:
    build: 
      context: .
      dockerfile: Dockerfile.dev
    ports:
      - "8000:8000"
    environment:
      - FLASK_ENV=development
      - FLASK_DEBUG=1
      - DATABASE_URL=sqlite:////app/instance/arweave_tracker.db
      - REDIS_URL=redis://redis:6379/0
      - SECRET_KEY=dev-secret-no-rebuilds-needed
      - PYTHONUNBUFFERED=1
    volumes:
      - .:/app  # MOUNT SOURCE CODE - NO MORE REBUILDS!
      - ./instance:/app/instance
    depends_on:
      - redis
    stdin_open: true
    tty: true
    command: python -m flask run --host=0.0.0.0 --port=8000 --reload
EOF

print_success "Development docker-compose.yml created"

# Create lightweight development Dockerfile
cat > Dockerfile.dev << 'EOF'
FROM python:3.11-slim

RUN apt-get update && apt-get install -y gcc && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Install dev tools
RUN pip install --no-cache-dir ipython ipdb flask-shell-ipython

EXPOSE 8000

# Source code mounted as volume - no rebuilds needed!
CMD ["python", "-m", "flask", "run", "--host=0.0.0.0", "--port=8000", "--reload"]
EOF

print_success "Development Dockerfile created"

# Step 2: Create local development runner
print_step "2️⃣ Creating local development runner (NO DOCKER!)..."

cat > run_local.py << 'EOF'
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
EOF

chmod +x run_local.py
print_success "Local development runner created"

# Step 3: Create development tools
print_step "3️⃣ Creating development productivity tools..."

cat > dev.py << 'EOF'
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
EOF

chmod +x dev.py
print_success "Development tools created"

# Step 4: Create instant commands
print_step "4️⃣ Creating instant development commands..."

# Create simple convenience scripts
cat > start-dev.sh << 'EOF'
#!/bin/bash
echo "🚀 Starting FAST development mode..."
echo "✅ Volume-mounted code (no rebuilds!)"
echo "✅ Real-time logs"

# Stop any existing containers
docker compose down 2>/dev/null || true

# Start with development config
docker compose -f docker-compose.dev.yml up --build
EOF

cat > start-local.sh << 'EOF'
#!/bin/bash
echo "🚀 Starting LOCAL development (fastest!)..."

# Start only Redis
docker run -d --name redis-dev -p 6379:6379 redis:7-alpine 2>/dev/null || docker start redis-dev

echo "✅ Redis ready on localhost:6379"
echo "🏃 Starting Python app locally..."

python run_local.py
EOF

cat > quick-logs.sh << 'EOF'
#!/bin/bash
echo "📺 Real-time logs (Ctrl+C to stop)"
docker compose -f docker-compose.dev.yml logs -f --tail=100
EOF

chmod +x start-dev.sh start-local.sh quick-logs.sh

print_success "Convenience scripts created"

# Step 5: Setup instructions
print_step "5️⃣ Final setup..."

echo ""
echo "🎉 DOCKER HELL ESCAPED! 🎉"
echo "========================"
echo ""
echo "🚀 CHOOSE YOUR DEVELOPMENT MODE:"
echo ""
echo "🥇 FASTEST (Recommended): Local Development"
echo "   ./start-local.sh     # Python runs locally, only Redis in Docker"
echo "   ✅ Instant startup, native debugging, no rebuilds"
echo ""
echo "🥈 FAST: Docker with Volume Mounting"  
echo "   ./start-dev.sh       # Code mounted as volume, no rebuilds"
echo "   ✅ Auto-reload on file changes, real-time logs"
echo ""
echo "🛠️ DEVELOPMENT TOOLS:"
echo "   python dev.py logs     # Real-time logs with colors"
echo "   python dev.py health   # Quick health check"
echo "   python dev.py shell    # Flask shell with app context"
echo "   python dev.py restart  # Quick restart (no rebuild)"
echo ""
echo "🎯 WHAT'S FIXED:"
echo "   ❌ No more constant Docker rebuilds"
echo "   ❌ No more digging through remote logs"
echo "   ❌ No more slow development cycle"
echo "   ✅ Instant code changes"
echo "   ✅ Real-time logs in your terminal"
echo "   ✅ Native debugging with breakpoints"
echo "   ✅ 10x faster iteration"
echo ""
echo "🏃 GET STARTED:"
echo "   ./start-local.sh   (recommended for fastest development)"
echo ""

print_success "Setup complete! Enjoy lightning-fast development! ⚡"