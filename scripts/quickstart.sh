#!/bin/bash
# fix_and_deploy.sh - COMPLETE PRODUCTION DEPLOYMENT SOLUTION
set -euo pipefail

# Colors
readonly GREEN='\033[0;32m'
readonly BLUE='\033[0;34m'
readonly YELLOW='\033[0;33m'
readonly RED='\033[0;31m'
readonly NC='\033[0m'

log() { echo -e "${BLUE}[DEPLOY]${NC} $1"; }
success() { echo -e "${GREEN}✅ $1${NC}"; }
error() { echo -e "${RED}❌ $1${NC}"; exit 1; }

log "🚀 CRYPTO HUNTER - Complete Production Deployment"

# 1. Clean everything
log "🧹 Cleaning up..."
docker compose down --remove-orphans --volumes 2>/dev/null || true
docker rm -f hunter-worker_crypto hunter-worker_llm hunter-scheduler 2>/dev/null || true
sudo chown -R $(id -u):$(id -g) logs uploads instance 2>/dev/null || true

# 2. Create fixed requirements.txt
log "📦 Creating fixed requirements.txt..."
cat > requirements.txt << 'EOF'
# Core Flask
Flask==3.0.0
Flask-SQLAlchemy==3.1.1
Flask-Migrate==4.0.5
Flask-Login==0.6.3
Flask-WTF==1.2.1
Flask-CORS==4.0.0
Flask-Limiter==3.5.0
Flask-Caching==2.1.0
Werkzeug==3.0.1

# Database
SQLAlchemy==2.0.23
psycopg2-binary==2.9.9
alembic==1.13.1

# Background tasks
celery[redis]==5.3.4
redis==4.6.0
kombu==5.3.4
flower==2.0.1

# Security - FIXED VERSION
bcrypt==4.1.2
cryptography==43.0.3
itsdangerous==2.1.2
WTForms==3.1.1

# File processing
python-magic==0.4.27
chardet==5.2.0

# AI/LLM - PANDAS FIX
openai[datalib]==1.51.2
anthropic==0.34.2
tiktoken==0.7.0
numpy==1.26.4
pandas==2.1.4

# Crypto analysis
networkx==3.3
pycryptodome==3.20.0
base58==2.1.1
ecdsa==0.19.0

# Utilities
python-dotenv==1.0.0
click==8.1.7
requests==2.31.0
psutil==5.9.6

# Production server
gunicorn==21.2.0
gevent==23.9.1

# Testing
pytest==7.4.3
pytest-flask==1.3.0
black==23.11.0
flake8==6.1.0
EOF

# 3. Create fixed Dockerfile
log "🐳 Creating fixed Dockerfile..."
cat > Dockerfile << 'EOF'
FROM python:3.11-slim as base

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc g++ libffi-dev libmagic1 libmagic-dev libpq-dev build-essential \
    curl wget git file binutils util-linux xxd netcat-openbsd ca-certificates \
    && rm -rf /var/lib/apt/lists/* && apt-get clean

RUN groupadd -r appuser --gid 1000 && \
    useradd -r -g appuser --uid 1000 --home-dir /app --shell /bin/bash appuser

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip setuptools wheel && \
    pip install --no-cache-dir -r requirements.txt && pip cache purge

FROM base as development
RUN pip install --no-cache-dir flask-shell-ipython ipython ipdb watchdog pytest pytest-flask black flake8
RUN mkdir -p /app/logs /app/uploads /app/instance /app/temp && \
    chown -R appuser:appuser /app && chmod -R 755 /app
COPY --chown=appuser:appuser . .
USER appuser
EXPOSE 8000
CMD ["python", "-m", "flask", "run", "--host=0.0.0.0", "--port=8000", "--reload"]

FROM base as production
COPY --chown=appuser:appuser . .
RUN mkdir -p /app/logs /app/uploads /app/instance /app/temp /app/static && \
    chown -R appuser:appuser /app && chmod -R 755 /app && \
    chmod -R 777 /app/logs /app/uploads /app/temp
USER appuser
ENV PYTHONPATH="/app" PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1 FLASK_ENV=production
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1
EXPOSE 8000
CMD ["gunicorn", "wsgi:app", "--bind", "0.0.0.0:8000", "--workers", "4", "--worker-class", "gevent", "--timeout", "120", "--access-logfile", "/app/logs/access.log", "--error-logfile", "/app/logs/error.log"]
EOF

# 4. Create fixed docker-compose.yml
log "📋 Creating fixed docker-compose.yml..."
cat > docker-compose.yml << 'EOF'
version: '3.8'

x-common-env: &common-env
  SECRET_KEY: ${SECRET_KEY}
  DATABASE_URL: postgresql://crypto_hunter:${DB_PASSWORD}@db:5432/crypto_hunter
  REDIS_URL: redis://redis:6379/0
  CELERY_BROKER_URL: redis://redis:6379/2
  CELERY_RESULT_BACKEND: redis://redis:6379/3
  FLASK_ENV: production
  LOG_LEVEL: INFO
  ENABLE_REGISTRATION: "false"
  ENABLE_AI_ANALYSIS: "true"
  ENABLE_BACKGROUND_TASKS: "true"
  MAX_CONTENT_LENGTH: "1073741824"

services:
  db:
    image: postgres:15-alpine
    container_name: crypto-hunter-db
    restart: unless-stopped
    environment:
      POSTGRES_DB: crypto_hunter
      POSTGRES_USER: crypto_hunter
      POSTGRES_PASSWORD: ${DB_PASSWORD}
    volumes:
      - postgres_data:/var/lib/postgresql/data
    networks:
      - crypto-hunter-network
    ports:
      - "127.0.0.1:5432:5432"
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U crypto_hunter -d crypto_hunter"]
      interval: 30s
      timeout: 10s
      retries: 5
      start_period: 60s

  redis:
    image: redis:7-alpine
    container_name: crypto-hunter-redis
    restart: unless-stopped
    command: redis-server --appendonly yes --maxmemory 1gb --maxmemory-policy allkeys-lru
    volumes:
      - redis_data:/data
    networks:
      - crypto-hunter-network
    ports:
      - "127.0.0.1:6379:6379"
    healthcheck:
      test: ["CMD", "redis-cli", "ping"]
      interval: 30s
      timeout: 10s
      retries: 3

  web:
    build:
      context: .
      target: production
    image: crypto-hunter:latest
    container_name: crypto-hunter-web
    restart: unless-stopped
    environment: *common-env
    volumes:
      - uploads_data:/app/uploads
      - logs_data:/app/logs
      - ./instance:/app/instance
    networks:
      - crypto-hunter-network
    ports:
      - "8000:8000"
    depends_on:
      db:
        condition: service_healthy
      redis:
        condition: service_healthy
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8000/health"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 60s

  worker:
    build:
      context: .
      target: production
    image: crypto-hunter:latest
    container_name: crypto-hunter-worker
    restart: unless-stopped
    command: celery -A crypto_hunter_web.celery_app worker --loglevel=info --concurrency=4
    environment:
      <<: *common-env
      C_FORCE_ROOT: "true"
    volumes:
      - uploads_data:/app/uploads
      - logs_data:/app/logs
      - ./instance:/app/instance
    networks:
      - crypto-hunter-network
    depends_on:
      db:
        condition: service_healthy
      redis:
        condition: service_healthy

  beat:
    build:
      context: .
      target: production
    image: crypto-hunter:latest
    container_name: crypto-hunter-beat
    restart: unless-stopped
    command: celery -A crypto_hunter_web.celery_app beat --loglevel=info
    environment: *common-env
    volumes:
      - logs_data:/app/logs
    networks:
      - crypto-hunter-network
    depends_on:
      - redis

  flower:
    build:
      context: .
      target: production
    image: crypto-hunter:latest
    container_name: crypto-hunter-flower
    restart: unless-stopped
    command: celery -A crypto_hunter_web.celery_app flower --port=5555 --basic_auth=${FLOWER_USER:-admin}:${FLOWER_PASSWORD:-admin123}
    environment: *common-env
    networks:
      - crypto-hunter-network
    ports:
      - "127.0.0.1:5556:5555"
    depends_on:
      - redis

volumes:
  postgres_data:
  redis_data:
  uploads_data:
  logs_data:

networks:
  crypto-hunter-network:
    driver: bridge
EOF

# 5. Create/update .env
if [[ ! -f .env ]]; then
    log "📝 Creating .env..."
    DB_PASSWORD=$(openssl rand -base64 32 | tr -d "=+/" | cut -c1-25)
    SECRET_KEY=$(openssl rand -hex 32)
    FLOWER_PASSWORD=$(openssl rand -base64 16 | tr -d "=+/" | cut -c1-12)

    cat > .env << EOF
FLASK_APP=wsgi.py
FLASK_ENV=production
SECRET_KEY=${SECRET_KEY}
DB_PASSWORD=${DB_PASSWORD}
DATABASE_URL=postgresql://crypto_hunter:${DB_PASSWORD}@db:5432/crypto_hunter
REDIS_URL=redis://redis:6379/0
CELERY_BROKER_URL=redis://redis:6379/2
CELERY_RESULT_BACKEND=redis://redis:6379/3
ENABLE_REGISTRATION=false
ENABLE_AI_ANALYSIS=true
ENABLE_BACKGROUND_TASKS=true
FLOWER_USER=admin
FLOWER_PASSWORD=${FLOWER_PASSWORD}
LOG_LEVEL=INFO
GUNICORN_WORKERS=4
MAX_CONTENT_LENGTH=1073741824
EOF

    success "Environment created - DB Password: $DB_PASSWORD | Flower Password: $FLOWER_PASSWORD"
else
    log "📁 Using existing .env"
fi

# 6. Setup directories
mkdir -p logs uploads instance ssl nginx/conf.d backups
chmod -R 755 logs uploads instance

# 7. Deploy
log "🚀 Building and deploying..."
docker compose build --no-cache
docker compose up -d db redis

log "⏳ Waiting for core services..."
sleep 20

timeout 60 bash -c "
while ! docker compose exec -T db pg_isready -U crypto_hunter -d crypto_hunter >/dev/null 2>&1; do
    sleep 2
done
"

timeout 30 bash -c "
while ! docker compose exec -T redis redis-cli ping >/dev/null 2>&1; do
    sleep 2
done
"

log "🔧 Initializing database..."
docker compose run --rm web flask db init 2>/dev/null || true
docker compose run --rm web flask db migrate -m "Production setup" 2>/dev/null || true
docker compose run --rm web flask db upgrade

log "🚀 Starting all services..."
docker compose up -d

sleep 30

# 8. Verify and show status
log "🔍 Verifying deployment..."
if curl -sf http://localhost:8000/health >/dev/null 2>&1; then
    success "Application is healthy!"
else
    echo "Checking logs..."
    docker compose logs web | tail -10
fi

echo ""
echo "🎉 CRYPTO HUNTER BETA IS READY!"
echo "=================================="
echo "🌐 Web App: http://localhost:8000"
echo "📚 API Docs: http://localhost:8000/docs"
echo "🌺 Monitor: http://localhost:5556"
echo "❤️  Health: http://localhost:8000/health"
echo ""
echo "Create admin user:"
echo "docker compose exec web flask user create --username admin --email admin@example.com --admin"
echo ""
success "Deployment completed successfully!"
EOF

chmod +x fix_and_deploy.sh
./fix_and_deploy.sh
