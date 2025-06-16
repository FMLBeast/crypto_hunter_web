"""
Production Deployment Configuration for Crypto Hunter Multi-Agent System
========================================================================

This file contains complete production deployment configuration including:
- Docker configuration
- Environment management
- Performance optimization
- Security settings
- Monitoring and logging
- Scaling configuration
"""

# ========================================================================
# docker-compose.yml
# ========================================================================

DOCKER_COMPOSE_YML = """
version: '3.8'

services:
  # =======================================
  # Web Application
  # =======================================
  crypto-hunter-web:
    build:
      context: .
      dockerfile: Dockerfile
    container_name: crypto-hunter-web
    restart: unless-stopped
    environment:
      - FLASK_ENV=production
      - DATABASE_URL=postgresql://cryptohunter:${POSTGRES_PASSWORD}@postgres:5432/cryptohunter_prod
      - REDIS_URL=redis://redis:6379/0
      - CELERY_BROKER_URL=redis://redis:6379/1
      - CELERY_RESULT_BACKEND=redis://redis:6379/2
      - SECRET_KEY=${SECRET_KEY}
      - AGENT_SYSTEM_ENABLED=true
      - REALTIME_COLLABORATION_ENABLED=true
      - AI_INTELLIGENCE_ENABLED=true
      - MAX_CONTENT_LENGTH=104857600  # 100MB
      - UPLOAD_FOLDER=/app/uploads
      - EXTRACTION_TEMP_DIR=/app/extractions
    volumes:
      - ./uploads:/app/uploads
      - ./extractions:/app/extractions
      - ./logs:/app/logs
      - ./config/production:/app/config/production
    ports:
      - "5000:5000"
    depends_on:
      - postgres
      - redis
    networks:
      - crypto-hunter-network
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:5000/health"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 40s
    deploy:
      resources:
        limits:
          memory: 4G
          cpus: '2.0'
        reservations:
          memory: 2G
          cpus: '1.0'

  # =======================================
  # Celery Workers for Agent Tasks
  # =======================================
  crypto-hunter-worker:
    build:
      context: .
      dockerfile: Dockerfile
    container_name: crypto-hunter-worker
    restart: unless-stopped
    command: celery -A crypto_hunter_web.celery_app worker --loglevel=info --concurrency=4 --queues=agent_tasks,steganography,crypto_analysis,default
    environment:
      - FLASK_ENV=production
      - DATABASE_URL=postgresql://cryptohunter:${POSTGRES_PASSWORD}@postgres:5432/cryptohunter_prod
      - REDIS_URL=redis://redis:6379/0
      - CELERY_BROKER_URL=redis://redis:6379/1
      - CELERY_RESULT_BACKEND=redis://redis:6379/2
      - SECRET_KEY=${SECRET_KEY}
      - AGENT_SYSTEM_ENABLED=true
      - C_FORCE_ROOT=1
    volumes:
      - ./uploads:/app/uploads
      - ./extractions:/app/extractions
      - ./logs:/app/logs
      - ./tools:/app/tools  # Mount extraction tools
    depends_on:
      - postgres
      - redis
    networks:
      - crypto-hunter-network
    deploy:
      resources:
        limits:
          memory: 8G
          cpus: '4.0'
        reservations:
          memory: 4G
          cpus: '2.0'

  # =======================================
  # Celery Beat for Scheduled Tasks
  # =======================================
  crypto-hunter-beat:
    build:
      context: .
      dockerfile: Dockerfile
    container_name: crypto-hunter-beat
    restart: unless-stopped
    command: celery -A crypto_hunter_web.celery_app beat --loglevel=info --scheduler=celery.beat:PersistentScheduler
    environment:
      - FLASK_ENV=production
      - DATABASE_URL=postgresql://cryptohunter:${POSTGRES_PASSWORD}@postgres:5432/cryptohunter_prod
      - REDIS_URL=redis://redis:6379/0
      - CELERY_BROKER_URL=redis://redis:6379/1
      - CELERY_RESULT_BACKEND=redis://redis:6379/2
      - SECRET_KEY=${SECRET_KEY}
    volumes:
      - ./logs:/app/logs
      - ./celerybeat-schedule:/app/celerybeat-schedule
    depends_on:
      - postgres
      - redis
    networks:
      - crypto-hunter-network

  # =======================================
  # PostgreSQL Database
  # =======================================
  postgres:
    image: postgres:15-alpine
    container_name: crypto-hunter-postgres
    restart: unless-stopped
    environment:
      - POSTGRES_DB=cryptohunter_prod
      - POSTGRES_USER=cryptohunter
      - POSTGRES_PASSWORD=${POSTGRES_PASSWORD}
      - POSTGRES_INITDB_ARGS=--encoding=UTF-8 --locale=C
    volumes:
      - postgres_data:/var/lib/postgresql/data
      - ./database/backups:/backups
      - ./database/init:/docker-entrypoint-initdb.d
    ports:
      - "5432:5432"
    networks:
      - crypto-hunter-network
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U cryptohunter -d cryptohunter_prod"]
      interval: 30s
      timeout: 10s
      retries: 3
    deploy:
      resources:
        limits:
          memory: 2G
          cpus: '1.0'

  # =======================================
  # Redis for Caching and Task Queue
  # =======================================
  redis:
    image: redis:7-alpine
    container_name: crypto-hunter-redis
    restart: unless-stopped
    command: redis-server --appendonly yes --maxmemory 512mb --maxmemory-policy allkeys-lru
    volumes:
      - redis_data:/data
      - ./config/redis/redis.conf:/usr/local/etc/redis/redis.conf
    ports:
      - "6379:6379"
    networks:
      - crypto-hunter-network
    healthcheck:
      test: ["CMD", "redis-cli", "ping"]
      interval: 30s
      timeout: 10s
      retries: 3

  # =======================================
  # Nginx Reverse Proxy
  # =======================================
  nginx:
    image: nginx:alpine
    container_name: crypto-hunter-nginx
    restart: unless-stopped
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./config/nginx/nginx.conf:/etc/nginx/nginx.conf
      - ./config/nginx/ssl:/etc/nginx/ssl
      - ./logs/nginx:/var/log/nginx
      - ./static:/var/www/static
    depends_on:
      - crypto-hunter-web
    networks:
      - crypto-hunter-network
    healthcheck:
      test: ["CMD", "wget", "--quiet", "--tries=1", "--spider", "http://localhost/health"]
      interval: 30s
      timeout: 10s
      retries: 3

  # =======================================
  # Monitoring with Prometheus
  # =======================================
  prometheus:
    image: prom/prometheus:latest
    container_name: crypto-hunter-prometheus
    restart: unless-stopped
    ports:
      - "9090:9090"
    volumes:
      - ./config/prometheus/prometheus.yml:/etc/prometheus/prometheus.yml
      - prometheus_data:/prometheus
    command:
      - '--config.file=/etc/prometheus/prometheus.yml'
      - '--storage.tsdb.path=/prometheus'
      - '--web.console.libraries=/etc/prometheus/console_libraries'
      - '--web.console.templates=/etc/prometheus/consoles'
      - '--storage.tsdb.retention.time=15d'
      - '--web.enable-lifecycle'
    networks:
      - crypto-hunter-network

  # =======================================
  # Grafana for Dashboards
  # =======================================
  grafana:
    image: grafana/grafana:latest
    container_name: crypto-hunter-grafana
    restart: unless-stopped
    ports:
      - "3000:3000"
    environment:
      - GF_SECURITY_ADMIN_PASSWORD=${GRAFANA_PASSWORD}
      - GF_USERS_ALLOW_SIGN_UP=false
    volumes:
      - grafana_data:/var/lib/grafana
      - ./config/grafana/provisioning:/etc/grafana/provisioning
      - ./config/grafana/dashboards:/var/lib/grafana/dashboards
    depends_on:
      - prometheus
    networks:
      - crypto-hunter-network

  # =======================================
  # Log Aggregation with Elasticsearch
  # =======================================
  elasticsearch:
    image: docker.elastic.co/elasticsearch/elasticsearch:8.10.0
    container_name: crypto-hunter-elasticsearch
    restart: unless-stopped
    environment:
      - discovery.type=single-node
      - ES_JAVA_OPTS=-Xms1g -Xmx1g
      - xpack.security.enabled=false
    volumes:
      - elasticsearch_data:/usr/share/elasticsearch/data
    ports:
      - "9200:9200"
    networks:
      - crypto-hunter-network
    healthcheck:
      test: ["CMD-SHELL", "curl -f http://localhost:9200/_cluster/health || exit 1"]
      interval: 30s
      timeout: 10s
      retries: 3

  # =======================================
  # Logstash for Log Processing
  # =======================================
  logstash:
    image: docker.elastic.co/logstash/logstash:8.10.0
    container_name: crypto-hunter-logstash
    restart: unless-stopped
    volumes:
      - ./config/logstash/logstash.yml:/usr/share/logstash/config/logstash.yml
      - ./config/logstash/pipelines:/usr/share/logstash/pipeline
      - ./logs:/app/logs
    depends_on:
      - elasticsearch
    networks:
      - crypto-hunter-network

  # =======================================
  # Kibana for Log Visualization
  # =======================================
  kibana:
    image: docker.elastic.co/kibana/kibana:8.10.0
    container_name: crypto-hunter-kibana
    restart: unless-stopped
    ports:
      - "5601:5601"
    environment:
      - ELASTICSEARCH_HOSTS=http://elasticsearch:9200
    depends_on:
      - elasticsearch
    networks:
      - crypto-hunter-network

# =======================================
# Volumes
# =======================================
volumes:
  postgres_data:
  redis_data:
  prometheus_data:
  grafana_data:
  elasticsearch_data:

# =======================================
# Networks
# =======================================
networks:
  crypto-hunter-network:
    driver: bridge
"""

# ========================================================================
# Dockerfile
# ========================================================================

DOCKERFILE = """
FROM python:3.11-slim

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \\
    PYTHONUNBUFFERED=1 \\
    DEBIAN_FRONTEND=noninteractive

# Install system dependencies
RUN apt-get update && apt-get install -y \\
    build-essential \\
    curl \\
    git \\
    libpq-dev \\
    libmagic1 \\
    libmagic-dev \\
    file \\
    unzip \\
    p7zip-full \\
    binwalk \\
    steghide \\
    zsteg \\
    foremost \\
    exiftool \\
    hexedit \\
    wget \\
    && rm -rf /var/lib/apt/lists/*

# Create app directory
WORKDIR /app

# Copy requirements and install Python dependencies
COPY requirements.txt requirements-prod.txt ./
RUN pip install --no-cache-dir -r requirements-prod.txt

# Create necessary directories
RUN mkdir -p /app/uploads /app/extractions /app/logs /app/tools

# Copy application code
COPY . .

# Set permissions
RUN chmod +x /app/scripts/*.sh

# Install additional extraction tools
RUN /app/scripts/install_tools.sh

# Expose port
EXPOSE 5000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \\
    CMD curl -f http://localhost:5000/health || exit 1

# Default command
CMD ["gunicorn", "--config", "config/gunicorn.conf.py", "crypto_hunter_web:create_app()"]
"""

# ========================================================================
# requirements-prod.txt
# ========================================================================

REQUIREMENTS_PROD = """
# Core Flask and extensions
Flask==3.0.0
Flask-SQLAlchemy==3.1.1
Flask-Migrate==4.0.5
Flask-Login==0.6.3
Flask-WTF==1.2.1
Flask-CORS==4.0.0
Flask-SocketIO==5.3.6

# Database
psycopg2-binary==2.9.9
SQLAlchemy==2.0.23

# Task queue
celery==5.3.4
redis==5.0.1

# Security
cryptography==41.0.7
bcrypt==4.1.2
PyJWT==2.8.0

# File processing
python-magic==0.4.27
Pillow==10.1.0
PyPDF2==3.0.1
python-docx==1.1.0

# HTTP and networking
requests==2.31.0
urllib3==2.1.0

# Data processing
pandas==2.1.4
numpy==1.25.2
scipy==1.11.4

# Utilities
click==8.1.7
python-dotenv==1.0.0
pyyaml==6.0.1
toml==0.10.2

# Web server
gunicorn==21.2.0
gevent==23.9.1

# Monitoring and logging
prometheus-client==0.19.0
structlog==23.2.0
sentry-sdk[flask]==1.38.0

# Development and testing (conditional)
pytest==7.4.3
pytest-cov==4.1.0
black==23.11.0
flake8==6.1.0

# AI and ML
openai==1.3.8
anthropic==0.7.8
sentence-transformers==2.2.2

# Graph processing
networkx==3.2.1

# Additional crypto tools
pycryptodome==3.19.0
hashlib-compat==1.0.1
"""

# ========================================================================
# gunicorn.conf.py
# ========================================================================

GUNICORN_CONFIG = """
# Gunicorn configuration for production
import multiprocessing
import os

# Basic settings
bind = "0.0.0.0:5000"
workers = min(multiprocessing.cpu_count() * 2 + 1, 8)
worker_class = "gevent"
worker_connections = 1000
max_requests = 1000
max_requests_jitter = 100
timeout = 300
keepalive = 2

# Logging
accesslog = "/app/logs/gunicorn_access.log"
errorlog = "/app/logs/gunicorn_error.log"
loglevel = "info"
access_log_format = '%(h)s %(l)s %(u)s %(t)s "%(r)s" %(s)s %(b)s "%(f)s" "%(a)s" %(D)s'

# Process naming
proc_name = "crypto-hunter-web"

# Preload application
preload_app = True

# Worker recycling
max_worker_memory = 2048  # MB
worker_tmp_dir = "/dev/shm"

# Security
limit_request_line = 8190
limit_request_fields = 100
limit_request_field_size = 8190

# SSL (if needed)
# keyfile = "/app/ssl/private.key"
# certfile = "/app/ssl/certificate.crt"

def when_ready(server):
    \"\"\"Called just after the server is started.\"\"\"
    server.log.info("Crypto Hunter server is ready. Listening on: %s", server.address)

def worker_int(worker):
    \"\"\"Called just after a worker has been killed.\"\"\"
    worker.log.info("Worker received INT or QUIT signal")

def on_exit(server):
    \"\"\"Called just before exiting.\"\"\"
    server.log.info("Crypto Hunter server is shutting down.")

def post_worker_init(worker):
    \"\"\"Called just after a worker has been forked.\"\"\"
    worker.log.info("Worker spawned (pid: %s)", worker.pid)
"""

# ========================================================================
# nginx.conf
# ========================================================================

NGINX_CONFIG = """
user nginx;
worker_processes auto;
error_log /var/log/nginx/error.log warn;
pid /var/run/nginx.pid;

events {
    worker_connections 1024;
    use epoll;
    multi_accept on;
}

http {
    include /etc/nginx/mime.types;
    default_type application/octet-stream;

    # Logging
    log_format main '$remote_addr - $remote_user [$time_local] "$request" '
                    '$status $body_bytes_sent "$http_referer" '
                    '"$http_user_agent" "$http_x_forwarded_for" '
                    'rt=$request_time uct="$upstream_connect_time" '
                    'uht="$upstream_header_time" urt="$upstream_response_time"';

    access_log /var/log/nginx/access.log main;

    # Performance settings
    sendfile on;
    tcp_nopush on;
    tcp_nodelay on;
    keepalive_timeout 65;
    types_hash_max_size 2048;
    client_max_body_size 100M;
    
    # Gzip compression
    gzip on;
    gzip_vary on;
    gzip_min_length 10240;
    gzip_proxied expired no-cache no-store private must-revalidate auth;
    gzip_types
        text/plain
        text/css
        text/xml
        text/javascript
        application/x-javascript
        application/xml+rss
        application/javascript
        application/json;

    # Rate limiting
    limit_req_zone $binary_remote_addr zone=api:10m rate=10r/s;
    limit_req_zone $binary_remote_addr zone=login:10m rate=1r/s;

    # Upstream for load balancing
    upstream crypto_hunter_backend {
        server crypto-hunter-web:5000 max_fails=3 fail_timeout=30s;
        keepalive 32;
    }

    # Main server block
    server {
        listen 80;
        server_name localhost;

        # Security headers
        add_header X-Frame-Options "SAMEORIGIN" always;
        add_header X-Content-Type-Options "nosniff" always;
        add_header X-XSS-Protection "1; mode=block" always;
        add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;

        # Static files
        location /static/ {
            alias /var/www/static/;
            expires 1y;
            add_header Cache-Control "public, immutable";
        }

        # Health check
        location /health {
            access_log off;
            return 200 "healthy\\n";
            add_header Content-Type text/plain;
        }

        # API rate limiting
        location /api/ {
            limit_req zone=api burst=20 nodelay;
            proxy_pass http://crypto_hunter_backend;
            include /etc/nginx/proxy_params;
        }

        # Login rate limiting
        location /login {
            limit_req zone=login burst=5 nodelay;
            proxy_pass http://crypto_hunter_backend;
            include /etc/nginx/proxy_params;
        }

        # WebSocket support for real-time collaboration
        location /socket.io/ {
            proxy_pass http://crypto_hunter_backend;
            proxy_http_version 1.1;
            proxy_set_header Upgrade $http_upgrade;
            proxy_set_header Connection "upgrade";
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
            proxy_cache_bypass $http_upgrade;
            proxy_read_timeout 86400;
        }

        # Main application
        location / {
            proxy_pass http://crypto_hunter_backend;
            include /etc/nginx/proxy_params;
        }
    }

    # SSL server block (optional)
    # server {
    #     listen 443 ssl http2;
    #     server_name your-domain.com;
    #
    #     ssl_certificate /etc/nginx/ssl/certificate.crt;
    #     ssl_certificate_key /etc/nginx/ssl/private.key;
    #     ssl_protocols TLSv1.2 TLSv1.3;
    #     ssl_ciphers ECDHE-RSA-AES256-GCM-SHA512:DHE-RSA-AES256-GCM-SHA512;
    #     ssl_prefer_server_ciphers off;
    #
    #     location / {
    #         proxy_pass http://crypto_hunter_backend;
    #         include /etc/nginx/proxy_params;
    #     }
    # }
}

# Include additional configs
include /etc/nginx/conf.d/*.conf;
"""

# ========================================================================
# proxy_params
# ========================================================================

PROXY_PARAMS = """
proxy_set_header Host $http_host;
proxy_set_header X-Real-IP $remote_addr;
proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
proxy_set_header X-Forwarded-Proto $scheme;
proxy_buffering off;
proxy_request_buffering off;
proxy_http_version 1.1;
proxy_intercept_errors on;
"""

# ========================================================================
# Production Configuration Class
# ========================================================================

PRODUCTION_CONFIG = """
# config/production.py
import os
from datetime import timedelta

class ProductionConfig:
    \"\"\"Production configuration\"\"\"
    
    # Basic Flask config
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'your-super-secret-production-key'
    
    # Database
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or \\
        'postgresql://cryptohunter:password@localhost/cryptohunter_prod'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ENGINE_OPTIONS = {
        'pool_pre_ping': True,
        'pool_recycle': 3600,
        'pool_size': 20,
        'max_overflow': 30
    }
    
    # Redis
    REDIS_URL = os.environ.get('REDIS_URL') or 'redis://localhost:6379/0'
    
    # Celery
    CELERY_BROKER_URL = os.environ.get('CELERY_BROKER_URL') or 'redis://localhost:6379/1'
    CELERY_RESULT_BACKEND = os.environ.get('CELERY_RESULT_BACKEND') or 'redis://localhost:6379/2'
    CELERY_TASK_SERIALIZER = 'json'
    CELERY_ACCEPT_CONTENT = ['json']
    CELERY_RESULT_SERIALIZER = 'json'
    CELERY_TIMEZONE = 'UTC'
    CELERY_ENABLE_UTC = True
    CELERY_TASK_ROUTES = {
        'crypto_hunter_web.tasks.agent_tasks.*': {'queue': 'agent_tasks'},
        'crypto_hunter_web.tasks.steganography.*': {'queue': 'steganography'},
        'crypto_hunter_web.tasks.crypto_analysis.*': {'queue': 'crypto_analysis'},
    }
    
    # File uploads
    MAX_CONTENT_LENGTH = 100 * 1024 * 1024  # 100MB
    UPLOAD_FOLDER = os.environ.get('UPLOAD_FOLDER') or '/app/uploads'
    EXTRACTION_TEMP_DIR = os.environ.get('EXTRACTION_TEMP_DIR') or '/app/extractions'
    
    # Security
    WTF_CSRF_ENABLED = True
    WTF_CSRF_TIME_LIMIT = 3600
    SESSION_COOKIE_SECURE = True
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    PERMANENT_SESSION_LIFETIME = timedelta(hours=24)
    
    # Agent system
    AGENT_SYSTEM_ENABLED = True
    AGENT_MAX_CONCURRENT_WORKFLOWS = 50
    AGENT_TASK_TIMEOUT = 1800  # 30 minutes
    AGENT_CLEANUP_INTERVAL = 3600  # 1 hour
    
    # Real-time collaboration
    REALTIME_COLLABORATION_ENABLED = True
    SOCKETIO_ASYNC_MODE = 'gevent'
    
    # AI Intelligence
    AI_INTELLIGENCE_ENABLED = True
    OPENAI_API_KEY = os.environ.get('OPENAI_API_KEY')
    ANTHROPIC_API_KEY = os.environ.get('ANTHROPIC_API_KEY')
    
    # Logging
    LOG_LEVEL = 'INFO'
    LOG_FORMAT = '%(asctime)s %(levelname)s %(name)s: %(message)s'
    LOG_FILE = '/app/logs/crypto_hunter.log'
    
    # Monitoring
    PROMETHEUS_ENABLED = True
    SENTRY_DSN = os.environ.get('SENTRY_DSN')
    
    # Performance
    CACHE_TYPE = 'redis'
    CACHE_REDIS_URL = os.environ.get('REDIS_URL') or 'redis://localhost:6379/0'
    CACHE_DEFAULT_TIMEOUT = 300
    
    # Rate limiting
    RATELIMIT_STORAGE_URL = os.environ.get('REDIS_URL') or 'redis://localhost:6379/0'
    RATELIMIT_DEFAULT = '1000 per hour'
    
    @staticmethod
    def init_app(app):
        \"\"\"Initialize app with production config\"\"\"
        
        # Configure logging
        import logging
        from logging.handlers import RotatingFileHandler
        
        if not app.debug:
            if not os.path.exists('logs'):
                os.mkdir('logs')
            
            file_handler = RotatingFileHandler(
                'logs/crypto_hunter.log',
                maxBytes=10240000,  # 10MB
                backupCount=10
            )
            file_handler.setFormatter(logging.Formatter(
                '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
            ))
            file_handler.setLevel(logging.INFO)
            app.logger.addHandler(file_handler)
            
            app.logger.setLevel(logging.INFO)
            app.logger.info('Crypto Hunter startup')
        
        # Configure Sentry for error tracking
        if ProductionConfig.SENTRY_DSN:
            import sentry_sdk
            from sentry_sdk.integrations.flask import FlaskIntegration
            from sentry_sdk.integrations.celery import CeleryIntegration
            
            sentry_sdk.init(
                dsn=ProductionConfig.SENTRY_DSN,
                integrations=[
                    FlaskIntegration(),
                    CeleryIntegration()
                ],
                traces_sample_rate=0.1
            )
"""

# ========================================================================
# Environment File Template
# ========================================================================

ENV_TEMPLATE = """
# .env.production
# Production environment variables

# Security
SECRET_KEY=your-super-secret-production-key-change-this
POSTGRES_PASSWORD=your-secure-postgres-password
GRAFANA_PASSWORD=your-secure-grafana-password

# Database
DATABASE_URL=postgresql://cryptohunter:${POSTGRES_PASSWORD}@postgres:5432/cryptohunter_prod

# Redis
REDIS_URL=redis://redis:6379/0
CELERY_BROKER_URL=redis://redis:6379/1
CELERY_RESULT_BACKEND=redis://redis:6379/2

# AI Services (optional)
OPENAI_API_KEY=your-openai-api-key
ANTHROPIC_API_KEY=your-anthropic-api-key

# Monitoring (optional)
SENTRY_DSN=your-sentry-dsn

# Application settings
FLASK_ENV=production
MAX_CONTENT_LENGTH=104857600
UPLOAD_FOLDER=/app/uploads
EXTRACTION_TEMP_DIR=/app/extractions

# Feature flags
AGENT_SYSTEM_ENABLED=true
REALTIME_COLLABORATION_ENABLED=true
AI_INTELLIGENCE_ENABLED=true
"""

# ========================================================================
# Installation Script
# ========================================================================

INSTALL_SCRIPT = """#!/bin/bash
# install_tools.sh
# Install additional extraction and analysis tools

set -e

echo "Installing additional crypto and steganography tools..."

# Create tools directory
mkdir -p /app/tools
cd /app/tools

# Install additional steganography tools
echo "Installing stegsolve..."
wget -q https://github.com/zardus/ctf-tools/raw/master/stegsolve/install -O stegsolve_install.sh
chmod +x stegsolve_install.sh
./stegsolve_install.sh

# Install additional crypto tools
echo "Installing john the ripper..."
apt-get update && apt-get install -y john

# Install hashcat (if GPU available)
echo "Installing hashcat..."
apt-get install -y hashcat

# Install additional file analysis tools
echo "Installing additional analysis tools..."
apt-get install -y \\
    xxd \\
    strings \\
    file \\
    hexdump \\
    objdump \\
    readelf \\
    nm \\
    ldd

# Install volatility for memory analysis
echo "Installing volatility..."
pip install volatility3

# Install additional Python tools
pip install \\
    pycrypto \\
    pynacl \\
    scapy \\
    z3-solver \\
    angr \\
    capstone \\
    keystone-engine \\
    unicorn

# Set permissions
chmod +x /app/tools/*

echo "Tools installation completed!"
"""

# ========================================================================
# Health Check Script
# ========================================================================

HEALTH_CHECK = """#!/bin/bash
# health_check.sh
# Comprehensive health check for the application

set -e

echo "Performing health checks..."

# Check web application
echo "Checking web application..."
curl -f http://localhost:5000/health || exit 1

# Check database connection
echo "Checking database connection..."
python3 -c "
import psycopg2
import os
try:
    conn = psycopg2.connect(os.environ['DATABASE_URL'])
    conn.close()
    print('Database connection: OK')
except Exception as e:
    print(f'Database connection failed: {e}')
    exit(1)
"

# Check Redis connection
echo "Checking Redis connection..."
python3 -c "
import redis
import os
try:
    r = redis.from_url(os.environ['REDIS_URL'])
    r.ping()
    print('Redis connection: OK')
except Exception as e:
    print(f'Redis connection failed: {e}')
    exit(1)
"

# Check Celery workers
echo "Checking Celery workers..."
celery -A crypto_hunter_web.celery_app status || echo "Warning: Celery workers not responding"

# Check disk space
echo "Checking disk space..."
df -h /app/uploads /app/extractions

# Check memory usage
echo "Checking memory usage..."
free -h

echo "Health check completed successfully!"
"""

# ========================================================================
# Backup Script
# ========================================================================

BACKUP_SCRIPT = """#!/bin/bash
# backup.sh
# Database and file backup script

set -e

BACKUP_DIR="/backups/$(date +%Y%m%d_%H%M%S)"
mkdir -p "$BACKUP_DIR"

echo "Starting backup to $BACKUP_DIR..."

# Backup database
echo "Backing up database..."
pg_dump "$DATABASE_URL" > "$BACKUP_DIR/database.sql"
gzip "$BACKUP_DIR/database.sql"

# Backup uploads
echo "Backing up uploads..."
tar -czf "$BACKUP_DIR/uploads.tar.gz" /app/uploads/

# Backup extractions (optional, can be large)
if [ "$BACKUP_EXTRACTIONS" = "true" ]; then
    echo "Backing up extractions..."
    tar -czf "$BACKUP_DIR/extractions.tar.gz" /app/extractions/
fi

# Backup configuration
echo "Backing up configuration..."
tar -czf "$BACKUP_DIR/config.tar.gz" /app/config/

# Create backup manifest
echo "Creating backup manifest..."
cat > "$BACKUP_DIR/manifest.txt" << EOF
Backup created: $(date)
Database: database.sql.gz
Uploads: uploads.tar.gz
Configuration: config.tar.gz
$(if [ "$BACKUP_EXTRACTIONS" = "true" ]; then echo "Extractions: extractions.tar.gz"; fi)
EOF

# Clean up old backups (keep last 7 days)
find /backups -type d -mtime +7 -exec rm -rf {} +

echo "Backup completed successfully!"
echo "Backup location: $BACKUP_DIR"
"""

# ========================================================================
# Monitoring Configuration
# ========================================================================

PROMETHEUS_CONFIG = """
# prometheus.yml
global:
  scrape_interval: 15s
  evaluation_interval: 15s

rule_files:
  # - "first_rules.yml"
  # - "second_rules.yml"

scrape_configs:
  - job_name: 'prometheus'
    static_configs:
      - targets: ['localhost:9090']

  - job_name: 'crypto-hunter-web'
    static_configs:
      - targets: ['crypto-hunter-web:5000']
    metrics_path: '/metrics'
    scrape_interval: 30s

  - job_name: 'postgres'
    static_configs:
      - targets: ['postgres:5432']

  - job_name: 'redis'
    static_configs:
      - targets: ['redis:6379']

  - job_name: 'nginx'
    static_configs:
      - targets: ['nginx:80']
"""

# ========================================================================
# Deployment Instructions
# ========================================================================

DEPLOYMENT_INSTRUCTIONS = """
# Crypto Hunter Production Deployment Guide

## Prerequisites
- Docker and Docker Compose installed
- At least 16GB RAM and 4 CPU cores recommended
- 100GB+ disk space for file storage
- SSL certificate (optional but recommended)

## Quick Start

1. Clone the repository:
   ```bash
   git clone <repository-url>
   cd crypto-hunter
   ```

2. Create environment file:
   ```bash
   cp .env.production.template .env.production
   # Edit .env.production with your values
   ```

3. Create necessary directories:
   ```bash
   mkdir -p uploads extractions logs database/backups config
   ```

4. Deploy with Docker Compose:
   ```bash
   docker-compose -f docker-compose.yml up -d
   ```

5. Initialize the database:
   ```bash
   docker-compose exec crypto-hunter-web flask db upgrade
   docker-compose exec crypto-hunter-web python -c "from crypto_hunter_web.models import init_database; init_database()"
   ```

6. Create admin user:
   ```bash
   docker-compose exec crypto-hunter-web python -c "
   from crypto_hunter_web.models import User, db
   admin = User(username='admin', email='admin@example.com', is_admin=True)
   admin.set_password('your-secure-password')
   db.session.add(admin)
   db.session.commit()
   "
   ```

7. Access the application:
   - Web interface: http://your-server/
   - Grafana monitoring: http://your-server:3000
   - Kibana logs: http://your-server:5601

## Configuration

### Environment Variables
Key environment variables in `.env.production`:
- `SECRET_KEY`: Flask secret key
- `POSTGRES_PASSWORD`: Database password
- `OPENAI_API_KEY`: OpenAI API key (optional)
- `SENTRY_DSN`: Error tracking (optional)

### SSL Configuration
To enable SSL:
1. Place certificate files in `config/nginx/ssl/`
2. Uncomment SSL server block in nginx.conf
3. Update domain name
4. Restart nginx container

### Scaling
To scale worker processes:
```bash
docker-compose up -d --scale crypto-hunter-worker=4
```

## Monitoring

### Prometheus Metrics
Available at http://your-server:9090
- Application performance metrics
- Database connection pool
- Task queue status
- System resources

### Grafana Dashboards
Available at http://your-server:3000
- Default credentials: admin/admin (change immediately)
- Pre-configured dashboards for:
  - Application overview
  - Database performance
  - Celery task monitoring
  - System resources

### Log Aggregation
Centralized logging with ELK stack:
- Elasticsearch: http://your-server:9200
- Kibana: http://your-server:5601

## Backup and Recovery

### Automated Backups
Run backup script:
```bash
docker-compose exec crypto-hunter-web /app/scripts/backup.sh
```

### Restore from Backup
```bash
# Restore database
gunzip -c /backups/YYYYMMDD_HHMMSS/database.sql.gz | docker-compose exec -T postgres psql -U cryptohunter -d cryptohunter_prod

# Restore files
tar -xzf /backups/YYYYMMDD_HHMMSS/uploads.tar.gz -C /
```

## Maintenance

### Update Application
```bash
git pull
docker-compose build
docker-compose up -d
```

### Database Migrations
```bash
docker-compose exec crypto-hunter-web flask db upgrade
```

### Clean Up
```bash
# Clean old task results
docker-compose exec crypto-hunter-web python -c "
from crypto_hunter_web.services.agent_extraction_service import agent_extraction_service
agent_extraction_service.cleanup_old_executions(days_old=7)
"

# Clean Docker images
docker system prune -a
```

## Security Considerations

1. **Change default passwords** in .env.production
2. **Enable SSL** for production use
3. **Configure firewall** to restrict access
4. **Regular security updates** for base images
5. **Monitor access logs** for suspicious activity
6. **Use strong passwords** for all accounts
7. **Enable fail2ban** for brute force protection

## Troubleshooting

### Check container status:
```bash
docker-compose ps
```

### View logs:
```bash
docker-compose logs crypto-hunter-web
docker-compose logs crypto-hunter-worker
```

### Test connectivity:
```bash
docker-compose exec crypto-hunter-web python -c "
from crypto_hunter_web.extensions import db
from crypto_hunter_web import create_app
app = create_app()
with app.app_context():
    db.engine.execute('SELECT 1')
    print('Database connection: OK')
"
```

## Performance Tuning

### Database Optimization
- Increase shared_buffers for PostgreSQL
- Configure connection pooling
- Regular VACUUM and ANALYZE

### Redis Optimization
- Configure maxmemory policy
- Monitor memory usage
- Use Redis persistence settings

### Application Tuning
- Adjust Gunicorn worker count
- Configure Celery concurrency
- Optimize task queue routing

For support, check the documentation or create an issue in the repository.
"""

# Export all configurations
def generate_production_configs():
    """Generate all production configuration files"""
    configs = {
        'docker-compose.yml': DOCKER_COMPOSE_YML,
        'Dockerfile': DOCKERFILE,
        'requirements-prod.txt': REQUIREMENTS_PROD,
        'config/gunicorn.conf.py': GUNICORN_CONFIG,
        'config/nginx/nginx.conf': NGINX_CONFIG,
        'config/nginx/proxy_params': PROXY_PARAMS,
        'config/production.py': PRODUCTION_CONFIG,
        '.env.production.template': ENV_TEMPLATE,
        'scripts/install_tools.sh': INSTALL_SCRIPT,
        'scripts/health_check.sh': HEALTH_CHECK,
        'scripts/backup.sh': BACKUP_SCRIPT,
        'config/prometheus/prometheus.yml': PROMETHEUS_CONFIG,
        'DEPLOYMENT.md': DEPLOYMENT_INSTRUCTIONS
    }
    
    return configs

if __name__ == '__main__':
    print("Production deployment configuration generated!")
    print("Files to create:")
    for filename in generate_production_configs().keys():
        print(f"  - {filename}")
