"""
Production Deployment Configuration for Crypto Hunter Multi-Agent System
========================================================================

This file contains comprehensive production deployment configurations including:
- Docker configurations
- Kubernetes manifests  
- Monitoring setup
- Load balancing
- Security configurations
- Auto-scaling policies
"""

# docker-compose.prod.yml
DOCKER_COMPOSE_PRODUCTION = """
version: '3.8'

services:
  # Main Application
  crypto-hunter-web:
    build:
      context: .
      dockerfile: Dockerfile.prod
      args:
        - BUILD_ENV=production
    image: crypto-hunter:latest
    container_name: crypto-hunter-web
    restart: unless-stopped
    environment:
      - ENVIRONMENT=production
      - DATABASE_URL=postgresql://crypto_user:${DB_PASSWORD}@postgres:5432/crypto_hunter_prod
      - REDIS_URL=redis://redis:6379/0
      - AGENT_MAX_MEMORY_MB=2048
      - AGENT_SANDBOX_MODE=true
      - LLM_API_KEY=${LLM_API_KEY}
      - SECRET_KEY=${SECRET_KEY}
      - WEBHOOK_URL=${WEBHOOK_URL}
    depends_on:
      - postgres
      - redis
      - prometheus
    ports:
      - "8000:8000"
    volumes:
      - ./uploads:/app/uploads:rw
      - ./temp:/app/temp:rw
      - ./logs:/app/logs:rw
    networks:
      - crypto-hunter-network
    deploy:
      resources:
        limits:
          memory: 4G
          cpus: '2.0'
        reservations:
          memory: 1G
          cpus: '0.5'
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8000/health"]
      interval: 30s
      timeout: 10s
      retries: 3

  # Agent Workers
  crypto-hunter-worker:
    build:
      context: .
      dockerfile: Dockerfile.worker
    image: crypto-hunter-worker:latest
    restart: unless-stopped
    environment:
      - ENVIRONMENT=production
      - DATABASE_URL=postgresql://crypto_user:${DB_PASSWORD}@postgres:5432/crypto_hunter_prod
      - REDIS_URL=redis://redis:6379/0
      - AGENT_MAX_MEMORY_MB=2048
      - AGENT_MAX_CONCURRENT_TASKS=5
      - CELERY_BROKER_URL=redis://redis:6379/1
    depends_on:
      - postgres
      - redis
    volumes:
      - ./uploads:/app/uploads:ro
      - ./temp:/app/temp:rw
      - ./tools:/app/tools:ro
    networks:
      - crypto-hunter-network
    deploy:
      replicas: 3
      resources:
        limits:
          memory: 3G
          cpus: '1.5'
        reservations:
          memory: 512M
          cpus: '0.25'
    healthcheck:
      test: ["CMD", "python", "-c", "import redis; redis.Redis(host='redis').ping()"]
      interval: 30s
      timeout: 10s
      retries: 3

  # PostgreSQL Database
  postgres:
    image: postgres:15-alpine
    container_name: crypto-hunter-postgres
    restart: unless-stopped
    environment:
      - POSTGRES_DB=crypto_hunter_prod
      - POSTGRES_USER=crypto_user
      - POSTGRES_PASSWORD=${DB_PASSWORD}
      - POSTGRES_INITDB_ARGS=--auth-host=scram-sha-256
    volumes:
      - postgres_data:/var/lib/postgresql/data
      - ./scripts/init-db.sql:/docker-entrypoint-initdb.d/init-db.sql:ro
    networks:
      - crypto-hunter-network
    ports:
      - "5432:5432"
    deploy:
      resources:
        limits:
          memory: 2G
          cpus: '1.0'
        reservations:
          memory: 256M
          cpus: '0.25'
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U crypto_user -d crypto_hunter_prod"]
      interval: 30s
      timeout: 10s
      retries: 3

  # Redis Cache & Message Broker
  redis:
    image: redis:7-alpine
    container_name: crypto-hunter-redis
    restart: unless-stopped
    command: redis-server --appendonly yes --maxmemory 1gb --maxmemory-policy allkeys-lru
    volumes:
      - redis_data:/data
      - ./config/redis.conf:/usr/local/etc/redis/redis.conf:ro
    networks:
      - crypto-hunter-network
    ports:
      - "6379:6379"
    deploy:
      resources:
        limits:
          memory: 1G
          cpus: '0.5'
        reservations:
          memory: 128M
          cpus: '0.1'
    healthcheck:
      test: ["CMD", "redis-cli", "ping"]
      interval: 30s
      timeout: 10s
      retries: 3

  # Nginx Load Balancer
  nginx:
    image: nginx:alpine
    container_name: crypto-hunter-nginx
    restart: unless-stopped
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./config/nginx.conf:/etc/nginx/nginx.conf:ro
      - ./config/ssl:/etc/nginx/ssl:ro
      - ./static:/var/www/static:ro
    depends_on:
      - crypto-hunter-web
    networks:
      - crypto-hunter-network
    deploy:
      resources:
        limits:
          memory: 256M
          cpus: '0.5'
        reservations:
          memory: 64M
          cpus: '0.1'
    healthcheck:
      test: ["CMD", "wget", "--quiet", "--tries=1", "--spider", "http://localhost/health"]
      interval: 30s
      timeout: 10s
      retries: 3

  # Prometheus Monitoring
  prometheus:
    image: prom/prometheus:latest
    container_name: crypto-hunter-prometheus
    restart: unless-stopped
    command:
      - '--config.file=/etc/prometheus/prometheus.yml'
      - '--storage.tsdb.path=/prometheus'
      - '--web.console.libraries=/etc/prometheus/console_libraries'
      - '--web.console.templates=/etc/prometheus/consoles'
      - '--storage.tsdb.retention.time=30d'
      - '--web.enable-lifecycle'
    volumes:
      - ./config/prometheus.yml:/etc/prometheus/prometheus.yml:ro
      - prometheus_data:/prometheus
    networks:
      - crypto-hunter-network
    ports:
      - "9090:9090"
    deploy:
      resources:
        limits:
          memory: 1G
          cpus: '0.5'
        reservations:
          memory: 256M
          cpus: '0.1'

  # Grafana Dashboard
  grafana:
    image: grafana/grafana:latest
    container_name: crypto-hunter-grafana
    restart: unless-stopped
    environment:
      - GF_SECURITY_ADMIN_PASSWORD=${GRAFANA_PASSWORD}
      - GF_INSTALL_PLUGINS=grafana-clock-panel,grafana-simple-json-datasource
    volumes:
      - grafana_data:/var/lib/grafana
      - ./config/grafana/dashboards:/etc/grafana/provisioning/dashboards:ro
      - ./config/grafana/datasources:/etc/grafana/provisioning/datasources:ro
    networks:
      - crypto-hunter-network
    ports:
      - "3000:3000"
    depends_on:
      - prometheus
    deploy:
      resources:
        limits:
          memory: 512M
          cpus: '0.5'
        reservations:
          memory: 128M
          cpus: '0.1'

  # Log Aggregation
  loki:
    image: grafana/loki:latest
    container_name: crypto-hunter-loki
    restart: unless-stopped
    command: -config.file=/etc/loki/local-config.yaml
    volumes:
      - ./config/loki.yml:/etc/loki/local-config.yaml:ro
      - loki_data:/loki
    networks:
      - crypto-hunter-network
    ports:
      - "3100:3100"
    deploy:
      resources:
        limits:
          memory: 512M
          cpus: '0.5'

  # Log Shipper
  promtail:
    image: grafana/promtail:latest
    container_name: crypto-hunter-promtail
    restart: unless-stopped
    command: -config.file=/etc/promtail/config.yml
    volumes:
      - ./config/promtail.yml:/etc/promtail/config.yml:ro
      - ./logs:/var/log/crypto-hunter:ro
      - /var/lib/docker/containers:/var/lib/docker/containers:ro
    networks:
      - crypto-hunter-network
    depends_on:
      - loki

volumes:
  postgres_data:
    driver: local
  redis_data:
    driver: local
  prometheus_data:
    driver: local
  grafana_data:
    driver: local
  loki_data:
    driver: local

networks:
  crypto-hunter-network:
    driver: bridge
    ipam:
      driver: default
      config:
        - subnet: 172.20.0.0/16
"""

# Dockerfile.prod
DOCKERFILE_PRODUCTION = """
FROM python:3.11-slim

# Set environment variables
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1
ENV ENVIRONMENT=production

# Install system dependencies
RUN apt-get update && apt-get install -y \\
    gcc \\
    g++ \\
    libpq-dev \\
    libmagic1 \\
    curl \\
    wget \\
    git \\
    exiftool \\
    binwalk \\
    zsteg \\
    steghide \\
    && rm -rf /var/lib/apt/lists/*

# Create app user
RUN groupadd -r appuser && useradd -r -g appuser appuser

# Set work directory
WORKDIR /app

# Copy requirements
COPY requirements.txt requirements-prod.txt ./

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements-prod.txt

# Copy application code
COPY . .

# Create necessary directories
RUN mkdir -p /app/uploads /app/temp /app/logs /app/static

# Set ownership
RUN chown -R appuser:appuser /app

# Switch to non-root user
USER appuser

# Expose port
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \\
    CMD curl -f http://localhost:8000/health || exit 1

# Start command
CMD ["gunicorn", "--config", "gunicorn.conf.py", "app:app"]
"""

# Dockerfile.worker
DOCKERFILE_WORKER = """
FROM python:3.11-slim

# Set environment variables
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1
ENV ENVIRONMENT=production

# Install system dependencies
RUN apt-get update && apt-get install -y \\
    gcc \\
    g++ \\
    libpq-dev \\
    libmagic1 \\
    exiftool \\
    binwalk \\
    zsteg \\
    steghide \\
    && rm -rf /var/lib/apt/lists/*

# Create app user
RUN groupadd -r worker && useradd -r -g worker worker

# Set work directory
WORKDIR /app

# Copy requirements
COPY requirements.txt requirements-prod.txt ./

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements-prod.txt

# Copy application code
COPY . .

# Create necessary directories
RUN mkdir -p /app/temp /app/logs

# Set ownership
RUN chown -R worker:worker /app

# Switch to non-root user
USER worker

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \\
    CMD python -c "import redis; redis.Redis(host='redis').ping()" || exit 1

# Start worker
CMD ["python", "-m", "celery", "worker", "-A", "crypto_hunter_web.celery_app", "--loglevel=info", "--concurrency=4"]
"""

# Kubernetes manifests
KUBERNETES_NAMESPACE = """
apiVersion: v1
kind: Namespace
metadata:
  name: crypto-hunter
  labels:
    name: crypto-hunter
    environment: production
---
apiVersion: v1
kind: ResourceQuota
metadata:
  name: crypto-hunter-quota
  namespace: crypto-hunter
spec:
  hard:
    requests.cpu: "8"
    requests.memory: 16Gi
    limits.cpu: "16"
    limits.memory: 32Gi
    persistentvolumeclaims: "10"
"""

KUBERNETES_DEPLOYMENT = """
apiVersion: apps/v1
kind: Deployment
metadata:
  name: crypto-hunter-web
  namespace: crypto-hunter
  labels:
    app: crypto-hunter-web
    version: v1
spec:
  replicas: 3
  selector:
    matchLabels:
      app: crypto-hunter-web
  template:
    metadata:
      labels:
        app: crypto-hunter-web
        version: v1
    spec:
      containers:
      - name: crypto-hunter-web
        image: crypto-hunter:latest
        ports:
        - containerPort: 8000
        env:
        - name: DATABASE_URL
          valueFrom:
            secretKeyRef:
              name: crypto-hunter-secrets
              key: database-url
        - name: REDIS_URL
          value: "redis://redis-service:6379/0"
        - name: ENVIRONMENT
          value: "production"
        resources:
          requests:
            memory: "1Gi"
            cpu: "500m"
          limits:
            memory: "4Gi"
            cpu: "2"
        livenessProbe:
          httpGet:
            path: /health
            port: 8000
          initialDelaySeconds: 30
          periodSeconds: 30
        readinessProbe:
          httpGet:
            path: /ready
            port: 8000
          initialDelaySeconds: 10
          periodSeconds: 10
        volumeMounts:
        - name: uploads
          mountPath: /app/uploads
        - name: temp
          mountPath: /app/temp
      volumes:
      - name: uploads
        persistentVolumeClaim:
          claimName: crypto-hunter-uploads-pvc
      - name: temp
        emptyDir: {}
---
apiVersion: v1
kind: Service
metadata:
  name: crypto-hunter-web-service
  namespace: crypto-hunter
spec:
  selector:
    app: crypto-hunter-web
  ports:
  - protocol: TCP
    port: 8000
    targetPort: 8000
  type: ClusterIP
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: crypto-hunter-worker
  namespace: crypto-hunter
  labels:
    app: crypto-hunter-worker
spec:
  replicas: 5
  selector:
    matchLabels:
      app: crypto-hunter-worker
  template:
    metadata:
      labels:
        app: crypto-hunter-worker
    spec:
      containers:
      - name: crypto-hunter-worker
        image: crypto-hunter-worker:latest
        env:
        - name: DATABASE_URL
          valueFrom:
            secretKeyRef:
              name: crypto-hunter-secrets
              key: database-url
        - name: REDIS_URL
          value: "redis://redis-service:6379/0"
        - name: CELERY_BROKER_URL
          value: "redis://redis-service:6379/1"
        resources:
          requests:
            memory: "512Mi"
            cpu: "250m"
          limits:
            memory: "3Gi"
            cpu: "1.5"
        volumeMounts:
        - name: temp
          mountPath: /app/temp
      volumes:
      - name: temp
        emptyDir: {}
"""

KUBERNETES_HPA = """
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: crypto-hunter-web-hpa
  namespace: crypto-hunter
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: crypto-hunter-web
  minReplicas: 2
  maxReplicas: 10
  metrics:
  - type: Resource
    resource:
      name: cpu
      target:
        type: Utilization
        averageUtilization: 70
  - type: Resource
    resource:
      name: memory
      target:
        type: Utilization
        averageUtilization: 80
---
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: crypto-hunter-worker-hpa
  namespace: crypto-hunter
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: crypto-hunter-worker
  minReplicas: 3
  maxReplicas: 20
  metrics:
  - type: Resource
    resource:
      name: cpu
      target:
        type: Utilization
        averageUtilization: 75
  behavior:
    scaleUp:
      stabilizationWindowSeconds: 60
      policies:
      - type: Percent
        value: 100
        periodSeconds: 60
    scaleDown:
      stabilizationWindowSeconds: 300
      policies:
      - type: Percent
        value: 50
        periodSeconds: 60
"""

# Monitoring configurations
PROMETHEUS_CONFIG = """
global:
  scrape_interval: 15s
  evaluation_interval: 15s

rule_files:
  - "crypto_hunter_rules.yml"

alerting:
  alertmanagers:
    - static_configs:
        - targets:
          - alertmanager:9093

scrape_configs:
  - job_name: 'crypto-hunter-web'
    static_configs:
      - targets: ['crypto-hunter-web:8000']
    metrics_path: '/metrics'
    scrape_interval: 30s

  - job_name: 'crypto-hunter-workers'
    static_configs:
      - targets: ['crypto-hunter-worker:8001']
    metrics_path: '/metrics'
    scrape_interval: 30s

  - job_name: 'postgres-exporter'
    static_configs:
      - targets: ['postgres-exporter:9187']

  - job_name: 'redis-exporter'
    static_configs:
      - targets: ['redis-exporter:9121']

  - job_name: 'node-exporter'
    static_configs:
      - targets: ['node-exporter:9100']
"""

GRAFANA_DASHBOARD = """
{
  "dashboard": {
    "id": null,
    "title": "Crypto Hunter Agent System",
    "tags": ["crypto-hunter", "agents"],
    "timezone": "browser",
    "panels": [
      {
        "id": 1,
        "title": "Agent System Overview",
        "type": "stat",
        "targets": [
          {
            "expr": "crypto_hunter_agents_active",
            "legendFormat": "Active Agents"
          },
          {
            "expr": "crypto_hunter_workflows_running",
            "legendFormat": "Running Workflows"
          },
          {
            "expr": "crypto_hunter_tasks_queued",
            "legendFormat": "Queued Tasks"
          }
        ],
        "gridPos": {"h": 4, "w": 24, "x": 0, "y": 0}
      },
      {
        "id": 2,
        "title": "Workflow Execution Rate",
        "type": "graph",
        "targets": [
          {
            "expr": "rate(crypto_hunter_workflows_completed_total[5m])",
            "legendFormat": "Workflows/sec"
          }
        ],
        "gridPos": {"h": 8, "w": 12, "x": 0, "y": 4}
      },
      {
        "id": 3,
        "title": "Agent Utilization",
        "type": "piechart",
        "targets": [
          {
            "expr": "crypto_hunter_agent_utilization_by_type",
            "legendFormat": "{{agent_type}}"
          }
        ],
        "gridPos": {"h": 8, "w": 12, "x": 12, "y": 4}
      },
      {
        "id": 4,
        "title": "System Resources",
        "type": "graph",
        "targets": [
          {
            "expr": "crypto_hunter_memory_usage_bytes",
            "legendFormat": "Memory Usage"
          },
          {
            "expr": "crypto_hunter_cpu_usage_percent",
            "legendFormat": "CPU Usage %"
          }
        ],
        "gridPos": {"h": 8, "w": 24, "x": 0, "y": 12}
      }
    ],
    "time": {
      "from": "now-1h",
      "to": "now"
    },
    "refresh": "10s"
  }
}
"""

# Nginx configuration
NGINX_CONFIG = """
events {
    worker_connections 1024;
}

http {
    upstream crypto_hunter_backend {
        server crypto-hunter-web:8000;
    }

    # Rate limiting
    limit_req_zone $binary_remote_addr zone=api:10m rate=10r/s;
    limit_req_zone $binary_remote_addr zone=upload:10m rate=5r/s;

    # Gzip compression
    gzip on;
    gzip_vary on;
    gzip_min_length 1024;
    gzip_types text/plain text/css application/json application/javascript text/xml application/xml;

    # SSL configuration
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-RSA-AES256-GCM-SHA512:DHE-RSA-AES256-GCM-SHA512:ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers off;

    server {
        listen 80;
        server_name _;
        return 301 https://$server_name$request_uri;
    }

    server {
        listen 443 ssl http2;
        server_name crypto-hunter.example.com;

        ssl_certificate /etc/nginx/ssl/cert.pem;
        ssl_certificate_key /etc/nginx/ssl/key.pem;

        # Security headers
        add_header X-Frame-Options DENY;
        add_header X-Content-Type-Options nosniff;
        add_header X-XSS-Protection "1; mode=block";
        add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;

        # File upload limits
        client_max_body_size 100M;
        client_body_timeout 60s;
        client_header_timeout 60s;

        # Static files
        location /static/ {
            alias /var/www/static/;
            expires 1y;
            add_header Cache-Control "public, immutable";
        }

        # API endpoints with rate limiting
        location /api/ {
            limit_req zone=api burst=20 nodelay;
            proxy_pass http://crypto_hunter_backend;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
            proxy_connect_timeout 60s;
            proxy_send_timeout 60s;
            proxy_read_timeout 60s;
        }

        # Upload endpoints with stricter rate limiting
        location /api/upload/ {
            limit_req zone=upload burst=5 nodelay;
            proxy_pass http://crypto_hunter_backend;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
            proxy_connect_timeout 300s;
            proxy_send_timeout 300s;
            proxy_read_timeout 300s;
        }

        # WebSocket for real-time features
        location /ws/ {
            proxy_pass http://crypto_hunter_backend;
            proxy_http_version 1.1;
            proxy_set_header Upgrade $http_upgrade;
            proxy_set_header Connection "upgrade";
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
        }

        # Health check
        location /health {
            proxy_pass http://crypto_hunter_backend;
            access_log off;
        }

        # Default location
        location / {
            proxy_pass http://crypto_hunter_backend;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
        }
    }
}
"""

# Gunicorn configuration
GUNICORN_CONFIG = """
import multiprocessing
import os

# Server socket
bind = "0.0.0.0:8000"
backlog = 2048

# Worker processes
workers = multiprocessing.cpu_count() * 2 + 1
worker_class = "gevent"
worker_connections = 1000
max_requests = 1000
max_requests_jitter = 50
preload_app = True
timeout = 60
keepalive = 2

# Logging
accesslog = "/app/logs/gunicorn_access.log"
errorlog = "/app/logs/gunicorn_error.log"
loglevel = "info"
access_log_format = '%(h)s %(l)s %(u)s %(t)s "%(r)s" %(s)s %(b)s "%(f)s" "%(a)s" %(D)s'

# Process naming
proc_name = "crypto_hunter_web"

# Server mechanics
daemon = False
pidfile = "/tmp/gunicorn.pid"
user = None
group = None
tmp_upload_dir = "/app/temp"

# SSL (if needed)
keyfile = None
certfile = None

def post_fork(server, worker):
    server.log.info("Worker spawned (pid: %s)", worker.pid)

def pre_fork(server, worker):
    pass

def when_ready(server):
    server.log.info("Server is ready. Spawning workers")

def worker_int(worker):
    worker.log.info("worker received INT or QUIT signal")

def pre_exec(server):
    server.log.info("Forked child, re-executing.")
"""

# Production environment file template
ENV_PRODUCTION = """
# Environment Configuration
ENVIRONMENT=production

# Database Configuration
DATABASE_URL=postgresql://crypto_user:${DB_PASSWORD}@postgres:5432/crypto_hunter_prod
DB_PASSWORD=${DB_PASSWORD}

# Redis Configuration  
REDIS_URL=redis://redis:6379/0
CELERY_BROKER_URL=redis://redis:6379/1

# Security
SECRET_KEY=${SECRET_KEY}
SECURITY_PASSWORD_SALT=${SECURITY_PASSWORD_SALT}

# Agent Configuration
AGENT_MAX_MEMORY_MB=2048
AGENT_MAX_CPU_PERCENT=75
AGENT_SANDBOX_MODE=true
AGENT_LOG_LEVEL=INFO

# External Integrations
LLM_API_KEY=${LLM_API_KEY}
LLM_PROVIDER=openai
LLM_MODEL=gpt-3.5-turbo

# Monitoring
ENABLE_METRICS=true
WEBHOOK_URL=${WEBHOOK_URL}
GRAFANA_PASSWORD=${GRAFANA_PASSWORD}

# File Storage
MAX_UPLOAD_SIZE=100MB
UPLOAD_FOLDER=/app/uploads
TEMP_FOLDER=/app/temp

# Performance
MAX_WORKERS=10
TASK_TIMEOUT=900
WORKFLOW_TIMEOUT=1800
"""

# Deploy script
DEPLOY_SCRIPT = """#!/bin/bash
set -e

echo "🚀 Starting Crypto Hunter Production Deployment..."

# Load environment variables
if [ -f .env.production ]; then
    export $(cat .env.production | grep -v '^#' | xargs)
else
    echo "❌ .env.production file not found!"
    exit 1
fi

# Validate required environment variables
required_vars=("DB_PASSWORD" "SECRET_KEY" "LLM_API_KEY")
for var in "${required_vars[@]}"; do
    if [ -z "${!var}" ]; then
        echo "❌ Required environment variable $var is not set!"
        exit 1
    fi
done

# Build images
echo "🔨 Building Docker images..."
docker-compose -f docker-compose.prod.yml build --no-cache

# Run database migrations
echo "📊 Running database migrations..."
docker-compose -f docker-compose.prod.yml run --rm crypto-hunter-web python -m flask db upgrade

# Create initial data
echo "🔧 Creating initial configuration..."
docker-compose -f docker-compose.prod.yml run --rm crypto-hunter-web python -c "
from crypto_hunter_web.services.complete_agent_system import initialize_complete_system
from crypto_hunter_web import create_app
app = create_app()
with app.app_context():
    initialize_complete_system(app)
    print('✅ Agent system initialized')
"

# Start services
echo "🎯 Starting production services..."
docker-compose -f docker-compose.prod.yml up -d

# Wait for services to be ready
echo "⏳ Waiting for services to be ready..."
sleep 30

# Health check
echo "🔍 Performing health checks..."
for i in {1..30}; do
    if curl -f http://localhost/health > /dev/null 2>&1; then
        echo "✅ Application is healthy!"
        break
    elif [ $i -eq 30 ]; then
        echo "❌ Health check failed after 30 attempts"
        docker-compose -f docker-compose.prod.yml logs
        exit 1
    else
        echo "⏳ Attempt $i/30: Waiting for application..."
        sleep 10
    fi
done

# Show status
echo "📊 Deployment Status:"
docker-compose -f docker-compose.prod.yml ps

echo "🎉 Crypto Hunter deployed successfully!"
echo "🌐 Access the application at: https://crypto-hunter.example.com"
echo "📊 Monitor at: http://localhost:3000 (Grafana)"
echo "📈 Metrics at: http://localhost:9090 (Prometheus)"
"""

# Backup script
BACKUP_SCRIPT = """#!/bin/bash
set -e

BACKUP_DIR="/backups"
DATE=$(date +%Y%m%d_%H%M%S)
DB_BACKUP_FILE="$BACKUP_DIR/crypto_hunter_db_$DATE.sql"
UPLOADS_BACKUP_FILE="$BACKUP_DIR/crypto_hunter_uploads_$DATE.tar.gz"

mkdir -p $BACKUP_DIR

echo "🔄 Starting backup process..."

# Database backup
echo "💾 Backing up database..."
docker exec crypto-hunter-postgres pg_dump -U crypto_user crypto_hunter_prod > $DB_BACKUP_FILE
gzip $DB_BACKUP_FILE

# Uploads backup
echo "📁 Backing up uploads..."
tar -czf $UPLOADS_BACKUP_FILE -C ./uploads .

# Agent configurations backup
echo "⚙️ Backing up configurations..."
docker exec crypto-hunter-web python -c "
from crypto_hunter_web.config.agent_config import config_manager
config = config_manager.load_config()
config_manager.save_config(config, True)
" > /dev/null

# Cleanup old backups (keep last 30 days)
find $BACKUP_DIR -name "crypto_hunter_*" -mtime +30 -delete

echo "✅ Backup completed successfully!"
echo "📊 Database backup: ${DB_BACKUP_FILE}.gz"
echo "📁 Uploads backup: $UPLOADS_BACKUP_FILE"
"""

if __name__ == "__main__":
    import sys
    import os
    from pathlib import Path
    
    def create_deployment_files():
        """Create all deployment configuration files"""
        
        # Create config directory
        config_dir = Path("./deployment/config")
        config_dir.mkdir(parents=True, exist_ok=True)
        
        scripts_dir = Path("./deployment/scripts")
        scripts_dir.mkdir(parents=True, exist_ok=True)
        
        k8s_dir = Path("./deployment/k8s")
        k8s_dir.mkdir(parents=True, exist_ok=True)
        
        # Write configuration files
        files = {
            "./deployment/docker-compose.prod.yml": DOCKER_COMPOSE_PRODUCTION,
            "./deployment/Dockerfile.prod": DOCKERFILE_PRODUCTION,
            "./deployment/Dockerfile.worker": DOCKERFILE_WORKER,
            "./deployment/k8s/namespace.yml": KUBERNETES_NAMESPACE,
            "./deployment/k8s/deployment.yml": KUBERNETES_DEPLOYMENT,
            "./deployment/k8s/hpa.yml": KUBERNETES_HPA,
            "./deployment/config/nginx.conf": NGINX_CONFIG,
            "./deployment/config/prometheus.yml": PROMETHEUS_CONFIG,
            "./deployment/config/gunicorn.conf.py": GUNICORN_CONFIG,
            "./deployment/.env.production.template": ENV_PRODUCTION,
            "./deployment/scripts/deploy.sh": DEPLOY_SCRIPT,
            "./deployment/scripts/backup.sh": BACKUP_SCRIPT,
            "./deployment/config/grafana-dashboard.json": GRAFANA_DASHBOARD
        }
        
        for file_path, content in files.items():
            file_path = Path(file_path)
            file_path.parent.mkdir(parents=True, exist_ok=True)
            
            with open(file_path, 'w') as f:
                f.write(content)
            
            # Make scripts executable
            if file_path.suffix == '.sh':
                os.chmod(file_path, 0o755)
        
        print("✅ Production deployment files created successfully!")
        print("📁 Files created in ./deployment/ directory")
        print("🔧 Next steps:")
        print("  1. Copy .env.production.template to .env.production")
        print("  2. Fill in your environment variables")
        print("  3. Run ./deployment/scripts/deploy.sh")
    
    if len(sys.argv) > 1 and sys.argv[1] == "create":
        create_deployment_files()
    else:
        print("Usage: python production_deployment.py create")
        print("This will create all production deployment configuration files.")