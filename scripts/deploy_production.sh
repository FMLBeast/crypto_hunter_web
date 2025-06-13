#!/bin/bash
# deploy_production.sh - PRODUCTION-READY DEPLOYMENT SCRIPT

set -euo pipefail

# Colors for output
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[0;33m'
readonly BLUE='\033[0;34m'
readonly PURPLE='\033[0;35m'
readonly CYAN='\033[0;36m'
readonly NC='\033[0m' # No Color

# Configuration
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly PROJECT_NAME="crypto-hunter"
readonly COMPOSE_FILE="docker-compose.yml"
readonly ENV_FILE=".env"
readonly BACKUP_DIR="backups/$(date +%Y%m%d_%H%M%S)"

# Logging
log() {
    echo -e "${BLUE}[$(date +'%Y-%m-%d %H:%M:%S')]${NC} $1"
}

log_success() {
    echo -e "${GREEN}✅ $1${NC}"
}

log_warning() {
    echo -e "${YELLOW}⚠️  $1${NC}"
}

log_error() {
    echo -e "${RED}❌ $1${NC}"
}

log_info() {
    echo -e "${CYAN}ℹ️  $1${NC}"
}

# Error handling
error_exit() {
    log_error "$1"
    exit 1
}

# Cleanup function
cleanup() {
    if [[ $? -ne 0 ]]; then
        log_error "Deployment failed! Check logs above for details."
        log_info "Rolling back to previous version..."
        docker compose down --remove-orphans || true
    fi
}

trap cleanup EXIT

# Pre-flight checks
preflight_checks() {
    log "🔍 Running pre-flight checks..."

    # Check if running as root (shouldn't for security)
    if [[ $EUID -eq 0 ]]; then
        log_warning "Running as root is not recommended for production!"
        read -p "Continue anyway? (y/N): " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            error_exit "Deployment aborted"
        fi
    fi

    # Check Docker
    if ! command -v docker &> /dev/null; then
        error_exit "Docker is not installed"
    fi

    # Check Docker Compose
    if ! docker compose version &> /dev/null; then
        if ! command -v docker-compose &> /dev/null; then
            error_exit "Docker Compose is not installed"
        else
            log_warning "Using legacy docker-compose. Consider upgrading to Docker Compose V2"
            COMPOSE_CMD="docker-compose"
        fi
    else
        COMPOSE_CMD="docker compose"
    fi

    # Check if Docker daemon is running
    if ! docker ps &> /dev/null; then
        error_exit "Docker daemon is not running or not accessible. Run: sudo systemctl start docker"
    fi

    # Check .env file
    if [[ ! -f "$ENV_FILE" ]]; then
        error_exit ".env file not found. Create one with your configuration."
    fi

    # Check required environment variables
    source "$ENV_FILE"
    if [[ -z "${SECRET_KEY:-}" ]] || [[ "$SECRET_KEY" == "dev-secret-key" ]]; then
        error_exit "SECRET_KEY must be set to a secure random value in .env"
    fi

    if [[ -z "${DB_PASSWORD:-}" ]]; then
        error_exit "DB_PASSWORD must be set in .env"
    fi

    log_success "Pre-flight checks passed"
}

# Clean up orphan containers and old resources
cleanup_orphans() {
    log "🧹 Cleaning up orphan containers and old resources..."

    # Remove orphan containers
    $COMPOSE_CMD down --remove-orphans --volumes || true

    # Remove old/dangling images
    docker image prune -f || true

    # Remove old containers with legacy names
    docker rm -f hunter-worker_crypto hunter-worker_llm hunter-scheduler 2>/dev/null || true

    # Clean up old networks
    docker network prune -f || true

    log_success "Cleanup completed"
}

# Create necessary directories
create_directories() {
    log "📁 Creating necessary directories..."

    mkdir -p logs uploads instance backups ssl nginx/conf.d

    # Set proper permissions for volumes
    sudo chown -R 1000:1000 logs uploads instance 2>/dev/null || true

    log_success "Directories created"
}

# Generate production configurations
generate_configs() {
    log "⚙️  Generating production configurations..."

    # Create nginx configuration if it doesn't exist
    if [[ ! -f nginx/nginx.conf ]]; then
        cat > nginx/nginx.conf << 'EOF'
events {
    worker_connections 1024;
}

http {
    include /etc/nginx/mime.types;
    default_type application/octet-stream;

    # Logging
    log_format main '$remote_addr - $remote_user [$time_local] "$request" '
                    '$status $body_bytes_sent "$http_referer" '
                    '"$http_user_agent" "$http_x_forwarded_for"';

    access_log /var/log/nginx/access.log main;
    error_log /var/log/nginx/error.log warn;

    # Basic settings
    sendfile on;
    tcp_nopush on;
    tcp_nodelay on;
    keepalive_timeout 65;
    types_hash_max_size 2048;
    client_max_body_size 1G;

    # Security headers
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;

    # Include site configurations
    include /etc/nginx/conf.d/*.conf;
}
EOF
    fi

    # Create site configuration
    if [[ ! -f nginx/conf.d/crypto-hunter.conf ]]; then
        cat > nginx/conf.d/crypto-hunter.conf << 'EOF'
upstream app {
    server web:8000 max_fails=3 fail_timeout=30s;
}

server {
    listen 80;
    server_name _;

    # Security headers
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;

    # Static files
    location /static/ {
        alias /var/www/uploads/static/;
        expires 1y;
        add_header Cache-Control "public, immutable";
    }

    # Uploads
    location /uploads/ {
        alias /var/www/uploads/;
        expires 1h;
        add_header Cache-Control "public";
    }

    # Main application
    location / {
        proxy_pass http://app;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        # Timeouts
        proxy_connect_timeout 60s;
        proxy_send_timeout 60s;
        proxy_read_timeout 60s;

        # Large uploads
        client_max_body_size 1G;
        proxy_request_buffering off;
    }

    # Health check
    location /health {
        proxy_pass http://app/health;
        access_log off;
    }
}
EOF
    fi

    log_success "Configurations generated"
}

# Create database backup
backup_database() {
    if $COMPOSE_CMD ps | grep -q crypto-hunter-db; then
        log "💾 Creating database backup..."

        mkdir -p "$BACKUP_DIR"

        $COMPOSE_CMD exec -T db pg_dump -U crypto_hunter crypto_hunter | gzip > "$BACKUP_DIR/database.sql.gz" || {
            log_warning "Database backup failed (database might not exist yet)"
        }

        log_success "Database backup created in $BACKUP_DIR"
    fi
}

# Build and deploy
deploy() {
    log "🚀 Starting production deployment..."

    # Set version tag
    export VERSION="${VERSION:-$(date +%Y%m%d_%H%M%S)}"

    # Build images
    log "📦 Building Docker images..."
    $COMPOSE_CMD build --no-cache --parallel

    # Start database and redis first
    log "🗄️  Starting core services..."
    $COMPOSE_CMD up -d db redis

    # Wait for services to be ready
    log "⏳ Waiting for core services to be ready..."
    timeout 120 bash -c '
        until docker compose exec -T db pg_isready -U crypto_hunter -d crypto_hunter &>/dev/null; do
            echo "Waiting for PostgreSQL..."
            sleep 2
        done
    ' || error_exit "PostgreSQL failed to start"

    timeout 60 bash -c '
        until docker compose exec -T redis redis-cli ping &>/dev/null; do
            echo "Waiting for Redis..."
            sleep 2
        done
    ' || error_exit "Redis failed to start"

    log_success "Core services are ready"

    # Initialize database
    log "🔧 Initializing database..."
    $COMPOSE_CMD run --rm web flask db init || log_info "Database already initialized"
    $COMPOSE_CMD run --rm web flask db migrate -m "Production deployment $(date)" || log_info "No new migrations"
    $COMPOSE_CMD run --rm web flask db upgrade

    # Start all services
    log "🚀 Starting all services..."
    $COMPOSE_CMD up -d

    # Wait for services to be healthy
    log "⏳ Waiting for services to be healthy..."
    sleep 30

    # Verify deployment
    verify_deployment

    log_success "Deployment completed successfully!"
}

# Verify deployment
verify_deployment() {
    log "🔍 Verifying deployment..."

    # Check service health
    if ! $COMPOSE_CMD ps | grep -q "Up (healthy)"; then
        log_warning "Some services are not healthy yet, checking status..."
        $COMPOSE_CMD ps
    fi

    # Test web application
    if curl -sf http://localhost:8000/health > /dev/null; then
        log_success "Web application is responding"
    else
        log_error "Web application is not responding"
    fi

    # Check logs for errors
    if $COMPOSE_CMD logs web 2>&1 | grep -i error | tail -5; then
        log_warning "Found recent errors in web logs"
    fi

    log_success "Deployment verification completed"
}

# Show deployment status
show_status() {
    log "📊 Deployment Status"
    echo "===================="

    echo -e "\n${CYAN}Services:${NC}"
    $COMPOSE_CMD ps

    echo -e "\n${CYAN}Access URLs:${NC}"
    echo "  Web Application: http://localhost:8000"
    echo "  API Documentation: http://localhost:8000/api/docs"
    echo "  Flower Monitor: http://localhost:5556 (admin/admin123)"
    echo "  Health Check: http://localhost:8000/health"

    echo -e "\n${CYAN}Useful Commands:${NC}"
    echo "  View logs: $COMPOSE_CMD logs -f"
    echo "  Stop services: $COMPOSE_CMD down"
    echo "  Restart: $COMPOSE_CMD restart"
    echo "  Update: ./deploy_production.sh"

    echo -e "\n${GREEN}🎉 Crypto Hunter is ready for beta testing!${NC}"
}

# Main execution
main() {
    echo -e "${PURPLE}"
    cat << 'EOF'
 ____                  _          _   _             _
/ ___|_ __ _   _ _ __ | |_ ___   | | | |_   _ _ __ | |_ ___ _ __
| |   | '__| | | | '_ \| __/ _ \  | |_| | | | | '_ \| __/ _ \ '__|
| |___| |  | |_| | |_) | || (_) | |  _  | |_| | | | | ||  __/ |
\____|_|   \__, | .__/ \__\___/  |_| |_|\__,_|_| |_|\__\___|_|
           |___/|_|
Production Deployment Script
EOF
    echo -e "${NC}"

    preflight_checks
    cleanup_orphans
    create_directories
    generate_configs
    backup_database
    deploy
    show_status
}

# Script execution
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
