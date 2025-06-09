#!/bin/bash
# check_status.sh - Check current status and continue deployment
set -euo pipefail

# Colors
readonly GREEN='\033[0;32m'
readonly BLUE='\033[0;34m'
readonly YELLOW='\033[0;33m'
readonly RED='\033[0;31m'
readonly NC='\033[0m'

log() { echo -e "${BLUE}[STATUS]${NC} $1"; }
success() { echo -e "${GREEN}✅ $1${NC}"; }
warning() { echo -e "${YELLOW}⚠️  $1${NC}"; }
error() { echo -e "${RED}❌ $1${NC}"; }

echo "🔍 CRYPTO HUNTER - Current Status Check"
echo "========================================"

# Check what's running
log "📊 Current container status:"
docker compose ps

echo ""
log "🔍 Checking service health..."

# Check database
if docker compose exec -T db pg_isready -U crypto_hunter -d crypto_hunter >/dev/null 2>&1; then
    success "PostgreSQL is ready"
    DB_READY=true
else
    warning "PostgreSQL not ready yet"
    DB_READY=false
fi

# Check Redis
if docker compose exec -T redis redis-cli ping >/dev/null 2>&1; then
    success "Redis is ready"
    REDIS_READY=true
else
    warning "Redis not ready yet"
    REDIS_READY=false
fi

# If both are ready, continue with database setup
if [[ "$DB_READY" == true && "$REDIS_READY" == true ]]; then
    log "🔧 Initializing database..."
    docker compose run --rm web flask db init 2>/dev/null || log "Database already initialized"
    docker compose run --rm web flask db migrate -m "Production setup" 2>/dev/null || log "No new migrations needed"
    docker compose run --rm web flask db upgrade

    log "🚀 Starting all services..."
    docker compose up -d

    log "⏳ Waiting for web application..."
    sleep 30

    # Check web health
    for i in {1..10}; do
        if curl -sf http://localhost:8000/health >/dev/null 2>&1; then
            success "Web application is healthy!"
            break
        elif [[ $i -eq 10 ]]; then
            warning "Health check timeout, checking logs..."
            docker compose logs web | tail -20
        else
            echo "Health check attempt $i/10..."
            sleep 5
        fi
    done

    echo ""
    echo "🎉 CRYPTO HUNTER BETA STATUS"
    echo "============================="
    echo "🌐 Web Application: http://localhost:8000"
    echo "📚 API Documentation: http://localhost:8000/docs"
    echo "🌺 Task Monitor: http://localhost:5555"
    echo "❤️  Health Check: http://localhost:8000/health"
    echo ""
    echo "🔐 Next Steps:"
    echo "1. Create admin user:"
    echo "   docker compose exec web flask user create --username admin --email admin@example.com --admin"
    echo ""
    echo "2. View logs:"
    echo "   docker compose logs -f"
    echo ""
    echo "3. Stop services:"
    echo "   docker compose down"
    echo ""
    success "Crypto Hunter Beta is ready for testing! 🚀"

elif [[ "$DB_READY" == false || "$REDIS_READY" == false ]]; then
    log "⏳ Services still starting up, waiting..."

    # Wait for database
    if [[ "$DB_READY" == false ]]; then
        log "Waiting for PostgreSQL..."
        timeout 120 bash -c "
        while ! docker compose exec -T db pg_isready -U crypto_hunter -d crypto_hunter >/dev/null 2>&1; do
            echo 'PostgreSQL starting...'
            sleep 3
        done
        " && success "PostgreSQL is now ready!" || error "PostgreSQL failed to start"
    fi

    # Wait for Redis
    if [[ "$REDIS_READY" == false ]]; then
        log "Waiting for Redis..."
        timeout 60 bash -c "
        while ! docker compose exec -T redis redis-cli ping >/dev/null 2>&1; do
            echo 'Redis starting...'
            sleep 2
        done
        " && success "Redis is now ready!" || error "Redis failed to start"
    fi

    # Recursively call this script to complete setup
    log "🔄 Core services ready, continuing setup..."
    exec "$0"
else
    error "Unexpected service state"
    docker compose logs | tail -30
fi