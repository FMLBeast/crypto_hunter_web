#!/bin/bash
# Docker setup script for Crypto Hunter with PostgreSQL

echo "🚀 Building Crypto Hunter with PostgreSQL..."

# Check if .env file exists
if [ ! -f .env ]; then
    echo "❌ .env file not found. Please create one with your configuration."
    echo "Example:"
    echo "SECRET_KEY=your-secret-key"
    echo "DB_PASSWORD=your-password"
    exit 1
fi

# Check if Docker is running
if ! docker ps > /dev/null 2>&1; then
    echo "❌ Docker is not running or not accessible."
    echo "Please ensure:"
    echo "  1. Docker daemon is running: sudo systemctl start docker"
    echo "  2. Your user is in docker group: sudo usermod -aG docker $USER"
    echo "  3. Logout and login again, or run: newgrp docker"
    exit 1
fi

# Use modern Docker Compose syntax (V2)
COMPOSE_CMD="docker compose"

# Fallback to legacy docker-compose if V2 not available
if ! docker compose version > /dev/null 2>&1; then
    if command -v docker-compose > /dev/null 2>&1; then
        COMPOSE_CMD="docker-compose"
        echo "⚠️  Using legacy docker-compose. Consider upgrading to Docker Compose V2"
    else
        echo "❌ Neither 'docker compose' nor 'docker-compose' is available."
        echo "Please install Docker Compose V2: sudo apt install docker-compose-plugin"
        exit 1
    fi
fi

echo "Using: $COMPOSE_CMD"

# Build the application
echo "📦 Building Docker images..."
$COMPOSE_CMD build

# Start database and cache services first
echo "🗄️ Starting PostgreSQL and Redis..."
$COMPOSE_CMD up -d db redis

# Wait for services to be ready
echo "⏳ Waiting for PostgreSQL and Redis to be ready..."
echo "   This may take up to 60 seconds for first-time setup..."

# Wait for PostgreSQL to be healthy
echo "   Checking PostgreSQL..."
timeout=60
counter=0
while [ $counter -lt $timeout ]; do
    if $COMPOSE_CMD exec -T db pg_isready -U crypto_hunter -d crypto_hunter > /dev/null 2>&1; then
        echo "   ✅ PostgreSQL is ready"
        break
    fi
    sleep 2
    counter=$((counter + 2))
    echo "   Waiting for PostgreSQL... (${counter}s)"
done

if [ $counter -ge $timeout ]; then
    echo "   ❌ PostgreSQL failed to start within ${timeout} seconds"
    $COMPOSE_CMD logs db
    exit 1
fi

# Wait for Redis to be healthy
echo "   Checking Redis..."
timeout=30
counter=0
while [ $counter -lt $timeout ]; do
    if $COMPOSE_CMD exec -T redis redis-cli ping > /dev/null 2>&1; then
        echo "   ✅ Redis is ready"
        break
    fi
    sleep 2
    counter=$((counter + 2))
    echo "   Waiting for Redis... (${counter}s)"
done

# Start web service temporarily for database setup
echo "🔧 Setting up database..."
$COMPOSE_CMD up -d web

# Wait for web service to be ready
sleep 10

# Initialize database
echo "   Initializing database schema..."
$COMPOSE_CMD exec web flask db init || echo "   Database already initialized"
$COMPOSE_CMD exec web flask db migrate -m "Initial migration" || echo "   No migrations needed"
$COMPOSE_CMD exec web flask db upgrade

# Start all services
echo "🚀 Starting all services..."
$COMPOSE_CMD up -d

# Wait a moment for everything to stabilize
sleep 5

# Show status
echo "📊 Service status:"
$COMPOSE_CMD ps

echo ""
echo "✅ Setup complete!"
echo ""
echo "🌐 Web App: http://localhost:8000"
echo "🌸 Flower (Celery Monitor): http://localhost:5556"
echo "🗄️ PostgreSQL: localhost:5432"
echo "📊 Redis: localhost:6379"
echo ""
echo "📋 Useful commands:"
echo "  $COMPOSE_CMD logs web     # View web logs"
echo "  $COMPOSE_CMD logs worker  # View worker logs"
echo "  $COMPOSE_CMD logs db      # View database logs"
echo "  $COMPOSE_CMD exec web flask user create-admin  # Create admin user"
echo "  $COMPOSE_CMD exec db psql -U crypto_hunter -d crypto_hunter  # Connect to database"
echo "  $COMPOSE_CMD down         # Stop all services"
echo "  $COMPOSE_CMD restart web  # Restart web service"
