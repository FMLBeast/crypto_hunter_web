#!/bin/bash
echo "🚀 Starting FAST development mode..."
echo "✅ Volume-mounted code (no rebuilds!)"
echo "✅ Real-time logs"

# Stop any existing containers
docker compose down 2>/dev/null || true

# Start with development config
docker compose -f docker-compose.dev.yml up --build
