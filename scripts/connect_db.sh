#!/bin/bash
# connect_db.sh - Quick script to connect to the Crypto Hunter PostgreSQL database
set -euo pipefail

echo "🔍 Connecting to Crypto Hunter PostgreSQL database..."

# Check if running in Docker environment
if [ -f /.dockerenv ] || grep -q docker /proc/1/cgroup; then
    echo "Running inside Docker container"
    # Inside Docker container
    psql -h db -p 5432 -U crypto_hunter -d crypto_hunter
else
    echo "Running outside Docker container"
    # Outside Docker container
    if command -v docker &> /dev/null; then
        echo "Using docker compose exec to connect to the database"
        docker compose exec db psql -U crypto_hunter -d crypto_hunter
    else
        echo "Connecting directly to the database"
        psql -h localhost -p 5432 -U crypto_hunter -d crypto_hunter
    fi
fi