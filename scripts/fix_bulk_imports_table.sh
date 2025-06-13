#!/bin/bash
# fix_bulk_imports_table.sh - Add missing task_id column to bulk_imports table
set -euo pipefail

echo "🔧 CRYPTO HUNTER - Fixing bulk_imports table"
echo "==========================================="

# Check if running in Docker environment
if [ -f /.dockerenv ] || grep -q docker /proc/1/cgroup; then
    echo "Running inside Docker container"
    # Inside Docker container
    psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -f add_task_id_column.sql
else
    echo "Running outside Docker container"
    # Outside Docker container, use docker compose
    # Mount the local SQL file into the container
    docker compose exec -T db psql -U crypto_hunter -d crypto_hunter < add_task_id_column.sql
fi

echo ""
echo "✅ bulk_imports table fixed successfully!"
echo ""
