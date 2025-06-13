#!/bin/bash
# fix_all_schema_issues.sh - Fix all database schema issues
set -euo pipefail

echo "🔧 CRYPTO HUNTER - Fixing Database Schema Issues"
echo "==============================================="

# Check if running in Docker environment
if [ -f /.dockerenv ] || grep -q docker /proc/1/cgroup; then
    echo "Running inside Docker container"
    INSIDE_DOCKER=true
else
    echo "Running outside Docker container"
    INSIDE_DOCKER=false
fi

# Function to execute SQL
execute_sql() {
    local sql="$1"
    
    if [ "$INSIDE_DOCKER" = true ]; then
        # Inside Docker container
        echo "$sql" | psql -U "$POSTGRES_USER" -d "$POSTGRES_DB"
    else
        # Outside Docker container, use docker compose
        echo "$sql" | docker compose exec -T db psql -U crypto_hunter -d crypto_hunter
    fi
}

echo "📊 Checking database connection..."
if [ "$INSIDE_DOCKER" = true ]; then
    psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -c "SELECT 1" > /dev/null
else
    docker compose exec db psql -U crypto_hunter -d crypto_hunter -c "SELECT 1" > /dev/null
fi
echo "✅ Database connection successful"

echo "🔍 Fixing critical issues..."

# 1. Fix missing task_id column in bulk_imports table
echo "  - Adding missing task_id column to bulk_imports table"
execute_sql "
ALTER TABLE bulk_imports ADD COLUMN IF NOT EXISTS task_id VARCHAR(36);
CREATE INDEX IF NOT EXISTS idx_bulk_imports_task_id ON bulk_imports(task_id);
"

# Verify the column was added
echo "  - Verifying task_id column was added"
TASK_ID_COLUMN=$(execute_sql "
SELECT column_name FROM information_schema.columns 
WHERE table_name = 'bulk_imports' AND column_name = 'task_id';
" | grep -c "task_id" || true)

if [ "$TASK_ID_COLUMN" -gt 0 ]; then
    echo "    ✅ task_id column exists in bulk_imports table"
else
    echo "    ❌ Failed to add task_id column to bulk_imports table"
    exit 1
fi

echo ""
echo "✅ All critical schema issues fixed successfully!"
echo ""
echo "📝 Note: Type representation differences (e.g., 'character varying' vs 'varchar') are not actual issues"
echo "   and don't require fixes. They are just differences in how SQLAlchemy and PostgreSQL represent types."
echo ""
echo "🔄 For ongoing schema management, consider implementing a proper database migration system"
echo "   like Alembic with Flask-Migrate to manage schema changes in a controlled manner."
echo ""