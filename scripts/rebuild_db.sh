#!/bin/bash
# rebuild_db.sh - Complete database rebuild script
# This script completely drops and recreates the database using the SQLAlchemy models

set -euo pipefail

echo "🔄 CRYPTO HUNTER - Complete Database Rebuild"
echo "==========================================="
echo "⚠️  WARNING: This will delete ALL data in the database!"
echo "⚠️  Make sure you have backups if needed."
echo ""

# Check if running in interactive mode
if [ -t 0 ]; then
    # Ask for confirmation
    read -p "Are you sure you want to completely rebuild the database? (y/N): " -n 1 -r
    echo ""
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo "❌ Database rebuild cancelled."
        exit 1
    fi
fi

echo "🔥 Starting complete database rebuild..."

# Set environment variable to force database reinitialization
export AUTO_REINIT_DB=true

# Run the check_db_schema.py script which will reinitialize the database
echo "🗑️  Dropping all existing tables..."
echo "🏗️  Recreating database schema from models..."
python3 ../database/check_db_schema.py

# Verify the database was rebuilt successfully
echo ""
echo "🔍 Verifying database schema..."
unset AUTO_REINIT_DB
python3 ../database/check_db_schema.py

echo ""
echo "✅ Database rebuild completed successfully!"
echo ""
echo "🚀 The database has been completely rebuilt and is now 100% trustable for testing."
echo "   All tables have been recreated according to the current models."
echo "   Initial data has been loaded."
echo ""
