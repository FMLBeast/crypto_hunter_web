# Database Management Guide

This document provides information about managing the Crypto Hunter database.

## Database Schema

The Crypto Hunter application uses a PostgreSQL database with the following main tables:

- `users`: User accounts and authentication
- `analysis_files`: Files uploaded for analysis
- `findings`: Cryptographic findings in analyzed files
- `vectors`: Vector representations of files for similarity search
- `api_keys`: API keys for programmatic access
- `audit_logs`: Audit trail of user actions

Additional tables are used for relationships and specialized features.

## Complete Database Rebuild

If you need to completely rebuild the database (e.g., after schema changes or to ensure a clean state for testing), you can use the `rebuild_db.sh` script:

```bash
./rebuild_db.sh
```

This script will:

1. Drop all existing tables in the database
2. Recreate the database schema using the SQLAlchemy models
3. Initialize the database with required data (including an admin user)

**Warning**: This will delete ALL data in the database. Make sure you have backups if needed.

## Non-Interactive Mode

To run the database rebuild in a non-interactive mode (e.g., in scripts or CI/CD pipelines), you can use:

```bash
echo "y" | ./rebuild_db.sh
```

## Manual Database Initialization

If you prefer to manually initialize the database, you can use:

```bash
# Check the database schema without making changes
python3 check_db_schema.py

# Force database reinitialization
AUTO_REINIT_DB=true python3 check_db_schema.py
```

## Known Issues

- There's a warning about a column type mismatch in 'users.created_at' (Model: DATETIME, DB: TIMESTAMP). This is a minor issue related to how SQLAlchemy and PostgreSQL handle date/time types. PostgreSQL uses `TIMESTAMP` while SQLAlchemy uses `DATETIME`, but they're functionally equivalent. This warning doesn't affect the functionality of the database.

## Database Backup and Restore

To backup the database:

```bash
docker compose exec db pg_dump -U crypto_hunter -d crypto_hunter > backup.sql
```

To restore the database:

```bash
cat backup.sql | docker compose exec -T db psql -U crypto_hunter -d crypto_hunter
```
