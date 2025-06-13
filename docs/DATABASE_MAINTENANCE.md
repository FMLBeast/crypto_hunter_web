# Database Schema Maintenance Guide

## Overview

This guide explains how to validate and maintain the database schema for the Crypto Hunter application. It provides instructions for using the tools created to identify and fix schema discrepancies between the SQLAlchemy models and the PostgreSQL database.

## Tools

The following tools are available for database schema maintenance:

1. **export_db_schema.py**: Exports the database schema and compares it with the SQLAlchemy models
2. **fix_all_schema_issues.sh**: Fixes all identified schema issues
3. **fix_bulk_imports_table.sh**: Specifically fixes the `task_id` column issue in the `bulk_imports` table

## Schema Validation

To validate the database schema against the SQLAlchemy models:

```bash
./export_db_schema.py
```

This script will:
1. Connect to the database
2. Export the complete database schema
3. Extract the schema information from all SQLAlchemy models
4. Compare the two schemas to identify discrepancies
5. Save the results to three JSON files:
   - `db_schema.json`: The database schema
   - `model_schema.json`: The model schema
   - `schema_discrepancies.json`: The discrepancies between the two
6. Print a summary of the findings

## Fixing Schema Issues

### Option 1: Fix All Issues

To fix all identified schema issues:

```bash
./fix_all_schema_issues.sh
```

This script will:
1. Check if it's running inside Docker or not and adjust commands accordingly
2. Verify the database connection
3. Add the missing `task_id` column to the `bulk_imports` table
4. Verify that the column was added successfully
5. Provide informative messages about the fixes

### Option 2: Fix Specific Issues

To fix only the `task_id` column issue in the `bulk_imports` table:

```bash
./fix_bulk_imports_table.sh
```

## Common Schema Issues

### 1. Missing `task_id` Column in `bulk_imports` Table

**Issue**: The `BulkImport` model includes a `task_id` column, but this column is missing from the database table.

**Error**: `column "task_id" of relation "bulk_imports" does not exist`

**Fix**: Run either `fix_all_schema_issues.sh` or `fix_bulk_imports_table.sh` to add the missing column.

### 2. Type Representation Differences

**Issue**: Differences in how types are represented in SQLAlchemy versus PostgreSQL.

**Example**:
- SQLAlchemy: `character varying(80)`
- PostgreSQL: `varchar(80)`

**Fix**: No fix needed. These differences are not actual issues but rather differences in representation.

## Best Practices

1. **Regular Validation**: Run the schema validation script regularly to catch schema drift early.

2. **Use Database Migrations**: Implement a proper database migration system (like Alembic with Flask-Migrate) to manage schema changes in a controlled manner.

3. **Update Documentation**: Keep database schema documentation up-to-date with any changes.

4. **Test After Schema Changes**: Always test the application after making schema changes to ensure everything works as expected.

5. **Backup Before Changes**: Always backup the database before making schema changes.

## Troubleshooting

### Script Fails to Connect to Database

1. Ensure the database is running
2. Check the database connection parameters in the script
3. Verify that you have the necessary permissions to access the database

### Column Not Added After Running Fix Script

1. Check the database logs for errors
2. Verify that you have the necessary permissions to modify the database schema
3. Try running the SQL commands manually:

```sql
ALTER TABLE bulk_imports ADD COLUMN IF NOT EXISTS task_id VARCHAR(36);
CREATE INDEX IF NOT EXISTS idx_bulk_imports_task_id ON bulk_imports(task_id);
```

## Conclusion

Maintaining database schema consistency is crucial for the proper functioning of the application. The tools provided in this guide help identify and fix schema discrepancies, ensuring that the database schema matches the SQLAlchemy models.