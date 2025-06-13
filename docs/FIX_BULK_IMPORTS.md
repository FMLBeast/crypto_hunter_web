# Fix for Bulk Imports Table

This fix addresses the error: `column "task_id" of relation "bulk_imports" does not exist`

## Problem

The `BulkImport` model in the application code includes a `task_id` column, but this column is missing from the database table. This causes errors when trying to create new bulk import records.

## Solution

The solution is to add the missing `task_id` column to the `bulk_imports` table in the database.

## How to Apply the Fix

1. Make sure the database is running
2. Run the fix script:

```bash
./fix_bulk_imports_table.sh
```

This script will:
1. Connect to the database
2. Add the missing `task_id` column to the `bulk_imports` table
3. Create an index on the column for better performance
4. Verify that the column was added successfully

## Alternative Approaches

If the script doesn't work for your environment, you can:

1. Run the SQL directly:
```bash
docker compose exec -T db psql -U crypto_hunter -d crypto_hunter < add_task_id_column.sql
```

2. Or create a database migration:
```bash
flask db migrate -m "Add task_id column to bulk_imports table"
flask db upgrade
```

## Verification

After applying the fix, you should be able to create new bulk import records without errors.
