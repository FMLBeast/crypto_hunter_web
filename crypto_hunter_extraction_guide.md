# Crypto Hunter Extraction Guide

This guide will help you get your Docker services up and running, start an extraction process that writes to the database, and follow the established data analysis flows.

## 1. Starting Docker Services

The Crypto Hunter system uses Docker Compose to manage its services. Follow these steps to start all services:

### Prerequisites
- Docker and Docker Compose installed on your system
- Access to the Crypto Hunter repository

### Steps to Start Docker Services

1. Navigate to the project root directory:
   ```bash
   cd /path/to/hunterAdvanced
   ```

2. Set up required environment variables (if not already done):
   ```bash
   export SECRET_KEY=your_secret_key
   export DB_PASSWORD=your_db_password
   ```

3. Start all Docker services:
   ```bash
   docker-compose up -d
   ```
   
   This will start the following services:
   - PostgreSQL database (db)
   - Redis for caching and task queues (redis)
   - Web application (web)
   - Celery worker for background tasks (worker)
   - Celery beat for scheduled tasks (beat)
   - Celery flower for monitoring (flower)

4. Verify that all services are running:
   ```bash
   docker-compose ps
   ```

   All services should show as "Up" in the status column.

## 2. Running Extraction Processes

There are two main ways to run extraction processes:

### Option 1: Using the run_extraction.py Script

This script provides a command-line interface for running extractions on specific files:

1. Run extraction using all recommended methods:
   ```bash
   ./crypto_hunter_web/scripts/run_extraction.py /path/to/your/file.png
   ```

2. Run extraction using a specific method:
   ```bash
   ./crypto_hunter_web/scripts/run_extraction.py /path/to/your/file.png --method zsteg
   ```

3. Run extraction in the background (using Celery):
   ```bash
   ./crypto_hunter_web/scripts/run_extraction.py /path/to/your/file.png --background
   ```

4. Run extraction and wait for the background task to complete:
   ```bash
   ./crypto_hunter_web/scripts/run_extraction.py /path/to/your/file.png --background --wait
   ```

### Option 2: Using the orchestrate_extraction.py Script

This script provides a more comprehensive approach, checking for required tools and coordinating the extraction process:

1. Run extraction on a specific file:
   ```bash
   ./extraction/orchestrate_extraction.py /path/to/your/file.png
   ```

2. Run extraction with a custom output directory:
   ```bash
   ./extraction/orchestrate_extraction.py /path/to/your/file.png --output-dir custom_output
   ```

The orchestrator script will:
- Check if all required tools are installed
- Prepare directories for extraction
- Run extraction using all available extractors
- Verify extraction success
- Print a summary of extraction results

## 3. Verifying Data is Being Written to the Database

After running an extraction, you can verify that data is being written to the database:

1. Check the logs of the web and worker containers:
   ```bash
   docker-compose logs -f web worker
   ```

   Look for messages indicating successful database operations.

2. Use the pgAdmin interface (if enabled in your docker-compose.yml):
   - Access pgAdmin at http://localhost:5051
   - Login with the credentials specified in your docker-compose.yml
   - Connect to the database and browse tables like `analysis_file`, `file_content`, and `finding`

3. Run a query to check for extracted files:
   ```bash
   docker-compose exec db psql -U crypto_hunter -d crypto_hunter -c "SELECT * FROM analysis_file ORDER BY created_at DESC LIMIT 10;"
   ```

4. Run a query to check for file content:
   ```bash
   docker-compose exec db psql -U crypto_hunter -d crypto_hunter -c "SELECT * FROM file_content ORDER BY created_at DESC LIMIT 10;"
   ```

## 4. Confirming Data Analysis Flows

After extraction, the system automatically triggers analysis flows. Here's how to confirm they're working:

1. Check the status of analysis tasks:
   ```bash
   docker-compose exec web flask cli analysis-status <file_id>
   ```
   Replace `<file_id>` with the ID of your file.

2. View analysis findings:
   ```bash
   docker-compose exec web flask cli get-findings <file_id>
   ```

3. Monitor Celery tasks using Flower:
   - Access Flower at http://localhost:5557
   - Login with the credentials specified in your docker-compose.yml
   - Check the status of tasks related to analysis and extraction

4. Check for regions of interest that were identified:
   ```bash
   docker-compose exec web flask cli get-regions <file_id>
   ```

## 5. Troubleshooting

If you encounter issues:

1. Check Docker container logs:
   ```bash
   docker-compose logs -f
   ```

2. Ensure all required tools are installed:
   ```bash
   sudo ./scripts/install_tools.py
   ```

3. Verify database connectivity:
   ```bash
   docker-compose exec web flask cli check-db
   ```

4. Restart services if needed:
   ```bash
   docker-compose restart web worker
   ```

5. Check Redis status:
   ```bash
   docker-compose exec redis redis-cli ping
   ```

## 6. Additional Resources

- For more details on the extraction system, see `docs/EXTRACTION_SYSTEM.md`
- For production extraction information, see `docs/PRODUCTION_EXTRACTION.md`
- For an architectural overview, see `architectural_overview.md`

## 7. Complete Workflow Example

Here's a complete example workflow:

```bash
# Start Docker services
docker-compose up -d

# Wait for services to initialize
sleep 10

# Run extraction on a file
./extraction/orchestrate_extraction.py /path/to/your/file.png

# Check the database for results
docker-compose exec db psql -U crypto_hunter -d crypto_hunter -c "SELECT * FROM analysis_file ORDER BY created_at DESC LIMIT 5;"

# Check findings
docker-compose exec web flask cli get-findings <file_id>

# When finished, stop Docker services
docker-compose down
```

Replace `<file_id>` with the actual file ID from the database query.