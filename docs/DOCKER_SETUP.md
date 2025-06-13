# Docker Setup for Crypto Hunter

This document provides instructions for setting up and running the Crypto Hunter application using Docker.

## Prerequisites

- Docker and Docker Compose installed on your system
- Git repository cloned to your local machine

## Quick Start

We've created a convenient management script to help you work with Docker. To get started:

1. Make sure the script is executable:
   ```bash
   chmod +x docker_manage.sh
   ```

2. Start the containers:
   ```bash
   ./docker_manage.sh start
   ```

3. Check the status of your containers:
   ```bash
   ./docker_manage.sh status
   ```

4. Access the application at [http://localhost:8000](http://localhost:8000)

## Using the Docker Management Script

The `docker_manage.sh` script provides several commands to help you manage your Docker environment:

- **Start containers**: `./docker_manage.sh start`
- **Stop containers**: `./docker_manage.sh stop`
- **Restart containers**: `./docker_manage.sh restart`
- **Check status**: `./docker_manage.sh status`
- **View logs**: 
  - All services: `./docker_manage.sh logs`
  - Specific service: `./docker_manage.sh logs web`
- **Rebuild containers**: `./docker_manage.sh build`
- **Clean up resources**: `./docker_manage.sh clean`
- **Show help**: `./docker_manage.sh help`

## Environment Configuration

The application uses environment variables defined in the `.env` file. The default configuration should work for most development scenarios, but you can modify these variables as needed:

- `FLASK_ENV`: Set to `development` for development mode
- `FLASK_DEBUG`: Set to `1` to enable debug mode
- `SECRET_KEY`: Secret key for the application
- `DATABASE_URL`: Database connection string
- `SQLALCHEMY_DATABASE_URI`: SQLAlchemy database URI
- `DB_PASSWORD`: Database password
- `CELERY_BROKER_URL`: Redis URL for Celery broker
- `CELERY_RESULT_BACKEND`: Redis URL for Celery result backend

## Development vs Production

- **Development**: Uses the `docker-compose.override.yml` file which enables:
  - Live code reloading
  - Flask debug mode
  - Volume mounting for local development

- **Production**: Uses the base `docker-compose.yml` configuration:
  - Optimized for performance
  - No debug mode
  - Uses Gunicorn as the WSGI server

## Troubleshooting

If you encounter issues:

1. Check container logs: `./docker_manage.sh logs`
2. Ensure Docker is running: `docker info`
3. Verify your `.env` file has the correct configuration
4. Try rebuilding the containers: `./docker_manage.sh build`
5. Clean up and start fresh: `./docker_manage.sh clean` followed by `./docker_manage.sh start`

## Additional Services

The Docker setup includes several services:

- **web**: The main Flask application
- **db**: PostgreSQL database
- **redis**: Redis for caching and message broker
- **worker**: Celery worker for background tasks
- **beat**: Celery beat for scheduled tasks
- **flower**: Celery monitoring tool (available at [http://localhost:5556](http://localhost:5556))

To access Flower, use the credentials defined in your `.env` file (default: admin/admin123).
