# Docker Quick Start Guide for Crypto Hunter

This guide provides quick instructions for starting and managing the Crypto Hunter application using Docker.

## Starting the Containers

We've made several improvements to the Docker configuration to ensure all services start correctly, including the web containers and Celery workers. To start the application:

1. Make sure the management script is executable:
   ```bash
   chmod +x docker_manage.sh
   ```

2. Start all containers:
   ```bash
   ./docker_manage.sh start
   ```

3. Check the status of your containers:
   ```bash
   ./docker_manage.sh status
   ```

## Troubleshooting

If you encounter issues with containers not starting:

1. Check the logs for specific services:
   ```bash
   # For web service
   ./docker_manage.sh logs web

   # For Celery worker
   ./docker_manage.sh logs worker

   # For Celery beat
   ./docker_manage.sh logs beat
   ```

2. If you see errors related to Redis or database connections, ensure those services are running:
   ```bash
   ./docker_manage.sh logs redis
   ./docker_manage.sh logs db
   ```

3. If you need to restart a specific service:
   ```bash
   docker compose --env-file .env restart [service_name]
   ```

4. If all else fails, try rebuilding the containers:
   ```bash
   ./docker_manage.sh build
   ./docker_manage.sh start
   ```

## Recent Changes

We've made the following improvements to fix issues with containers not starting:

1. Updated the `docker-compose.override.yml` file to include configurations for all services in development mode
2. Fixed the Celery task paths in `celery_app.py` to correctly reference tasks in the maintenance_tasks.py file
3. Added all task modules to the Celery include list to ensure they're properly registered

## Accessing the Application

- Web application: [http://localhost:8000](http://localhost:8000)
- Celery monitoring (Flower): [http://localhost:5556](http://localhost:5556)
  - Username: admin
  - Password: admin123 (or as configured in your .env file)

## Additional Commands

- Stop all containers: `./docker_manage.sh stop`
- Restart all containers: `./docker_manage.sh restart`
- Clean up resources: `./docker_manage.sh clean`

For more detailed information about the Docker setup, please refer to the `DOCKER_SETUP.md` file.
