# Database Connection Options for Crypto Hunter

This document provides an overview of the different ways to connect to the Crypto Hunter PostgreSQL database.

## Quick Reference

- **Host**: 
  - Inside Docker: `db`
  - Outside Docker: `localhost` or `127.0.0.1`
- **Port**: `5432`
- **Database**: `crypto_hunter`
- **Username**: `crypto_hunter`
- **Password**: `secure_password_123`

## Available Connection Methods

### 1. Command Line Script

For quick command-line access, use the provided script:

```bash
./connect_db.sh
```

This script automatically detects whether you're running inside Docker or on the host machine and connects accordingly.

### 2. Database Viewers

For a graphical interface, you can connect various database viewers to the PostgreSQL database. See [DATABASE_VIEWER.md](DATABASE_VIEWER.md) for detailed instructions on connecting:

- pgAdmin 4
- DBeaver
- DataGrip
- And more...

### 3. pgAdmin in Docker

If you prefer to keep everything in Docker, you can run pgAdmin directly in a container. See [DOCKER_PGADMIN.md](DOCKER_PGADMIN.md) for instructions on:

- Adding pgAdmin to your Docker Compose setup
- Configuring automatic database connections
- Accessing pgAdmin through your web browser

## Database Maintenance

For information on maintaining the database schema and fixing issues, see:

- [DATABASE_MAINTENANCE.md](DATABASE_MAINTENANCE.md) - General maintenance guide
- [FIX_BULK_IMPORTS.md](FIX_BULK_IMPORTS.md) - Specific fix for bulk imports table

## Security Considerations

- The database is only accessible from localhost (127.0.0.1) by default
- Use strong passwords in production environments
- Consider enabling SSL for database connections in production
- Be careful with storing database credentials in plain text files

## Troubleshooting

If you encounter connection issues:

1. Verify that the Docker containers are running:
   ```bash
   docker compose ps
   ```

2. Check the database logs:
   ```bash
   docker compose logs db
   ```

3. Make sure no other service is using port 5432 on your host machine

4. If you've modified the connection details, ensure they match in all configuration files

## Conclusion

You now have multiple options for connecting to the Crypto Hunter PostgreSQL database. Choose the method that best fits your workflow and preferences.