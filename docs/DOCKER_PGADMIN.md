# Running pgAdmin in Docker for Crypto Hunter

This guide explains how to run pgAdmin in Docker and connect it to the Crypto Hunter PostgreSQL database.

## Overview

Running pgAdmin in Docker can be a convenient way to manage your PostgreSQL database without installing additional software on your host machine. This guide will show you how to:

1. Add pgAdmin to your Docker Compose setup
2. Configure pgAdmin to automatically connect to your database
3. Access pgAdmin through your web browser

## Adding pgAdmin to Docker Compose

Add the following service to your `docker-compose.yml` file:

```yaml
  pgadmin:
    image: dpage/pgadmin4:latest
    container_name: crypto-hunter-pgadmin
    restart: unless-stopped
    environment:
      PGADMIN_DEFAULT_EMAIL: admin@example.com
      PGADMIN_DEFAULT_PASSWORD: admin
      PGADMIN_CONFIG_SERVER_MODE: 'False'
    volumes:
      - pgadmin_data:/var/lib/pgadmin
    ports:
      - "127.0.0.1:5050:80"
    networks:
      - crypto-hunter-network
    depends_on:
      - db
```

Also, add the volume to the volumes section at the bottom of the file:

```yaml
volumes:
  postgres_data:
  redis_data:
  uploads_data:
  logs_data:
  pgadmin_data:  # Add this line
```

## Automatic Server Configuration

To automatically configure pgAdmin to connect to your PostgreSQL database, you can create a `servers.json` file and mount it to the pgAdmin container.

1. Create a `pgadmin/servers.json` file in your project directory:

```json
{
  "Servers": {
    "1": {
      "Name": "Crypto Hunter DB",
      "Group": "Servers",
      "Host": "db",
      "Port": 5432,
      "MaintenanceDB": "crypto_hunter",
      "Username": "crypto_hunter",
      "SSLMode": "prefer",
      "PassFile": "/pgpass"
    }
  }
}
```

2. Create a `pgadmin/pgpass` file with the database password:

```
db:5432:crypto_hunter:crypto_hunter:secure_password_123
```

3. Update the pgAdmin service in your `docker-compose.yml` to mount these files:

```yaml
  pgadmin:
    image: dpage/pgadmin4:latest
    container_name: crypto-hunter-pgadmin
    restart: unless-stopped
    environment:
      PGADMIN_DEFAULT_EMAIL: admin@example.com
      PGADMIN_DEFAULT_PASSWORD: admin
      PGADMIN_CONFIG_SERVER_MODE: 'False'
    volumes:
      - pgadmin_data:/var/lib/pgadmin
      - ./pgadmin/servers.json:/pgadmin4/servers.json
      - ./pgadmin/pgpass:/pgpass
    ports:
      - "127.0.0.1:5050:80"
    networks:
      - crypto-hunter-network
    depends_on:
      - db
```

## Starting pgAdmin

After updating your Docker Compose file, start the services:

```bash
docker compose up -d
```

## Accessing pgAdmin

1. Open your web browser and navigate to: http://localhost:5050
2. Log in with:
   - Email: admin@example.com
   - Password: admin
3. You should see the "Crypto Hunter DB" server in the left sidebar
4. Click on it to connect to the database

> **Note:** The actual configuration in the project's docker-compose.yml file may differ from this documentation. The docker-compose.yml file configures pgAdmin to run on port 5051 and is only enabled in the "dev" and "tools" profiles. If you're running pgAdmin through docker-compose, you may need to:
> ```bash
> # Start pgAdmin with the appropriate profile
> docker compose --profile tools up -d
> # Then access it at http://localhost:5051
> ```
> 
> If you're running pgAdmin directly with Docker (not through docker-compose), make sure to use the credentials shown above.

## Security Considerations

- The pgAdmin interface is only accessible from localhost (127.0.0.1) for security reasons
- Change the default email and password in production environments
- Consider using SSL for pgAdmin in production
- The password is stored in plain text in the pgpass file, so ensure it has appropriate permissions

## Troubleshooting

### Cannot Access pgAdmin

1. Check if the pgAdmin container is running:
   ```bash
   docker compose ps pgadmin
   ```

2. Check pgAdmin logs:
   ```bash
   docker compose logs pgadmin
   ```

3. Make sure no other service is using port 5050 on your host machine.

### Cannot Connect to Database

1. Check if the database container is running:
   ```bash
   docker compose ps db
   ```

2. Verify that both containers are on the same network:
   ```bash
   docker network inspect crypto-hunter-network
   ```

3. Check if the servers.json file is correctly mounted:
   ```bash
   docker compose exec pgadmin ls -la /pgadmin4/servers.json
   ```

## Conclusion

You now have pgAdmin running in Docker and connected to your Crypto Hunter PostgreSQL database. This provides a convenient web-based interface for managing your database without installing additional software on your host machine.
