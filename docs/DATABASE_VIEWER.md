# Connecting Database Viewers to Crypto Hunter PostgreSQL

This guide explains how to connect various database viewers to the PostgreSQL database used by the Crypto Hunter application.

## Connection Details

The PostgreSQL database has the following connection details:

- **Host**: 
  - Inside Docker: `db`
  - Outside Docker (on host machine): `localhost` or `127.0.0.1`
- **Port**: `5432`
- **Database**: `crypto_hunter`
- **Username**: `crypto_hunter`
- **Password**: `secure_password_123` (as defined in `.env` file)

## Connection Options

### 1. pgAdmin 4

[pgAdmin](https://www.pgadmin.org/) is a popular open-source administration and management tool for PostgreSQL.

#### Installation

- **Windows/macOS**: Download and install from [pgAdmin website](https://www.pgadmin.org/download/)
- **Linux**: 
  ```bash
  sudo apt install pgadmin4  # Debian/Ubuntu
  sudo dnf install pgadmin4  # Fedora
  ```

#### Connection Steps

1. Open pgAdmin
2. Right-click on "Servers" and select "Create" > "Server..."
3. In the "General" tab, enter a name (e.g., "Crypto Hunter")
4. In the "Connection" tab, enter:
   - Host: `localhost` or `127.0.0.1`
   - Port: `5432`
   - Maintenance database: `crypto_hunter`
   - Username: `crypto_hunter`
   - Password: `secure_password_123`
5. Click "Save"

### 2. DBeaver

[DBeaver](https://dbeaver.io/) is a free universal database tool that supports PostgreSQL.

#### Installation

- **Windows/macOS/Linux**: Download and install from [DBeaver website](https://dbeaver.io/download/)

#### Connection Steps

1. Open DBeaver
2. Click "New Database Connection" (database+ icon)
3. Select "PostgreSQL" and click "Next"
4. Enter:
   - Host: `localhost`
   - Port: `5432`
   - Database: `crypto_hunter`
   - Username: `crypto_hunter`
   - Password: `secure_password_123`
5. Click "Test Connection" to verify
6. Click "Finish"

### 3. DataGrip

[DataGrip](https://www.jetbrains.com/datagrip/) is a commercial database IDE by JetBrains.

#### Connection Steps

1. Open DataGrip
2. Click "New" > "Data Source" > "PostgreSQL"
3. Enter:
   - Host: `localhost`
   - Port: `5432`
   - Database: `crypto_hunter`
   - User: `crypto_hunter`
   - Password: `secure_password_123`
4. Click "Test Connection" to verify
5. Click "OK"

### 4. Command Line (psql)

PostgreSQL's command-line client `psql` can be used to connect directly.

#### Connection Command

```bash
psql -h localhost -p 5432 -U crypto_hunter -d crypto_hunter
```

When prompted, enter the password: `secure_password_123`

### 5. Connecting from Inside Docker

If you want to connect a database viewer running inside a Docker container, use the following connection details:

- **Host**: `db` (the service name in docker-compose.yml)
- **Port**: `5432`
- **Database**: `crypto_hunter`
- **Username**: `crypto_hunter`
- **Password**: `secure_password_123`

## Troubleshooting

### Cannot Connect to Database

1. **Check if Docker is running**: Make sure the Docker containers are up and running:
   ```bash
   docker compose ps
   ```

2. **Check database logs**: View the database logs for any errors:
   ```bash
   docker compose logs db
   ```

3. **Port conflicts**: Make sure no other service is using port 5432 on your host machine.

4. **Firewall issues**: Check if your firewall is blocking connections to port 5432.

### Connection Refused

If you get a "Connection refused" error, it might be because:

1. The database container is not running
2. The port mapping is not correctly set up
3. The database is still starting up

Try restarting the database container:

```bash
docker compose restart db
```

## Security Considerations

- The database is currently only accessible from localhost (127.0.0.1) for security reasons
- If you need to access the database from another machine, you'll need to modify the port mapping in docker-compose.yml
- Always use strong passwords in production environments
- Consider using SSL for database connections in production

## Recommended Database Viewers

1. **pgAdmin 4**: Best for PostgreSQL-specific features and administration
2. **DBeaver**: Great all-around database tool with good PostgreSQL support
3. **DataGrip**: Excellent IDE-like experience with advanced features (commercial)
4. **TablePlus**: Clean, modern interface with good PostgreSQL support (freemium)
5. **Beekeeper Studio**: Open-source, lightweight alternative

## Conclusion

You now have multiple options for connecting database viewers to the Crypto Hunter PostgreSQL database. Choose the one that best fits your workflow and preferences.