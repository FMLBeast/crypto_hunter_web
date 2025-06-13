-- Initialize the database for Crypto Hunter

-- Create extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pg_trgm";

-- Set up permissions for the crypto_hunter user
-- Note: User creation is handled by the POSTGRES_USER environment variable in docker-compose.yml
GRANT ALL PRIVILEGES ON DATABASE crypto_hunter TO crypto_hunter;

-- Create schema if it doesn't exist (optional, as the default is public)
-- CREATE SCHEMA IF NOT EXISTS crypto_hunter;
-- GRANT ALL ON SCHEMA crypto_hunter TO crypto_hunter;

-- The actual tables and indexes will be created by the application when it starts
-- through SQLAlchemy's ORM and the init_database function