#!/usr/bin/env python3
"""
Database Initialization Script
This script initializes the database with all required tables and initial data.
"""

import os
import sys
from pathlib import Path

# Add project root to Python path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

# Load environment variables
from dotenv import load_dotenv
load_dotenv()

def init_database():
    """Initialize the database with all tables and initial data"""
    from flask import Flask
    from crypto_hunter_web.extensions import db
    import psycopg2
    from psycopg2.extensions import ISOLATION_LEVEL_AUTOCOMMIT
    from werkzeug.security import generate_password_hash
    import os
    import socket
    import subprocess

    # Check if we're running inside Docker
    def is_running_in_docker():
        try:
            with open('/proc/1/cgroup', 'r') as f:
                return any('docker' in line for line in f)
        except:
            return False

    # Check if Docker is running and the db container is available
    def is_docker_db_available():
        try:
            result = subprocess.run(['docker', 'ps', '--filter', 'name=crypto-hunter-db', '--format', '{{.Names}}'], 
                                   capture_output=True, text=True, check=True)
            return 'crypto-hunter-db' in result.stdout
        except:
            return False

    # Create a minimal Flask app
    app = Flask(__name__)

    # Determine the appropriate database connection
    if is_running_in_docker():
        # Inside Docker, use the Docker network hostname
        db_url = os.getenv('DATABASE_URL', 'postgresql://crypto_hunter:secure_password_123@db:5432/crypto_hunter')
        print("Running inside Docker container, using Docker network")
    elif is_docker_db_available():
        # Outside Docker but Docker is running with the db container
        db_url = 'postgresql://crypto_hunter:secure_password_123@localhost:5432/crypto_hunter'
        print("Docker database container detected, using localhost connection")
    else:
        # Fallback to SQLite for local development without Docker
        instance_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'instance')
        os.makedirs(instance_path, exist_ok=True)
        db_path = os.path.join(instance_path, 'crypto_hunter.db')
        db_url = f'sqlite:///{db_path}'
        print(f"No Docker database available, using SQLite at {db_path}")

    app.config['SQLALCHEMY_DATABASE_URI'] = db_url
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

    # Check if we're using PostgreSQL or SQLite
    if db_url.startswith('postgresql://'):
        # Parse the database URL to get connection parameters
        db_parts = db_url.replace('postgresql://', '').split('@')
        user_pass = db_parts[0].split(':')
        host_port_db = db_parts[1].split('/')

        db_user = user_pass[0]
        db_password = user_pass[1]
        db_host = host_port_db[0].split(':')[0]
        db_port = host_port_db[0].split(':')[1] if ':' in host_port_db[0] else '5432'
        db_name = host_port_db[1]

        print(f"Connecting to PostgreSQL database: {db_host}:{db_port}/{db_name} as {db_user}")

    try:
        print("Creating database tables...")

        if db_url.startswith('postgresql://'):
            # PostgreSQL initialization
            conn = psycopg2.connect(
                host=db_host,
                port=db_port,
                user=db_user,
                password=db_password,
                dbname=db_name
            )
            conn.set_isolation_level(ISOLATION_LEVEL_AUTOCOMMIT)
            cursor = conn.cursor()

            # Drop existing tables if they exist
            cursor.execute("DROP TABLE IF EXISTS findings CASCADE;")
            cursor.execute("DROP TABLE IF EXISTS analysis_files CASCADE;")
            cursor.execute("DROP TABLE IF EXISTS users CASCADE;")

            # Create users table
            cursor.execute("""
            CREATE TABLE users (
                id SERIAL PRIMARY KEY,
                public_id UUID DEFAULT gen_random_uuid() UNIQUE NOT NULL,
                username VARCHAR(80) UNIQUE NOT NULL,
                email VARCHAR(120) UNIQUE NOT NULL,
                password_hash VARCHAR(255) NOT NULL,
                display_name VARCHAR(100),
                is_admin BOOLEAN DEFAULT FALSE,
                is_verified BOOLEAN DEFAULT FALSE,
                created_at TIMESTAMP DEFAULT NOW(),
                updated_at TIMESTAMP DEFAULT NOW()
            );
            """)

            # Create analysis_files table
            cursor.execute("""
            CREATE TABLE analysis_files (
                id SERIAL PRIMARY KEY,
                filename VARCHAR(255) NOT NULL,
                file_size BIGINT NOT NULL,
                file_type VARCHAR(100),
                sha256_hash VARCHAR(64) UNIQUE NOT NULL,
                md5_hash VARCHAR(32),
                status VARCHAR(50) DEFAULT 'pending',
                is_encrypted BOOLEAN DEFAULT FALSE,
                contains_crypto BOOLEAN DEFAULT FALSE,
                created_at TIMESTAMP DEFAULT NOW(),
                updated_at TIMESTAMP DEFAULT NOW(),
                created_by INTEGER REFERENCES users(id)
            );
            """)

            # Create findings table
            cursor.execute("""
            CREATE TABLE findings (
                id SERIAL PRIMARY KEY,
                file_id INTEGER REFERENCES analysis_files(id),
                finding_type VARCHAR(100) NOT NULL,
                confidence FLOAT DEFAULT 0.0,
                description TEXT,
                metadata JSON,
                created_at TIMESTAMP DEFAULT NOW(),
                created_by INTEGER REFERENCES users(id)
            );
            """)

            # Create indexes for performance
            cursor.execute("CREATE INDEX idx_files_sha256 ON analysis_files(sha256_hash);")
            cursor.execute("CREATE INDEX idx_files_status ON analysis_files(status);")
            cursor.execute("CREATE INDEX idx_findings_type ON findings(finding_type);")
            cursor.execute("CREATE INDEX idx_findings_confidence ON findings(confidence);")

            # Check if admin user exists
            cursor.execute("SELECT id, username FROM users WHERE username = 'admin';")
            admin = cursor.fetchone()

            # Create admin user if not exists
            if not admin:
                # Generate password hash for 'admin123'
                password_hash = generate_password_hash('admin123')

                # Generate a UUID for public_id
                import uuid
                public_id = uuid.uuid4()

                cursor.execute("""
                INSERT INTO users (public_id, username, email, password_hash, display_name, is_admin, is_verified, created_at, updated_at)
                VALUES (%s, %s, %s, %s, %s, %s, %s, NOW(), NOW());
                """, (public_id, 'admin', 'admin@example.com', password_hash, 'Administrator', True, True))

                print("Created admin user with username 'admin' and password 'admin123'")
            else:
                print(f"Admin user exists: {admin[1]} (ID: {admin[0]})")

            # Show created tables
            cursor.execute("SELECT table_name FROM information_schema.tables WHERE table_schema = 'public';")
            tables = cursor.fetchall()
            print("Created tables:")
            for table in tables:
                print(f"  - {table[0]}")

            # Close connection
            cursor.close()
            conn.close()

        else:
            # SQLite initialization
            import sqlite3

            # Connect to SQLite database
            db_path = db_url.replace('sqlite:///', '')
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()

            # Create users table (simplified schema)
            cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                public_id TEXT UNIQUE NOT NULL,
                username VARCHAR(80) UNIQUE NOT NULL,
                email VARCHAR(120) UNIQUE NOT NULL,
                password_hash VARCHAR(255) NOT NULL,
                display_name VARCHAR(100),
                is_admin BOOLEAN DEFAULT 0,
                is_verified BOOLEAN DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
            ''')

            # Create analysis_files table (simplified schema)
            cursor.execute('''
            CREATE TABLE IF NOT EXISTS analysis_files (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                filename VARCHAR(255) NOT NULL,
                file_size BIGINT NOT NULL,
                file_type VARCHAR(100),
                sha256_hash VARCHAR(64) UNIQUE NOT NULL,
                md5_hash VARCHAR(32),
                status VARCHAR(50) DEFAULT 'pending',
                is_encrypted BOOLEAN DEFAULT 0,
                contains_crypto BOOLEAN DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                created_by INTEGER,
                FOREIGN KEY (created_by) REFERENCES users (id)
            )
            ''')

            # Create findings table (simplified schema)
            cursor.execute('''
            CREATE TABLE IF NOT EXISTS findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                file_id INTEGER,
                finding_type VARCHAR(100) NOT NULL,
                confidence FLOAT DEFAULT 0.0,
                description TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                created_by INTEGER,
                FOREIGN KEY (file_id) REFERENCES analysis_files (id),
                FOREIGN KEY (created_by) REFERENCES users (id)
            )
            ''')

            # Create indexes for performance
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_files_sha256 ON analysis_files(sha256_hash);")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_files_status ON analysis_files(status);")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_findings_type ON findings(finding_type);")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_findings_confidence ON findings(confidence);")

            # Check if admin user exists
            cursor.execute("SELECT id, username FROM users WHERE username = 'admin'")
            admin = cursor.fetchone()

            # Create admin user if not exists
            if not admin:
                # Generate password hash for 'admin123'
                password_hash = generate_password_hash('admin123')

                # Generate a UUID for public_id
                import uuid
                public_id = str(uuid.uuid4())

                cursor.execute('''
                INSERT INTO users (public_id, username, email, password_hash, display_name, is_admin, is_verified)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ''', (public_id, 'admin', 'admin@example.com', password_hash, 'Administrator', 1, 1))

                print("Created admin user with username 'admin' and password 'admin123'")
            else:
                print(f"Admin user exists: {admin[1]} (ID: {admin[0]})")

            # Commit changes and close connection
            conn.commit()
            conn.close()

            print("SQLite database tables created successfully")

        print("Database initialization completed successfully!")

    except Exception as e:
        print(f"Error initializing database: {e}")
        raise

if __name__ == "__main__":
    print("🔧 CRYPTO HUNTER - Database Initialization")
    print("=========================================")
    init_database()
    print("=========================================")
    print("✅ Database setup completed!")
