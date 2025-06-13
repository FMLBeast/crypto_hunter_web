#!/usr/bin/env python3
"""
Database Schema Validation Script

This script checks if the current database schema matches the SQLAlchemy models.
If there's a mismatch, it can re-initialize the database.
"""

import logging
import os
import subprocess
import sys
from pathlib import Path

# Add project root to Python path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

# Load environment variables
from dotenv import load_dotenv
load_dotenv()

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('db_schema_validator')

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

def get_database_url():
    """
    Determine the appropriate database connection URL based on the environment.

    Returns:
        str: The database connection URL
    """
    # Determine the appropriate database connection
    if is_running_in_docker():
        # Inside Docker, use the Docker network hostname
        db_url = os.getenv('DATABASE_URL', 'postgresql://crypto_hunter:secure_password_123@db:5432/crypto_hunter')
        logger.info("Running inside Docker container, using Docker network")
    elif is_docker_db_available():
        # Outside Docker but Docker is running with the db container
        db_url = 'postgresql://crypto_hunter:secure_password_123@localhost:5432/crypto_hunter'
        logger.info("Docker database container detected, using localhost connection")
    else:
        # Fallback to SQLite for local development without Docker
        instance_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'instance')
        os.makedirs(instance_path, exist_ok=True)
        db_path = os.path.join(instance_path, 'crypto_hunter.db')
        db_url = f'sqlite:///{db_path}'
        logger.info(f"No Docker database available, using SQLite at {db_path}")

    return db_url

def check_schema_match():
    """
    Check if the database schema matches the SQLAlchemy models.

    Returns:
        bool: True if the schema matches, False otherwise
    """
    from flask import Flask
    from sqlalchemy import inspect
    from crypto_hunter_web.extensions import db
    from crypto_hunter_web.models import User, AnalysisFile, Finding, Vector, ApiKey, AuditLog

    # Create a minimal Flask app
    app = Flask(__name__)

    # Get the appropriate database URL
    db_url = get_database_url()

    app.config['SQLALCHEMY_DATABASE_URI'] = db_url
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

    # Initialize the app with the database
    db.init_app(app)

    with app.app_context():
        # Get the inspector
        inspector = inspect(db.engine)

        # Check if all tables exist
        expected_tables = {table.__tablename__ for table in [User, AnalysisFile, Finding, Vector, ApiKey, AuditLog]}
        actual_tables = set(inspector.get_table_names())

        missing_tables = expected_tables - actual_tables
        if missing_tables:
            logger.warning(f"Missing tables: {missing_tables}")
            return False

        # Check columns for each table
        for model_class in [User, AnalysisFile, Finding, Vector, ApiKey, AuditLog]:
            table_name = model_class.__tablename__

            # Get expected columns from the model
            model_columns = {column.name: column for column in model_class.__table__.columns}

            # Get actual columns from the database
            db_columns = {column['name']: column for column in inspector.get_columns(table_name)}

            # Check for missing columns
            missing_columns = set(model_columns.keys()) - set(db_columns.keys())
            if missing_columns:
                logger.warning(f"Table '{table_name}' is missing columns: {missing_columns}")
                return False

            # Check column types (simplified check)
            for col_name, model_col in model_columns.items():
                if col_name in db_columns:
                    # This is a simplified type check and might need refinement
                    model_type = str(model_col.type)
                    db_type = db_columns[col_name]['type']

                    # For UUID columns, PostgreSQL might report them as different types
                    if 'UUID' in model_type and ('uuid' in str(db_type).lower() or 'char' in str(db_type).lower()):
                        continue

                    # For other columns, do a basic string comparison
                    if model_type.lower() not in str(db_type).lower() and str(db_type).lower() not in model_type.lower():
                        logger.warning(f"Column type mismatch in '{table_name}.{col_name}': "
                                      f"Model: {model_type}, DB: {db_type}")
                        return False

        # If we got here, the schema matches
        return True

def reinitialize_database():
    """
    Re-initialize the database with the current schema.
    """
    logger.info("Re-initializing database...")

    # Import the initialization function
    from crypto_hunter_web.models import init_database
    from flask import Flask
    from crypto_hunter_web.extensions import db
    from sqlalchemy import text

    # Create a minimal Flask app
    app = Flask(__name__)

    # Get the appropriate database URL
    db_url = get_database_url()

    app.config['SQLALCHEMY_DATABASE_URI'] = db_url
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

    # Initialize the app with the database
    db.init_app(app)

    with app.app_context():
        # Check if we're using PostgreSQL
        is_postgres = 'postgresql' in db_url

        if is_postgres:
            # For PostgreSQL, use custom SQL to create tables in the correct order
            # with all necessary constraints
            try:
                # Drop all tables
                db.session.execute(text("DROP TABLE IF EXISTS findings CASCADE;"))
                db.session.execute(text("DROP TABLE IF EXISTS vectors CASCADE;"))
                db.session.execute(text("DROP TABLE IF EXISTS api_keys CASCADE;"))
                db.session.execute(text("DROP TABLE IF EXISTS audit_logs CASCADE;"))
                db.session.execute(text("DROP TABLE IF EXISTS file_content CASCADE;"))
                db.session.execute(text("DROP TABLE IF EXISTS combination_sources CASCADE;"))
                db.session.execute(text("DROP TABLE IF EXISTS combination_relationships CASCADE;"))
                db.session.execute(text("DROP TABLE IF EXISTS extraction_relationships CASCADE;"))
                db.session.execute(text("DROP TABLE IF EXISTS file_derivations CASCADE;"))
                db.session.execute(text("DROP TABLE IF EXISTS regions_of_interest CASCADE;"))
                db.session.execute(text("DROP TABLE IF EXISTS graph_edges CASCADE;"))
                db.session.execute(text("DROP TABLE IF EXISTS file_nodes CASCADE;"))
                db.session.execute(text("DROP TABLE IF EXISTS analysis_files CASCADE;"))
                db.session.execute(text("DROP TABLE IF EXISTS users CASCADE;"))
                db.session.execute(text("DROP TABLE IF EXISTS bulk_imports CASCADE;"))

                # Drop and recreate enum types
                db.session.execute(text("""
                DROP TYPE IF EXISTS userlevel CASCADE;
                DROP TYPE IF EXISTS filestatus CASCADE;
                DROP TYPE IF EXISTS findingstatus CASCADE;

                CREATE TYPE filestatus AS ENUM ('pending', 'processing', 'complete', 'error', 'archived');
                CREATE TYPE findingstatus AS ENUM ('unverified', 'confirmed', 'false_positive', 'needs_review');
                CREATE TYPE userlevel AS ENUM ('ANALYST', 'INTERMEDIATE', 'ADVANCED', 'EXPERT', 'MASTER');
                """))

                db.session.commit()

                # Now use SQLAlchemy's create_all to create all tables
                db.create_all()

                # Initialize the database with required data
                init_database()

            except Exception as e:
                db.session.rollback()
                logger.error(f"Error during database reinitialization: {e}")
                raise
        else:
            # For SQLite, use the standard approach
            # Drop all tables
            db.drop_all()

            # Re-create all tables
            db.create_all()

            # Initialize the database with required data
            init_database()

    logger.info("Database re-initialization complete.")

def main():
    """
    Main function to check the schema and re-initialize if needed.
    """
    logger.info("Checking database schema...")

    try:
        schema_matches = check_schema_match()

        if schema_matches:
            logger.info("Database schema matches the models. No action needed.")
        else:
            logger.warning("Database schema does not match the models.")

            # Ask for confirmation before re-initializing
            if os.getenv('AUTO_REINIT_DB', 'false').lower() == 'true':
                logger.info("AUTO_REINIT_DB is set to true. Re-initializing database...")
                reinitialize_database()
            else:
                response = input("Do you want to re-initialize the database? This will delete all data. (y/N): ")
                if response.lower() == 'y':
                    reinitialize_database()
                else:
                    logger.info("Database re-initialization cancelled.")

    except Exception as e:
        logger.error(f"Error checking database schema: {e}")
        return 1

    return 0

if __name__ == "__main__":
    sys.exit(main())
