#!/usr/bin/env python3
"""
Database Schema Export Script

This script exports the complete PostgreSQL database schema and compares it with the SQLAlchemy models.
"""

import json
import logging
import os
import sys
from collections import defaultdict
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
logger = logging.getLogger('db_schema_exporter')

def is_running_in_docker():
    """Check if we're running inside Docker"""
    try:
        with open('/proc/1/cgroup', 'r') as f:
            return any('docker' in line for line in f)
    except:
        return False

def is_docker_db_available():
    """Check if Docker is running and the db container is available"""
    try:
        import subprocess
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

def export_database_schema():
    """
    Export the complete database schema.

    Returns:
        dict: A dictionary containing the database schema information
    """
    from flask import Flask
    from sqlalchemy import inspect
    from crypto_hunter_web.extensions import db

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

        # Get all tables
        tables = inspector.get_table_names()
        
        schema = {}
        
        for table_name in tables:
            schema[table_name] = {
                'columns': {},
                'primary_key': [],
                'foreign_keys': [],
                'indexes': [],
                'unique_constraints': []
            }
            
            # Get columns
            for column in inspector.get_columns(table_name):
                schema[table_name]['columns'][column['name']] = {
                    'type': str(column['type']),
                    'nullable': column.get('nullable', True),
                    'default': str(column.get('default', 'None'))
                }
            
            # Get primary key
            pk = inspector.get_pk_constraint(table_name)
            if pk and 'constrained_columns' in pk:
                schema[table_name]['primary_key'] = pk['constrained_columns']
            
            # Get foreign keys
            for fk in inspector.get_foreign_keys(table_name):
                schema[table_name]['foreign_keys'].append({
                    'constrained_columns': fk['constrained_columns'],
                    'referred_table': fk['referred_table'],
                    'referred_columns': fk['referred_columns']
                })
            
            # Get indexes
            for idx in inspector.get_indexes(table_name):
                schema[table_name]['indexes'].append({
                    'name': idx['name'],
                    'columns': idx['column_names'],
                    'unique': idx['unique']
                })
            
            # Get unique constraints
            try:
                for constraint in inspector.get_unique_constraints(table_name):
                    schema[table_name]['unique_constraints'].append({
                        'name': constraint.get('name', ''),
                        'columns': constraint['column_names']
                    })
            except NotImplementedError:
                # Some dialects might not implement this
                pass
        
        return schema

def get_model_schema():
    """
    Get the schema information from the SQLAlchemy models.

    Returns:
        dict: A dictionary containing the model schema information
    """
    from flask import Flask
    from crypto_hunter_web.extensions import db
    from crypto_hunter_web.models import (
        User, AnalysisFile, FileContent, Finding, Vector, ApiKey, AuditLog,
        ExtractionRelationship, FileNode, GraphEdge, RegionOfInterest,
        FileDerivation, CombinationRelationship, CombinationSource, BulkImport
    )

    # Create a minimal Flask app
    app = Flask(__name__)

    # Get the appropriate database URL
    db_url = get_database_url()

    app.config['SQLALCHEMY_DATABASE_URI'] = db_url
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

    # Initialize the app with the database
    db.init_app(app)

    with app.app_context():
        model_schema = {}
        
        # List of all models
        models = [
            User, AnalysisFile, FileContent, Finding, Vector, ApiKey, AuditLog,
            ExtractionRelationship, FileNode, GraphEdge, RegionOfInterest,
            FileDerivation, CombinationRelationship, CombinationSource, BulkImport
        ]
        
        for model in models:
            table_name = model.__tablename__
            model_schema[table_name] = {
                'columns': {},
                'primary_key': [],
                'foreign_keys': [],
                'indexes': [],
                'unique_constraints': []
            }
            
            # Get columns
            for column in model.__table__.columns:
                model_schema[table_name]['columns'][column.name] = {
                    'type': str(column.type),
                    'nullable': column.nullable,
                    'default': str(column.default)
                }
            
            # Get primary key
            model_schema[table_name]['primary_key'] = [c.name for c in model.__table__.primary_key.columns]
            
            # Get foreign keys
            for fk in model.__table__.foreign_keys:
                target = fk.target_fullname.split('.')
                model_schema[table_name]['foreign_keys'].append({
                    'constrained_columns': [fk.parent.name],
                    'referred_table': target[0],
                    'referred_columns': [target[1]]
                })
            
            # Get indexes
            for idx in model.__table__.indexes:
                model_schema[table_name]['indexes'].append({
                    'name': idx.name,
                    'columns': [c.name for c in idx.columns],
                    'unique': idx.unique
                })
            
            # Get unique constraints
            for constraint in model.__table__.constraints:
                if hasattr(constraint, 'columns') and constraint.name and 'uq' in constraint.name.lower():
                    model_schema[table_name]['unique_constraints'].append({
                        'name': constraint.name,
                        'columns': [c.name for c in constraint.columns]
                    })
        
        return model_schema

def compare_schemas(db_schema, model_schema):
    """
    Compare the database schema with the model schema and identify discrepancies.

    Args:
        db_schema (dict): The database schema
        model_schema (dict): The model schema

    Returns:
        dict: A dictionary containing the discrepancies
    """
    discrepancies = {
        'missing_tables': [],
        'extra_tables': [],
        'table_discrepancies': defaultdict(lambda: {
            'missing_columns': [],
            'extra_columns': [],
            'column_type_mismatches': [],
            'column_nullable_mismatches': [],
            'missing_foreign_keys': [],
            'extra_foreign_keys': [],
            'missing_indexes': [],
            'extra_indexes': []
        })
    }
    
    # Check for missing tables
    for table_name in model_schema:
        if table_name not in db_schema:
            discrepancies['missing_tables'].append(table_name)
    
    # Check for extra tables
    for table_name in db_schema:
        if table_name not in model_schema:
            discrepancies['extra_tables'].append(table_name)
    
    # Check table details
    for table_name in model_schema:
        if table_name not in db_schema:
            continue
        
        # Check for missing columns
        for column_name in model_schema[table_name]['columns']:
            if column_name not in db_schema[table_name]['columns']:
                discrepancies['table_discrepancies'][table_name]['missing_columns'].append(column_name)
        
        # Check for extra columns
        for column_name in db_schema[table_name]['columns']:
            if column_name not in model_schema[table_name]['columns']:
                discrepancies['table_discrepancies'][table_name]['extra_columns'].append(column_name)
        
        # Check column types and nullable
        for column_name in model_schema[table_name]['columns']:
            if column_name not in db_schema[table_name]['columns']:
                continue
            
            model_type = model_schema[table_name]['columns'][column_name]['type'].lower()
            db_type = db_schema[table_name]['columns'][column_name]['type'].lower()
            
            # Normalize types for comparison
            model_type = model_type.replace('varchar', 'character varying')
            model_type = model_type.replace('integer', 'int')
            db_type = db_type.replace('integer', 'int')
            
            # For UUID columns, PostgreSQL might report them as different types
            if 'uuid' in model_type and ('uuid' in db_type or 'char' in db_type):
                pass
            # For JSON columns
            elif 'json' in model_type and 'json' in db_type:
                pass
            # For TIMESTAMP columns
            elif 'timestamp' in model_type and 'timestamp' in db_type:
                pass
            # For other columns, do a basic string comparison
            elif model_type not in db_type and db_type not in model_type:
                discrepancies['table_discrepancies'][table_name]['column_type_mismatches'].append({
                    'column': column_name,
                    'model_type': model_type,
                    'db_type': db_type
                })
            
            # Check nullable
            model_nullable = model_schema[table_name]['columns'][column_name]['nullable']
            db_nullable = db_schema[table_name]['columns'][column_name]['nullable']
            if model_nullable != db_nullable:
                discrepancies['table_discrepancies'][table_name]['column_nullable_mismatches'].append({
                    'column': column_name,
                    'model_nullable': model_nullable,
                    'db_nullable': db_nullable
                })
        
        # Check for missing foreign keys
        for fk in model_schema[table_name]['foreign_keys']:
            found = False
            for db_fk in db_schema[table_name]['foreign_keys']:
                if (fk['constrained_columns'] == db_fk['constrained_columns'] and
                    fk['referred_table'] == db_fk['referred_table'] and
                    fk['referred_columns'] == db_fk['referred_columns']):
                    found = True
                    break
            if not found:
                discrepancies['table_discrepancies'][table_name]['missing_foreign_keys'].append(fk)
        
        # Check for extra foreign keys
        for db_fk in db_schema[table_name]['foreign_keys']:
            found = False
            for fk in model_schema[table_name]['foreign_keys']:
                if (fk['constrained_columns'] == db_fk['constrained_columns'] and
                    fk['referred_table'] == db_fk['referred_table'] and
                    fk['referred_columns'] == db_fk['referred_columns']):
                    found = True
                    break
            if not found:
                discrepancies['table_discrepancies'][table_name]['extra_foreign_keys'].append(db_fk)
        
        # Check for missing indexes (simplified)
        for idx in model_schema[table_name]['indexes']:
            found = False
            for db_idx in db_schema[table_name]['indexes']:
                if set(idx['columns']) == set(db_idx['columns']) and idx['unique'] == db_idx['unique']:
                    found = True
                    break
            if not found:
                discrepancies['table_discrepancies'][table_name]['missing_indexes'].append(idx)
        
        # Check for extra indexes (simplified)
        for db_idx in db_schema[table_name]['indexes']:
            found = False
            for idx in model_schema[table_name]['indexes']:
                if set(idx['columns']) == set(db_idx['columns']) and idx['unique'] == db_idx['unique']:
                    found = True
                    break
            if not found:
                discrepancies['table_discrepancies'][table_name]['extra_indexes'].append(db_idx)
    
    # Clean up empty discrepancies
    for table_name in list(discrepancies['table_discrepancies'].keys()):
        table_disc = discrepancies['table_discrepancies'][table_name]
        empty = True
        for key, value in table_disc.items():
            if value:
                empty = False
                break
        if empty:
            del discrepancies['table_discrepancies'][table_name]
    
    return discrepancies

def main():
    """
    Main function to export the database schema and compare it with the models.
    """
    logger.info("Exporting database schema...")
    
    try:
        # Export database schema
        db_schema = export_database_schema()
        
        # Get model schema
        model_schema = get_model_schema()
        
        # Compare schemas
        discrepancies = compare_schemas(db_schema, model_schema)
        
        # Save schemas to files
        with open('db_schema.json', 'w') as f:
            json.dump(db_schema, f, indent=2)
        
        with open('model_schema.json', 'w') as f:
            json.dump(model_schema, f, indent=2)
        
        # Save discrepancies to file
        with open('schema_discrepancies.json', 'w') as f:
            json.dump(discrepancies, f, indent=2)
        
        # Print summary
        print("\n=== Database Schema Export Summary ===")
        print(f"Database tables: {len(db_schema)}")
        print(f"Model tables: {len(model_schema)}")
        
        if discrepancies['missing_tables']:
            print(f"\nMissing tables (in models but not in database): {len(discrepancies['missing_tables'])}")
            for table in discrepancies['missing_tables']:
                print(f"  - {table}")
        
        if discrepancies['extra_tables']:
            print(f"\nExtra tables (in database but not in models): {len(discrepancies['extra_tables'])}")
            for table in discrepancies['extra_tables']:
                print(f"  - {table}")
        
        if discrepancies['table_discrepancies']:
            print("\nTable discrepancies:")
            for table, disc in discrepancies['table_discrepancies'].items():
                print(f"\n  Table: {table}")
                
                if disc['missing_columns']:
                    print(f"    Missing columns: {len(disc['missing_columns'])}")
                    for col in disc['missing_columns']:
                        print(f"      - {col}")
                
                if disc['extra_columns']:
                    print(f"    Extra columns: {len(disc['extra_columns'])}")
                    for col in disc['extra_columns']:
                        print(f"      - {col}")
                
                if disc['column_type_mismatches']:
                    print(f"    Column type mismatches: {len(disc['column_type_mismatches'])}")
                    for mismatch in disc['column_type_mismatches']:
                        print(f"      - {mismatch['column']}: Model: {mismatch['model_type']}, DB: {mismatch['db_type']}")
                
                if disc['column_nullable_mismatches']:
                    print(f"    Column nullable mismatches: {len(disc['column_nullable_mismatches'])}")
                    for mismatch in disc['column_nullable_mismatches']:
                        print(f"      - {mismatch['column']}: Model: {mismatch['model_nullable']}, DB: {mismatch['db_nullable']}")
        
        print("\nDetailed results saved to:")
        print("  - db_schema.json")
        print("  - model_schema.json")
        print("  - schema_discrepancies.json")
        
    except Exception as e:
        logger.error(f"Error exporting database schema: {e}", exc_info=True)
        return 1
    
    return 0

if __name__ == "__main__":
    sys.exit(main())