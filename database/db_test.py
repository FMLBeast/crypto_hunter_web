#!/usr/bin/env python3
"""
Test script to verify PostgreSQL connection from dev machine
"""

import os
import sys
from typing import Dict, Any

import psycopg2
from psycopg2.extras import RealDictCursor


class DatabaseConnection:
    def __init__(self, 
                 host: str = "localhost",
                 port: int = 5432,
                 database: str = "crypto_hunter",
                 user: str = "crypto_hunter",
                 password: str = None):
        # Get password from environment if not provided
        if password is None:
            password = os.getenv('DB_PASSWORD', 'secure_password_123')
        self.connection_params = {
            'host': host,
            'port': port,
            'database': database,
            'user': user,
            'password': password
        }
        self.connection = None
    
    def connect(self) -> bool:
        """Establish database connection"""
        try:
            self.connection = psycopg2.connect(
                **self.connection_params,
                cursor_factory=RealDictCursor
            )
            print(f"✅ Successfully connected to PostgreSQL database '{self.connection_params['database']}'")
            return True
        except psycopg2.Error as e:
            print(f"❌ Failed to connect to database: {e}")
            return False
    
    def test_connection(self) -> Dict[str, Any]:
        """Test database connection and return server info"""
        if not self.connection:
            return {"status": "error", "message": "No connection established"}
        
        try:
            with self.connection.cursor() as cursor:
                # Test basic connectivity
                cursor.execute("SELECT version(), current_database(), current_user, now();")
                result = cursor.fetchone()
                
                # Get database size
                cursor.execute("""
                    SELECT pg_size_pretty(pg_database_size(current_database())) as db_size;
                """)
                size_result = cursor.fetchone()
                
                # List tables
                cursor.execute("""
                    SELECT table_name 
                    FROM information_schema.tables 
                    WHERE table_schema = 'public'
                    ORDER BY table_name;
                """)
                tables = [row['table_name'] for row in cursor.fetchall()]
                
                return {
                    "status": "success",
                    "version": result['version'],
                    "database": result['current_database'],
                    "user": result['current_user'],
                    "timestamp": result['now'],
                    "size": size_result['db_size'],
                    "tables": tables
                }
        except psycopg2.Error as e:
            return {"status": "error", "message": str(e)}
    
    def close(self):
        """Close database connection"""
        if self.connection:
            self.connection.close()
            print("🔌 Database connection closed")

def main():
    """Main function to test database connectivity"""
    print("🔍 Testing PostgreSQL Database Connection...")
    print("-" * 50)
    
    # Initialize connection
    db = DatabaseConnection()
    
    # Test connection
    if not db.connect():
        sys.exit(1)
    
    # Run tests
    test_results = db.test_connection()
    
    if test_results["status"] == "success":
        print("\n📊 Database Information:")
        print(f"Database: {test_results['database']}")
        print(f"User: {test_results['user']}")
        print(f"Size: {test_results['size']}")
        print(f"Connected at: {test_results['timestamp']}")
        print(f"Version: {test_results['version'][:50]}...")
        
        if test_results['tables']:
            print(f"\n📋 Tables ({len(test_results['tables'])}):")
            for table in test_results['tables']:
                print(f"  - {table}")
        else:
            print("\n📋 No tables found (empty database)")
            
    else:
        print(f"❌ Test failed: {test_results['message']}")
    
    # Clean up
    db.close()

if __name__ == "__main__":
    main()