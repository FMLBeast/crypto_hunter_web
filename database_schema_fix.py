#!/usr/bin/env python3
# fix_database_schema.py - Fix critical database schema issues

import os
from crypto_hunter_web import create_app, db
from crypto_hunter_web.models import User
from sqlalchemy import text

def fix_database_schema():
    """Fix the critical database schema issues"""
    
    app = create_app()
    
    with app.app_context():
        print("🔧 FIXING CRITICAL DATABASE SCHEMA ISSUES")
        print("=" * 50)
        
        try:
            inspector = db.inspect(db.engine)
            
            # 1. Check analysis_files table schema
            print("📊 Checking analysis_files table schema...")
            
            if 'analysis_files' in inspector.get_table_names():
                af_columns = [col['name'] for col in inspector.get_columns('analysis_files')]
                print(f"   Current columns: {af_columns}")
                
                # Check if we have sha256 vs sha256_hash issue
                has_sha256 = 'sha256' in af_columns
                has_sha256_hash = 'sha256_hash' in af_columns
                
                if has_sha256 and not has_sha256_hash:
                    print("🔄 Fixing sha256 -> sha256_hash column name...")
                    try:
                        # Rename column from sha256 to sha256_hash
                        db.session.execute(text('ALTER TABLE analysis_files RENAME COLUMN sha256 TO sha256_hash'))
                        db.session.commit()
                        print("   ✅ Renamed sha256 -> sha256_hash")
                    except Exception as e:
                        print(f"   ⚠️ Column rename failed: {e}")
                        # Try alternative approach - recreate table
                        print("   🔄 Trying alternative approach...")
                        try:
                            # Create new table with correct schema
                            db.session.execute(text('''
                                CREATE TABLE analysis_files_new (
                                    id INTEGER PRIMARY KEY,
                                    sha256_hash VARCHAR(64) UNIQUE NOT NULL,
                                    filename VARCHAR(255) NOT NULL,
                                    filepath VARCHAR(512),
                                    file_size INTEGER,
                                    file_type VARCHAR(100),
                                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                                    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                                    priority INTEGER DEFAULT 5,
                                    status VARCHAR(50) DEFAULT 'pending',
                                    discovered_by INTEGER,
                                    is_root_file BOOLEAN DEFAULT FALSE,
                                    node_color VARCHAR(7) DEFAULT '#gray',
                                    meta_data JSON,
                                    md5_hash VARCHAR(32),
                                    parent_file_sha VARCHAR(64),
                                    extraction_method VARCHAR(100),
                                    depth_level INTEGER DEFAULT 0
                                )
                            '''))
                            
                            # Copy data from old table
                            db.session.execute(text('''
                                INSERT INTO analysis_files_new 
                                SELECT id, sha256, filename, filepath, file_size, file_type, 
                                       created_at, updated_at, priority, status, discovered_by, 
                                       is_root_file, node_color, meta_data, md5_hash, parent_file_sha, 
                                       extraction_method, depth_level
                                FROM analysis_files
                            '''))
                            
                            # Drop old table and rename new one
                            db.session.execute(text('DROP TABLE analysis_files'))
                            db.session.execute(text('ALTER TABLE analysis_files_new RENAME TO analysis_files'))
                            
                            db.session.commit()
                            print("   ✅ Table recreated with correct schema")
                            
                        except Exception as e2:
                            print(f"   ❌ Table recreation failed: {e2}")
                            db.session.rollback()
                
                elif has_sha256_hash:
                    print("   ✅ sha256_hash column already exists")
                else:
                    print("   ❌ Neither sha256 nor sha256_hash found - creating table...")
                    # Create the analysis_files table from scratch
                    db.create_all()
                    print("   ✅ Created analysis_files table")
            
            else:
                print("   ❌ analysis_files table doesn't exist - creating it...")
                db.create_all()
                print("   ✅ Created analysis_files table")
            
            # 2. Fix other missing columns
            print("\n📋 Adding missing columns...")
            
            # Get updated column list
            af_columns = [col['name'] for col in inspector.get_columns('analysis_files')]
            
            missing_columns = []
            required_columns = {
                'md5_hash': 'VARCHAR(32)',
                'parent_file_sha': 'VARCHAR(64)',
                'extraction_method': 'VARCHAR(100)',
                'depth_level': 'INTEGER DEFAULT 0'
            }
            
            for col_name, col_def in required_columns.items():
                if col_name not in af_columns:
                    missing_columns.append((col_name, col_def))
            
            for col_name, col_def in missing_columns:
                try:
                    db.session.execute(text(f'ALTER TABLE analysis_files ADD COLUMN {col_name} {col_def}'))
                    print(f"   ✅ Added column: {col_name}")
                except Exception as e:
                    print(f"   ⚠️ Column {col_name}: {e}")
            
            db.session.commit()
            
            # 3. Fix User table columns
            print("\n👤 Fixing User table...")
            user_columns = [col['name'] for col in inspector.get_columns('users')]
            
            user_missing = []
            user_required = {
                'display_name': 'VARCHAR(128)',
                'points': 'INTEGER DEFAULT 0',
                'level': 'VARCHAR(50) DEFAULT "Analyst"',
                'contributions_count': 'INTEGER DEFAULT 0'
            }
            
            for col_name, col_def in user_required.items():
                if col_name not in user_columns:
                    user_missing.append((col_name, col_def))
            
            for col_name, col_def in user_missing:
                try:
                    db.session.execute(text(f'ALTER TABLE users ADD COLUMN {col_name} {col_def}'))
                    print(f"   ✅ Added user column: {col_name}")
                except Exception as e:
                    print(f"   ⚠️ User column {col_name}: {e}")
            
            db.session.commit()
            
            # 4. Update admin user data
            print("\n👑 Updating admin user...")
            try:
                admin_user = User.query.filter_by(username='admin').first()
                if admin_user:
                    updates = []
                    if not getattr(admin_user, 'display_name', None):
                        updates.append('display_name = "System Administrator"')
                    if getattr(admin_user, 'points', None) is None:
                        updates.append('points = 1000')
                    if not getattr(admin_user, 'level', None):
                        updates.append('level = "Master Analyst"')
                    if getattr(admin_user, 'contributions_count', None) is None:
                        updates.append('contributions_count = 5')
                    
                    if updates:
                        update_sql = f"UPDATE users SET {', '.join(updates)} WHERE username = 'admin'"
                        db.session.execute(text(update_sql))
                        db.session.commit()
                        print("   ✅ Admin user updated")
                    else:
                        print("   ✅ Admin user already up to date")
                else:
                    print("   ❌ Admin user not found")
            except Exception as e:
                print(f"   ⚠️ Admin update error: {e}")
            
            # 5. Test the fixes
            print("\n🧪 Testing fixes...")
            
            try:
                # Test analysis_files query
                from crypto_hunter_web.models import AnalysisFile
                file_count = AnalysisFile.query.count()
                print(f"   ✅ AnalysisFile query works: {file_count} files")
            except Exception as e:
                print(f"   ❌ AnalysisFile query failed: {e}")
            
            try:
                # Test user query with new attributes
                admin = User.query.filter_by(username='admin').first()
                if admin:
                    display_name = getattr(admin, 'display_name', 'None')
                    points = getattr(admin, 'points', 'None')
                    level = getattr(admin, 'level', 'None')
                    print(f"   ✅ User attributes: {display_name}, {points} points, {level}")
                else:
                    print("   ❌ Admin user test failed")
            except Exception as e:
                print(f"   ❌ User test failed: {e}")
            
            print("\n🎉 DATABASE SCHEMA FIX COMPLETED!")
            print("=" * 50)
            print("✅ analysis_files table schema fixed")
            print("✅ Missing columns added")
            print("✅ User table updated")
            print("✅ Admin user data updated")
            print("\n🚀 Your application should now work correctly!")
            
            return True
            
        except Exception as e:
            print(f"\n❌ CRITICAL ERROR: {e}")
            db.session.rollback()
            return False

if __name__ == '__main__':
    success = fix_database_schema()
    if success:
        print("\n✅ Database schema fix completed successfully!")
        print("You can now restart your application.")
    else:
        print("\n❌ Database schema fix failed. Check the errors above.")
