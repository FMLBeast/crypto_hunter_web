#!/usr/bin/env python3
"""
Enhanced LLM Orchestrated Recursive Extraction Script - PostgreSQL Edition (FIXED)

CRITICAL FIX: Fixed SQLAlchemy enum handling and exception scoping issues
- Fixed FileStatus enum comparison issues
- Improved exception handling to prevent variable scoping conflicts
- Added better database state validation
- Enhanced error reporting and debugging

This script now:
1. Sets PostgreSQL URL in environment FIRST
2. Creates Flask app (which picks up the PostgreSQL config)
3. Verifies PostgreSQL connection properly
4. NO SQLite fallback - PostgreSQL only as requested
5. FIXED: Proper enum handling and exception management

Requirements:
- PostgreSQL database (Docker container running)
- psycopg2-binary: pip install psycopg2-binary

Usage:
    python3 test_hybrid_fixed.py --test-db-only   # Test connection first
    python3 test_hybrid_fixed.py --db-host localhost  # For host connection
    python3 test_hybrid_fixed.py --verbose-db     # Debug connection issues
"""

import os
import sys
import time
import logging
import argparse
import hashlib
import json
import base64
import subprocess
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, Any, List, Set, Optional, Union

# Configure logging - CLEAN VERSION (no SQLAlchemy noise)
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler()]
)

# Suppress noisy loggers by default
logging.getLogger('sqlalchemy.engine').setLevel(logging.WARNING)
logging.getLogger('sqlalchemy.pool').setLevel(logging.WARNING)
logging.getLogger('sqlalchemy.dialects').setLevel(logging.WARNING)
logging.getLogger('sqlalchemy.orm').setLevel(logging.WARNING)
logging.getLogger('urllib3').setLevel(logging.WARNING)
logging.getLogger('requests').setLevel(logging.WARNING)

logger = logging.getLogger(__name__)

# Add parent directory to path to allow imports
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# Import Flask app and database models
from crypto_hunter_web import create_app, db
from crypto_hunter_web.models import (
    AnalysisFile, FileContent, Finding, ExtractionRelationship,
    FileNode, GraphEdge, FileStatus, FileDerivation
)
from crypto_hunter_web.services.extractors import get_extractor

try:
    from crypto_hunter_web.services.llm_crypto_orchestrator import LLMCryptoOrchestrator
except ImportError:
    logger.warning("LLMCryptoOrchestrator not available - LLM features will be disabled")
    LLMCryptoOrchestrator = None

# Import SQLAlchemy text for raw SQL queries
from sqlalchemy import text, func
from sqlalchemy.exc import SQLAlchemyError, InvalidRequestError

# Constants
IMAGE_PATH = "../../uploads/image.png"
OUTPUT_DIR = "../../production"
MAX_DEPTH = 10
ADMIN_USER_ID = 1
EXTRACTION_STATE_FILE = "extraction_state.json"


def safe_enum_comparison(status_value: Any) -> Optional[FileStatus]:
    """Safely compare and convert status values to FileStatus enum"""
    if status_value is None:
        return None

    # If it's already a FileStatus enum, return it
    if isinstance(status_value, FileStatus):
        return status_value

    # If it's a string, try to match it to enum values
    if isinstance(status_value, str):
        status_upper = status_value.upper()
        for status in FileStatus:
            if status.name.upper() == status_upper or status.value.upper() == status_upper:
                return status

    # If no match found, return None
    return None


def safe_status_filter(query, status_enum: FileStatus):
    """Safely filter query by status, handling both enum names and values"""
    try:
        # Try filtering by the enum directly first
        return query.filter(AnalysisFile.status == status_enum)
    except (SQLAlchemyError, InvalidRequestError):
        try:
            # If that fails, try by enum value
            return query.filter(AnalysisFile.status == status_enum.value)
        except (SQLAlchemyError, InvalidRequestError):
            try:
                # If that fails, try by enum name
                return query.filter(AnalysisFile.status == status_enum.name)
            except (SQLAlchemyError, InvalidRequestError):
                # If all fail, return the original query (will likely return empty results)
                logger.warning(f"Could not filter by status {status_enum}")
                return query.filter(AnalysisFile.status == "impossible_status_value")


class EnhancedLLMExtractor:
    """Enhanced LLM Orchestrated Recursive Extractor with Advanced Steganography"""

    def __init__(self, resume: bool = False, input_file: str = None, output_dir: str = None):
        self.resume = resume
        self.force_reprocess = False  # Can be set later by main()
        self.input_file = input_file or IMAGE_PATH
        self.output_dir = output_dir or OUTPUT_DIR
        self.processed_files = set()
        self.db_file_records = {}
        self.extraction_state = self._load_extraction_state() if resume else {}

        # CRITICAL: Set database URL in environment BEFORE creating Flask app
        self._set_database_environment()

        # Initialize LLM orchestrator with error handling and warning suppression
        try:
            if LLMCryptoOrchestrator:
                # Suppress the specific Anthropic proxies warning
                import warnings
                old_filters = warnings.filters[:]
                warnings.filterwarnings("ignore", category=UserWarning, message=".*proxies.*")
                warnings.filterwarnings("ignore", category=UserWarning, module="anthropic.*")

                self.llm_orchestrator = LLMCryptoOrchestrator()

                # Restore original warning filters
                warnings.filters[:] = old_filters

                logger.info("✅ LLM orchestrator initialized successfully")
            else:
                self.llm_orchestrator = None
                logger.warning("⚠️  LLM orchestrator not available")
        except Exception as llm_error:
            logger.warning(f"⚠️  LLM orchestrator initialization failed: {llm_error}")
            self.llm_orchestrator = None

        # Create Flask app AFTER setting database environment
        self.app = create_app()

        # AGGRESSIVE PostgreSQL configuration enforcement
        postgresql_url = self._get_database_url()

        # Force set ALL possible database configuration keys
        self.app.config['DATABASE_URL'] = postgresql_url
        self.app.config['SQLALCHEMY_DATABASE_URI'] = postgresql_url
        self.app.config['SQLALCHEMY_BINDS'] = None  # Clear any binds that might use SQLite

        # Disable SQLite-specific configurations
        if 'SQLALCHEMY_ENGINE_OPTIONS' not in self.app.config:
            self.app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {}

        self.app.config['SQLALCHEMY_ENGINE_OPTIONS'].update({
            'pool_timeout': 10,
            'pool_recycle': 3600,
            'pool_pre_ping': True,
            'connect_args': {
                'connect_timeout': 10,
                'application_name': 'crypto_hunter_extractor'
            }
        })

        # Verify the database URL was set correctly
        db_url = self.app.config.get('SQLALCHEMY_DATABASE_URI', 'NOT SET')

        if 'postgresql://' not in db_url:
            logger.error(f"❌ Flask app STILL not using PostgreSQL! Current URL: {db_url}")

            # Nuclear option: force override everything
            self.app.config.update({
                'SQLALCHEMY_DATABASE_URI': postgresql_url,
                'DATABASE_URL': postgresql_url,
            })

            # Clear any cached database engines
            if hasattr(db, 'engine') and db.engine:
                db.engine.dispose()

            logger.info(f"🔧 NUCLEAR OVERRIDE: Forced PostgreSQL")
        else:
            logger.info(f"✅ Flask app using PostgreSQL")

        # Create app context and push it immediately
        self.app_context = self.app.app_context()
        self.app_context.push()
        logger.info("✅ Flask application context activated")

        # Create necessary directories
        os.makedirs(self.output_dir, exist_ok=True)

        # Ensure instance directory exists with proper permissions
        instance_dir = Path(__file__).parent / 'instance'
        instance_dir.mkdir(mode=0o755, exist_ok=True)
        logger.info(f"📁 Instance directory: {instance_dir}")

        # Initialize database with proper error handling
        self._initialize_database()

        # Analyze current database state and prompt user for action (unless in resume mode)
        if not resume:
            self._handle_database_consultation()

    def _set_database_environment(self):
        """Set database environment variables BEFORE Flask app creation"""
        postgresql_url = self._get_database_url()

        # Set in environment so create_app() picks it up
        os.environ['DATABASE_URL'] = postgresql_url

        # CRITICAL: Also set Flask-specific environment variables
        os.environ['FLASK_ENV'] = 'production'  # Prevent dev SQLite override
        os.environ['SQLALCHEMY_DATABASE_URI'] = postgresql_url

        # Also set individual components for any other code that might need them
        if 'postgresql://' in postgresql_url:
            parts = postgresql_url.replace('postgresql://', '').split('@')
            if len(parts) == 2:
                user_pass = parts[0].split(':')
                host_db = parts[1].split('/')

                if len(user_pass) == 2:
                    os.environ['DB_USER'] = user_pass[0]
                    os.environ['DB_PASSWORD'] = user_pass[1]

                if len(host_db) == 2:
                    host_port = host_db[0].split(':')
                    if len(host_port) == 2:
                        os.environ['DB_HOST'] = host_port[0]
                        os.environ['DB_PORT'] = host_port[1]
                    os.environ['DB_NAME'] = host_db[1]

        logger.info(
            f"🐘 PostgreSQL config set: {postgresql_url.split('@')[1] if '@' in postgresql_url else 'configured'}")
        logger.info(f"🐘 Environment: FLASK_ENV=production")

    def _handle_database_consultation(self):
        """Handle database consultation and user interaction"""
        try:
            # Analyze current database state
            logger.info("🔍 Analyzing current database state...")
            stats = self.analyze_database_state()

            # Display current state
            self.display_database_state(stats)

            # If database is empty, continue without prompting
            if stats.get('is_empty', True):
                logger.info("🚀 Starting fresh analysis...")
                return

            # Prompt user for action
            action = self.prompt_user_action(stats)

            if action == 'exit':
                logger.info("👋 Exiting without changes...")
                sys.exit(0)
            elif action == 'show_details':
                self.show_detailed_statistics(stats)
                logger.info("📊 Continuing with existing data...")
            elif action in ['clean_all', 'clean_incomplete']:
                success = self.clean_database_records(action)
                if success:
                    logger.info("🚀 Starting fresh analysis...")
                else:
                    logger.error("❌ Failed to clean database. Exiting...")
                    sys.exit(1)
            elif action == 'continue':
                logger.info("🔄 Continuing with existing data...")
                # Update resume flag to use existing data
                self.resume = True
                self.extraction_state = self._load_extraction_state()
                if 'processed_files' in self.extraction_state:
                    self.processed_files = set(self.extraction_state.get('processed_files', []))
                    logger.info(f"📂 Loaded {len(self.processed_files)} previously processed files")

        except Exception as consultation_error:
            logger.error(f"Error during database consultation: {consultation_error}")
            logger.warning("⚠️  Continuing with default behavior...")

    def _get_database_url(self) -> str:
        """Get PostgreSQL database URL - PostgreSQL only, no SQLite fallback"""
        # Check for explicit DATABASE_URL first
        if os.environ.get('DATABASE_URL'):
            logger.info("🔗 Using DATABASE_URL environment variable")
            return os.environ.get('DATABASE_URL')

        # Get database configuration
        db_password = os.environ.get('DB_PASSWORD', 'secure_password_123')
        db_host = os.environ.get('DB_HOST', 'localhost')
        db_port = os.environ.get('DB_PORT', '5432')
        db_name = os.environ.get('DB_NAME', 'crypto_hunter')
        db_user = os.environ.get('DB_USER', 'crypto_hunter')

        # Build PostgreSQL URL
        postgresql_url = f'postgresql://{db_user}:{db_password}@{db_host}:{db_port}/{db_name}'
        logger.info(f"🐘 PostgreSQL URL: {db_user}@{db_host}:{db_port}/{db_name}")

        return postgresql_url

    def _check_postgresql_requirements(self) -> bool:
        """Check if PostgreSQL requirements are met"""
        try:
            import psycopg2
            logger.info("✅ psycopg2 driver available")
            return True
        except ImportError:
            logger.error("❌ psycopg2 not installed!")
            logger.error("💡 Install with: pip install psycopg2-binary")
            return False

    def _test_postgresql_connection(self, database_url: str) -> bool:
        """Test PostgreSQL connection with detailed diagnostics"""
        try:
            # Extract connection details for logging
            parts = database_url.replace('postgresql://', '').split('@')
            if len(parts) == 2:
                user_pass = parts[0]
                host_db = parts[1]
                host_port = host_db.split('/')[0]
                logger.info(f"🔌 Testing connection to: {host_port}")

            # Create a temporary app to test connection
            test_app = create_app()
            test_app.config['SQLALCHEMY_DATABASE_URI'] = database_url
            test_app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
                'pool_timeout': 5,
                'pool_recycle': 300,
                'connect_args': {
                    'connect_timeout': 5
                }
            }

            with test_app.app_context():
                db.session.execute(text('SELECT version()'))
                result = db.session.execute(text('SELECT version()')).scalar()
                logger.info(f"✅ PostgreSQL connection successful: {result.split(',')[0] if result else 'Connected'}")
                return True

        except Exception as connection_error:
            logger.debug(f"❌ Connection test failed: {connection_error}")
            return False

    def _initialize_database(self):
        """Initialize PostgreSQL database connection - simplified and robust"""
        logger.info("🐘 Initializing PostgreSQL database...")

        # Check PostgreSQL requirements first
        if not self._check_postgresql_requirements():
            raise RuntimeError("PostgreSQL driver (psycopg2) is required but not installed")

        # Verify we're in Flask app context
        try:
            from flask import current_app
        except RuntimeError as context_error:
            logger.error(f"❌ Flask application context error: {context_error}")
            raise RuntimeError("Flask application context not properly set up")

        # Get current database URL from Flask config
        current_url = self.app.config.get('SQLALCHEMY_DATABASE_URI', 'NOT SET')

        # If it's not PostgreSQL, something went wrong
        if 'postgresql://' not in current_url:
            logger.error(f"❌ Flask app using wrong database: {current_url}")
            postgresql_url = self._get_database_url()

            # Force update Flask config
            self.app.config['SQLALCHEMY_DATABASE_URI'] = postgresql_url
            self.app.config['DATABASE_URL'] = postgresql_url

            # Clear SQLAlchemy engine cache to force reconnection
            if hasattr(db, 'engine') and db.engine:
                db.engine.dispose()

            logger.info(f"🔧 Force-updated to PostgreSQL")
            current_url = postgresql_url

        # Extract connection details for diagnostics
        if 'postgresql://' in current_url:
            # Parse connection details from URL
            parts = current_url.replace('postgresql://', '').split('@')
            if len(parts) == 2:
                user_pass = parts[0].split(':')
                host_db = parts[1].split('/')
                if len(user_pass) >= 1 and len(host_db) >= 1:
                    db_user = user_pass[0]
                    host_port = host_db[0]
                    db_name = host_db[1] if len(host_db) > 1 else 'unknown'
                    logger.info(f"🔌 Connecting to: {db_user}@{host_port}/{db_name}")

        # Simple connection test within app context
        try:
            # Try a simple query
            with self.app.app_context():
                result = db.session.execute(text('SELECT version()'))
                version_info = result.scalar()

                logger.info(f"✅ PostgreSQL connected!")
                if version_info:
                    version_short = version_info.split(',')[0] if ',' in version_info else version_info[:50]
                    logger.info(f"📊 Database version: {version_short}")

                # Test basic table operations
                db.create_all()
                logger.info("✅ Database tables verified/created")
                logger.info("🎯 Database initialization completed")
                return

        except Exception as db_error:
            logger.error(f"❌ PostgreSQL connection failed: {db_error}")

            # If we got a SQLite error while trying PostgreSQL, that's the config issue
            if 'sqlite' in str(db_error).lower():
                logger.error("💥 CRITICAL: Getting SQLite error while trying PostgreSQL!")
                logger.error("🔧 Flask app is still configured for SQLite")
                raise RuntimeError("Flask app configuration error: SQLite being used instead of PostgreSQL")

        # If primary connection failed, try alternative hosts
        logger.info("🔄 Trying alternative PostgreSQL hosts...")

        # Extract current host from URL for alternative attempts
        original_host = 'localhost'
        if 'postgresql://' in current_url:
            try:
                parts = current_url.split('@')[1].split(':')[0]
                original_host = parts
            except:
                pass

        # Try different hosts
        alternative_hosts = ['db', '127.0.0.1', 'localhost', 'host.docker.internal']
        if original_host in alternative_hosts:
            alternative_hosts.remove(original_host)  # Don't try the same host twice

        db_user = os.environ.get('DB_USER', 'crypto_hunter')
        db_password = os.environ.get('DB_PASSWORD', 'secure_password_123')
        db_name = os.environ.get('DB_NAME', 'crypto_hunter')

        for alt_host in alternative_hosts:
            logger.info(f"🔄 Trying {alt_host}:5432...")

            # Build alternative URL
            alt_url = f'postgresql://{db_user}:{db_password}@{alt_host}:5432/{db_name}'

            # Update Flask config
            self.app.config['SQLALCHEMY_DATABASE_URI'] = alt_url
            self.app.config['DATABASE_URL'] = alt_url

            # Clear engine cache
            if hasattr(db, 'engine') and db.engine:
                db.engine.dispose()

            try:
                # Test connection with new host
                with self.app.app_context():
                    result = db.session.execute(text('SELECT version()'))
                    version_info = result.scalar()

                    logger.info(f"✅ Connected to PostgreSQL at {alt_host}:5432")
                    if version_info:
                        version_short = version_info.split(',')[0] if ',' in version_info else version_info[:50]
                        logger.info(f"📊 Database version: {version_short}")

                    # Update environment for consistency
                    os.environ['DATABASE_URL'] = alt_url
                    os.environ['DB_HOST'] = alt_host

                    # Ensure tables exist
                    db.create_all()
                    logger.info("✅ Database tables verified/created")
                    logger.info("🎯 Database initialization completed")
                    return

            except Exception as alt_error:
                logger.debug(f"❌ {alt_host} failed: {alt_error}")
                continue

        # All attempts failed
        logger.error("❌ All PostgreSQL connection attempts failed!")
        logger.error("🔧 TROUBLESHOOTING:")
        logger.error("1. Check container: docker ps | grep postgres")
        logger.error("2. Test connection: docker exec -it crypto-hunter-db psql -U crypto_hunter -d crypto_hunter")
        logger.error("3. Check logs: docker logs crypto-hunter-db")
        logger.error("4. Verify port: telnet localhost 5432")

        raise RuntimeError("Could not establish PostgreSQL connection with any host configuration")

    def __del__(self):
        """Clean up resources"""
        try:
            if hasattr(self, 'app_context') and self.app_context:
                self.app_context.pop()
        except Exception:
            # Ignore cleanup errors
            pass

    def _load_extraction_state(self) -> Dict[str, Any]:
        """Load extraction state from file and database for resume capability"""
        state = {}

        # Load from state file
        if os.path.exists(EXTRACTION_STATE_FILE):
            try:
                with open(EXTRACTION_STATE_FILE, 'r') as f:
                    state = json.load(f)
                logger.info(
                    f"📂 Loaded extraction state file with {len(state.get('processed_files', []))} processed files")
            except Exception as state_error:
                logger.error(f"Failed to load extraction state file: {state_error}")

        # Also load processed files from database (for cross-session resume)
        try:
            # Create temporary app context to query database
            temp_app = create_app()
            with temp_app.app_context():
                processed_files_from_db = set()

                # Get all files that have been fully analyzed (by content hash)
                analyzed_files = AnalysisFile.query.filter(
                    AnalysisFile.status.in_([FileStatus.ANALYZED, FileStatus.COMPLETE])
                ).all()

                for file_record in analyzed_files:
                    # Add primary hash
                    processed_files_from_db.add(file_record.sha256_hash)

                    # Also add MD5 and SHA1 if available for cross-hash duplicate detection
                    if file_record.md5_hash:
                        processed_files_from_db.add(f"md5:{file_record.md5_hash}")
                    if file_record.sha1_hash:
                        processed_files_from_db.add(f"sha1:{file_record.sha1_hash}")

                logger.info(f"🗄️  Loaded {len(analyzed_files)} analyzed files from database")
                logger.info(f"🔑 Total content hashes for duplicate detection: {len(processed_files_from_db)}")

                # Merge with state file data
                state_processed = set(state.get('processed_files', []))
                all_processed = state_processed.union(processed_files_from_db)
                state['processed_files'] = list(all_processed)

                # Add content duplicate statistics
                duplicate_refs = FileContent.query.filter_by(
                    content_type='duplicate_reference'
                ).count()

                state['duplicate_references'] = duplicate_refs
                logger.info(f"📊 Total processed files for resume: {len(all_processed)}")
                logger.info(f"🎯 Previously detected duplicates: {duplicate_refs}")

        except Exception as db_load_error:
            logger.warning(f"Could not load processed files from database: {db_load_error}")

        return state

    def _save_extraction_state(self):
        """Save extraction state to file for resume capability"""
        state = {
            'processed_files': list(self.processed_files),
            'timestamp': datetime.utcnow().isoformat(),
            'last_file_id': max([0] + [r.id for r in self.db_file_records.values()]) if self.db_file_records else 0
        }

        try:
            with open(EXTRACTION_STATE_FILE, 'w') as f:
                json.dump(state, f, indent=2)
            logger.info(f"Saved extraction state with {len(state['processed_files'])} processed files")
        except Exception as save_error:
            logger.error(f"Failed to save extraction state: {save_error}")

    def serialize_for_json(self, obj):
        """Convert objects to JSON-serializable format"""
        if isinstance(obj, bytes):
            return base64.b64encode(obj).decode('ascii')
        elif isinstance(obj, dict):
            return {k: self.serialize_for_json(v) for k, v in obj.items()}
        elif isinstance(obj, list):
            return [self.serialize_for_json(item) for item in obj]
        elif isinstance(obj, (int, float, str, bool, type(None))):
            return obj
        else:
            return str(obj)

    def run(self):
        """Run the enhanced LLM orchestrated recursive extraction"""
        logger.info("Starting enhanced LLM orchestrated recursive extraction")

        # Check if input file exists, create a test file if not
        if not os.path.exists(self.input_file):
            logger.warning(f"Image file not found at {self.input_file}")
            self._create_test_image()

        # Initialize from resume state if needed
        if self.resume and 'processed_files' in self.extraction_state:
            self.processed_files = set(self.extraction_state.get('processed_files', []))
            logger.info(f"Resuming extraction with {len(self.processed_files)} previously processed files")

        # Process the initial file
        root_file_record = self.process_file(self.input_file, self.output_dir, 0)

        if root_file_record:
            self.create_file_node(root_file_record, node_type='root', graph_level=0)
            logger.info(f"Created root node for {root_file_record.filename}")

        logger.info("Enhanced LLM orchestrated recursive extraction completed")
        self.print_summary()

    def _create_test_image(self):
        """Create a test PNG image if the input file doesn't exist"""
        try:
            # Create uploads directory
            upload_dir = Path(self.input_file).parent
            upload_dir.mkdir(exist_ok=True)

            # Create a simple PNG file for testing
            import struct

            # Minimal PNG file structure
            png_header = b'\x89PNG\r\n\x1a\n'

            # IHDR chunk (width=100, height=100, bit_depth=8, color_type=2 (RGB))
            width, height = 100, 100
            ihdr_data = struct.pack('>IIBBBBB', width, height, 8, 2, 0, 0, 0)
            ihdr_crc = self._crc32(b'IHDR' + ihdr_data)
            ihdr_chunk = struct.pack('>I', len(ihdr_data)) + b'IHDR' + ihdr_data + struct.pack('>I', ihdr_crc)

            # Simple IDAT chunk with minimal data (red pixel)
            idat_data = b'\x78\x9c\x01\x01\x00\xfe\xff\xff\x00\x00\x00\x00\x00\x02\x00\x01'
            idat_crc = self._crc32(b'IDAT' + idat_data)
            idat_chunk = struct.pack('>I', len(idat_data)) + b'IDAT' + idat_data + struct.pack('>I', idat_crc)

            # IEND chunk
            iend_crc = self._crc32(b'IEND')
            iend_chunk = struct.pack('>I', 0) + b'IEND' + struct.pack('>I', iend_crc)

            # Write PNG file
            with open(self.input_file, 'wb') as f:
                f.write(png_header + ihdr_chunk + idat_chunk + iend_chunk)

            logger.info(f"Created test PNG image at {self.input_file}")

        except Exception as create_error:
            logger.error(f"Failed to create test image: {create_error}")
            # Create a simple text file as fallback
            with open(self.input_file, 'w') as f:
                f.write("This is a test file for crypto hunter extraction testing.\n")
                f.write("Base64 test: SGVsbG8gV29ybGQ=\n")  # "Hello World" in base64
                f.write("Hex test: 48656c6c6f20576f726c64\n")  # "Hello World" in hex
            logger.info(f"Created test text file at {self.input_file}")

    def _log_processing_stats(self):
        """Log periodic processing statistics"""
        try:
            processed_count = len(self.processed_files)
            db_file_count = db.session.query(AnalysisFile).count()
            duplicate_refs = db.session.query(FileContent).filter_by(
                content_type='duplicate_reference'
            ).count()

            logger.info("📊 PROCESSING CHECKPOINT:")
            logger.info(
                f"   🔄 Processed: {processed_count} | 🗄️ Database: {db_file_count} | 🎯 Duplicates: {duplicate_refs}")

            if db_file_count > processed_count:
                efficiency = ((db_file_count - processed_count) / db_file_count) * 100
                logger.info(f"   ⚡ Efficiency: {efficiency:.1f}% duplicates avoided")

        except Exception as stats_error:
            logger.debug(f"Error logging processing stats: {stats_error}")

    def analyze_content_duplicates(self, show_details: bool = False):
        """Analyze and report on content duplicates in the database"""
        try:
            logger.info("🔍 CONTENT DUPLICATE ANALYSIS:")

            # Find files with identical SHA256 hashes
            sha256_duplicates = db.session.query(
                AnalysisFile.sha256_hash,
                func.count(AnalysisFile.id).label('count')
            ).group_by(AnalysisFile.sha256_hash).having(
                func.count(AnalysisFile.id) > 1
            ).all()

            # Find files with identical MD5 hashes
            md5_duplicates = db.session.query(
                AnalysisFile.md5_hash,
                func.count(AnalysisFile.id).label('count')
            ).filter(AnalysisFile.md5_hash.isnot(None)).group_by(
                AnalysisFile.md5_hash
            ).having(func.count(AnalysisFile.id) > 1).all()

            logger.info(f"   🔑 SHA256 duplicate groups: {len(sha256_duplicates)}")
            logger.info(f"   🔑 MD5 duplicate groups: {len(md5_duplicates)}")

            if show_details and sha256_duplicates:
                logger.info("   📋 SHA256 duplicate details:")
                for hash_val, count in sha256_duplicates[:5]:  # Show first 5
                    files = AnalysisFile.query.filter_by(sha256_hash=hash_val).all()
                    logger.info(f"      🔑 {hash_val[:16]}... ({count} files):")
                    for file_record in files:
                        logger.info(f"         - {file_record.filename} (ID: {file_record.id})")

            # Count duplicate references
            duplicate_refs = db.session.query(FileContent).filter_by(
                content_type='duplicate_reference'
            ).count()

            logger.info(f"   📝 Duplicate references: {duplicate_refs}")

            return {
                'sha256_duplicate_groups': len(sha256_duplicates),
                'md5_duplicate_groups': len(md5_duplicates),
                'duplicate_references': duplicate_refs
            }

        except Exception as dup_error:
            logger.error(f"Error analyzing content duplicates: {dup_error}")
            return {}

    def _crc32(self, data):
        """Simple CRC32 calculation for PNG"""
        import zlib
        return zlib.crc32(data) & 0xffffffff

    def process_file(self, file_path: str, output_dir: str, depth: int) -> Optional[AnalysisFile]:
        """Process a file with enhanced LLM orchestration and comprehensive duplicate detection"""
        if depth > MAX_DEPTH:
            logger.warning(f"Maximum recursion depth reached for {file_path}")
            return None

        # Calculate content hashes for comprehensive duplicate detection
        content_hashes = self.calculate_comprehensive_hashes(file_path)
        primary_hash = content_hashes['sha256']

        # Check if file has already been processed in current session
        if primary_hash in self.processed_files and not self.force_reprocess:
            logger.info(f"⏭️  Skipping already processed file (session): {os.path.basename(file_path)}")
            return self.db_file_records.get(primary_hash)

        # Check for content duplicates in database (multiple hash algorithms + fingerprinting)
        if not self.force_reprocess:
            duplicate_record = self.check_content_duplicates(file_path)
            if duplicate_record:
                logger.info(f"⏭️  Skipping content duplicate: {os.path.basename(file_path)}")
                logger.info(f"   → References existing: {duplicate_record.filename} (ID: {duplicate_record.id})")

                # Create a reference/alias record for this path but don't process
                self.create_duplicate_reference(file_path, duplicate_record, content_hashes)

                self.processed_files.add(primary_hash)
                self.db_file_records[primary_hash] = duplicate_record
                return duplicate_record
        else:
            logger.info(f"🔄 Force reprocessing enabled for: {os.path.basename(file_path)}")

        # File is unique content - proceed with processing
        file_record = self.get_or_create_file_record(file_path, content_hashes)
        if not file_record:
            logger.error(f"Failed to create file record for {file_path}")
            return None

        self.processed_files.add(primary_hash)

        if len(self.processed_files) % 10 == 0:
            self._save_extraction_state()
            self._log_processing_stats()

        file_output_dir = os.path.join(output_dir, f"{file_record.id}_{os.path.basename(file_path)}")
        os.makedirs(file_output_dir, exist_ok=True)

        logger.info(f"🔄 Processing unique content: {os.path.basename(file_path)} (depth: {depth})")
        logger.info(f"   📁 Output dir: {file_output_dir}")
        logger.info(f"   🔑 Content hashes - SHA256: {primary_hash[:16]}..., MD5: {content_hashes['md5'][:16]}...")

        # Get LLM analysis and extraction strategy
        extraction_strategy = self.get_llm_extraction_strategy(file_record, file_path)

        # Apply LLM-recommended methods
        for method in extraction_strategy['methods']:
            extracted_files = self.extract_with_method(file_record, file_path, method, file_output_dir, depth)

            for extracted_file in extracted_files:
                child_record = self.process_file(extracted_file, output_dir, depth + 1)
                if child_record and file_record:
                    self.create_file_relationship(file_record, child_record, method)

        # Apply advanced steganography if LLM recommends it
        if extraction_strategy.get('apply_advanced_steganography', False):
            logger.info("🧬 LLM recommends advanced steganographic analysis")
            advanced_files = self.run_advanced_steganography(file_record, file_path, file_output_dir, depth)

            for extracted_file in advanced_files:
                child_record = self.process_file(extracted_file, output_dir, depth + 1)
                if child_record and file_record:
                    self.create_file_relationship(file_record, child_record, 'advanced_steganography')

        # Mark file as analyzed
        if file_record:
            file_record.status = FileStatus.ANALYZED
            file_record.analyzed_at = datetime.utcnow()
            db.session.commit()

        return file_record

    def get_llm_extraction_strategy(self, file_record: AnalysisFile, file_path: str) -> Dict[str, Any]:
        """Get LLM-powered extraction strategy"""
        try:
            # Read file preview for LLM analysis
            with open(file_path, 'rb') as f:
                content = f.read(8192)
                content_preview = content.decode('utf-8', errors='ignore')

            # Get file type and basic analysis
            file_type = file_record.file_type.lower() if file_record.file_type else ""
            file_size = os.path.getsize(file_path)

            # Use LLM to analyze file and determine strategy (if available)
            if self.llm_orchestrator:
                llm_results = self.llm_orchestrator.analyze_file_with_llm(
                    file_record.id,
                    content_preview,
                    {'file_type': file_type, 'file_size': file_size}
                )

                # Store LLM analysis
                self.store_llm_results(file_record.id, llm_results)

                # Determine extraction methods based on LLM analysis
                methods = self.extract_methods_from_llm_results(llm_results, file_type)

                # Determine if advanced steganography is needed
                apply_advanced = self.should_apply_advanced_steganography(llm_results, file_type, file_size)

                strategy = {
                    'methods': methods,
                    'apply_advanced_steganography': apply_advanced,
                    'llm_confidence': llm_results.get('confidence', 0.5),
                    'analysis_results': llm_results
                }

                logger.info(f"LLM extraction strategy: {len(methods)} methods, advanced={apply_advanced}")
                return strategy
            else:
                logger.warning("LLM orchestrator not available, using default strategy")
                return self.get_default_extraction_strategy(file_record, file_path)

        except Exception as llm_strategy_error:
            logger.error(f"LLM extraction strategy failed: {llm_strategy_error}")
            # Fallback to default methods
            return self.get_default_extraction_strategy(file_record, file_path)

    def extract_methods_from_llm_results(self, llm_results: Dict, file_type: str) -> List[str]:
        """Extract recommended methods from LLM analysis"""
        methods = []

        # Parse LLM recommendations
        for result in llm_results.get('analysis_results', []):
            for rec in result.get('recommendations', []):
                rec_lower = rec.lower()
                for method in ["zsteg", "binwalk", "strings", "exiftool", "steghide",
                               "base64", "hex", "xor", "aes", "unzip", "hexdump"]:
                    if method in rec_lower and method not in methods:
                        methods.append(method)

        # Add defaults based on file type if no LLM methods found
        if not methods:
            if "png" in file_type or "image" in file_type:
                methods = ["zsteg", "binwalk", "strings"]
            elif "text" in file_type:
                methods = ["base64", "hex", "strings"]
            else:
                methods = ["binwalk", "strings"]

        return methods

    def should_apply_advanced_steganography(self, llm_results: Dict, file_type: str, file_size: int) -> bool:
        """Determine if advanced steganographic analysis should be applied"""
        # Apply advanced analysis if:
        # 1. LLM indicates high steganography potential
        # 2. File is an image with suspicious characteristics
        # 3. File size suggests hidden content

        llm_confidence = llm_results.get('confidence', 0.0)

        # Check LLM recommendations for steganography keywords
        stego_keywords = ['steganography', 'hidden', 'embedded', 'lsb', 'bitplane']
        llm_suggests_stego = any(
            any(keyword in rec.lower() for keyword in stego_keywords)
            for result in llm_results.get('analysis_results', [])
            for rec in result.get('recommendations', [])
        )

        # Image files with high confidence or suspicious size
        is_suspicious_image = (
                ("image" in file_type or "png" in file_type) and
                (llm_confidence > 0.7 or file_size > 1000000)  # Large images
        )

        return llm_suggests_stego or is_suspicious_image or llm_confidence > 0.8

    def run_advanced_steganography(self, file_record: AnalysisFile, file_path: str,
                                   output_dir: str, depth: int) -> List[str]:
        """Run advanced mathematical steganographic analysis"""
        logger.info("🧬 Running advanced mathematical steganographic analysis")

        stego_dir = Path(output_dir) / "advanced_steganography"
        stego_dir.mkdir(parents=True, exist_ok=True)

        extracted_files = []

        # Mathematical patterns for steganography
        fibonacci_sequence = [1, 2, 3, 5, 8]
        prime_numbers = [2, 3, 5, 7, 11]
        traversals = ['xy', 'yx']
        channels = ['rgb', 'r', 'g', 'b']
        operations = ['lsb', 'msb']

        commands = []

        # Build comprehensive command list
        for fib in fibonacci_sequence:
            for channel in channels:
                for operation in operations:
                    for traversal in traversals:
                        cmd = ['zsteg', '-E', f'b{fib},{channel},{operation},{traversal}', str(file_path)]
                        commands.append((cmd, f'fibonacci_{fib}_{channel}_{operation}_{traversal}'))

        for prime in prime_numbers:
            for channel in ['rgb', 'r', 'g', 'b']:
                for traversal in ['xy', 'yx']:
                    cmd = ['zsteg', '-E', f'b{prime},{channel},lsb,{traversal}', str(file_path)]
                    commands.append((cmd, f'prime_{prime}_{channel}_{traversal}'))

        logger.info(f"🚀 Running {len(commands)} advanced steganographic commands")

        # Execute commands
        for i, (cmd, method_name) in enumerate(commands):
            try:
                logger.info(f"[{i + 1}/{len(commands)}] {method_name}")

                result = subprocess.run(cmd, capture_output=True, timeout=60)

                if result.returncode == 0 and result.stdout:
                    # Save extracted data
                    output_file = stego_dir / f"stego_{i:03d}_{method_name}.bin"
                    with open(output_file, 'wb') as f:
                        f.write(result.stdout)

                    if len(result.stdout) > 50:  # Significant data found
                        extracted_files.append(str(output_file))

                        # Store in database
                        self.store_advanced_stego_result(
                            file_record, result.stdout, method_name, cmd
                        )

                        logger.info(f"✅ {method_name}: {len(result.stdout)} bytes extracted")

            except subprocess.TimeoutExpired:
                logger.warning(f"⏰ {method_name}: Timeout")
            except Exception as stego_error:
                logger.error(f"💥 {method_name}: Error - {stego_error}")

        logger.info(f"🎯 Advanced steganography completed: {len(extracted_files)} extractions")
        return extracted_files

    def store_advanced_stego_result(self, file_record: AnalysisFile, data: bytes,
                                    method_name: str, command: List[str]):
        """Store advanced steganography results in database"""
        try:
            # Store as FileContent
            content = FileContent(
                file_id=file_record.id,
                content_type='advanced_steganography',
                content_format='binary',
                extraction_method='advanced_zsteg',
                content_bytes=data,
                content_size=len(data),
                extraction_extra_data=self.serialize_for_json({
                    'method_name': method_name,
                    'command': ' '.join(command),
                    'data_size': len(data)
                })
            )

            db.session.add(content)

            # Create Finding
            finding = Finding(
                file_id=file_record.id,
                finding_type='advanced_steganography',
                category='steganography',
                confidence_level=8,
                severity='high',
                status='unverified',
                title=f"Advanced steganography: {method_name}",
                description=f"Mathematical steganography detected: {len(data)} bytes extracted using {method_name}",
                evidence_data=self.serialize_for_json({
                    'method': method_name,
                    'command': ' '.join(command),
                    'data_size': len(data)
                }),
                created_by=ADMIN_USER_ID
            )

            db.session.add(finding)
            db.session.commit()

            logger.info(f"💾 Stored advanced steganography result: {method_name}")

        except Exception as store_error:
            logger.error(f"Failed to store advanced stego result: {store_error}")
            db.session.rollback()

    def get_default_extraction_strategy(self, file_record: AnalysisFile, file_path: str) -> Dict[str, Any]:
        """Get default extraction strategy when LLM fails"""
        file_type = file_record.file_type.lower() if file_record.file_type else ""

        if "png" in file_type or "image" in file_type:
            methods = ["zsteg", "binwalk", "strings"]
            apply_advanced = True  # Always apply advanced to images by default
        elif "text" in file_type:
            methods = ["base64", "hex", "strings"]
            apply_advanced = False
        else:
            methods = ["binwalk", "strings"]
            apply_advanced = False

        return {
            'methods': methods,
            'apply_advanced_steganography': apply_advanced,
            'llm_confidence': 0.5,
            'analysis_results': {}
        }

    def extract_with_method(self, file_record: AnalysisFile, file_path: str,
                            method: str, output_dir: str, depth: int) -> List[str]:
        """Extract content using a specific method with LLM optimization"""
        logger.info(f"Extracting from {os.path.basename(file_path)} using {method}")

        extracted_files = []

        try:
            extractor = get_extractor(method)
            if not extractor:
                logger.warning(f"Extractor not found for method: {method}")
                return extracted_files

            # Read file preview for LLM optimization
            try:
                with open(file_path, 'rb') as f:
                    content = f.read(8192)
                    content_preview = content.decode('utf-8', errors='ignore')
            except:
                content_preview = ""

            parameters = {}

            # Use LLM to optimize extraction parameters (if available)
            if content_preview and self.llm_orchestrator:
                try:
                    llm_result = self.llm_orchestrator.extract_with_llm(
                        file_record.id,
                        content_preview,
                        method,
                        parameters
                    )

                    if llm_result.get('success') and llm_result.get('optimized_parameters'):
                        parameters = llm_result.get('optimized_parameters', {})
                        logger.info(f"Using LLM-optimized parameters for {method}: {parameters}")
                except Exception as llm_extract_error:
                    logger.error(f"LLM parameter optimization failed: {llm_extract_error}")

            # Perform extraction
            result = extractor.extract(file_path, parameters)

            if result.get('success'):
                if result.get('data'):
                    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                    output_filename = f"{method}_{timestamp}_{os.path.basename(file_path)}.bin"
                    output_path = os.path.join(output_dir, output_filename)

                    with open(output_path, 'wb') as f:
                        f.write(result['data'])

                    logger.info(f"Extracted data saved to {output_path}")
                    extracted_files.append(output_path)

                    self.create_extraction_relationship(
                        file_record,
                        output_path,
                        method,
                        result.get('command_line', ''),
                        depth
                    )

                if result.get('extracted_files'):
                    for ext_file in result.get('extracted_files', []):
                        if os.path.exists(ext_file):
                            logger.info(f"Found extracted file: {ext_file}")
                            extracted_files.append(ext_file)

                            self.create_extraction_relationship(
                                file_record,
                                ext_file,
                                method,
                                result.get('command_line', ''),
                                depth
                            )
            else:
                logger.warning(f"Extraction failed with {method}: {result.get('error', 'Unknown error')}")

        except Exception as extract_error:
            logger.error(f"Error during extraction with {method}: {extract_error}")

        return extracted_files

    def check_content_duplicates(self, file_path: str) -> Optional[AnalysisFile]:
        """Check for duplicate content using multiple hashing algorithms and content analysis"""
        try:
            # Calculate comprehensive content hashes
            content_hashes = self.calculate_comprehensive_hashes(file_path)

            # Check for exact content matches using multiple hash algorithms
            duplicate_checks = [
                ('sha256_hash', content_hashes['sha256'], 'SHA256'),
                ('md5_hash', content_hashes['md5'], 'MD5'),
                ('sha1_hash', content_hashes['sha1'], 'SHA1')
            ]

            for field_name, hash_value, hash_type in duplicate_checks:
                if hash_value and hash_value != 'unknown':
                    duplicate_file = AnalysisFile.query.filter(
                        getattr(AnalysisFile, field_name) == hash_value
                    ).first()

                    if duplicate_file:
                        # Verify it's actually been processed using safe enum comparison
                        file_status = safe_enum_comparison(duplicate_file.status)
                        if file_status in [FileStatus.ANALYZED, FileStatus.COMPLETE]:
                            logger.info(
                                f"🎯 DUPLICATE detected via {hash_type}: {os.path.basename(file_path)} → {duplicate_file.filename}")
                            return duplicate_file

            # Check for near-duplicate content using size + fingerprint
            if content_hashes['file_size'] > 0:
                similar_files = AnalysisFile.query.filter(
                    AnalysisFile.file_size == content_hashes['file_size']
                ).all()

                for similar_file in similar_files:
                    file_status = safe_enum_comparison(similar_file.status)
                    if file_status in [FileStatus.ANALYZED, FileStatus.COMPLETE]:
                        # Check if we can get the content fingerprint from extra data
                        if hasattr(similar_file, 'analysis_extra_data') and similar_file.analysis_extra_data:
                            stored_fingerprint = similar_file.analysis_extra_data.get('content_fingerprint')
                            if stored_fingerprint == content_hashes['content_fingerprint']:
                                logger.info(f"🎯 CONTENT DUPLICATE detected via fingerprint!")
                                logger.info(f"   Original: {similar_file.filename} (ID: {similar_file.id})")
                                logger.info(f"   Duplicate: {os.path.basename(file_path)}")
                                logger.info(f"   Size: {content_hashes['file_size']} bytes")
                                return similar_file

            logger.debug(f"✅ No content duplicates found for {os.path.basename(file_path)}")
            return None

        except Exception as dup_check_error:
            logger.error(f"Error checking content duplicates: {dup_check_error}")
            return None

    def calculate_comprehensive_hashes(self, file_path: str) -> Dict[str, str]:
        """Calculate multiple content hashes for comprehensive duplicate detection"""
        try:
            hashes = {
                'sha256': hashlib.sha256(),
                'md5': hashlib.md5(),
                'sha1': hashlib.sha1()
            }

            file_size = 0
            with open(file_path, "rb") as f:
                while True:
                    chunk = f.read(8192)
                    if not chunk:
                        break
                    file_size += len(chunk)
                    for hash_obj in hashes.values():
                        hash_obj.update(chunk)

            result = {
                'sha256': hashes['sha256'].hexdigest(),
                'md5': hashes['md5'].hexdigest(),
                'sha1': hashes['sha1'].hexdigest(),
                'file_size': file_size
            }

            # Add content fingerprint (first 1KB + last 1KB + size)
            try:
                with open(file_path, "rb") as f:
                    header = f.read(1024)
                    f.seek(-min(1024, file_size), 2) if file_size > 1024 else f.seek(0)
                    footer = f.read(1024) if file_size > 1024 else b""

                fingerprint_data = header + footer + str(file_size).encode()
                result['content_fingerprint'] = hashlib.sha256(fingerprint_data).hexdigest()[:16]
            except:
                result['content_fingerprint'] = 'unknown'

            return result

        except Exception as hash_error:
            logger.error(f"Failed to calculate hashes for {file_path}: {hash_error}")
            return {
                'sha256': f"error_{int(time.time())}",
                'md5': 'unknown',
                'sha1': 'unknown',
                'file_size': 0,
                'content_fingerprint': 'error'
            }

    def calculate_file_hash(self, file_path: str) -> str:
        """Calculate primary SHA-256 hash (for backward compatibility)"""
        hashes = self.calculate_comprehensive_hashes(file_path)
        return hashes['sha256']

    def create_duplicate_reference(self, file_path: str, original_record: AnalysisFile, content_hashes: Dict[str, str]):
        """Create a reference record for a duplicate file without processing it"""
        try:
            # Create a lightweight record that references the original
            duplicate_ref = {
                'original_file_id': original_record.id,
                'original_sha256': original_record.sha256_hash,
                'duplicate_path': file_path,
                'duplicate_filename': os.path.basename(file_path),
                'content_hashes': content_hashes,
                'detected_at': datetime.utcnow().isoformat(),
                'detection_method': 'content_hash_duplicate'
            }

            # Store as FileContent record for tracking
            content_record = FileContent(
                file_id=original_record.id,
                content_type='duplicate_reference',
                content_format='text',
                extraction_method='content_duplicate_detection',
                content_text=json.dumps(duplicate_ref, indent=2),
                content_size=len(json.dumps(duplicate_ref)),
                extraction_extra_data=self.serialize_for_json({
                    'duplicate_path': file_path,
                    'detection_method': 'comprehensive_content_hashing',
                    'content_fingerprint': content_hashes.get('content_fingerprint'),
                    'file_size': content_hashes.get('file_size')
                })
            )

            db.session.add(content_record)
            db.session.commit()

            logger.info(f"📝 Created duplicate reference: {os.path.basename(file_path)} → {original_record.filename}")

        except Exception as dup_ref_error:
            logger.error(f"Failed to create duplicate reference: {dup_ref_error}")
            db.session.rollback()

    def get_or_create_file_record(self, file_path: str, content_hashes: Dict[str, str] = None) -> Optional[
        AnalysisFile]:
        """Get or create a file record with comprehensive content hashing"""
        try:
            if content_hashes is None:
                content_hashes = self.calculate_comprehensive_hashes(file_path)

            file_hash = content_hashes['sha256']

            # Check if we already have this file in our cache
            if file_hash in self.db_file_records:
                return self.db_file_records[file_hash]

            # Check if file exists in database
            file_record = AnalysisFile.query.filter_by(sha256_hash=file_hash).first()

            if not file_record:
                # Create new file record with comprehensive hashing
                filename = os.path.basename(file_path)
                file_type = self.identify_file_type(file_path)

                file_record = AnalysisFile(
                    filename=filename,
                    filepath=file_path,
                    file_size=content_hashes['file_size'],
                    file_type=file_type,
                    mime_type=file_type,
                    sha256_hash=content_hashes['sha256'],
                    md5_hash=content_hashes['md5'],
                    sha1_hash=content_hashes['sha1'],
                    status=FileStatus.PROCESSING,
                    is_root_file=(file_path == self.input_file),
                    created_by=ADMIN_USER_ID,
                    created_at=datetime.utcnow(),
                    analysis_extra_data=self.serialize_for_json({
                        'content_fingerprint': content_hashes['content_fingerprint'],
                        'file_size_verified': content_hashes['file_size'],
                        'content_hashes': content_hashes,
                        'duplicate_detection_enabled': True
                    })
                )
                db.session.add(file_record)
                db.session.commit()
                logger.info(f"✅ Created new file record: {filename}")
                logger.info(
                    f"   🔑 SHA256: {content_hashes['sha256'][:16]}... | Size: {content_hashes['file_size']} bytes")
            else:
                # Update existing record if needed
                current_status = safe_enum_comparison(file_record.status)
                if current_status not in [FileStatus.PROCESSING, FileStatus.ANALYZED, FileStatus.COMPLETE]:
                    file_record.status = FileStatus.PROCESSING
                    db.session.commit()
                logger.info(f"📁 Found existing file record: {file_record.filename} (ID: {file_record.id})")

            # Cache the file record
            self.db_file_records[file_hash] = file_record
            return file_record

        except Exception as file_record_error:
            logger.error(f"Failed to get or create file record: {file_record_error}")
            db.session.rollback()
            return None

    def identify_file_type(self, file_path: str) -> str:
        """Identify file type"""
        try:
            import magic
            mime = magic.Magic(mime=True)
            return mime.from_file(file_path)
        except:
            ext = os.path.splitext(file_path)[1].lower()
            type_map = {
                '.png': 'image/png',
                '.jpg': 'image/jpeg',
                '.jpeg': 'image/jpeg',
                '.txt': 'text/plain',
                '.zip': 'application/zip'
            }
            return type_map.get(ext, 'application/octet-stream')

    def store_llm_results(self, file_id: int, results: Dict):
        """Store LLM analysis results"""
        try:
            content = FileContent(
                file_id=file_id,
                content_type='llm_analysis_complete',
                content_text=json.dumps(results, indent=2),
                content_size=len(json.dumps(results)),
                created_at=datetime.utcnow()
            )
            db.session.add(content)
            db.session.commit()
            logger.info(f"Stored LLM results for file_id: {file_id}")
            return True
        except Exception as llm_store_error:
            logger.error(f"Failed to store LLM results: {llm_store_error}")
            db.session.rollback()
            return False

    def create_extraction_relationship(self, source_file: AnalysisFile,
                                       extracted_path: str, method: str,
                                       command: str, depth: int):
        """Create extraction relationship in database"""
        try:
            extracted_file = self.get_or_create_file_record(extracted_path)
            if not extracted_file:
                logger.error(f"Failed to create file record for {extracted_path}")
                return

            relationship = ExtractionRelationship(
                source_file_id=source_file.id,
                source_file_sha=source_file.sha256_hash,
                extracted_file_id=extracted_file.id,
                extracted_file_sha=extracted_file.sha256_hash,
                extraction_method=method,
                extraction_command=command,
                extraction_depth=depth,
                created_at=datetime.utcnow()
            )

            db.session.add(relationship)
            db.session.commit()

            source_node = self.create_file_node(source_file, 'source', depth)
            target_node = self.create_file_node(extracted_file, 'extracted', depth + 1)

            if source_node and target_node:
                self.create_graph_edge(source_node, target_node, method)

            derivation = FileDerivation(
                parent_sha=source_file.sha256_hash,
                child_sha=extracted_file.sha256_hash,
                operation=method,
                tool=method,
                parameters=command,
                confidence=1.0
            )

            db.session.add(derivation)
            db.session.commit()

            logger.info(
                f"Created extraction relationship: {source_file.filename} -> {extracted_file.filename} via {method}")

        except Exception as rel_error:
            logger.error(f"Failed to create extraction relationship: {rel_error}")
            db.session.rollback()

    def create_file_node(self, file: AnalysisFile, node_type: str, graph_level: int) -> Optional[FileNode]:
        """Create or get file node for visualization"""
        try:
            node = FileNode.query.filter_by(file_sha=file.sha256_hash).first()

            if not node:
                node = FileNode(
                    file_id=file.id,
                    file_sha=file.sha256_hash,
                    node_type=node_type,
                    graph_level=graph_level,
                    node_color='#ff0000' if node_type == 'root' else '#0000ff',
                    node_size=15 if node_type == 'root' else 10,
                    extra_data={'extraction_depth': graph_level}
                )

                db.session.add(node)
                db.session.commit()

            return node

        except Exception as node_error:
            logger.error(f"Failed to create file node: {node_error}")
            db.session.rollback()
            return None

    def create_graph_edge(self, source_node: FileNode, target_node: FileNode, edge_type: str) -> Optional[GraphEdge]:
        """Create graph edge between nodes"""
        try:
            edge = GraphEdge.query.filter_by(
                source_node_id=source_node.id,
                target_node_id=target_node.id
            ).first()

            if not edge:
                edge = GraphEdge(
                    source_node_id=source_node.id,
                    target_node_id=target_node.id,
                    edge_type=f"extracted_via_{edge_type}",
                    weight=1.0,
                    edge_color='#00ff00',
                    extra_data={'extraction_method': edge_type}
                )

                db.session.add(edge)
                db.session.commit()

            return edge

        except Exception as edge_error:
            logger.error(f"Failed to create graph edge: {edge_error}")
            db.session.rollback()
            return None

    def create_file_relationship(self, parent: AnalysisFile, child: AnalysisFile, method: str):
        """Create relationship between parent and child files"""
        try:
            relationship = ExtractionRelationship(
                source_file_id=parent.id,
                source_file_sha=parent.sha256_hash,
                extracted_file_id=child.id,
                extracted_file_sha=child.sha256_hash,
                extraction_method=method,
                created_at=datetime.utcnow()
            )

            db.session.add(relationship)
            db.session.commit()

            logger.info(f"Created file relationship: {parent.filename} -> {child.filename}")

        except Exception as rel_create_error:
            logger.error(f"Failed to create file relationship: {rel_create_error}")
            db.session.rollback()

    def analyze_database_state(self) -> Dict[str, Any]:
        """Analyze current database state and return comprehensive statistics - FIXED enum handling"""
        stats = {}

        # Make sure we start with a clean session state
        db.session.rollback()

        # Use a separate session for basic file statistics
        with db.create_scoped_session() as session:
            try:
                total_files = session.query(AnalysisFile).count()
                stats['total_files'] = total_files

                if total_files == 0:
                    stats['is_empty'] = True
                    return stats

                stats['is_empty'] = False
            except Exception as e:
                logger.warning(f"Error getting file count: {e}")
                stats['total_files'] = 0
                stats['is_empty'] = True
                return stats

        # Files by status - FIXED: Use safe enum filtering
        status_breakdown = {}
        for status_enum in [FileStatus.PENDING, FileStatus.PROCESSING, FileStatus.ANALYZED, FileStatus.COMPLETE,
                            FileStatus.ERROR]:
            with db.create_scoped_session() as session:
                try:
                    # Use the safe status filter function
                    query = safe_status_filter(session.query(AnalysisFile), status_enum)
                    count = query.count()
                    if count > 0:
                        status_breakdown[status_enum.value] = count
                except Exception as status_error:
                    logger.warning(f"Could not count files with status {status_enum}: {status_error}")
        stats['status_breakdown'] = status_breakdown

        # File type analysis
        with db.create_scoped_session() as session:
            try:
                file_types = session.query(
                    AnalysisFile.mime_type, func.count(AnalysisFile.id)
                ).group_by(AnalysisFile.mime_type).all()
                stats['file_types'] = {mime_type: count for mime_type, count in file_types if mime_type}
            except Exception as file_type_error:
                logger.warning(f"Could not analyze file types: {file_type_error}")
                stats['file_types'] = {}

        # Size analysis
        with db.create_scoped_session() as session:
            try:
                total_size = session.query(func.sum(AnalysisFile.file_size)).scalar() or 0
                stats['total_size_bytes'] = total_size
                stats['total_size_mb'] = round(total_size / (1024 * 1024), 2)
            except Exception as size_error:
                logger.warning(f"Could not calculate file sizes: {size_error}")
                stats['total_size_bytes'] = 0
                stats['total_size_mb'] = 0

        # Content and extraction statistics
        with db.create_scoped_session() as session:
            try:
                stats['total_content_records'] = session.query(FileContent).count()
            except Exception as e:
                logger.warning(f"Error getting content records count: {e}")
                stats['total_content_records'] = 0

        with db.create_scoped_session() as session:
            try:
                stats['total_findings'] = session.query(Finding).count()
            except Exception as e:
                logger.warning(f"Error getting findings count: {e}")
                stats['total_findings'] = 0

        with db.create_scoped_session() as session:
            try:
                stats['total_relationships'] = session.query(ExtractionRelationship).count()
            except Exception as e:
                logger.warning(f"Error getting relationships count: {e}")
                stats['total_relationships'] = 0

        with db.create_scoped_session() as session:
            try:
                stats['total_nodes'] = session.query(FileNode).count()
            except Exception as e:
                logger.warning(f"Error getting nodes count: {e}")
                stats['total_nodes'] = 0

        with db.create_scoped_session() as session:
            try:
                stats['total_edges'] = session.query(GraphEdge).count()
            except Exception as e:
                logger.warning(f"Error getting edges count: {e}")
                stats['total_edges'] = 0

        # Duplicate detection statistics
        with db.create_scoped_session() as session:
            try:
                duplicate_refs = session.query(FileContent).filter_by(
                    content_type='duplicate_reference'
                ).count()
                stats['duplicate_references'] = duplicate_refs
            except Exception as dup_error:
                logger.warning(f"Could not count duplicate references: {dup_error}")
                stats['duplicate_references'] = 0

        # Content type breakdown
        with db.create_scoped_session() as session:
            try:
                content_types = session.query(
                    FileContent.content_type, func.count(FileContent.id)
                ).group_by(FileContent.content_type).all()
                stats['content_types'] = {content_type: count for content_type, count in content_types}
            except Exception as content_type_error:
                logger.warning(f"Could not analyze content types: {content_type_error}")
                stats['content_types'] = {}

        # Recent activity
        with db.create_scoped_session() as session:
            try:
                recent_files = session.query(AnalysisFile).filter(
                    AnalysisFile.created_at >= datetime.utcnow() - timedelta(days=7)
                ).count()
                stats['recent_files_7days'] = recent_files
            except Exception as recent_error:
                logger.warning(f"Could not count recent files: {recent_error}")
                stats['recent_files_7days'] = 0

        # Processing completeness - FIXED: Use safe enum comparison
        complete_files = 0
        with db.create_scoped_session() as session:
            try:
                for status_enum in [FileStatus.ANALYZED, FileStatus.COMPLETE]:
                    query = safe_status_filter(session.query(AnalysisFile), status_enum)
                    complete_files += query.count()

                stats['completion_rate'] = round((complete_files / stats['total_files']) * 100, 1) if stats['total_files'] > 0 else 0
            except Exception as completion_error:
                logger.warning(f"Could not calculate completion rate: {completion_error}")
                stats['completion_rate'] = 0

        # Find largest files
        with db.create_scoped_session() as session:
            try:
                largest_files = session.query(AnalysisFile).order_by(
                    AnalysisFile.file_size.desc()
                ).limit(3).all()
                stats['largest_files'] = [
                    {
                        'filename': f.filename,
                        'size_mb': round(f.file_size / (1024 * 1024), 2),
                        'status': str(f.status) if f.status else 'unknown'
                    } for f in largest_files
                ]
            except Exception as largest_error:
                logger.warning(f"Could not find largest files: {largest_error}")
                stats['largest_files'] = []

        # Most productive extraction methods
        with db.create_scoped_session() as session:
            try:
                extraction_methods = session.query(
                    ExtractionRelationship.extraction_method,
                    func.count(ExtractionRelationship.id)
                ).group_by(ExtractionRelationship.extraction_method).order_by(
                    func.count(ExtractionRelationship.id).desc()
                ).limit(5).all()
                stats['top_extraction_methods'] = {method: count for method, count in extraction_methods}
            except Exception as extraction_error:
                logger.warning(f"Could not analyze extraction methods: {extraction_error}")
                stats['top_extraction_methods'] = {}

        return stats

    def display_database_state(self, stats: Dict[str, Any]):
        """Display comprehensive database state information"""
        logger.info("=" * 70)
        logger.info("🗄️  CURRENT DATABASE STATE ANALYSIS")
        logger.info("=" * 70)

        if stats.get('is_empty', True):
            logger.info("📭 Database is empty - no previous analysis data found")
            logger.info("🆕 This will be a fresh start")
            return

        # Basic statistics
        logger.info("📊 OVERVIEW:")
        logger.info(f"   📁 Total files: {stats['total_files']:,}")
        logger.info(f"   💾 Total size: {stats['total_size_mb']:,} MB ({stats['total_size_bytes']:,} bytes)")
        logger.info(f"   ✅ Completion rate: {stats['completion_rate']}%")
        logger.info(f"   📅 Recent files (7 days): {stats['recent_files_7days']}")

        # Status breakdown
        if stats.get('status_breakdown'):
            logger.info("📋 FILE STATUS BREAKDOWN:")
            for status, count in stats['status_breakdown'].items():
                logger.info(f"   - {status}: {count:,}")

        # File types
        if stats.get('file_types'):
            logger.info("📂 FILE TYPES:")
            for mime_type, count in sorted(stats['file_types'].items(), key=lambda x: x[1], reverse=True)[:5]:
                logger.info(f"   - {mime_type}: {count:,}")

        # Processing results
        logger.info("🔍 ANALYSIS RESULTS:")
        logger.info(f"   📄 Content records: {stats['total_content_records']:,}")
        logger.info(f"   🎯 Findings: {stats['total_findings']:,}")
        logger.info(f"   🔗 Extraction relationships: {stats['total_relationships']:,}")
        logger.info(f"   🎯 Duplicate references: {stats['duplicate_references']:,}")

        # Visualization data
        if stats['total_nodes'] > 0 or stats['total_edges'] > 0:
            logger.info("🌐 GRAPH VISUALIZATION DATA:")
            logger.info(f"   🔵 Nodes: {stats['total_nodes']:,}")
            logger.info(f"   🔗 Edges: {stats['total_edges']:,}")

        # Top extraction methods
        if stats.get('top_extraction_methods'):
            logger.info("🏆 TOP EXTRACTION METHODS:")
            for method, count in list(stats['top_extraction_methods'].items())[:3]:
                logger.info(f"   - {method}: {count:,} extractions")

        # Largest files
        if stats.get('largest_files'):
            logger.info("📏 LARGEST FILES:")
            for file_info in stats['largest_files']:
                logger.info(f"   - {file_info['filename']}: {file_info['size_mb']} MB ({file_info['status']})")

        logger.info("=" * 70)

    def prompt_user_action(self, stats: Dict[str, Any]) -> str:
        """Prompt user for action based on database state"""
        if stats.get('is_empty', True):
            return 'continue'

        print("\n🤔 What would you like to do?")
        print("   1. 🔄 Continue where left off (resume existing analysis)")
        print("   2. 🧹 Clean ALL database records and start fresh")
        print("   3. 🎯 Clean only incomplete/failed records")
        print("   4. 📊 Show detailed statistics and continue")
        print("   5. ❌ Exit without changes")

        while True:
            try:
                choice = input("\nEnter your choice (1-5): ").strip()

                if choice == '1':
                    return 'continue'
                elif choice == '2':
                    confirm = input("⚠️  This will DELETE ALL existing data. Are you sure? (yes/no): ").strip().lower()
                    if confirm in ['yes', 'y']:
                        return 'clean_all'
                    else:
                        print("❌ Operation cancelled. Continuing with existing data...")
                        return 'continue'
                elif choice == '3':
                    return 'clean_incomplete'
                elif choice == '4':
                    return 'show_details'
                elif choice == '5':
                    return 'exit'
                else:
                    print("❌ Invalid choice. Please enter 1-5.")
            except (KeyboardInterrupt, EOFError):
                print("\n❌ Operation cancelled.")
                return 'exit'

    def clean_database_records(self, clean_type: str) -> bool:
        """Clean database records based on specified type"""
        try:
            if clean_type == 'clean_all':
                logger.info("🧹 Cleaning ALL database records...")

                # Delete each table in a separate transaction to avoid cascading failures
                tables_to_delete = [
                    (GraphEdge, "Graph Edges"),
                    (FileNode, "File Nodes"),
                    (ExtractionRelationship, "Extraction Relationships"),
                    (FileDerivation, "File Derivations"),
                    (Finding, "Findings"),
                    (FileContent, "File Content"),
                    (AnalysisFile, "Analysis Files")
                ]

                # Create a fresh session for the entire operation
                from crypto_hunter_web.extensions import db

                for model, name in tables_to_delete:
                    # Create a new session for each table deletion to ensure complete isolation
                    with db.create_scoped_session() as isolated_session:
                        try:
                            # Use a completely separate transaction for each table
                            count = isolated_session.query(model).delete()
                            isolated_session.commit()
                            logger.info(f"✅ Deleted {count} {name} records")
                        except Exception as e:
                            # Roll back this specific deletion but continue with others
                            isolated_session.rollback()
                            logger.warning(f"⚠️ Failed to delete {name}: {e}")

                # Make sure the main session is in a clean state
                db.session.rollback()
                logger.info("✅ Database cleaning completed")

            elif clean_type == 'clean_incomplete':
                logger.info("🎯 Cleaning incomplete/failed records...")

                # Make sure we have a clean session state
                db.session.rollback()

                # Find incomplete files using safe status filtering
                incomplete_files = []
                for status_enum in [FileStatus.PENDING, FileStatus.PROCESSING, FileStatus.ERROR]:
                    try:
                        # Use a separate session for querying to avoid transaction issues
                        with db.create_scoped_session() as query_session:
                            query = safe_status_filter(query_session.query(AnalysisFile), status_enum)
                            # Get the IDs only to avoid session-bound objects
                            file_ids = [f.id for f in query.all()]

                        # Now fetch the actual objects with the main session
                        for file_id in file_ids:
                            file_obj = db.session.query(AnalysisFile).get(file_id)
                            if file_obj:
                                incomplete_files.append(file_obj)
                    except Exception as status_filter_error:
                        logger.warning(f"Could not filter by status {status_enum}: {status_filter_error}")
                        continue

                incomplete_count = len(incomplete_files)
                if incomplete_count == 0:
                    logger.info("ℹ️  No incomplete records found")
                    return True

                # Track successfully cleaned files
                cleaned_count = 0

                # Delete related records for incomplete files
                for file_record in incomplete_files:
                    # Use a separate session for each file to isolate failures
                    with db.create_scoped_session() as file_session:
                        try:
                            # Get a fresh copy of the file record in this session
                            file_id = file_record.id
                            file_sha = file_record.sha256_hash

                            # Re-fetch the file in this session
                            current_file = file_session.query(AnalysisFile).get(file_id)
                            if not current_file:
                                logger.warning(f"File {file_id} no longer exists, skipping")
                                continue

                            # Delete graph elements
                            file_session.query(GraphEdge).filter(
                                (GraphEdge.source_node_id.in_(
                                    file_session.query(FileNode.id).filter_by(file_id=file_id)
                                )) |
                                (GraphEdge.target_node_id.in_(
                                    file_session.query(FileNode.id).filter_by(file_id=file_id)
                                ))
                            ).delete(synchronize_session=False)

                            file_session.query(FileNode).filter_by(file_id=file_id).delete()

                            # Delete extraction relationships
                            file_session.query(ExtractionRelationship).filter(
                                (ExtractionRelationship.source_file_id == file_id) |
                                (ExtractionRelationship.extracted_file_id == file_id)
                            ).delete(synchronize_session=False)

                            # Delete derivations
                            file_session.query(FileDerivation).filter(
                                (FileDerivation.parent_sha == file_sha) |
                                (FileDerivation.child_sha == file_sha)
                            ).delete(synchronize_session=False)

                            # Delete findings and content
                            file_session.query(Finding).filter_by(file_id=file_id).delete()
                            file_session.query(FileContent).filter_by(file_id=file_id).delete()

                            # Delete the file record itself
                            file_session.delete(current_file)

                            # Commit this file's changes
                            file_session.commit()
                            cleaned_count += 1

                        except Exception as delete_error:
                            file_session.rollback()
                            logger.warning(f"Could not delete incomplete record {file_id}: {delete_error}")
                            continue

                # Make sure the main session is in a clean state
                db.session.rollback()
                logger.info(f"✅ Cleaned {cleaned_count} of {incomplete_count} incomplete records successfully")

            return True

        except Exception as clean_error:
            logger.error(f"❌ Error cleaning database records: {clean_error}")
            db.session.rollback()
            return False

    def show_detailed_statistics(self, stats: Dict[str, Any]):
        """Show detailed database statistics"""
        logger.info("=" * 70)
        logger.info("📊 DETAILED DATABASE STATISTICS")
        logger.info("=" * 70)

        # Content type breakdown
        if stats.get('content_types'):
            logger.info("📄 CONTENT TYPE BREAKDOWN:")
            for content_type, count in sorted(stats['content_types'].items(), key=lambda x: x[1], reverse=True):
                logger.info(f"   - {content_type}: {count:,}")

        # All file types
        if stats.get('file_types'):
            logger.info("📂 ALL FILE TYPES:")
            for mime_type, count in sorted(stats['file_types'].items(), key=lambda x: x[1], reverse=True):
                logger.info(f"   - {mime_type}: {count:,}")

        # All extraction methods
        if stats.get('top_extraction_methods'):
            logger.info("🔧 ALL EXTRACTION METHODS:")
            for method, count in sorted(stats['top_extraction_methods'].items(), key=lambda x: x[1], reverse=True):
                logger.info(f"   - {method}: {count:,}")

        logger.info("=" * 70)

    def print_summary(self):
        """Print comprehensive summary of extraction results with duplicate detection stats"""
        try:
            total_files = len(self.processed_files)
            total_relationships = db.session.query(ExtractionRelationship).count()
            total_nodes = db.session.query(FileNode).count()
            total_edges = db.session.query(GraphEdge).count()

            # Count files by status - FIXED: Use safe enum handling
            status_counts = {}
            for file_record in self.db_file_records.values():
                status = safe_enum_comparison(file_record.status)
                if status:
                    status_name = status.value if status else 'unknown'
                    status_counts[status_name] = status_counts.get(status_name, 0) + 1

            # Comprehensive duplicate detection statistics
            total_db_files = db.session.query(AnalysisFile).count()
            duplicate_references = db.session.query(FileContent).filter_by(
                content_type='duplicate_reference'
            ).count()

            # Content hash statistics
            unique_sha256 = db.session.query(AnalysisFile.sha256_hash).distinct().count()
            unique_md5 = db.session.query(AnalysisFile.md5_hash).filter(
                AnalysisFile.md5_hash.isnot(None)
            ).distinct().count()
            unique_sha1 = db.session.query(AnalysisFile.sha1_hash).filter(
                AnalysisFile.sha1_hash.isnot(None)
            ).distinct().count()

            logger.info("=" * 70)
            logger.info("🧬 ENHANCED LLM ORCHESTRATED EXTRACTION SUMMARY")
            logger.info("=" * 70)

            # Processing statistics
            logger.info("📊 PROCESSING STATISTICS:")
            logger.info(f"   📁 Files processed this session: {total_files}")
            logger.info(f"   🗄️  Total files in database: {total_db_files}")
            logger.info(f"   🔗 Extraction relationships: {total_relationships}")
            logger.info(f"   🌐 Graph nodes: {total_nodes}")
            logger.info(f"   🔄 Graph edges: {total_edges}")

            # File status breakdown
            if status_counts:
                logger.info("📋 FILE STATUS BREAKDOWN:")
                for status, count in status_counts.items():
                    logger.info(f"   - {status}: {count}")

            # Content duplicate detection statistics
            logger.info("🎯 CONTENT DUPLICATE DETECTION:")
            logger.info(f"   🔑 Unique SHA256 hashes: {unique_sha256}")
            logger.info(f"   🔑 Unique MD5 hashes: {unique_md5}")
            logger.info(f"   🔑 Unique SHA1 hashes: {unique_sha1}")
            logger.info(f"   📝 Duplicate references created: {duplicate_references}")

            # Calculate efficiency metrics
            if total_db_files > total_files:
                session_skipped = total_db_files - total_files
                session_efficiency = (session_skipped / total_db_files) * 100
                logger.info(f"   ⏭️  Files skipped this session: {session_skipped}")
                logger.info(f"   ⚡ Session efficiency: {session_efficiency:.1f}% duplicates avoided")

            if duplicate_references > 0:
                total_content_efficiency = (duplicate_references / (total_db_files + duplicate_references)) * 100
                logger.info(f"   🎯 Overall content dedup rate: {total_content_efficiency:.1f}%")

                # Calculate time/resource savings
                avg_processing_time_saved = duplicate_references * 30  # Assume 30 seconds per file average
                if avg_processing_time_saved > 3600:
                    time_saved_str = f"{avg_processing_time_saved / 3600:.1f} hours"
                elif avg_processing_time_saved > 60:
                    time_saved_str = f"{avg_processing_time_saved / 60:.1f} minutes"
                else:
                    time_saved_str = f"{avg_processing_time_saved} seconds"

                logger.info(f"   ⏱️  Estimated processing time saved: ~{time_saved_str}")

            # Hash collision detection (should be 0 for good hash functions)
            potential_collisions = total_db_files - unique_sha256
            if potential_collisions > 0:
                logger.warning(f"   ⚠️  Potential hash collisions detected: {potential_collisions}")
            else:
                logger.info(f"   ✅ No hash collisions detected")

            # Storage and processing efficiency
            if total_files > 0:
                avg_relationships_per_file = total_relationships / total_files
                logger.info(f"   📈 Avg extractions per file: {avg_relationships_per_file:.1f}")

            logger.info("=" * 70)
            logger.info("🎉 CONTENT-AWARE DUPLICATE DETECTION ENABLED!")
            logger.info("🔍 Multi-algorithm hashing: SHA256 + MD5 + SHA1 + Fingerprinting")
            logger.info("💾 Cross-session duplicate memory via database")
            if duplicate_references > 0:
                logger.info(f"⚡ Efficiency boost: {duplicate_references} duplicates avoided this session!")
            logger.info("=" * 70)

        except Exception as summary_error:
            logger.error(f"Failed to print summary: {summary_error}")
            logger.exception("Summary error details:")


def main():
    """Main function"""
    parser = argparse.ArgumentParser(
        description='Enhanced LLM Orchestrated Recursive Extraction with Content Duplicate Detection - FIXED',
        epilog="""
Examples:
  python3 %(prog)s                          # Interactive mode with database consultation
  python3 %(prog)s --resume                 # Resume previous work without consultation
  python3 %(prog)s --no-prompt              # Skip consultation and start fresh
  python3 %(prog)s --clean-all               # Clean all records and start fresh
  python3 %(prog)s --show-duplicates        # Show duplicate statistics only
  python3 %(prog)s --input-file image.jpg   # Process different input file
  python3 %(prog)s --db-host db              # Connect to Docker PostgreSQL service
  python3 %(prog)s --db-host localhost      # Connect to local PostgreSQL
  python3 %(prog)s --test-db-only           # Test database connection only
  python3 %(prog)s --verbose-db             # Show detailed database diagnostics

Environment Variables:
  DATABASE_URL                               # Complete PostgreSQL URL (overrides all other DB settings)
  DB_HOST                                    # PostgreSQL host (default: localhost)
  DB_PORT                                    # PostgreSQL port (default: 5432)
  DB_NAME                                    # PostgreSQL database name (default: crypto_hunter)
  DB_USER                                    # PostgreSQL username (default: crypto_hunter)
  DB_PASSWORD                                # PostgreSQL password (default: secure_password_123)

Docker PostgreSQL Setup:
  docker run -d --name crypto-hunter-db \\
    -p 5432:5432 \\
    -e POSTGRES_DB=crypto_hunter \\
    -e POSTGRES_USER=crypto_hunter \\
    -e POSTGRES_PASSWORD=secure_password_123 \\
    postgres:13

  From host: python3 %(prog)s --db-host localhost
  From container: python3 %(prog)s --db-host db

Requirements:
  pip install psycopg2-binary  # PostgreSQL driver (required)

FIXES in this version:
  - Fixed SQLAlchemy enum handling with safe_enum_comparison()
  - Improved exception handling to prevent variable scoping conflicts
  - Enhanced database state validation with proper error handling
  - Better enum status filtering with fallback mechanisms
  - Comprehensive error logging without breaking execution flow
        """,
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument('--resume', action='store_true', help='Resume from previous state (skip database consultation)')
    parser.add_argument('--input-file', default=IMAGE_PATH, help='Input file to analyze')
    parser.add_argument('--output-dir', default=OUTPUT_DIR, help='Output directory')
    parser.add_argument('--force-reprocess', action='store_true', help='Force reprocessing of already processed files')
    parser.add_argument('--show-duplicates', action='store_true', help='Show duplicate statistics and exit')
    parser.add_argument('--verbose-duplicates', action='store_true', help='Show detailed duplicate detection logs')
    parser.add_argument('--no-prompt', action='store_true', help='Skip database consultation and start immediately')
    parser.add_argument('--clean-all', action='store_true', help='Clean all database records before starting')
    parser.add_argument('--clean-incomplete', action='store_true', help='Clean only incomplete records before starting')
    parser.add_argument('--db-url', help='Complete PostgreSQL database URL (overrides other DB settings)')
    parser.add_argument('--db-host', default='localhost',
                        help='PostgreSQL host (default: localhost, use "db" for Docker)')
    parser.add_argument('--db-port', default='5432', help='PostgreSQL port (default: 5432)')
    parser.add_argument('--db-name', default='crypto_hunter', help='PostgreSQL database name (default: crypto_hunter)')
    parser.add_argument('--db-user', default='crypto_hunter', help='PostgreSQL username (default: crypto_hunter)')
    parser.add_argument('--db-password', help='PostgreSQL password (default: secure_password_123)')
    parser.add_argument('--verbose-db', action='store_true', help='Show detailed database connection logs')
    parser.add_argument('--test-db-only', action='store_true', help='Test database connection only and exit')
    args = parser.parse_args()

    # Pre-flight checks for PostgreSQL
    try:
        import psycopg2
    except ImportError:
        print("❌ ERROR: psycopg2 is required for PostgreSQL connection")
        print("💡 Install with: pip install psycopg2-binary")
        print("🐳 Or: docker exec <container> pip install psycopg2-binary")
        return 1

    # CRITICAL: Set database environment variables FIRST, before any imports or Flask app creation
    if args.db_url:
        os.environ['DATABASE_URL'] = args.db_url
    if args.db_host != 'localhost':
        os.environ['DB_HOST'] = args.db_host
    if args.db_port != '5432':
        os.environ['DB_PORT'] = args.db_port
    if args.db_name != 'crypto_hunter':
        os.environ['DB_NAME'] = args.db_name
    if args.db_user != 'crypto_hunter':
        os.environ['DB_USER'] = args.db_user
    if args.db_password:
        os.environ['DB_PASSWORD'] = args.db_password

    # Set PostgreSQL-only environment to prevent SQLite fallback
    os.environ['FLASK_ENV'] = 'production'  # Prevent dev overrides

    # Build and set the PostgreSQL URL immediately
    if not os.environ.get('DATABASE_URL'):
        db_user = os.environ.get('DB_USER', 'crypto_hunter')
        db_password = os.environ.get('DB_PASSWORD', 'secure_password_123')
        db_host = os.environ.get('DB_HOST', 'localhost')
        db_port = os.environ.get('DB_PORT', '5432')
        db_name = os.environ.get('DB_NAME', 'crypto_hunter')

        postgresql_url = f'postgresql://{db_user}:{db_password}@{db_host}:{db_port}/{db_name}'
        os.environ['DATABASE_URL'] = postgresql_url
        os.environ['SQLALCHEMY_DATABASE_URI'] = postgresql_url

    # Use the provided arguments directly
    input_file = args.input_file
    output_dir = args.output_dir

    # Set verbose logging for database if requested (otherwise keep it quiet)
    if args.verbose_db:
        logging.getLogger('sqlalchemy.engine').setLevel(logging.INFO)
        logging.getLogger('sqlalchemy.pool').setLevel(logging.INFO)
        logger.info("🔧 SQLAlchemy verbose logging enabled")
    else:
        # Ensure SQLAlchemy stays quiet
        logging.getLogger('sqlalchemy.engine').setLevel(logging.WARNING)
        logging.getLogger('sqlalchemy.pool').setLevel(logging.WARNING)

    # Set verbose logging for duplicate detection if requested
    if args.verbose_duplicates:
        logging.getLogger(__name__).setLevel(logging.DEBUG)

    # Log final database configuration (concise version)
    logger.info("🔧 Database Configuration:")
    logger.info(f"   DATABASE_URL: {'***SET***' if os.environ.get('DATABASE_URL') else 'Not set'}")
    logger.info(f"   DB_HOST: {os.environ.get('DB_HOST', 'localhost')}")
    logger.info(f"   DB_PORT: {os.environ.get('DB_PORT', '5432')}")
    logger.info(f"   DB_NAME: {os.environ.get('DB_NAME', 'crypto_hunter')}")
    logger.info(f"   DB_USER: {os.environ.get('DB_USER', 'crypto_hunter')}")

    # Quick Docker environment check for better guidance
    if os.environ.get('DB_HOST') == 'db' or args.db_host == 'db':
        try:
            import subprocess
            result = subprocess.run(['docker', 'ps', '--format', '{{.Names}}\t{{.Status}}'],
                                    capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                containers = result.stdout.strip().split('\n')
                postgres_containers = [c for c in containers if 'crypto-hunter-db' in c or 'postgres' in c.lower()]
                if postgres_containers:
                    docker_check_result = f"Found PostgreSQL containers: {postgres_containers[0]}"
                else:
                    docker_check_result = "No crypto-hunter-db container found"
        except Exception:
            docker_check_result = "Could not check Docker containers"

        if docker_check_result:
            logger.info(f"🐳 Docker status: {docker_check_result}")

    logger.info("=" * 70)
    logger.info("🧬 ENHANCED LLM ORCHESTRATED RECURSIVE EXTRACTOR")
    logger.info("=" * 70)
    logger.info(f"Input file: {input_file}")
    logger.info(f"Output directory: {output_dir}")
    logger.info(f"Resume mode: {args.resume}")
    logger.info(f"Force reprocess: {args.force_reprocess}")
    logger.info(f"Show duplicates only: {args.show_duplicates}")
    logger.info(f"No interactive prompt: {args.no_prompt}")
    logger.info("=" * 70)

    if not any([args.resume, args.no_prompt, args.show_duplicates, args.clean_all, args.clean_incomplete]):
        logger.info("ℹ️  Interactive mode enabled - you'll be prompted about existing database contents")
        logger.info("💡 Use --no-prompt to skip consultation, --resume to continue previous work")
        logger.info("🐳 Ensure PostgreSQL container is running and accessible")
        logger.info("🔧 If connection fails, try --db-host db (Docker) or --verbose-db for diagnostics")

    logger.info("=" * 70)

    try:
        # Handle database connection test only
        if args.test_db_only:
            logger.info("🧪 Testing database connection only...")
            try:
                extractor = EnhancedLLMExtractor(
                    resume=True,  # Skip consultation
                    input_file=input_file,
                    output_dir=output_dir
                )
                logger.info("✅ Database connection test successful!")
                return 0
            except Exception as test_error:
                logger.error(f"❌ Database connection test failed: {test_error}")
                return 1

        # Handle pre-processing database operations
        if args.clean_all or args.clean_incomplete:
            logger.info("🧹 Pre-processing database cleanup requested...")
            temp_extractor = EnhancedLLMExtractor(
                resume=True,  # Skip consultation
                input_file=input_file,
                output_dir=output_dir
            )

            clean_type = 'clean_all' if args.clean_all else 'clean_incomplete'
            success = temp_extractor.clean_database_records(clean_type)

            if not success:
                logger.error("❌ Pre-processing cleanup failed. Exiting...")
                return 1

            # Continue with fresh state
            args.resume = False
            args.no_prompt = True

        # Create main extractor with detailed logging
        logger.info("🚀 Creating main extractor instance...")
        skip_consultation = args.resume or args.no_prompt

        extractor = EnhancedLLMExtractor(
            resume=skip_consultation,
            input_file=input_file,
            output_dir=output_dir
        )
        extractor.force_reprocess = args.force_reprocess

        if args.show_duplicates:
            # Just show duplicate statistics without processing
            extractor.analyze_content_duplicates(show_details=True)
            extractor.print_summary()
            logger.info("🎯 Duplicate analysis complete - no processing performed")
            return 0
        else:
            logger.info("🎯 Starting main extraction process...")
            extractor.run()
            logger.info("✅ Extraction completed successfully")
            return 0
    except KeyboardInterrupt:
        logger.info("👋 Extraction cancelled by user")
        return 0
    except Exception as main_error:
        logger.error(f"❌ Extraction failed: {main_error}")

        # Add specific debugging for database configuration issues
        if 'sqlite' in str(main_error).lower() and 'postgresql' in str(main_error).lower():
            logger.error("🔍 DIAGNOSIS: Database configuration conflict detected!")
            logger.error("💡 The Flask app is trying to use SQLite instead of PostgreSQL")
            logger.error("🔧 TRY THESE SOLUTIONS:")
            logger.error("1. Set DATABASE_URL before running:")
            logger.error(
                "   export DATABASE_URL='postgresql://crypto_hunter:secure_password_123@localhost:5432/crypto_hunter'")
            logger.error("2. Or run with explicit database URL:")
            logger.error(
                "   python3 test_hybrid_fixed.py --db-url 'postgresql://crypto_hunter:secure_password_123@localhost:5432/crypto_hunter'")
            logger.error("3. Check if crypto-hunter-db container is accessible:")
            logger.error(
                "   docker exec -it crypto-hunter-db psql -U crypto_hunter -d crypto_hunter -c 'SELECT version();'")

        # Enhanced enum-specific error diagnosis
        if 'ANALYZED' in str(main_error) or 'enum' in str(main_error).lower():
            logger.error("🔍 DIAGNOSIS: SQLAlchemy enum handling issue detected!")
            logger.error("💡 This version includes fixes for enum handling problems")
            logger.error("🔧 The error suggests database enum values don't match Python enum definitions")
            logger.error("🏥 RECOVERY SUGGESTIONS:")
            logger.error("1. Clean incomplete records: python3 test_hybrid_fixed.py --clean-incomplete")
            logger.error("2. Or clean all data: python3 test_hybrid_fixed.py --clean-all")
            logger.error(
                "3. Check database schema: docker exec -it crypto-hunter-db psql -U crypto_hunter -d crypto_hunter -c '\\d analysis_files'")

        if args.verbose_db:
            logger.exception("Full traceback:")
        else:
            logger.error("💡 Add --verbose-db for full traceback")
        return 1


if __name__ == "__main__":
    import sys

    sys.exit(main())
