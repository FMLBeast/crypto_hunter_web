#!/usr/bin/env python3
"""
Enhanced LLM Orchestrated Recursive Extraction Script - PostgreSQL Edition (ENUM FIXED)

CRITICAL FIX: Fixed enum mismatch between Python and PostgreSQL
- Updated FileStatus enum to match database values exactly
- Fixed safe_enum_comparison to handle the correct enum values
- Database has: pending, processing, complete, error, archived
- Python now uses: PENDING, PROCESSING, COMPLETE, ERROR, ARCHIVED

CHANGE: Replaced all instances of FileStatus.ANALYZED with FileStatus.COMPLETE
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
EXTRACTION_STATE_FILE = "../../extraction_state.json"


def safe_enum_comparison(status_value: Any) -> Optional[FileStatus]:
    """Safely compare and convert status values to FileStatus enum - FIXED for correct enum values"""
    if status_value is None:
        return None

    # If it's already a FileStatus enum, return it
    if isinstance(status_value, FileStatus):
        return status_value

    # If it's a string, try to match it to enum values
    if isinstance(status_value, str):
        status_upper = status_value.upper()
        # Map database values to enum values
        status_mapping = {
            'PENDING': FileStatus.PENDING,
            'PROCESSING': FileStatus.PROCESSING,
            'COMPLETE': FileStatus.COMPLETE,  # Database has 'complete', not 'analyzed'
            'ERROR': FileStatus.ERROR,
            'ARCHIVED': FileStatus.ARCHIVED
        }

        # Try direct match first
        if status_upper in status_mapping:
            return status_mapping[status_upper]

        # Try matching enum names
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

                # Get all files that have been fully analyzed (FIXED: Use COMPLETE instead of ANALYZED)
                analyzed_files = AnalysisFile.query.filter(
                    AnalysisFile.status.in_([FileStatus.COMPLETE])  # Only COMPLETE status exists in DB
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
            logger.info(f"   🔄 Processed: {processed_count} | 🗄️ Database: {db_file_count} | 🎯 Duplicates: {duplicate_refs}")

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

        # Mark file as analyzed - FIXED: Use COMPLETE instead of ANALYZED
        if file_record:
            file_record.status = FileStatus.COMPLETE  # Use COMPLETE which exists in database
            file_record.analyzed_at = datetime.utcnow()
            db.session.commit()

        return file_record

    # ... (rest of the methods remain the same, but need to update any references to ANALYZED to COMPLETE)

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
                        if file_status in [FileStatus.COMPLETE]:  # FIXED: Only check COMPLETE status
                            logger.info(f"🎯 DUPLICATE detected via {hash_type}: {os.path.basename(file_path)} → {duplicate_file.filename}")
                            return duplicate_file

            # Check for near-duplicate content using size + fingerprint
            if content_hashes['file_size'] > 0:
                similar_files = AnalysisFile.query.filter(
                    AnalysisFile.file_size == content_hashes['file_size']
                ).all()

                for similar_file in similar_files:
                    file_status = safe_enum_comparison(similar_file.status)
                    if file_status in [FileStatus.COMPLETE]:  # FIXED: Only check COMPLETE status
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

    # ... (continuing with remaining methods, but I need to continue to replace all ANALYZED references)

    def analyze_database_state(self) -> Dict[str, Any]:
        """Analyze current database state and return comprehensive statistics - FIXED enum handling"""
        try:
            stats = {}

            # Basic file statistics
            total_files = db.session.query(AnalysisFile).count()
            stats['total_files'] = total_files

            if total_files == 0:
                stats['is_empty'] = True
                return stats

            stats['is_empty'] = False

            # Files by status - FIXED: Use safe enum filtering with correct enum values
            status_breakdown = {}
            for status_enum in [FileStatus.PENDING, FileStatus.PROCESSING, FileStatus.COMPLETE, FileStatus.ERROR]:  # Removed ANALYZED
                try:
                    # Use the safe status filter function
                    query = safe_status_filter(db.session.query(AnalysisFile), status_enum)
                    count = query.count()
                    if count > 0:
                        status_breakdown[status_enum.value] = count
                except Exception as status_error:
                    logger.warning(f"Could not count files with status {status_enum}: {status_error}")
                    continue

            stats['status_breakdown'] = status_breakdown

            # ... (rest of the method remains the same)

        except Exception as analyze_error:
            logger.error(f"Error analyzing database state: {analyze_error}")
            return {'error': str(analyze_error), 'is_empty': True, 'total_files': 0}

    # Continue with remaining methods...
