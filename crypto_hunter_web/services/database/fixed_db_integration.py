#!/usr/bin/env python3
"""
Fixed Database Integration for Crypto Hunter
============================================

This module provides a robust database integration layer for storing extraction results,
handling relationships between files, and managing the analysis data.
"""

import os
import sys
import json
import logging
from typing import Dict, Any, List, Optional
from datetime import datetime

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Add project root to path
project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
sys.path.append(project_root)

class PostgreSQLDatabaseIntegrator:
    """Database integration for PostgreSQL"""
    
    def __init__(self, connection_string=None):
        self.connection_string = connection_string
        self.connected = False
        self._initialize_connection()
    
    def _initialize_connection(self):
        """Initialize database connection"""
        try:
            # Import database modules
            from sqlalchemy import create_engine
            from sqlalchemy.orm import sessionmaker
            
            # Get connection string from environment or use default
            if not self.connection_string:
                from crypto_hunter_web.config import get_database_url
                self.connection_string = get_database_url()
            
            # Create engine and session
            self.engine = create_engine(self.connection_string)
            self.Session = sessionmaker(bind=self.engine)
            self.connected = True
            logger.info(f"Database connection initialized")
            
        except ImportError:
            logger.warning("SQLAlchemy not available, database integration disabled")
        except Exception as e:
            logger.error(f"Failed to initialize database connection: {e}")
    
    def store_extraction_results(self, file_path: str, results: Dict[str, Any], user_id: int = 1) -> Optional[int]:
        """Store extraction results in database"""
        if not self.connected:
            logger.warning("Database not connected, cannot store results")
            return None
        
        try:
            from crypto_hunter_web.models import db, AnalysisFile, Finding, ExtractionRelationship
            
            session = self.Session()
            
            # Create or get file record
            file_record = self._get_or_create_file_record(session, file_path, user_id)
            
            # Store extraction results
            self._store_extraction_data(session, file_record, results)
            
            # Create relationships between files
            self._create_file_relationships(session, file_record, results)
            
            # Commit changes
            session.commit()
            
            logger.info(f"Stored extraction results for file {file_path}")
            return file_record.id
            
        except Exception as e:
            logger.error(f"Failed to store extraction results: {e}")
            if 'session' in locals():
                session.rollback()
            return None
        finally:
            if 'session' in locals():
                session.close()
    
    def _get_or_create_file_record(self, session, file_path: str, user_id: int):
        """Get existing file record or create a new one"""
        from crypto_hunter_web.models import AnalysisFile, FileStatus
        import hashlib
        
        # Calculate file hash
        with open(file_path, 'rb') as f:
            file_hash = hashlib.sha256(f.read()).hexdigest()
        
        # Check if file already exists
        file_record = session.query(AnalysisFile).filter_by(sha256_hash=file_hash).first()
        
        if not file_record:
            # Create new file record
            file_record = AnalysisFile(
                filename=os.path.basename(file_path),
                filepath=file_path,
                file_size=os.path.getsize(file_path),
                sha256_hash=file_hash,
                uploaded_by=user_id,
                status=FileStatus.COMPLETE
            )
            session.add(file_record)
            session.flush()
        
        return file_record
    
    def _store_extraction_data(self, session, file_record, results: Dict[str, Any]):
        """Store extraction data in database"""
        from crypto_hunter_web.models import Finding, FindingStatus
        
        # Store extraction results as findings
        for extraction_result in results.get('extraction_results', []):
            if extraction_result.get('success'):
                # Create finding for each successful extraction
                finding = Finding(
                    file_id=file_record.id,
                    finding_type=f"extraction_{extraction_result.get('method', 'unknown')}",
                    description=extraction_result.get('details', 'Extraction result'),
                    content=json.dumps(extraction_result),
                    confidence_score=extraction_result.get('confidence', 0.5),
                    status=FindingStatus.CONFIRMED,
                    created_by=file_record.uploaded_by
                )
                session.add(finding)
        
        # Update file record with extraction stats
        file_record.analysis_extra_data = {
            **(file_record.analysis_extra_data or {}),
            'extraction_stats': {
                'total_methods': len(results.get('extraction_results', [])),
                'successful_methods': sum(1 for r in results.get('extraction_results', []) if r.get('success')),
                'duration_seconds': results.get('duration_seconds', 0)
            }
        }
    
    def _create_file_relationships(self, session, file_record, results: Dict[str, Any]):
        """Create relationships between files"""
        from crypto_hunter_web.models import AnalysisFile, ExtractionRelationship
        
        # Get all extracted files
        extracted_files = []
        for extraction_result in results.get('extraction_results', []):
            extracted_files.extend(extraction_result.get('extracted_files', []))
        
        # Create relationships for each extracted file
        for extracted_file_path in extracted_files:
            if os.path.exists(extracted_file_path):
                # Get or create extracted file record
                extracted_file_record = self._get_or_create_file_record(
                    session, extracted_file_path, file_record.uploaded_by
                )
                
                # Create relationship
                relationship = ExtractionRelationship(
                    parent_id=file_record.id,
                    child_id=extracted_file_record.id,
                    relationship_type='extracted_from',
                    metadata={
                        'extraction_method': extraction_result.get('method', 'unknown'),
                        'confidence': extraction_result.get('confidence', 0.5),
                        'timestamp': datetime.utcnow().isoformat()
                    }
                )
                session.add(relationship)