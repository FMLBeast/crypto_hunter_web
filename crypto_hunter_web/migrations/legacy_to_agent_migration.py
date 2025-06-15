"""
crypto_hunter_web/migrations/legacy_to_agent_migration.py
Migration script to transition from legacy extraction system to agent-based system
"""

import os
import sys
import json
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
from sqlalchemy import text

# Add project root to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))

from crypto_hunter_web import create_app
from crypto_hunter_web.extensions import db
from crypto_hunter_web.models import (
    AnalysisFile, Finding, ExtractionRelationship, FileContent,
    PuzzleSession, PuzzleStep
)

logger = logging.getLogger(__name__)


class LegacyToAgentMigration:
    """Handles migration from legacy extraction system to agent system"""
    
    def __init__(self):
        self.app = None
        self.migration_stats = {
            'files_migrated': 0,
            'findings_migrated': 0,
            'relationships_migrated': 0,
            'sessions_updated': 0,
            'errors': []
        }
    
    def initialize(self):
        """Initialize Flask app context"""
        self.app = create_app()
        return self.app
    
    def run_full_migration(self, backup_data: bool = True, dry_run: bool = False):
        """Run complete migration from legacy to agent system"""
        with self.app.app_context():
            logger.info("Starting legacy to agent system migration...")
            
            try:
                # Step 1: Backup existing data
                if backup_data:
                    self.backup_legacy_data()
                
                # Step 2: Create agent system tables
                self.create_agent_tables()
                
                # Step 3: Migrate existing analysis data
                self.migrate_analysis_files()
                
                # Step 4: Migrate findings to new format
                self.migrate_findings()
                
                # Step 5: Migrate extraction relationships
                self.migrate_extraction_relationships()
                
                # Step 6: Update puzzle sessions
                self.update_puzzle_sessions()
                
                # Step 7: Create initial agent configurations
                self.create_agent_configurations()
                
                # Step 8: Update application configuration
                if not dry_run:
                    self.update_app_configuration()
                
                logger.info("Migration completed successfully!")
                self.print_migration_summary()
                
            except Exception as e:
                logger.exception(f"Migration failed: {e}")
                self.migration_stats['errors'].append(str(e))
                raise
    
    def backup_legacy_data(self):
        """Backup existing data before migration"""
        logger.info("Creating backup of legacy data...")
        
        backup_dir = f"backups/migration_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        os.makedirs(backup_dir, exist_ok=True)
        
        # Backup critical tables
        tables_to_backup = [
            'analysis_files', 'findings', 'extraction_relationships',
            'file_content', 'puzzle_sessions', 'puzzle_steps'
        ]
        
        for table in tables_to_backup:
            try:
                result = db.engine.execute(text(f"SELECT * FROM {table}"))
                data = [dict(row) for row in result]
                
                # Convert datetime objects to strings for JSON serialization
                for row in data:
                    for key, value in row.items():
                        if isinstance(value, datetime):
                            row[key] = value.isoformat()
                
                backup_file = os.path.join(backup_dir, f"{table}_backup.json")
                with open(backup_file, 'w') as f:
                    json.dump(data, f, indent=2, default=str)
                
                logger.info(f"Backed up {len(data)} records from {table}")
                
            except Exception as e:
                logger.error(f"Failed to backup table {table}: {e}")
        
        logger.info(f"Backup completed in {backup_dir}")
    
    def create_agent_tables(self):
        """Create agent system database tables"""
        logger.info("Creating agent system tables...")
        
        try:
            from crypto_hunter_web.models.agent_models import create_agent_tables
            create_agent_tables()
            logger.info("Agent tables created successfully")
        except Exception as e:
            logger.error(f"Failed to create agent tables: {e}")
            raise
    
    def migrate_analysis_files(self):
        """Migrate analysis files to support agent system"""
        logger.info("Migrating analysis files...")
        
        # Add agent-related columns to existing files
        try:
            # Check if agent columns already exist
            result = db.engine.execute(text("""
                SELECT column_name FROM information_schema.columns 
                WHERE table_name = 'analysis_files' AND column_name = 'agent_analysis_status'
            """))
            
            if not result.fetchone():
                # Add new columns for agent tracking
                db.engine.execute(text("""
                    ALTER TABLE analysis_files 
                    ADD COLUMN agent_analysis_status VARCHAR(50) DEFAULT 'pending',
                    ADD COLUMN last_agent_analysis TIMESTAMP,
                    ADD COLUMN agent_analysis_summary JSON
                """))
                logger.info("Added agent tracking columns to analysis_files")
            
            # Update existing files to be ready for agent analysis
            files = AnalysisFile.query.filter(
                AnalysisFile.status == 'completed'
            ).all()
            
            for file in files:
                # Mark for re-analysis with agent system
                db.engine.execute(text("""
                    UPDATE analysis_files 
                    SET agent_analysis_status = 'ready_for_analysis'
                    WHERE id = :file_id
                """), file_id=file.id)
                
                self.migration_stats['files_migrated'] += 1
            
            db.session.commit()
            logger.info(f"Migrated {len(files)} analysis files")
            
        except Exception as e:
            logger.error(f"Failed to migrate analysis files: {e}")
            db.session.rollback()
            raise
    
    def migrate_findings(self):
        """Migrate existing findings to new agent-based format"""
        logger.info("Migrating findings...")
        
        try:
            from crypto_hunter_web.models.agent_models import PatternFinding, CipherAnalysis
            
            findings = Finding.query.all()
            
            for finding in findings:
                # Determine if this is a pattern finding or cipher analysis
                if self._is_crypto_finding(finding):
                    # Create cipher analysis record
                    cipher_analysis = CipherAnalysis(
                        file_id=finding.file_id,
                        cipher_type=self._extract_cipher_type(finding),
                        cipher_name=finding.title,
                        description=finding.description,
                        confidence_score=finding.confidence_score or 0.0,
                        analyzed_by_agent='legacy_migration',
                        created_at=finding.created_at or datetime.utcnow()
                    )
                    db.session.add(cipher_analysis)
                else:
                    # Create pattern finding record
                    pattern_finding = PatternFinding(
                        file_id=finding.file_id,
                        pattern_type=self._extract_pattern_type(finding),
                        pattern_name=finding.title,
                        description=finding.description,
                        confidence_score=finding.confidence_score or 0.0,
                        discovered_by_agent='legacy_migration',
                        created_at=finding.created_at or datetime.utcnow()
                    )
                    db.session.add(pattern_finding)
                
                self.migration_stats['findings_migrated'] += 1
            
            db.session.commit()
            logger.info(f"Migrated {len(findings)} findings")
            
        except Exception as e:
            logger.error(f"Failed to migrate findings: {e}")
            db.session.rollback()
            raise
    
    def migrate_extraction_relationships(self):
        """Migrate extraction relationships to agent format"""
        logger.info("Migrating extraction relationships...")
        
        try:
            from crypto_hunter_web.models.agent_models import FileCorrelation
            
            relationships = ExtractionRelationship.query.all()
            
            for rel in relationships:
                # Create file correlation record
                correlation = FileCorrelation(
                    file1_id=rel.parent_file_id,
                    file2_id=rel.extracted_file_id,
                    correlation_type='extraction_relationship',
                    correlation_strength=1.0,  # Extraction relationships are definitive
                    description=f"Extracted using {rel.extraction_method}",
                    evidence_data={
                        'extraction_method': rel.extraction_method,
                        'extraction_tool': rel.extraction_tool,
                        'parameters': rel.parameters,
                        'legacy_relationship_id': rel.id
                    },
                    discovered_by_agent='legacy_migration',
                    created_at=rel.created_at or datetime.utcnow()
                )
                db.session.add(correlation)
                
                self.migration_stats['relationships_migrated'] += 1
            
            db.session.commit()
            logger.info(f"Migrated {len(relationships)} extraction relationships")
            
        except Exception as e:
            logger.error(f"Failed to migrate extraction relationships: {e}")
            db.session.rollback()
            raise
    
    def update_puzzle_sessions(self):
        """Update puzzle sessions for agent compatibility"""
        logger.info("Updating puzzle sessions...")
        
        try:
            # Add agent columns to puzzle sessions if they don't exist
            result = db.engine.execute(text("""
                SELECT column_name FROM information_schema.columns 
                WHERE table_name = 'puzzle_sessions' AND column_name = 'agent_assistance_level'
            """))
            
            if not result.fetchone():
                db.engine.execute(text("""
                    ALTER TABLE puzzle_sessions 
                    ADD COLUMN agent_assistance_level VARCHAR(20) DEFAULT 'standard',
                    ADD COLUMN agent_insights JSON,
                    ADD COLUMN last_agent_update TIMESTAMP
                """))
                logger.info("Added agent columns to puzzle_sessions")
            
            # Update existing sessions
            sessions = PuzzleSession.query.all()
            
            for session in sessions:
                db.engine.execute(text("""
                    UPDATE puzzle_sessions 
                    SET agent_assistance_level = 'standard',
                        agent_insights = '{}',
                        last_agent_update = :update_time
                    WHERE id = :session_id
                """), update_time=datetime.utcnow(), session_id=session.id)
                
                self.migration_stats['sessions_updated'] += 1
            
            db.session.commit()
            logger.info(f"Updated {len(sessions)} puzzle sessions")
            
        except Exception as e:
            logger.error(f"Failed to update puzzle sessions: {e}")
            db.session.rollback()
            raise
    
    def create_agent_configurations(self):
        """Create initial agent configurations"""
        logger.info("Creating agent configurations...")
        
        try:
            from crypto_hunter_web.models.agent_models import AgentExecution
            
            # Create sample workflow executions for testing
            sample_workflows = [
                {
                    'workflow_id': 'migration_test_001',
                    'workflow_name': 'file_analysis',
                    'status': 'completed',
                    'total_steps': 5,
                    'completed_steps': 5,
                    'success': True
                }
            ]
            
            for workflow_data in sample_workflows:
                from crypto_hunter_web.models.agent_models import WorkflowExecution
                workflow = WorkflowExecution(**workflow_data)
                db.session.add(workflow)
            
            db.session.commit()
            logger.info("Created initial agent configurations")
            
        except Exception as e:
            logger.error(f"Failed to create agent configurations: {e}")
            db.session.rollback()
            raise
    
    def update_app_configuration(self):
        """Update application configuration for agent system"""
        logger.info("Updating application configuration...")
        
        config_updates = {
            'AGENT_SYSTEM_ENABLED': True,
            'LEGACY_EXTRACTION_ENABLED': False,
            'AGENT_MIGRATION_COMPLETED': True,
            'MIGRATION_DATE': datetime.utcnow().isoformat()
        }
        
        # Write configuration updates to a file
        config_file = 'config/agent_migration_config.py'
        os.makedirs(os.path.dirname(config_file), exist_ok=True)
        
        with open(config_file, 'w') as f:
            f.write("# Agent system configuration generated by migration\n")
            f.write(f"# Generated on {datetime.utcnow().isoformat()}\n\n")
            
            for key, value in config_updates.items():
                if isinstance(value, str):
                    f.write(f"{key} = '{value}'\n")
                else:
                    f.write(f"{key} = {value}\n")
        
        logger.info(f"Configuration updates written to {config_file}")
    
    def _is_crypto_finding(self, finding: Finding) -> bool:
        """Determine if a finding is crypto-related"""
        crypto_keywords = [
            'cipher', 'encrypt', 'decrypt', 'key', 'hash', 'base64',
            'crypto', 'encode', 'decode', 'rot13', 'caesar'
        ]
        
        text_to_check = (finding.title + ' ' + (finding.description or '')).lower()
        return any(keyword in text_to_check for keyword in crypto_keywords)
    
    def _extract_cipher_type(self, finding: Finding) -> str:
        """Extract cipher type from finding"""
        title_lower = finding.title.lower()
        
        if 'base64' in title_lower:
            return 'base64'
        elif 'rot13' in title_lower or 'caesar' in title_lower:
            return 'caesar'
        elif 'hex' in title_lower:
            return 'hexadecimal'
        elif 'encrypt' in title_lower:
            return 'encrypted_content'
        else:
            return 'unknown'
    
    def _extract_pattern_type(self, finding: Finding) -> str:
        """Extract pattern type from finding"""
        title_lower = finding.title.lower()
        
        if 'steg' in title_lower:
            return 'steganography'
        elif 'string' in title_lower:
            return 'string_pattern'
        elif 'metadata' in title_lower:
            return 'metadata'
        elif 'binary' in title_lower:
            return 'binary_pattern'
        else:
            return 'general'
    
    def print_migration_summary(self):
        """Print migration summary"""
        print("\n" + "="*60)
        print("MIGRATION SUMMARY")
        print("="*60)
        print(f"Files migrated: {self.migration_stats['files_migrated']}")
        print(f"Findings migrated: {self.migration_stats['findings_migrated']}")
        print(f"Relationships migrated: {self.migration_stats['relationships_migrated']}")
        print(f"Sessions updated: {self.migration_stats['sessions_updated']}")
        
        if self.migration_stats['errors']:
            print(f"\nErrors encountered: {len(self.migration_stats['errors'])}")
            for error in self.migration_stats['errors']:
                print(f"  - {error}")
        else:
            print("\n✅ Migration completed without errors!")
        
        print("\nNext steps:")
        print("1. Test the agent system with sample files")
        print("2. Update your application to use the new agent endpoints")
        print("3. Monitor agent performance and adjust configurations")
        print("4. Consider removing legacy extraction code after validation")
        print("="*60)


def validate_migration():
    """Validate that migration was successful"""
    app = create_app()
    
    with app.app_context():
        print("Validating migration...")
        
        # Check agent tables exist
        try:
            from crypto_hunter_web.models.agent_models import AgentExecution, PatternFinding
            agent_count = AgentExecution.query.count()
            pattern_count = PatternFinding.query.count()
            print(f"✅ Agent tables accessible - {agent_count} executions, {pattern_count} patterns")
        except Exception as e:
            print(f"❌ Agent tables validation failed: {e}")
            return False
        
        # Check file migration
        try:
            result = db.engine.execute(text("""
                SELECT COUNT(*) as count FROM analysis_files 
                WHERE agent_analysis_status IS NOT NULL
            """))
            migrated_files = result.fetchone()[0]
            print(f"✅ {migrated_files} files ready for agent analysis")
        except Exception as e:
            print(f"❌ File migration validation failed: {e}")
            return False
        
        # Check agent system can be initialized
        try:
            from crypto_hunter_web.services.agent_extraction_service import AgentExtractionService
            service = AgentExtractionService()
            service.initialize()
            print("✅ Agent system initializes successfully")
        except Exception as e:
            print(f"❌ Agent system validation failed: {e}")
            return False
        
        print("🎉 Migration validation completed successfully!")
        return True


def rollback_migration():
    """Rollback migration if needed"""
    app = create_app()
    
    with app.app_context():
        print("Rolling back migration...")
        
        try:
            # Remove agent columns from existing tables
            db.engine.execute(text("""
                ALTER TABLE analysis_files 
                DROP COLUMN IF EXISTS agent_analysis_status,
                DROP COLUMN IF EXISTS last_agent_analysis,
                DROP COLUMN IF EXISTS agent_analysis_summary
            """))
            
            db.engine.execute(text("""
                ALTER TABLE puzzle_sessions 
                DROP COLUMN IF EXISTS agent_assistance_level,
                DROP COLUMN IF EXISTS agent_insights,
                DROP COLUMN IF EXISTS last_agent_update
            """))
            
            # Drop agent tables
            agent_tables = [
                'session_intelligence', 'file_correlations', 'cipher_analyses',
                'pattern_findings', 'workflow_executions', 'agent_executions'
            ]
            
            for table in agent_tables:
                try:
                    db.engine.execute(text(f"DROP TABLE IF EXISTS {table} CASCADE"))
                    print(f"Dropped table {table}")
                except Exception as e:
                    print(f"Warning: Could not drop table {table}: {e}")
            
            print("✅ Migration rollback completed")
            
        except Exception as e:
            print(f"❌ Rollback failed: {e}")
            raise


if __name__ == '__main__':
    import argparse
    
    parser = argparse.ArgumentParser(description='Migrate from legacy to agent system')
    parser.add_argument('--action', choices=['migrate', 'validate', 'rollback'], 
                       default='migrate', help='Action to perform')
    parser.add_argument('--dry-run', action='store_true', 
                       help='Perform migration without making changes')
    parser.add_argument('--no-backup', action='store_true', 
                       help='Skip backup creation')
    
    args = parser.parse_args()
    
    # Configure logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    if args.action == 'migrate':
        migration = LegacyToAgentMigration()
        migration.initialize()
        migration.run_full_migration(
            backup_data=not args.no_backup,
            dry_run=args.dry_run
        )
    elif args.action == 'validate':
        validate_migration()
    elif args.action == 'rollback':
        rollback_migration()
