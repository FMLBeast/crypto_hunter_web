"""
crypto_hunter_web/migrations/create_agent_tables.py
Database migration script for agent system tables
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql
import uuid

# Revision identifiers
revision = 'agent_system_001'
down_revision = 'existing_base'  # Replace with your actual base revision
branch_labels = None
depends_on = None


def upgrade():
    """Create agent system tables"""
    
    # 1. Create agent_executions table
    op.create_table(
        'agent_executions',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('public_id', postgresql.UUID(as_uuid=True), nullable=False, default=uuid.uuid4),
        sa.Column('task_id', sa.String(255), nullable=False),
        sa.Column('task_type', sa.String(100), nullable=False),
        sa.Column('agent_id', sa.String(255), nullable=False),
        sa.Column('agent_type', sa.String(50), nullable=False),
        sa.Column('workflow_id', sa.String(255), nullable=True),
        sa.Column('parent_task_id', sa.String(255), nullable=True),
        sa.Column('session_id', sa.String(255), nullable=True),
        sa.Column('status', sa.String(20), nullable=False, default='pending'),
        sa.Column('priority', sa.Integer(), nullable=False, default=3),
        sa.Column('created_at', sa.TIMESTAMP(), nullable=False, default=sa.text('CURRENT_TIMESTAMP')),
        sa.Column('started_at', sa.TIMESTAMP(), nullable=True),
        sa.Column('completed_at', sa.TIMESTAMP(), nullable=True),
        sa.Column('execution_time', sa.Float(), nullable=True),
        sa.Column('input_data', postgresql.JSON(astext_type=sa.Text()), nullable=True, default={}),
        sa.Column('output_data', postgresql.JSON(astext_type=sa.Text()), nullable=True, default={}),
        sa.Column('error_message', sa.Text(), nullable=True),
        sa.Column('warnings', postgresql.JSON(astext_type=sa.Text()), nullable=True, default=[]),
        sa.Column('metadata', postgresql.JSON(astext_type=sa.Text()), nullable=True, default={}),
        sa.Column('success', sa.Boolean(), nullable=True),
        sa.Column('confidence_score', sa.Float(), nullable=True),
        sa.PrimaryKeyConstraint('id')
    )
    
    # Create indexes for agent_executions
    op.create_index('idx_agent_exec_task', 'agent_executions', ['task_id'])
    op.create_index('idx_agent_exec_agent', 'agent_executions', ['agent_id'])
    op.create_index('idx_agent_exec_status', 'agent_executions', ['status'])
    op.create_index('idx_agent_exec_created', 'agent_executions', ['created_at'])
    op.create_index('idx_agent_exec_workflow', 'agent_executions', ['workflow_id'])
    op.create_index('idx_agent_exec_public_id', 'agent_executions', ['public_id'], unique=True)
    
    # 2. Create workflow_executions table
    op.create_table(
        'workflow_executions',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('public_id', postgresql.UUID(as_uuid=True), nullable=False, default=uuid.uuid4),
        sa.Column('workflow_id', sa.String(255), nullable=False, unique=True),
        sa.Column('workflow_name', sa.String(100), nullable=False),
        sa.Column('session_id', sa.String(255), nullable=True),
        sa.Column('status', sa.String(20), nullable=False, default='pending'),
        sa.Column('created_at', sa.TIMESTAMP(), nullable=False, default=sa.text('CURRENT_TIMESTAMP')),
        sa.Column('started_at', sa.TIMESTAMP(), nullable=True),
        sa.Column('completed_at', sa.TIMESTAMP(), nullable=True),
        sa.Column('total_steps', sa.Integer(), nullable=False, default=0),
        sa.Column('completed_steps', sa.Integer(), nullable=False, default=0),
        sa.Column('failed_steps', sa.Integer(), nullable=False, default=0),
        sa.Column('initial_data', postgresql.JSON(astext_type=sa.Text()), nullable=True, default={}),
        sa.Column('final_data', postgresql.JSON(astext_type=sa.Text()), nullable=True, default={}),
        sa.Column('error_message', sa.Text(), nullable=True),
        sa.Column('success', sa.Boolean(), nullable=True),
        sa.PrimaryKeyConstraint('id')
    )
    
    # Create indexes for workflow_executions
    op.create_index('idx_workflow_exec_id', 'workflow_executions', ['workflow_id'])
    op.create_index('idx_workflow_exec_status', 'workflow_executions', ['status'])
    op.create_index('idx_workflow_exec_created', 'workflow_executions', ['created_at'])
    op.create_index('idx_workflow_exec_session', 'workflow_executions', ['session_id'])
    op.create_index('idx_workflow_exec_public_id', 'workflow_executions', ['public_id'], unique=True)
    
    # 3. Create pattern_findings table
    op.create_table(
        'pattern_findings',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('public_id', postgresql.UUID(as_uuid=True), nullable=False, default=uuid.uuid4),
        sa.Column('file_id', sa.Integer(), nullable=False),
        sa.Column('pattern_type', sa.String(100), nullable=False),
        sa.Column('pattern_name', sa.String(255), nullable=False),
        sa.Column('start_offset', sa.BigInteger(), nullable=True),
        sa.Column('end_offset', sa.BigInteger(), nullable=True),
        sa.Column('confidence_score', sa.Float(), nullable=False, default=0.0),
        sa.Column('pattern_data', postgresql.JSON(astext_type=sa.Text()), nullable=True, default={}),
        sa.Column('discovered_by_agent', sa.String(255), nullable=True),
        sa.Column('agent_execution_id', sa.Integer(), nullable=True),
        sa.Column('is_active', sa.Boolean(), nullable=False, default=True),
        sa.Column('is_validated', sa.Boolean(), nullable=False, default=False),
        sa.Column('created_at', sa.TIMESTAMP(), nullable=False, default=sa.text('CURRENT_TIMESTAMP')),
        sa.Column('validated_at', sa.TIMESTAMP(), nullable=True),
        sa.PrimaryKeyConstraint('id'),
        sa.ForeignKeyConstraint(['file_id'], ['analysis_files.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['agent_execution_id'], ['agent_executions.id'], ondelete='SET NULL')
    )
    
    # Create indexes for pattern_findings
    op.create_index('idx_pattern_file', 'pattern_findings', ['file_id'])
    op.create_index('idx_pattern_agent', 'pattern_findings', ['discovered_by_agent'])
    op.create_index('idx_pattern_type', 'pattern_findings', ['pattern_type'])
    op.create_index('idx_pattern_confidence', 'pattern_findings', ['confidence_score'])
    op.create_index('idx_pattern_public_id', 'pattern_findings', ['public_id'], unique=True)
    
    # 4. Create cipher_analyses table
    op.create_table(
        'cipher_analyses',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('public_id', postgresql.UUID(as_uuid=True), nullable=False, default=uuid.uuid4),
        sa.Column('file_id', sa.Integer(), nullable=False),
        sa.Column('cipher_type', sa.String(100), nullable=False),
        sa.Column('cipher_name', sa.String(255), nullable=True),
        sa.Column('confidence_score', sa.Float(), nullable=False, default=0.0),
        sa.Column('key_candidates', postgresql.JSON(astext_type=sa.Text()), nullable=True, default=[]),
        sa.Column('is_solved', sa.Boolean(), nullable=False, default=False),
        sa.Column('solution_text', sa.Text(), nullable=True),
        sa.Column('solution_key', sa.String(500), nullable=True),
        sa.Column('frequency_analysis', postgresql.JSON(astext_type=sa.Text()), nullable=True, default={}),
        sa.Column('analysis_method', sa.String(100), nullable=True),
        sa.Column('analysis_data', postgresql.JSON(astext_type=sa.Text()), nullable=True, default={}),
        sa.Column('discovered_by_agent', sa.String(255), nullable=True),
        sa.Column('agent_execution_id', sa.Integer(), nullable=True),
        sa.Column('is_active', sa.Boolean(), nullable=False, default=True),
        sa.Column('is_validated', sa.Boolean(), nullable=False, default=False),
        sa.Column('created_at', sa.TIMESTAMP(), nullable=False, default=sa.text('CURRENT_TIMESTAMP')),
        sa.Column('solved_at', sa.TIMESTAMP(), nullable=True),
        sa.Column('validated_at', sa.TIMESTAMP(), nullable=True),
        sa.PrimaryKeyConstraint('id'),
        sa.ForeignKeyConstraint(['file_id'], ['analysis_files.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['agent_execution_id'], ['agent_executions.id'], ondelete='SET NULL')
    )
    
    # Create indexes for cipher_analyses
    op.create_index('idx_cipher_file', 'cipher_analyses', ['file_id'])
    op.create_index('idx_cipher_type', 'cipher_analyses', ['cipher_type'])
    op.create_index('idx_cipher_solved', 'cipher_analyses', ['is_solved'])
    op.create_index('idx_cipher_agent', 'cipher_analyses', ['discovered_by_agent'])
    op.create_index('idx_cipher_public_id', 'cipher_analyses', ['public_id'], unique=True)
    
    # 5. Create file_correlations table
    op.create_table(
        'file_correlations',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('public_id', postgresql.UUID(as_uuid=True), nullable=False, default=uuid.uuid4),
        sa.Column('file1_id', sa.Integer(), nullable=False),
        sa.Column('file2_id', sa.Integer(), nullable=False),
        sa.Column('correlation_type', sa.String(100), nullable=False),
        sa.Column('correlation_strength', sa.Float(), nullable=False),
        sa.Column('evidence_data', postgresql.JSON(astext_type=sa.Text()), nullable=True, default={}),
        sa.Column('discovered_by_agent', sa.String(255), nullable=True),
        sa.Column('agent_execution_id', sa.Integer(), nullable=True),
        sa.Column('is_active', sa.Boolean(), nullable=False, default=True),
        sa.Column('is_validated', sa.Boolean(), nullable=False, default=False),
        sa.Column('created_at', sa.TIMESTAMP(), nullable=False, default=sa.text('CURRENT_TIMESTAMP')),
        sa.Column('validated_at', sa.TIMESTAMP(), nullable=True),
        sa.PrimaryKeyConstraint('id'),
        sa.ForeignKeyConstraint(['file1_id'], ['analysis_files.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['file2_id'], ['analysis_files.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['agent_execution_id'], ['agent_executions.id'], ondelete='SET NULL'),
        sa.CheckConstraint('file1_id != file2_id', name='check_different_files')
    )
    
    # Create indexes for file_correlations
    op.create_index('idx_correlation_file1', 'file_correlations', ['file1_id'])
    op.create_index('idx_correlation_file2', 'file_correlations', ['file2_id'])
    op.create_index('idx_correlation_type', 'file_correlations', ['correlation_type'])
    op.create_index('idx_correlation_strength', 'file_correlations', ['correlation_strength'])
    op.create_index('idx_correlation_agent', 'file_correlations', ['discovered_by_agent'])
    op.create_index('idx_correlation_public_id', 'file_correlations', ['public_id'], unique=True)
    
    # 6. Create session_intelligence table
    op.create_table(
        'session_intelligence',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('public_id', postgresql.UUID(as_uuid=True), nullable=False, default=uuid.uuid4),
        sa.Column('session_id', sa.String(255), nullable=False),
        sa.Column('intelligence_type', sa.String(100), nullable=False),
        sa.Column('title', sa.String(500), nullable=False),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('confidence_score', sa.Float(), nullable=False, default=0.0),
        sa.Column('supporting_evidence', postgresql.JSON(astext_type=sa.Text()), nullable=True, default=[]),
        sa.Column('recommendations', postgresql.JSON(astext_type=sa.Text()), nullable=True, default=[]),
        sa.Column('intelligence_data', postgresql.JSON(astext_type=sa.Text()), nullable=True, default={}),
        sa.Column('generated_by_agent', sa.String(255), nullable=True),
        sa.Column('agent_execution_id', sa.Integer(), nullable=True),
        sa.Column('is_active', sa.Boolean(), nullable=False, default=True),
        sa.Column('is_validated', sa.Boolean(), nullable=False, default=False),
        sa.Column('created_at', sa.TIMESTAMP(), nullable=False, default=sa.text('CURRENT_TIMESTAMP')),
        sa.Column('validated_at', sa.TIMESTAMP(), nullable=True),
        sa.PrimaryKeyConstraint('id'),
        sa.ForeignKeyConstraint(['session_id'], ['puzzle_sessions.session_id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['agent_execution_id'], ['agent_executions.id'], ondelete='SET NULL')
    )
    
    # Create indexes for session_intelligence
    op.create_index('idx_intel_session', 'session_intelligence', ['session_id'])
    op.create_index('idx_intel_type', 'session_intelligence', ['intelligence_type'])
    op.create_index('idx_intel_confidence', 'session_intelligence', ['confidence_score'])
    op.create_index('idx_intel_agent', 'session_intelligence', ['generated_by_agent'])
    op.create_index('idx_intel_public_id', 'session_intelligence', ['public_id'], unique=True)
    
    # 7. Add agent-related columns to existing tables
    
    # Enhance analysis_files table
    op.add_column('analysis_files', sa.Column('agent_analysis_status', sa.String(50), nullable=True))
    op.add_column('analysis_files', sa.Column('last_agent_analysis', sa.TIMESTAMP(), nullable=True))
    op.add_column('analysis_files', sa.Column('agent_analysis_summary', postgresql.JSON(astext_type=sa.Text()), nullable=True, default={}))
    op.add_column('analysis_files', sa.Column('agent_confidence_score', sa.Float(), nullable=True))
    
    # Enhance puzzle_sessions table
    op.add_column('puzzle_sessions', sa.Column('agent_assistance_level', sa.String(20), nullable=True, default='medium'))
    op.add_column('puzzle_sessions', sa.Column('agent_insights', postgresql.JSON(astext_type=sa.Text()), nullable=True, default={}))
    op.add_column('puzzle_sessions', sa.Column('last_agent_update', sa.TIMESTAMP(), nullable=True))
    op.add_column('puzzle_sessions', sa.Column('active_workflows', postgresql.JSON(astext_type=sa.Text()), nullable=True, default=[]))
    
    # Create indexes for new columns
    op.create_index('idx_analysis_files_agent_status', 'analysis_files', ['agent_analysis_status'])
    op.create_index('idx_puzzle_sessions_agent_level', 'puzzle_sessions', ['agent_assistance_level'])


def downgrade():
    """Remove agent system tables"""
    
    # Remove indexes first
    op.drop_index('idx_puzzle_sessions_agent_level', 'puzzle_sessions')
    op.drop_index('idx_analysis_files_agent_status', 'analysis_files')
    
    # Remove columns from existing tables
    op.drop_column('puzzle_sessions', 'active_workflows')
    op.drop_column('puzzle_sessions', 'last_agent_update')
    op.drop_column('puzzle_sessions', 'agent_insights')
    op.drop_column('puzzle_sessions', 'agent_assistance_level')
    
    op.drop_column('analysis_files', 'agent_confidence_score')
    op.drop_column('analysis_files', 'agent_analysis_summary')
    op.drop_column('analysis_files', 'last_agent_analysis')
    op.drop_column('analysis_files', 'agent_analysis_status')
    
    # Drop agent tables in reverse order
    op.drop_table('session_intelligence')
    op.drop_table('file_correlations')
    op.drop_table('cipher_analyses')
    op.drop_table('pattern_findings')
    op.drop_table('workflow_executions')
    op.drop_table('agent_executions')


# Data migration functions
def migrate_existing_data():
    """Migrate existing analysis data to agent format"""
    from sqlalchemy.orm import Session
    from sqlalchemy import create_engine
    import os
    
    # Get database URL from environment
    database_url = os.environ.get('DATABASE_URL')
    if not database_url:
        print("Warning: No DATABASE_URL found, skipping data migration")
        return
    
    engine = create_engine(database_url)
    session = Session(engine)
    
    try:
        # Migrate existing findings to pattern_findings
        print("Migrating existing findings to pattern_findings...")
        
        # This is a simplified migration - adjust based on your existing schema
        existing_findings = session.execute("""
            SELECT id, file_id, finding_type, content, confidence, created_at 
            FROM findings 
            WHERE finding_type IN ('pattern', 'signature', 'anomaly')
        """).fetchall()
        
        for finding in existing_findings:
            session.execute("""
                INSERT INTO pattern_findings 
                (file_id, pattern_type, pattern_name, confidence_score, pattern_data, created_at)
                VALUES (%s, %s, %s, %s, %s, %s)
            """, (
                finding.file_id,
                finding.finding_type,
                f"Legacy {finding.finding_type}",
                finding.confidence or 0.5,
                {'legacy_content': finding.content},
                finding.created_at
            ))
        
        print(f"Migrated {len(existing_findings)} existing findings")
        
        # Migrate existing extractions to create relationships
        print("Creating file relationships from existing extractions...")
        
        existing_extractions = session.execute("""
            SELECT source_file_id, extracted_file_id, extractor_name, created_at
            FROM extraction_relationships
        """).fetchall()
        
        for extraction in existing_extractions:
            session.execute("""
                INSERT INTO file_correlations 
                (file1_id, file2_id, correlation_type, correlation_strength, evidence_data, created_at)
                VALUES (%s, %s, %s, %s, %s, %s)
            """, (
                extraction.source_file_id,
                extraction.extracted_file_id,
                'extraction_relationship',
                1.0,  # High confidence for actual extractions
                {'extractor': extraction.extractor_name, 'type': 'legacy_extraction'},
                extraction.created_at
            ))
        
        print(f"Migrated {len(existing_extractions)} extraction relationships")
        
        session.commit()
        print("✅ Data migration completed successfully")
        
    except Exception as e:
        session.rollback()
        print(f"❌ Data migration failed: {e}")
        raise
    finally:
        session.close()


def create_initial_agent_config():
    """Create initial agent configuration data"""
    from sqlalchemy.orm import Session
    from sqlalchemy import create_engine
    import os
    
    database_url = os.environ.get('DATABASE_URL')
    if not database_url:
        return
    
    engine = create_engine(database_url)
    session = Session(engine)
    
    try:
        # Create sample workflow execution for testing
        session.execute("""
            INSERT INTO workflow_executions 
            (workflow_id, workflow_name, status, total_steps, completed_steps, initial_data)
            VALUES 
            ('sample_workflow_001', 'file_analysis', 'completed', 5, 5, '{"test": true}')
        """)
        
        print("✅ Initial agent configuration created")
        session.commit()
        
    except Exception as e:
        session.rollback()
        print(f"Warning: Could not create initial config: {e}")
    finally:
        session.close()


# Utility functions for manual migration
def run_migration():
    """Run the complete migration process"""
    print("🚀 Starting agent system database migration...")
    
    try:
        # Run the main migration
        upgrade()
        print("✅ Database schema migration completed")
        
        # Migrate existing data
        migrate_existing_data()
        print("✅ Data migration completed")
        
        # Create initial configuration
        create_initial_agent_config()
        print("✅ Initial configuration created")
        
        print("🎉 Agent system migration completed successfully!")
        
    except Exception as e:
        print(f"❌ Migration failed: {e}")
        raise


def rollback_migration():
    """Rollback the migration"""
    print("🔄 Rolling back agent system migration...")
    
    try:
        downgrade()
        print("✅ Migration rollback completed")
        
    except Exception as e:
        print(f"❌ Rollback failed: {e}")
        raise


if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python create_agent_tables.py [upgrade|downgrade|migrate|rollback]")
        sys.exit(1)
    
    command = sys.argv[1].lower()
    
    if command == "upgrade":
        upgrade()
    elif command == "downgrade":
        downgrade()
    elif command == "migrate":
        run_migration()
    elif command == "rollback":
        rollback_migration()
    else:
        print(f"Unknown command: {command}")
        print("Available commands: upgrade, downgrade, migrate, rollback")
        sys.exit(1)