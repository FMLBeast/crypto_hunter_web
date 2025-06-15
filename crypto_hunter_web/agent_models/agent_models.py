"""
crypto_hunter_web/models/agent_models.py
Database models for agent framework tracking
"""

from datetime import datetime
from sqlalchemy.dialects.postgresql import UUID, JSON
from sqlalchemy import Index, text
import uuid

from crypto_hunter_web.extensions import db


class AgentExecution(db.Model):
    """Track agent task executions"""
    __tablename__ = 'agent_executions'
    __table_args__ = (
        Index('idx_agent_exec_task', 'task_id'),
        Index('idx_agent_exec_agent', 'agent_id'),
        Index('idx_agent_exec_status', 'status'),
        Index('idx_agent_exec_created', 'created_at'),
        Index('idx_agent_exec_workflow', 'workflow_id'),
    )

    id = db.Column(db.Integer, primary_key=True)
    public_id = db.Column(UUID(as_uuid=True), default=uuid.uuid4, unique=True, nullable=False, index=True)
    
    # Task identification
    task_id = db.Column(db.String(255), nullable=False, index=True)
    task_type = db.Column(db.String(100), nullable=False)
    agent_id = db.Column(db.String(255), nullable=False)
    agent_type = db.Column(db.String(50), nullable=False)
    
    # Workflow tracking
    workflow_id = db.Column(db.String(255), index=True)
    parent_task_id = db.Column(db.String(255), index=True)
    session_id = db.Column(db.String(255), index=True)
    
    # Execution status
    status = db.Column(db.String(20), default='pending', nullable=False)  # pending, running, completed, failed, cancelled
    priority = db.Column(db.Integer, default=3)
    
    # Timing
    created_at = db.Column(db.TIMESTAMP, default=datetime.utcnow, nullable=False)
    started_at = db.Column(db.TIMESTAMP)
    completed_at = db.Column(db.TIMESTAMP)
    execution_time = db.Column(db.Float)  # seconds
    
    # Data
    input_data = db.Column(JSON, default=dict)
    output_data = db.Column(JSON, default=dict)
    error_message = db.Column(db.Text)
    warnings = db.Column(JSON, default=list)
    metadata = db.Column(JSON, default=dict)
    
    # Results
    success = db.Column(db.Boolean)
    confidence_score = db.Column(db.Float)
    
    def to_dict(self):
        return {
            'id': self.id,
            'public_id': str(self.public_id),
            'task_id': self.task_id,
            'task_type': self.task_type,
            'agent_id': self.agent_id,
            'agent_type': self.agent_type,
            'workflow_id': self.workflow_id,
            'status': self.status,
            'priority': self.priority,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'started_at': self.started_at.isoformat() if self.started_at else None,
            'completed_at': self.completed_at.isoformat() if self.completed_at else None,
            'execution_time': self.execution_time,
            'success': self.success,
            'error_message': self.error_message,
            'confidence_score': self.confidence_score
        }

    def __repr__(self):
        return f'<AgentExecution {self.task_id} ({self.status})>'


class WorkflowExecution(db.Model):
    """Track workflow executions"""
    __tablename__ = 'workflow_executions'
    __table_args__ = (
        Index('idx_workflow_exec_id', 'workflow_id'),
        Index('idx_workflow_exec_status', 'status'),
        Index('idx_workflow_exec_created', 'created_at'),
        Index('idx_workflow_exec_session', 'session_id'),
    )

    id = db.Column(db.Integer, primary_key=True)
    public_id = db.Column(UUID(as_uuid=True), default=uuid.uuid4, unique=True, nullable=False, index=True)
    
    # Workflow identification
    workflow_id = db.Column(db.String(255), nullable=False, unique=True, index=True)
    workflow_name = db.Column(db.String(100), nullable=False)
    session_id = db.Column(db.String(255), index=True)
    
    # Status
    status = db.Column(db.String(20), default='pending', nullable=False)
    
    # Timing
    created_at = db.Column(db.TIMESTAMP, default=datetime.utcnow, nullable=False)
    started_at = db.Column(db.TIMESTAMP)
    completed_at = db.Column(db.TIMESTAMP)
    
    # Progress tracking
    total_steps = db.Column(db.Integer, default=0)
    completed_steps = db.Column(db.Integer, default=0)
    failed_steps = db.Column(db.Integer, default=0)
    
    # Data
    initial_data = db.Column(JSON, default=dict)
    final_data = db.Column(JSON, default=dict)
    error_message = db.Column(db.Text)
    
    # Results
    success = db.Column(db.Boolean)
    
    def to_dict(self):
        return {
            'id': self.id,
            'public_id': str(self.public_id),
            'workflow_id': self.workflow_id,
            'workflow_name': self.workflow_name,
            'session_id': self.session_id,
            'status': self.status,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'started_at': self.started_at.isoformat() if self.started_at else None,
            'completed_at': self.completed_at.isoformat() if self.completed_at else None,
            'total_steps': self.total_steps,
            'completed_steps': self.completed_steps,
            'failed_steps': self.failed_steps,
            'success': self.success,
            'error_message': self.error_message
        }

    def __repr__(self):
        return f'<WorkflowExecution {self.workflow_id} ({self.status})>'


class PatternFinding(db.Model):
    """Store pattern findings from agents"""
    __tablename__ = 'pattern_findings'
    __table_args__ = (
        Index('idx_pattern_file', 'file_id'),
        Index('idx_pattern_agent', 'discovered_by_agent'),
        Index('idx_pattern_type', 'pattern_type'),
        Index('idx_pattern_confidence', 'confidence_score'),
    )

    id = db.Column(db.Integer, primary_key=True)
    public_id = db.Column(UUID(as_uuid=True), default=uuid.uuid4, unique=True, nullable=False, index=True)
    
    # File association
    file_id = db.Column(db.Integer, db.ForeignKey('analysis_files.id'), nullable=False)
    
    # Pattern information
    pattern_type = db.Column(db.String(100), nullable=False)
    pattern_name = db.Column(db.String(255))
    description = db.Column(db.Text)
    
    # Location within file
    start_offset = db.Column(db.BigInteger)
    end_offset = db.Column(db.BigInteger)
    
    # Analysis results
    confidence_score = db.Column(db.Float, default=0.0)
    pattern_data = db.Column(JSON, default=dict)
    
    # Discovery tracking
    discovered_by_agent = db.Column(db.String(255))
    agent_execution_id = db.Column(db.Integer, db.ForeignKey('agent_executions.id'))
    
    # Timestamps
    created_at = db.Column(db.TIMESTAMP, default=datetime.utcnow, nullable=False)
    
    # Relationships
    file = db.relationship('AnalysisFile', backref='pattern_findings')
    execution = db.relationship('AgentExecution', backref='pattern_findings')

    def __repr__(self):
        return f'<PatternFinding {self.pattern_type}: {self.pattern_name}>'


class CipherAnalysis(db.Model):
    """Store cipher analysis results from crypto agents"""
    __tablename__ = 'cipher_analyses'
    __table_args__ = (
        Index('idx_cipher_file', 'file_id'),
        Index('idx_cipher_type', 'cipher_type'),
        Index('idx_cipher_confidence', 'confidence_score'),
        Index('idx_cipher_agent', 'analyzed_by_agent'),
    )

    id = db.Column(db.Integer, primary_key=True)
    public_id = db.Column(UUID(as_uuid=True), default=uuid.uuid4, unique=True, nullable=False, index=True)
    
    # File association
    file_id = db.Column(db.Integer, db.ForeignKey('analysis_files.id'))
    content_text = db.Column(db.Text)  # For text-based cipher analysis
    
    # Cipher information
    cipher_type = db.Column(db.String(100), nullable=False)
    cipher_name = db.Column(db.String(255))
    description = db.Column(db.Text)
    
    # Analysis results
    confidence_score = db.Column(db.Float, default=0.0)
    key_candidates = db.Column(JSON, default=list)
    decryption_attempts = db.Column(JSON, default=list)
    frequency_analysis = db.Column(JSON, default=dict)
    
    # Success tracking
    is_solved = db.Column(db.Boolean, default=False)
    solution_text = db.Column(db.Text)
    solution_key = db.Column(db.String(255))
    
    # Discovery tracking
    analyzed_by_agent = db.Column(db.String(255))
    agent_execution_id = db.Column(db.Integer, db.ForeignKey('agent_executions.id'))
    
    # Timestamps
    created_at = db.Column(db.TIMESTAMP, default=datetime.utcnow, nullable=False)
    
    # Relationships
    file = db.relationship('AnalysisFile', backref='cipher_analyses')
    execution = db.relationship('AgentExecution', backref='cipher_analyses')

    def __repr__(self):
        return f'<CipherAnalysis {self.cipher_type}: {self.cipher_name}>'


class FileCorrelation(db.Model):
    """Store correlations between files discovered by agents"""
    __tablename__ = 'file_correlations'
    __table_args__ = (
        Index('idx_correlation_file1', 'file1_id'),
        Index('idx_correlation_file2', 'file2_id'),
        Index('idx_correlation_type', 'correlation_type'),
        Index('idx_correlation_strength', 'correlation_strength'),
    )

    id = db.Column(db.Integer, primary_key=True)
    public_id = db.Column(UUID(as_uuid=True), default=uuid.uuid4, unique=True, nullable=False, index=True)
    
    # File relationships
    file1_id = db.Column(db.Integer, db.ForeignKey('analysis_files.id'), nullable=False)
    file2_id = db.Column(db.Integer, db.ForeignKey('analysis_files.id'), nullable=False)
    
    # Correlation information
    correlation_type = db.Column(db.String(100), nullable=False)  # content_similarity, extraction_relationship, etc.
    correlation_strength = db.Column(db.Float, default=0.0)  # 0.0 to 1.0
    description = db.Column(db.Text)
    
    # Supporting evidence
    evidence_data = db.Column(JSON, default=dict)
    
    # Discovery tracking
    discovered_by_agent = db.Column(db.String(255))
    agent_execution_id = db.Column(db.Integer, db.ForeignKey('agent_executions.id'))
    
    # Timestamps
    created_at = db.Column(db.TIMESTAMP, default=datetime.utcnow, nullable=False)
    
    # Relationships
    file1 = db.relationship('AnalysisFile', foreign_keys=[file1_id], backref='correlations_as_file1')
    file2 = db.relationship('AnalysisFile', foreign_keys=[file2_id], backref='correlations_as_file2')
    execution = db.relationship('AgentExecution', backref='file_correlations')

    def __repr__(self):
        return f'<FileCorrelation {self.correlation_type}: {self.correlation_strength:.2f}>'


class SessionIntelligence(db.Model):
    """Store intelligence synthesis for puzzle sessions"""
    __tablename__ = 'session_intelligence'
    __table_args__ = (
        Index('idx_intel_session', 'session_id'),
        Index('idx_intel_confidence', 'confidence_score'),
        Index('idx_intel_created', 'created_at'),
    )

    id = db.Column(db.Integer, primary_key=True)
    public_id = db.Column(UUID(as_uuid=True), default=uuid.uuid4, unique=True, nullable=False, index=True)
    
    # Session association
    session_id = db.Column(db.Integer, db.ForeignKey('puzzle_sessions.id'), nullable=False)
    
    # Intelligence data
    intelligence_type = db.Column(db.String(100), nullable=False)  # synthesis, hypothesis, recommendation
    title = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text)
    
    # Analysis results
    confidence_score = db.Column(db.Float, default=0.0)
    supporting_evidence = db.Column(JSON, default=list)
    recommendations = db.Column(JSON, default=list)
    
    # Intelligence data
    intelligence_data = db.Column(JSON, default=dict)
    
    # Discovery tracking
    generated_by_agent = db.Column(db.String(255))
    agent_execution_id = db.Column(db.Integer, db.ForeignKey('agent_executions.id'))
    
    # Status
    is_active = db.Column(db.Boolean, default=True)
    is_validated = db.Column(db.Boolean, default=False)
    
    # Timestamps
    created_at = db.Column(db.TIMESTAMP, default=datetime.utcnow, nullable=False)
    validated_at = db.Column(db.TIMESTAMP)
    
    # Relationships
    session = db.relationship('PuzzleSession', backref='intelligence')
    execution = db.relationship('AgentExecution', backref='session_intelligence')

    def __repr__(self):
        return f'<SessionIntelligence {self.intelligence_type}: {self.title}>'


# Update existing models file
def add_agent_models_to_init():
    """
    Add this to your crypto_hunter_web/models/__init__.py file:
    """
    agent_models_import = '''
# Agent framework models
from .agent_models import (
    AgentExecution, WorkflowExecution, PatternFinding, 
    CipherAnalysis, FileCorrelation, SessionIntelligence
)

__all__.extend([
    'AgentExecution', 'WorkflowExecution', 'PatternFinding',
    'CipherAnalysis', 'FileCorrelation', 'SessionIntelligence'
])
'''
    return agent_models_import


# Database migration script
def create_agent_tables():
    """
    Create agent-related database tables
    """
    from crypto_hunter_web.extensions import db
    
    # Create all agent tables
    AgentExecution.__table__.create(db.engine, checkfirst=True)
    WorkflowExecution.__table__.create(db.engine, checkfirst=True)
    PatternFinding.__table__.create(db.engine, checkfirst=True)
    CipherAnalysis.__table__.create(db.engine, checkfirst=True)
    FileCorrelation.__table__.create(db.engine, checkfirst=True)
    SessionIntelligence.__table__.create(db.engine, checkfirst=True)
    
    # Create indexes
    try:
        # Agent execution indexes
        db.engine.execute(text('''
            CREATE INDEX IF NOT EXISTS idx_agent_exec_composite 
                ON agent_executions(status, agent_type, created_at)
        '''))
        
        # Pattern finding full-text search
        db.engine.execute(text('''
            CREATE INDEX IF NOT EXISTS idx_pattern_fulltext
                ON pattern_findings USING gin(to_tsvector('english', 
                    COALESCE(pattern_name, '') || ' ' || COALESCE(description, '')))
        '''))
        
        # Cipher analysis full-text search
        db.engine.execute(text('''
            CREATE INDEX IF NOT EXISTS idx_cipher_fulltext
                ON cipher_analyses USING gin(to_tsvector('english', 
                    COALESCE(cipher_name, '') || ' ' || COALESCE(description, '')))
        '''))
        
    except Exception as e:
        # Fallback for SQLite or other databases
        print(f"Index creation warning: {e}")
        pass


if __name__ == '__main__':
    # Example usage for creating tables
    from crypto_hunter_web import create_app
    from crypto_hunter_web.extensions import db
    
    app = create_app()
    with app.app_context():
        create_agent_tables()
        print("Agent tables created successfully!")
