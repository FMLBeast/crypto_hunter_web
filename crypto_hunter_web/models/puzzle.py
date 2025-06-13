"""
Models for puzzle solving sessions
"""
import uuid
from datetime import datetime
from typing import Optional, List, Dict, Any

from sqlalchemy import Index, event
from sqlalchemy.dialects.postgresql import JSON, UUID, TIMESTAMP
from sqlalchemy.ext.hybrid import hybrid_property
from sqlalchemy.orm import validates

from crypto_hunter_web import db
from crypto_hunter_web.models import User, AnalysisFile, Finding, RegionOfInterest


class PuzzleSession(db.Model):
    """Model for puzzle solving sessions"""
    __tablename__ = 'puzzle_sessions'
    __table_args__ = (
        Index('idx_session_owner', 'owner_id'),
        Index('idx_session_public', 'is_public'),
        Index('idx_session_status', 'status'),
        Index('idx_session_created', 'created_at'),
    )

    id = db.Column(db.Integer, primary_key=True)
    public_id = db.Column(UUID(as_uuid=True), default=uuid.uuid4, unique=True, nullable=False, index=True)
    
    # Basic information
    name = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text)
    
    # Ownership and access
    owner_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)
    is_public = db.Column(db.Boolean, default=False, nullable=False)
    
    # Status and metadata
    status = db.Column(db.String(20), default='active', nullable=False)  # active, paused, completed, archived
    tags = db.Column(JSON, default=list)
    
    # Timestamps
    created_at = db.Column(TIMESTAMP, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(TIMESTAMP, default=datetime.utcnow, onupdate=datetime.utcnow)
    completed_at = db.Column(TIMESTAMP)
    
    # Relationships
    owner = db.relationship('User', foreign_keys=[owner_id], backref='owned_sessions')
    steps = db.relationship('PuzzleStep', backref='session', lazy='dynamic', cascade='all, delete-orphan')
    collaborators = db.relationship('PuzzleCollaborator', backref='session', lazy='dynamic', cascade='all, delete-orphan')
    
    @validates('status')
    def validate_status(self, key, status):
        """Validate status"""
        valid_statuses = ['active', 'paused', 'completed', 'archived']
        if status not in valid_statuses:
            raise ValueError(f"Invalid status: {status}. Must be one of: {valid_statuses}")
        return status
    
    def get_active_step(self) -> Optional['PuzzleStep']:
        """Get the active step for this session"""
        return self.steps.filter_by(is_active=True).first()
    
    def add_collaborator(self, user_id: int, role: str = 'viewer') -> 'PuzzleCollaborator':
        """Add a collaborator to this session"""
        # Check if user is already a collaborator
        existing = PuzzleCollaborator.query.filter_by(
            session_id=self.id, user_id=user_id).first()
        
        if existing:
            existing.role = role
            db.session.commit()
            return existing
        
        collaborator = PuzzleCollaborator(
            session_id=self.id,
            user_id=user_id,
            role=role
        )
        db.session.add(collaborator)
        db.session.commit()
        return collaborator
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert session to dictionary"""
        return {
            'id': self.public_id.hex,
            'name': self.name,
            'description': self.description,
            'owner_id': self.owner_id,
            'owner': self.owner.username,
            'is_public': self.is_public,
            'status': self.status,
            'tags': self.tags,
            'created_at': self.created_at.isoformat(),
            'updated_at': self.updated_at.isoformat(),
            'completed_at': self.completed_at.isoformat() if self.completed_at else None,
            'steps_count': self.steps.count(),
            'collaborators_count': self.collaborators.count()
        }
    
    def __repr__(self):
        return f'<PuzzleSession {self.name}({self.status})>'


class PuzzleStep(db.Model):
    """Model for steps in a puzzle solving session"""
    __tablename__ = 'puzzle_steps'
    __table_args__ = (
        Index('idx_step_session', 'session_id'),
        Index('idx_step_creator', 'created_by'),
        Index('idx_step_active', 'is_active'),
        Index('idx_step_created', 'created_at'),
    )

    id = db.Column(db.Integer, primary_key=True)
    public_id = db.Column(UUID(as_uuid=True), default=uuid.uuid4, unique=True, nullable=False, index=True)
    
    # Relationship to session
    session_id = db.Column(db.Integer, db.ForeignKey('puzzle_sessions.id'), nullable=False)
    
    # Step information
    title = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text)
    
    # Status
    is_active = db.Column(db.Boolean, default=False, nullable=False)
    
    # Metadata
    tags = db.Column(JSON, default=list)
    extra_data = db.Column(JSON, default=dict)
    
    # Timestamps and tracking
    created_at = db.Column(TIMESTAMP, default=datetime.utcnow, nullable=False)
    created_by = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    
    # Relationships
    creator = db.relationship('User', foreign_keys=[created_by], backref='created_steps')
    files = db.relationship('PuzzleStepFile', backref='step', lazy='dynamic', cascade='all, delete-orphan')
    findings = db.relationship('PuzzleStepFinding', backref='step', lazy='dynamic', cascade='all, delete-orphan')
    regions = db.relationship('PuzzleStepRegion', backref='step', lazy='dynamic', cascade='all, delete-orphan')
    
    def add_file(self, file_id: int, note: str = None) -> 'PuzzleStepFile':
        """Add a file to this step"""
        # Check if file is already in this step
        existing = PuzzleStepFile.query.filter_by(
            step_id=self.id, file_id=file_id).first()
        
        if existing:
            if note:
                existing.note = note
                db.session.commit()
            return existing
        
        step_file = PuzzleStepFile(
            step_id=self.id,
            file_id=file_id,
            note=note
        )
        db.session.add(step_file)
        db.session.commit()
        return step_file
    
    def add_finding(self, finding_id: int, note: str = None) -> 'PuzzleStepFinding':
        """Add a finding to this step"""
        # Check if finding is already in this step
        existing = PuzzleStepFinding.query.filter_by(
            step_id=self.id, finding_id=finding_id).first()
        
        if existing:
            if note:
                existing.note = note
                db.session.commit()
            return existing
        
        step_finding = PuzzleStepFinding(
            step_id=self.id,
            finding_id=finding_id,
            note=note
        )
        db.session.add(step_finding)
        db.session.commit()
        return step_finding
    
    def add_region(self, region_id: int, note: str = None) -> 'PuzzleStepRegion':
        """Add a region to this step"""
        # Check if region is already in this step
        existing = PuzzleStepRegion.query.filter_by(
            step_id=self.id, region_id=region_id).first()
        
        if existing:
            if note:
                existing.note = note
                db.session.commit()
            return existing
        
        step_region = PuzzleStepRegion(
            step_id=self.id,
            region_id=region_id,
            note=note
        )
        db.session.add(step_region)
        db.session.commit()
        return step_region
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert step to dictionary"""
        return {
            'id': self.public_id.hex,
            'session_id': self.session_id,
            'title': self.title,
            'description': self.description,
            'is_active': self.is_active,
            'tags': self.tags,
            'extra_data': self.extra_data,
            'created_at': self.created_at.isoformat(),
            'created_by': self.created_by,
            'creator': self.creator.username,
            'files_count': self.files.count(),
            'findings_count': self.findings.count(),
            'regions_count': self.regions.count()
        }
    
    def __repr__(self):
        return f'<PuzzleStep {self.title}{"*" if self.is_active else ""}>'


class PuzzleCollaborator(db.Model):
    """Model for collaborators in a puzzle solving session"""
    __tablename__ = 'puzzle_collaborators'
    __table_args__ = (
        Index('idx_collaborator_session', 'session_id'),
        Index('idx_collaborator_user', 'user_id'),
        Index('idx_collaborator_role', 'role'),
        db.UniqueConstraint('session_id', 'user_id', name='uq_session_user'),
    )

    id = db.Column(db.Integer, primary_key=True)
    
    # Relationships
    session_id = db.Column(db.Integer, db.ForeignKey('puzzle_sessions.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    
    # Role and permissions
    role = db.Column(db.String(20), default='viewer', nullable=False)  # viewer, editor, admin
    
    # Status
    is_online = db.Column(db.Boolean, default=False, nullable=False)
    last_active = db.Column(TIMESTAMP)
    
    # Relationship
    user = db.relationship('User', backref='collaborations')
    
    @validates('role')
    def validate_role(self, key, role):
        """Validate role"""
        valid_roles = ['viewer', 'editor', 'admin']
        if role not in valid_roles:
            raise ValueError(f"Invalid role: {role}. Must be one of: {valid_roles}")
        return role
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert collaborator to dictionary"""
        return {
            'id': self.id,
            'session_id': self.session_id,
            'user_id': self.user_id,
            'username': self.user.username,
            'role': self.role,
            'is_online': self.is_online,
            'last_active': self.last_active.isoformat() if self.last_active else None
        }
    
    def __repr__(self):
        return f'<PuzzleCollaborator {self.user.username}({self.role})>'


class PuzzleStepFile(db.Model):
    """Junction model for files in a puzzle step"""
    __tablename__ = 'puzzle_step_files'
    __table_args__ = (
        Index('idx_step_file_step', 'step_id'),
        Index('idx_step_file_file', 'file_id'),
        db.UniqueConstraint('step_id', 'file_id', name='uq_step_file'),
    )

    id = db.Column(db.Integer, primary_key=True)
    step_id = db.Column(db.Integer, db.ForeignKey('puzzle_steps.id'), nullable=False)
    file_id = db.Column(db.Integer, db.ForeignKey('analysis_files.id'), nullable=False)
    note = db.Column(db.Text)
    added_at = db.Column(TIMESTAMP, default=datetime.utcnow, nullable=False)
    
    # Relationship
    file = db.relationship('AnalysisFile')
    
    def __repr__(self):
        return f'<PuzzleStepFile {self.file.filename}>'


class PuzzleStepFinding(db.Model):
    """Junction model for findings in a puzzle step"""
    __tablename__ = 'puzzle_step_findings'
    __table_args__ = (
        Index('idx_step_finding_step', 'step_id'),
        Index('idx_step_finding_finding', 'finding_id'),
        db.UniqueConstraint('step_id', 'finding_id', name='uq_step_finding'),
    )

    id = db.Column(db.Integer, primary_key=True)
    step_id = db.Column(db.Integer, db.ForeignKey('puzzle_steps.id'), nullable=False)
    finding_id = db.Column(db.Integer, db.ForeignKey('findings.id'), nullable=False)
    note = db.Column(db.Text)
    added_at = db.Column(TIMESTAMP, default=datetime.utcnow, nullable=False)
    
    # Relationship
    finding = db.relationship('Finding')
    
    def __repr__(self):
        return f'<PuzzleStepFinding {self.finding.title}>'


class PuzzleStepRegion(db.Model):
    """Junction model for regions of interest in a puzzle step"""
    __tablename__ = 'puzzle_step_regions'
    __table_args__ = (
        Index('idx_step_region_step', 'step_id'),
        Index('idx_step_region_region', 'region_id'),
        db.UniqueConstraint('step_id', 'region_id', name='uq_step_region'),
    )

    id = db.Column(db.Integer, primary_key=True)
    step_id = db.Column(db.Integer, db.ForeignKey('puzzle_steps.id'), nullable=False)
    region_id = db.Column(db.Integer, db.ForeignKey('regions_of_interest.id'), nullable=False)
    note = db.Column(db.Text)
    added_at = db.Column(TIMESTAMP, default=datetime.utcnow, nullable=False)
    
    # Relationship
    region = db.relationship('RegionOfInterest')
    
    def __repr__(self):
        return f'<PuzzleStepRegion {self.region.title}>'


# Event handlers
@event.listens_for(PuzzleStep, 'before_insert')
def puzzle_step_before_insert(mapper, connection, target):
    """Set is_active to True for the first step in a session"""
    if target.session.steps.count() == 0:
        target.is_active = True
    elif target.is_active:
        # If this step is active, deactivate all other steps
        for step in target.session.steps.filter(PuzzleStep.id != target.id).all():
            step.is_active = False


@event.listens_for(PuzzleStep, 'before_update')
def puzzle_step_before_update(mapper, connection, target):
    """Ensure only one step is active in a session"""
    if target.is_active:
        # If this step is being activated, deactivate all other steps
        for step in target.session.steps.filter(PuzzleStep.id != target.id).all():
            step.is_active = False