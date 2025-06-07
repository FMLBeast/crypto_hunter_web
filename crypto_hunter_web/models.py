# crypto_hunter_web/models.py - COMPLETE FIXED VERSION

import hashlib
import os
from datetime import datetime
from flask_login import UserMixin
from sqlalchemy import JSON
from werkzeug.security import generate_password_hash, check_password_hash

# Import db from parent package
from crypto_hunter_web import db

# Association table for many-to-many relationship between PuzzleSession and FileNode
table_puzzle_files = db.Table(
    'puzzle_files',
    db.Column('session_id', db.Integer, db.ForeignKey('puzzle_sessions.id'), primary_key=True),
    db.Column('file_sha256', db.String(64), db.ForeignKey('file_nodes.sha256'), primary_key=True),
    db.Column('added_at', db.DateTime, default=datetime.utcnow)
)


class User(UserMixin, db.Model):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(256))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_active = db.Column(db.DateTime, default=datetime.utcnow)
    is_active = db.Column(db.Boolean, default=True)
    is_admin = db.Column(db.Boolean, default=False)

    # FIXED: Added missing attributes
    display_name = db.Column(db.String(128))
    points = db.Column(db.Integer, default=0)
    level = db.Column(db.String(50), default='Analyst')
    contributions_count = db.Column(db.Integer, default=0)

    # Relationships
    annotations = db.relationship('Annotation', back_populates='user', lazy='dynamic')
    sessions_created = db.relationship('PuzzleSession', back_populates='creator', lazy='dynamic')
    assignments = db.relationship('FileAssignment', foreign_keys='FileAssignment.assigned_by',
                                  back_populates='assigner', lazy='dynamic')

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    # FIXED: Added missing methods
    def award_points(self, points, reason):
        """Award points to user and update level"""
        self.points = (self.points or 0) + points
        self.contributions_count = (self.contributions_count or 0) + 1

        # Update level based on points
        if self.points >= 10000:
            self.level = 'Master Analyst'
        elif self.points >= 5000:
            self.level = 'Senior Analyst'
        elif self.points >= 1000:
            self.level = 'Expert Analyst'
        elif self.points >= 500:
            self.level = 'Advanced Analyst'
        else:
            self.level = 'Analyst'

    def can_verify_findings(self):
        """Check if user can verify findings (expert level)"""
        return self.is_admin or self.level in ['Expert Analyst', 'Senior Analyst', 'Master Analyst']

    def __repr__(self):
        return f'<User {self.username}>'


class AuditLog(db.Model):
    __tablename__ = 'audit_logs'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    action = db.Column(db.String, nullable=False)
    details = db.Column(db.Text, nullable=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)


class PuzzleSession(db.Model):
    __tablename__ = 'puzzle_sessions'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    creator_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    is_active = db.Column(db.Boolean, default=True)
    meta_data = db.Column(JSON)

    # Relationships
    creator = db.relationship('User', back_populates='sessions_created')
    files = db.relationship('FileNode', secondary=table_puzzle_files, back_populates='sessions')
    annotations = db.relationship('Annotation', back_populates='session', lazy='dynamic')

    def __repr__(self):
        return f'<PuzzleSession {self.name}>'


class FileNode(db.Model):
    __tablename__ = 'file_nodes'

    sha256 = db.Column(db.String(64), primary_key=True)
    path = db.Column(db.String, nullable=False)
    description = db.Column(db.String)
    file_type = db.Column(db.String)
    mime_type = db.Column(db.String)
    size_bytes = db.Column(db.Integer)
    creation_date = db.Column(db.DateTime)
    modification_date = db.Column(db.DateTime)
    entropy = db.Column(db.Float)
    imported_at = db.Column(db.DateTime, default=datetime.utcnow)

    # Relationships
    sessions = db.relationship('PuzzleSession', secondary=table_puzzle_files, back_populates='files')
    parent_derivations = db.relationship('FileDerivation', foreign_keys='FileDerivation.child_sha',
                                         back_populates='child')
    child_derivations = db.relationship('FileDerivation', foreign_keys='FileDerivation.parent_sha',
                                        back_populates='parent')
    annotations = db.relationship('Annotation', back_populates='file', lazy='dynamic')

    def __repr__(self):
        return f'<FileNode {self.sha256[:8]}...>'


class FileDerivation(db.Model):
    __tablename__ = 'file_derivations'

    id = db.Column(db.Integer, primary_key=True)
    parent_sha = db.Column(db.String(64), db.ForeignKey('file_nodes.sha256'), nullable=False)
    child_sha = db.Column(db.String(64), db.ForeignKey('file_nodes.sha256'), nullable=False)
    operation = db.Column(db.String(100))
    tool = db.Column(db.String(100))
    parameters = db.Column(db.Text)
    confidence = db.Column(db.Float, default=1.0)
    discovered_at = db.Column(db.DateTime, default=datetime.utcnow)
    discovered_by = db.Column(db.Integer, db.ForeignKey('users.id'))

    # Relationships
    parent = db.relationship('FileNode', foreign_keys=[parent_sha], back_populates='child_derivations')
    child = db.relationship('FileNode', foreign_keys=[child_sha], back_populates='parent_derivations')

    __table_args__ = (db.UniqueConstraint('parent_sha', 'child_sha'),)

    def __repr__(self):
        return f'<FileDerivation {self.parent_sha[:8]}...→{self.child_sha[:8]}...>'


class Annotation(db.Model):
    __tablename__ = 'annotations'

    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    annotation_type = db.Column(db.String(50))  # 'note', 'finding', 'question', 'hypothesis'
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Foreign keys
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    file_sha256 = db.Column(db.String(64), db.ForeignKey('file_nodes.sha256'))
    session_id = db.Column(db.Integer, db.ForeignKey('puzzle_sessions.id'))

    # Relationships
    user = db.relationship('User', back_populates='annotations')
    file = db.relationship('FileNode', back_populates='annotations')
    session = db.relationship('PuzzleSession', back_populates='annotations')

    def __repr__(self):
        return f'<Annotation {self.id} by User {self.user_id}>'


class BulkImport(db.Model):
    __tablename__ = 'bulk_imports'

    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(255))
    total_files = db.Column(db.Integer, default=0)
    successful_imports = db.Column(db.Integer, default=0)
    failed_imports = db.Column(db.Integer, default=0)
    status = db.Column(db.String(50), default='pending')
    error_log = db.Column(db.Text)
    started_at = db.Column(db.DateTime, default=datetime.utcnow)
    completed_at = db.Column(db.DateTime)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))

    def __repr__(self):
        return f'<BulkImport {self.filename}>'


class FileAssignment(db.Model):
    __tablename__ = 'file_assignments'

    id = db.Column(db.Integer, primary_key=True)
    file_sha256 = db.Column(db.String(64), db.ForeignKey('file_nodes.sha256'), nullable=False)
    assigned_to = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    assigned_by = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    assigned_at = db.Column(db.DateTime, default=datetime.utcnow)
    status = db.Column(db.String(50), default='pending')
    notes = db.Column(db.Text)

    # Relationships
    file = db.relationship('FileNode', backref='assignments')
    assignee = db.relationship('User', foreign_keys=[assigned_to], backref='received_assignments')
    assigner = db.relationship('User', foreign_keys=[assigned_by], overlaps="assignments")

    def __repr__(self):
        return f'<FileAssignment {self.file_sha256[:8]}... to User {self.assigned_to}>'


# Analysis-related models
class AnalysisFile(db.Model):
    __tablename__ = 'analysis_files'

    id = db.Column(db.Integer, primary_key=True)
    sha256_hash = db.Column(db.String(64), unique=True, nullable=False, index=True)
    filename = db.Column(db.String(255), nullable=False)
    filepath = db.Column(db.String(512))
    file_size = db.Column(db.Integer)
    file_type = db.Column(db.String(100))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    priority = db.Column(db.Integer, default=5)
    status = db.Column(db.String(50), default='pending')
    discovered_by = db.Column(db.Integer, db.ForeignKey('users.id'))
    is_root_file = db.Column(db.Boolean, default=False)
    node_color = db.Column(db.String(7), default='#gray')
    meta_data = db.Column(JSON)

    # FIXED: Added missing fields
    md5_hash = db.Column(db.String(32))
    parent_file_sha = db.Column(db.String(64))
    extraction_method = db.Column(db.String(100))
    depth_level = db.Column(db.Integer, default=0)

    # FIXED: Added missing static methods
    @staticmethod
    def calculate_sha256(filepath):
        """Calculate SHA256 hash of a file"""
        if not os.path.exists(filepath):
            return None

        sha256_hash = hashlib.sha256()
        try:
            with open(filepath, "rb") as f:
                for byte_block in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(byte_block)
            return sha256_hash.hexdigest()
        except Exception as e:
            print(f"Error calculating SHA256 for {filepath}: {e}")
            return None

    @staticmethod
    def find_by_sha(sha256_hash):
        """Find file by SHA256 hash"""
        return AnalysisFile.query.filter_by(sha256_hash=sha256_hash).first()

    # FIXED: Added missing instance methods
    def get_parents(self):
        """Get parent files (files this was derived from)"""
        # Simple implementation - could be enhanced with actual derivation relationships
        if self.parent_file_sha:
            parent = AnalysisFile.find_by_sha(self.parent_file_sha)
            return [parent] if parent else []
        return []

    def get_children(self):
        """Get child files (files derived from this)"""
        # Simple implementation - could be enhanced with actual derivation relationships
        return AnalysisFile.query.filter_by(parent_file_sha=self.sha256_hash).all()

    def __repr__(self):
        return f'<AnalysisFile {self.filename}>'


class FileContent(db.Model):
    __tablename__ = 'file_contents'

    id = db.Column(db.Integer, primary_key=True)
    file_id = db.Column(db.Integer, db.ForeignKey('analysis_files.id'), nullable=False)
    content_type = db.Column(db.String(50))
    content_text = db.Column(db.Text)
    content_bytes = db.Column(db.LargeBinary)
    content_size = db.Column(db.Integer)
    extracted_at = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f'<FileContent {self.content_type} for file_id={self.file_id}>'


class Vector(db.Model):
    __tablename__ = 'vectors'

    id = db.Column(db.Integer, primary_key=True)
    file_id = db.Column(db.Integer, db.ForeignKey('analysis_files.id'), nullable=False)
    vector_type = db.Column(db.String(50))
    vector_data = db.Column(JSON)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    # Relationship
    file = db.relationship('AnalysisFile', backref='vectors')

    def __repr__(self):
        return f'<Vector {self.vector_type} for file_id={self.file_id}>'


class Finding(db.Model):
    __tablename__ = 'findings'

    id = db.Column(db.Integer, primary_key=True)
    file_id = db.Column(db.Integer, db.ForeignKey('analysis_files.id'), nullable=False)
    vector_id = db.Column(db.Integer, db.ForeignKey('vectors.id'))
    analyst_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    finding_type = db.Column(db.String(100))
    title = db.Column(db.String(255))
    description = db.Column(db.Text)
    confidence = db.Column(db.Float, default=0.5)
    confidence_level = db.Column(db.Integer, default=5)
    technical_details = db.Column(db.Text)
    extracted_data = db.Column(db.Text)
    next_steps = db.Column(db.Text)
    impact_level = db.Column(db.String(20), default='low')
    is_breakthrough = db.Column(db.Boolean, default=False)
    status = db.Column(db.String(50), default='pending')
    meta_data = db.Column(JSON)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    created_by = db.Column(db.Integer, db.ForeignKey('users.id'))

    # Relationships
    file = db.relationship('AnalysisFile', backref='findings')
    vector = db.relationship('Vector', backref='findings')
    analyst = db.relationship('User', foreign_keys=[analyst_id])

    def __repr__(self):
        return f'<Finding {self.title}>'


class RegionOfInterest(db.Model):
    __tablename__ = 'regions_of_interest'

    id = db.Column(db.Integer, primary_key=True)
    file_id = db.Column(db.Integer, db.ForeignKey('analysis_files.id'), nullable=False)
    start_offset = db.Column(db.Integer)
    end_offset = db.Column(db.Integer)
    region_type = db.Column(db.String(50))
    description = db.Column(db.Text)
    meta_data = db.Column(JSON)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    # Relationship
    file = db.relationship('AnalysisFile', backref='regions')

    def __repr__(self):
        return f'<RegionOfInterest {self.region_type} in file_id={self.file_id}>'


class Attachment(db.Model):
    __tablename__ = 'attachments'

    id = db.Column(db.Integer, primary_key=True)
    finding_id = db.Column(db.Integer, db.ForeignKey('findings.id'), nullable=False)
    filename = db.Column(db.String(255))
    filepath = db.Column(db.String(512))
    file_type = db.Column(db.String(100))
    description = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    # Relationship
    finding = db.relationship('Finding', backref='attachments')

    def __repr__(self):
        return f'<Attachment {self.filename}>'


# Combination-related models (for steganography analysis)
class CombinationSource(db.Model):
    __tablename__ = 'combination_sources'

    id = db.Column(db.Integer, primary_key=True)
    file_id = db.Column(db.Integer, db.ForeignKey('analysis_files.id'), nullable=False)
    source_type = db.Column(db.String(50))
    source_data = db.Column(JSON)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f'<CombinationSource {self.source_type}>'


class CombinationRelationship(db.Model):
    __tablename__ = 'combination_relationships'

    id = db.Column(db.Integer, primary_key=True)
    source1_id = db.Column(db.Integer, db.ForeignKey('combination_sources.id'), nullable=False)
    source2_id = db.Column(db.Integer, db.ForeignKey('combination_sources.id'), nullable=False)
    relationship_type = db.Column(db.String(50))
    confidence = db.Column(db.Float, default=0.5)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f'<CombinationRelationship {self.relationship_type}>'


class ExtractionRelationship(db.Model):
    __tablename__ = 'extraction_relationships'

    id = db.Column(db.Integer, primary_key=True)
    parent_file_id = db.Column(db.Integer, db.ForeignKey('analysis_files.id'), nullable=False)
    child_file_id = db.Column(db.Integer, db.ForeignKey('analysis_files.id'), nullable=False)
    extraction_method = db.Column(db.String(100))
    extraction_tool = db.Column(db.String(100))
    extraction_parameters = db.Column(db.Text)
    confidence = db.Column(db.Float, default=1.0)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f'<ExtractionRelationship {self.extraction_method}>'