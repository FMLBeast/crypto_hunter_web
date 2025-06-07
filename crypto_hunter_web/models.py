# crypto_hunter_web/models.py

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

    # Relationships
    annotations = db.relationship('Annotation', back_populates='user', lazy='dynamic')
    sessions_created = db.relationship('PuzzleSession', back_populates='creator', lazy='dynamic')
    assignments = db.relationship('FileAssignment', foreign_keys='FileAssignment.assigned_by',
                                  back_populates='assigner', lazy='dynamic')

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def __repr__(self):
        return f'<User {self.username}>'


class PuzzleSession(db.Model):
    __tablename__ = 'puzzle_sessions'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    creator_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    is_active = db.Column(db.Boolean, default=True)
    meta_data = db.Column(JSON)  # Fixed: renamed from metadata

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
    sha256 = db.Column(db.String(64), unique=True, nullable=False, index=True)
    filename = db.Column(db.String(255), nullable=False)
    filepath = db.Column(db.String(512))
    filesize = db.Column(db.Integer)
    file_type = db.Column(db.String(100))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    priority = db.Column(db.Integer, default=5)
    status = db.Column(db.String(50), default='pending')
    discovered_by = db.Column(db.Integer, db.ForeignKey('users.id'))
    is_root_file = db.Column(db.Boolean, default=False)
    node_color = db.Column(db.String(7), default='#gray')
    meta_data = db.Column(JSON)  # Fixed: renamed from metadata

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
        return f'<FileContent for file_id={self.file_id}>'


class ExtractionRelationship(db.Model):
    __tablename__ = 'extraction_relationships'

    id = db.Column(db.Integer, primary_key=True)
    source_file_id = db.Column(db.Integer, db.ForeignKey('analysis_files.id'), nullable=False)
    extracted_file_id = db.Column(db.Integer, db.ForeignKey('analysis_files.id'), nullable=False)
    extraction_method = db.Column(db.String(100))
    extraction_params = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    # Relationships
    source_file = db.relationship('AnalysisFile', foreign_keys=[source_file_id], backref='extracted_from')
    extracted_file = db.relationship('AnalysisFile', foreign_keys=[extracted_file_id], backref='extractions')

    def __repr__(self):
        return f'<ExtractionRelationship {self.source_file_id} -> {self.extracted_file_id}>'


class CombinationRelationship(db.Model):
    __tablename__ = 'combination_relationships'

    id = db.Column(db.Integer, primary_key=True)
    result_file_id = db.Column(db.Integer, db.ForeignKey('analysis_files.id'), nullable=False)
    combination_method = db.Column(db.String(100))
    combination_params = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    # Relationship to the result file
    result_file = db.relationship('AnalysisFile', backref='combination_result')

    def __repr__(self):
        return f'<CombinationRelationship result={self.result_file_id}>'


class CombinationSource(db.Model):
    __tablename__ = 'combination_sources'

    id = db.Column(db.Integer, primary_key=True)
    combination_id = db.Column(db.Integer, db.ForeignKey('combination_relationships.id'), nullable=False)
    source_file_id = db.Column(db.Integer, db.ForeignKey('analysis_files.id'), nullable=False)
    source_order = db.Column(db.Integer, default=0)

    # Relationships
    combination = db.relationship('CombinationRelationship', backref='sources')
    source_file = db.relationship('AnalysisFile')

    def __repr__(self):
        return f'<CombinationSource combo={self.combination_id} source={self.source_file_id}>'


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
    finding_type = db.Column(db.String(100))
    title = db.Column(db.String(255))
    description = db.Column(db.Text)
    confidence = db.Column(db.Float, default=0.5)
    meta_data = db.Column(JSON)  # Fixed: renamed from metadata
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    created_by = db.Column(db.Integer, db.ForeignKey('users.id'))

    # Relationships
    file = db.relationship('AnalysisFile', backref='findings')

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
    meta_data = db.Column(JSON)  # Fixed: renamed from metadata
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