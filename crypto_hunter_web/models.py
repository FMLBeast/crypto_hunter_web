# crypto_hunter_web/models.py

from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
import hashlib

# Initialize SQLAlchemy
db = SQLAlchemy()

# Association table: PuzzleSession ↔ FileNode
table_puzzle_files = db.Table(
    'puzzle_files',
    db.Column('session_id', db.Integer, db.ForeignKey('puzzle_sessions.id'), primary_key=True),
    db.Column('file_sha', db.String(64), db.ForeignKey('file_nodes.sha256'), primary_key=True)
)

# User model (authentication and roles)
class User(db.Model):
    __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), nullable=False, unique=True)
    email = db.Column(db.String(128), nullable=False, unique=True)
    password_hash = db.Column(db.String(256), nullable=False)
    display_name = db.Column(db.String(128))
    role = db.Column(db.String(32), default='analyst')
    is_active = db.Column(db.Boolean, default=True)
    expertise_areas = db.Column(db.Text)
    contributions_count = db.Column(db.Integer, default=0)
    points = db.Column(db.Integer, default=0)
    level = db.Column(db.String(32), default='Analyst')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime)
    last_activity = db.Column(db.DateTime, default=datetime.utcnow)

    # Relationships
    annotations = db.relationship('Annotation', back_populates='user_account', cascade='all, delete-orphan')
    imports = db.relationship('BulkImport', back_populates='importer')
    assignments = db.relationship('FileAssignment', foreign_keys='FileAssignment.assigned_by')

    def set_password(self, password):
        from werkzeug.security import generate_password_hash
        self.password_hash = generate_password_hash(password)
    def check_password(self, password):
        from werkzeug.security import check_password_hash
        return check_password_hash(self.password_hash, password)
    def __repr__(self):
        return f"<User {self.username}>"

# Puzzle session grouping
class PuzzleSession(db.Model):
    __tablename__ = 'puzzle_sessions'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(128), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    # Relationships
    files = db.relationship('FileNode', secondary=table_puzzle_files, back_populates='sessions')
    annotations = db.relationship('Annotation', back_populates='session', cascade='all, delete-orphan')
    def __repr__(self): return f"<PuzzleSession {self.name}>"

# Core file metadata for graph
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
    parent_edges = db.relationship('FileDerivation', foreign_keys='FileDerivation.child_sha', back_populates='child_node', cascade='all, delete-orphan')
    child_edges = db.relationship('FileDerivation', foreign_keys='FileDerivation.parent_sha', back_populates='parent_node', cascade='all, delete-orphan')
    annotations = db.relationship('Annotation', back_populates='file_node', cascade='all, delete-orphan')
    def __repr__(self): return f"<FileNode {self.sha256[:8]}>"

# Explicit derivation edges
class FileDerivation(db.Model):
    __tablename__ = 'file_derivations'
    id = db.Column(db.Integer, primary_key=True)
    parent_sha = db.Column(db.String(64), db.ForeignKey('file_nodes.sha256'), nullable=False)
    child_sha = db.Column(db.String(64), db.ForeignKey('file_nodes.sha256'), nullable=False)
    relation = db.Column(db.String(32), default='derived', nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    # Relationships
    parent_node = db.relationship('FileNode', foreign_keys=[parent_sha], back_populates='child_edges')
    child_node = db.relationship('FileNode', foreign_keys=[child_sha], back_populates='parent_edges')
    def __repr__(self): return f"<Derivation {self.parent_sha[:8]}→{self.child_sha[:8]}>"

# Application annotations
class Annotation(db.Model):
    __tablename__ = 'annotations'
    id = db.Column(db.Integer, primary_key=True)
    session_id = db.Column(db.Integer, db.ForeignKey('puzzle_sessions.id'), nullable=True)
    file_sha = db.Column(db.String(64), db.ForeignKey('file_nodes.sha256'), nullable=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    content = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    # Relationships
    session = db.relationship('PuzzleSession', back_populates='annotations')
    file_node = db.relationship('FileNode', back_populates='annotations')
    user_account = db.relationship('User', back_populates='annotations')
    def __repr__(self): return f"<Annotation {self.id}>"

# Bulk import tracking
class BulkImport(db.Model):
    __tablename__ = 'bulk_import'
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(256), nullable=False)
    imported_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    total_files = db.Column(db.Integer, default=0)
    processed_files = db.Column(db.Integer, default=0)
    successful_imports = db.Column(db.Integer, default=0)
    duplicates_found = db.Column(db.Integer, default=0)
    errors_count = db.Column(db.Integer, default=0)
    status = db.Column(db.String(32), default='processing')
    error_log = db.Column(db.Text)
    started_at = db.Column(db.DateTime, default=datetime.utcnow)
    completed_at = db.Column(db.DateTime)
    importer = db.relationship('User', back_populates='imports')
    def __repr__(self): return f"<BulkImport {self.filename}>"

# File assignment tracking
class FileAssignment(db.Model):
    __tablename__ = 'file_assignment'
    id = db.Column(db.Integer, primary_key=True)
    file_id = db.Column(db.Integer, db.ForeignKey('analysis_file.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    vector_id = db.Column(db.Integer, db.ForeignKey('vector.id'), nullable=False)
    assigned_at = db.Column(db.DateTime, default=datetime.utcnow)
    assigned_by = db.Column(db.Integer, db.ForeignKey('user.id'))
    due_date = db.Column(db.DateTime)
    status = db.Column(db.String(32), default='active')
    notes = db.Column(db.Text)
    file = db.relationship('AnalysisFile', backref='assignments')
    user = db.relationship('User', foreign_keys=[user_id])
    assigner = db.relationship('User', foreign_keys=[assigned_by])
    vector = db.relationship('Vector')
    def __repr__(self): return f"<FileAssignment {self.file_id} to {self.user.username}>"

# ------------------ Content Analysis Models ------------------
# Analysis file core
class AnalysisFile(db.Model):
    __tablename__ = 'analysis_file'
    id = db.Column(db.Integer, primary_key=True)
    sha256_hash = db.Column(db.String(64), nullable=False, unique=True, index=True)
    filename = db.Column(db.String(512), nullable=False)
    filepath = db.Column(db.String(1024), nullable=False)
    original_path = db.Column(db.String(1024))
    file_type = db.Column(db.String(256))
    file_size = db.Column(db.BigInteger)
    md5_hash = db.Column(db.String(32))
    parent_file_sha = db.Column(db.String(64))
    extraction_method = db.Column(db.String(128))
    discovered_by = db.Column(db.Integer, db.ForeignKey('user.id'))
    node_color = db.Column(db.String(7), default='#6366f1')
    node_shape = db.Column(db.String(32), default='circle')
    is_root_file = db.Column(db.Boolean, default=False)
    depth_level = db.Column(db.Integer, default=0)
    status = db.Column(db.String(32), default='pending')
    priority = db.Column(db.Integer, default=5)
    magic_signature = db.Column(db.String(256))
    entropy = db.Column(db.Float)
    is_encrypted = db.Column(db.Boolean, default=False)
    is_compressed = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow)
    discovered_at = db.Column(db.DateTime, default=datetime.utcnow)
    discoverer = db.relationship('User', foreign_keys=[discovered_by])
    def __repr__(self): return f"<AnalysisFile {self.filename}>"
    @staticmethod
    def calculate_sha256(file_path):
        h = hashlib.sha256()
        try:
            with open(file_path,'rb') as f:
                for chunk in iter(lambda: f.read(4096), b''): h.update(chunk)
            return h.hexdigest()
        except: return None
    @classmethod
    def find_by_sha(cls, sha): return cls.query.filter_by(sha256_hash=sha).first()
    def get_children(self):
        from .models import ExtractionRelationship
        rels=ExtractionRelationship.query.filter_by(source_file_id=self.id).all()
        return [r.derived_file for r in rels]
    def get_parents(self):
        from .models import ExtractionRelationship
        rels=ExtractionRelationship.query.filter_by(derived_file_id=self.id).all()
        return [r.source_file for r in rels]

class FileContent(db.Model):
    __tablename__ = 'file_content'
    id = db.Column(db.Integer, primary_key=True)
    file_id = db.Column(db.Integer, db.ForeignKey('analysis_file.id'), nullable=False)
    content_type = db.Column(db.String(32), nullable=False)
    content_data = db.Column(db.LargeBinary)
    content_text = db.Column(db.Text)
    content_preview = db.Column(db.Text)
    content_size = db.Column(db.BigInteger, default=0)
    encoding = db.Column(db.String(32), default='utf-8')
    strings_extracted = db.Column(db.Boolean, default=False)
    hex_analyzed = db.Column(db.Boolean, default=False)
    entropy_calculated = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow)
    file = db.relationship('AnalysisFile', backref='content_analysis')
    def __repr__(self): return f"<FileContent {self.content_type}>"

class ExtractionRelationship(db.Model):
    __tablename__ = 'extraction_relationship'
    id = db.Column(db.Integer, primary_key=True)
    source_file_id = db.Column(db.Integer, db.ForeignKey('analysis_file.id'), nullable=False)
    derived_file_id = db.Column(db.Integer, db.ForeignKey('analysis_file.id'), nullable=False)
    extraction_method = db.Column(db.String(128), nullable=False)
    extraction_parameters = db.Column(db.Text)
    tool_used = db.Column(db.String(64))
    command_line = db.Column(db.Text)
    edge_color = db.Column(db.String(7), default='#64748b')
    edge_style = db.Column(db.String(32), default='solid')
    edge_weight = db.Column(db.Float, default=1.0)
    confidence_level = db.Column(db.Integer, default=5)
    notes = db.Column(db.Text)
    discovered_by = db.Column(db.Integer, db.ForeignKey('user.id'))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    source_file = db.relationship('AnalysisFile', foreign_keys=[source_file_id], backref='extraction_relationships')
    derived_file = db.relationship('AnalysisFile', foreign_keys=[derived_file_id], backref='derived_relationships')
    discoverer = db.relationship('User', foreign_keys=[discovered_by])
    @property
    def method_display_name(self):
        names={'zsteg_bitplane':'ZSteg Bitplane','steghide':'Steghide','binwalk':'Binwalk','strings':'Strings','hexdump':'Hexdump','exiftool':'EXIF','foremost':'Foremost','dd':'DD','manual':'Manual'}
        return names.get(self.extraction_method.split('_')[0], self.extraction_method)
    def __repr__(self): return f"<ExtractionRel {self.source_file.filename}->{self.derived_file.filename}>"

class CombinationRelationship(db.Model):
    __tablename__ = 'combination_relationship'
    id = db.Column(db.Integer, primary_key=True)
    result_file_id = db.Column(db.Integer, db.ForeignKey('analysis_file.id'), nullable=False)
    combination_method = db.Column(db.String(128), nullable=False)
    notes = db.Column(db.Text)
    discovered_by = db.Column(db.Integer, db.ForeignKey('user.id'))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    result_file = db.relationship('AnalysisFile', backref='combination_results')
    discoverer = db.relationship('User', foreign_keys=[discovered_by])
    def __repr__(self): return f"<ComboRel ->{self.result_file.filename}>"

class CombinationSource(db.Model):
    __tablename__ = 'combination_source'
    id = db.Column(db.Integer, primary_key=True)
    combination_id = db.Column(db.Integer, db.ForeignKey('combination_relationship.id'), nullable=False)
    source_file_id = db.Column(db.Integer, db.ForeignKey('analysis_file.id'), nullable=False)
    order_index = db.Column(db.Integer, default=0)
    combination = db.relationship('CombinationRelationship', backref='source_files')
    source_file = db.relationship('AnalysisFile')
    def __repr__(self): return f"<ComboSrc {self.source_file.filename}>"

class Vector(db.Model):
    __tablename__ = 'vector'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(128), nullable=False, unique=True)
    description = db.Column(db.Text)
    color = db.Column(db.String(7), default='#6366f1')
    icon = db.Column(db.String(32), default='📁')
    status = db.Column(db.String(32), default='active')
    progress_percentage = db.Column(db.Integer, default=0)
    files_analyzed = db.Column(db.Integer, default=0)
    findings_count = db.Column(db.Integer, default=0)
    def __repr__(self): return f"<Vector {self.name}>"

class Finding(db.Model):
    __tablename__ = 'finding'
    id = db.Column(db.Integer, primary_key=True)
    file_id = db.Column(db.Integer, db.ForeignKey('analysis_file.id'), nullable=False)
    vector_id = db.Column(db.Integer, db.ForeignKey('vector.id'), nullable=False)
    analyst_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    title = db.Column(db.String(256), nullable=False)
    description = db.Column(db.Text)
    finding_type = db.Column(db.String(64))
    confidence_level = db.Column(db.Integer, default=5)
    tools_used = db.Column(db.Text)
    technical_details = db.Column(db.Text)
    extracted_data = db.Column(db.Text)
    cross_references = db.Column(db.Text)
    next_steps = db.Column(db.Text)
    status = db.Column(db.String(32), default='draft')
    verified_by = db.Column(db.Integer, db.ForeignKey('user.id'))
    verification_date = db.Column(db.DateTime)
    verification_notes = db.Column(db.Text)
    impact_level = db.Column(db.String(32), default='low')
    is_breakthrough = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow)
    file = db.relationship('AnalysisFile', backref='findings')
    vector = db.relationship('Vector', backref='findings')
    analyst = db.relationship('User', foreign_keys=[analyst_id])
    verifier = db.relationship('User', foreign_keys=[verified_by])
    @property
    def is_verified(self): return self.status=='verified'
    def __repr__(self): return f"<Finding {self.title}>"

class RegionOfInterest(db.Model):
    __tablename__ = 'region_of_interest'
    id = db.Column(db.Integer, primary_key=True)
    file_content_id = db.Column(db.Integer, db.ForeignKey('file_content.id'), nullable=False)
    analyst_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    start_offset = db.Column(db.BigInteger, nullable=False)
    end_offset = db.Column(db.BigInteger, nullable=False)
    start_line = db.Column(db.Integer)
    end_line = db.Column(db.Integer)
    x_start = db.Column(db.Integer)
    y_start = db.Column(db.Integer)
    x_end = db.Column(db.Integer)
    y_end = db.Column(db.Integer)
    title = db.Column(db.String(256), nullable=False)
    description = db.Column(db.Text)
    region_type = db.Column(db.String(64))
    color = db.Column(db.String(7), default='#ef4444')
    extraction_method = db.Column(db.String(128))
    related_finding_id = db.Column(db.Integer, db.ForeignKey('finding.id'))
    confidence_level = db.Column(db.Integer, default=5)
    status = db.Column(db.String(32), default='active')
    verified_by = db.Column(db.Integer, db.ForeignKey('user.id'))
    verification_date = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    file_content = db.relationship('FileContent', backref='regions')
    analyst = db.relationship('User', foreign_keys=[analyst_id])
    verifier = db.relationship('User', foreign_keys=[verified_by])
    related_finding = db.relationship('Finding')
    def __repr__(self): return f"<Region {self.title}>"

class Attachment(db.Model):
    __tablename__ = 'attachment'
    id = db.Column(db.Integer, primary_key=True)
    finding_id = db.Column(db.Integer, db.ForeignKey('finding.id'), nullable=False)
    filename = db.Column(db.String(256), nullable=False)
    original_filename = db.Column(db.String(256))
    file_path = db.Column(db.String(512), nullable=False)
    file_type = db.Column(db.String(64))
    file_size = db.Column(db.BigInteger)
    sha256_hash = db.Column(db.String(64))
    description = db.Column(db.Text)
    is_safe = db.Column(db.Boolean, default=True)
    uploaded_by = db.Column(db.Integer, db.ForeignKey('user.id'))
    uploaded_at = db.Column(db.DateTime, default=datetime.utcnow)
    finding = db.relationship('Finding', backref='attachments')
    uploader = db.relationship('User')
    def __repr__(self): return f"<Attachment {self.filename}>"
