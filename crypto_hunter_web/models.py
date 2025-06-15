# crypto_hunter_web/models.py - COMPLETE CONSOLIDATED MODELS

import hashlib
import uuid
from datetime import datetime
from datetime import timedelta
from enum import Enum
from typing import Optional, Dict, Any, Union, List

from flask_login import UserMixin
from sqlalchemy import Index, text, event
from sqlalchemy.dialects.postgresql import JSON, UUID, TIMESTAMP, DOUBLE_PRECISION
from sqlalchemy.ext.hybrid import hybrid_property
from sqlalchemy.orm import validates
from werkzeug.security import generate_password_hash, check_password_hash

# Import db from extensions
from crypto_hunter_web.extensions import db


class UserLevel(Enum):
    """User experience levels"""
    ANALYST = "ANALYST"
    INTERMEDIATE = "INTERMEDIATE"
    ADVANCED = "ADVANCED"
    EXPERT = "EXPERT"
    MASTER = "MASTER"


class FileStatus(str, Enum):
    PENDING = "pending"
    PROCESSING = "processing"
    COMPLETE = "complete"
    FAILED = "failed"
    ERROR = "error"
    ARCHIVED = "archived"
    ANALYZED = "analyzed"
    CRYPTO_ANALYZED = "crypto_analyzed"
    HIGH_VALUE_CRYPTO = "high_value_crypto"
    BASIC_ANALYSIS_COMPLETE = "basic_analysis_complete"
    ANALYSIS_PARTIAL = "analysis_partial"
    ANALYSIS_FAILED = "analysis_failed"


class FindingStatus(Enum):
    """Finding validation status"""
    UNVERIFIED = "unverified"
    CONFIRMED = "confirmed"
    FALSE_POSITIVE = "false_positive"
    NEEDS_REVIEW = "needs_review"


class User(UserMixin, db.Model):
    """Enhanced User model with security, audit, and gamification"""
    __tablename__ = 'users'
    __table_args__ = (
        Index('idx_user_username', 'username'),
        Index('idx_user_email', 'email'),
        Index('idx_user_active_created', 'is_active', 'created_at'),
        Index('idx_user_points_level', 'points', 'level'),
    )

    id = db.Column(db.Integer, primary_key=True)
    public_id = db.Column(UUID(as_uuid=True), default=uuid.uuid4, unique=True, nullable=False, index=True)

    # Authentication
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)

    # Profile information
    display_name = db.Column(db.String(100))
    first_name = db.Column(db.String(50))
    last_name = db.Column(db.String(50))
    bio = db.Column(db.Text)
    avatar_url = db.Column(db.String(255))

    # Status and permissions
    is_active = db.Column(db.Boolean, default=True, nullable=False, index=True)
    is_admin = db.Column(db.Boolean, default=False, nullable=False)
    is_verified = db.Column(db.Boolean, default=False, nullable=False)
    is_suspended = db.Column(db.Boolean, default=False, nullable=False)

    # Gamification
    points = db.Column(db.Integer, default=0, nullable=False, index=True)
    level = db.Column(db.Enum(UserLevel), default=UserLevel.ANALYST, nullable=False, index=True)
    contributions_count = db.Column(db.Integer, default=0, nullable=False)
    streak_days = db.Column(db.Integer, default=0, nullable=False)

    # Timestamps
    created_at = db.Column(TIMESTAMP, default=datetime.utcnow, nullable=False, index=True)
    updated_at = db.Column(TIMESTAMP, default=datetime.utcnow, onupdate=datetime.utcnow)
    last_login = db.Column(TIMESTAMP, index=True)
    last_active = db.Column(TIMESTAMP, default=datetime.utcnow)
    login_count = db.Column(db.Integer, default=0, nullable=False)

    # Security
    two_factor_enabled = db.Column(db.Boolean, default=False, nullable=False)
    two_factor_secret = db.Column(db.String(32))
    api_key_hash = db.Column(db.String(255))
    failed_login_attempts = db.Column(db.Integer, default=0, nullable=False)
    locked_until = db.Column(TIMESTAMP)
    password_changed_at = db.Column(TIMESTAMP, default=datetime.utcnow)

    # Preferences and settings
    preferences = db.Column(JSON, default=dict)
    timezone = db.Column(db.String(50), default='UTC')
    notification_settings = db.Column(JSON, default=dict)

    # Relationships
    created_files = db.relationship('AnalysisFile', foreign_keys='AnalysisFile.created_by',
                                    backref='creator', lazy='dynamic')
    created_findings = db.relationship('Finding', foreign_keys='Finding.created_by',
                                       backref='creator_user', lazy='dynamic')
    validated_findings = db.relationship('Finding', foreign_keys='Finding.validated_by',
                                         backref='validator_user', lazy='dynamic')
    vectors = db.relationship('Vector', backref='user', lazy='dynamic')
    api_keys = db.relationship('ApiKey', backref='user', lazy='dynamic')
    audit_logs = db.relationship('AuditLog', backref='user', lazy='dynamic')
    owned_sessions = db.relationship('PuzzleSession', foreign_keys='PuzzleSession.owner_id', backref='owner',
                                     lazy='dynamic')
    collaborations = db.relationship('PuzzleCollaborator', backref='user', lazy='dynamic')
    created_steps = db.relationship('PuzzleStep', foreign_keys='PuzzleStep.created_by', backref='creator',
                                    lazy='dynamic')
    created_regions = db.relationship('RegionOfInterest', backref='creator', lazy='dynamic')

    @validates('email')
    def validate_email(self, key, email):
        """Validate email format"""
        import re
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        if not re.match(pattern, email):
            raise ValueError("Invalid email format")
        return email.lower()

    @validates('username')
    def validate_username(self, key, username):
        """Validate username format"""
        import re
        if not re.match(r'^[a-zA-Z0-9_-]{3,80}$', username):
            raise ValueError("Username must be 3-80 characters, alphanumeric, underscore, or hyphen only")
        return username.lower()

    def set_password(self, password: str):
        """Set password with security requirements"""
        if len(password) < 8:
            raise ValueError("Password must be at least 8 characters")
        self.password_hash = generate_password_hash(password, method='pbkdf2:sha256:100000')
        self.password_changed_at = datetime.utcnow()

    def check_password(self, password: str) -> bool:
        """Check password against hash"""
        return check_password_hash(self.password_hash, password)

    def is_locked(self) -> bool:
        """Check if account is locked"""
        return self.locked_until and self.locked_until > datetime.utcnow()

    def lock_account(self, duration_minutes: int = 30):
        """Lock account for specified duration"""
        self.locked_until = datetime.utcnow() + timedelta(minutes=duration_minutes)
        self.failed_login_attempts += 1

    def unlock_account(self):
        """Unlock account and reset failed attempts"""
        self.locked_until = None
        self.failed_login_attempts = 0

    def add_points(self, points: int, reason: str = None):
        """Add points and update level"""
        self.points += points
        self.contributions_count += 1

        # Update level based on points
        if self.points >= 10000:
            self.level = UserLevel.MASTER
        elif self.points >= 5000:
            self.level = UserLevel.EXPERT
        elif self.points >= 1000:
            self.level = UserLevel.ADVANCED
        elif self.points >= 250:
            self.level = UserLevel.INTERMEDIATE
        else:
            self.level = UserLevel.ANALYST

    @hybrid_property
    def full_name(self):
        """Get user's full name"""
        if self.first_name and self.last_name:
            return f"{self.first_name} {self.last_name}"
        return self.display_name or self.username

    def to_dict(self) -> Dict[str, Any]:
        """Convert user to dictionary (safe for API)"""
        return {
            'id': self.public_id.hex,
            'username': self.username,
            'display_name': self.display_name,
            'full_name': self.full_name,
            'level': self.level.value,
            'points': self.points,
            'contributions_count': self.contributions_count,
            'is_active': self.is_active,
            'is_verified': self.is_verified,
            'created_at': self.created_at.isoformat(),
            'last_active': self.last_active.isoformat() if self.last_active else None,
            'avatar_url': self.avatar_url,
            'timezone': self.timezone
        }

    def __repr__(self):
        return f'<User {self.username}({self.level.value})>'


class AnalysisFile(db.Model):
    """Enhanced file model with comprehensive analysis tracking"""
    __tablename__ = 'analysis_files'
    __table_args__ = (
        Index('idx_file_sha256', 'sha256_hash'),
        Index('idx_file_status_priority', 'status', 'priority'),
        Index('idx_file_type_size', 'file_type', 'file_size'),
        Index('idx_file_parent', 'parent_file_sha'),
        Index('idx_file_created', 'created_at'),
        Index('idx_file_root', 'is_root_file'),
        db.UniqueConstraint('sha256_hash', name='uq_file_sha256'),
    )

    id = db.Column(db.Integer, primary_key=True)
    public_id = db.Column(UUID(as_uuid=True), default=uuid.uuid4, unique=True, nullable=False, index=True)

    # Core file information
    filename = db.Column(db.String(255), nullable=False, index=True)
    filepath = db.Column(db.Text)
    original_path = db.Column(db.Text)
    file_size = db.Column(db.BigInteger, nullable=False, index=True)
    file_type = db.Column(db.String(100), index=True)
    mime_type = db.Column(db.String(100))

    # Cryptographic hashes
    sha256_hash = db.Column(db.String(64), unique=True, nullable=False, index=True)
    md5_hash = db.Column(db.String(32), index=True)
    sha1_hash = db.Column(db.String(40))
    crc32 = db.Column(db.String(8))

    # Analysis status and metadata
    status = db.Column(db.String(20), default=FileStatus.PENDING.value, nullable=False, index=True)
    priority = db.Column(db.Integer, default=5, nullable=False, index=True)  # 1-10 scale
    confidence_score = db.Column(DOUBLE_PRECISION, default=0.0)  # AI confidence in analysis
    # File classification
    is_root_file = db.Column(db.Boolean, default=False, nullable=False, index=True)
    is_encrypted = db.Column(db.Boolean, default=False, nullable=False)
    is_archive = db.Column(db.Boolean, default=False, nullable=False)
    is_executable = db.Column(db.Boolean, default=False, nullable=False)
    contains_crypto = db.Column(db.Boolean, default=False, nullable=False, index=True)

    # Relationships and hierarchy
    parent_file_sha = db.Column(db.String(64), db.ForeignKey('analysis_files.sha256_hash'), index=True)
    extraction_depth = db.Column(db.Integer, default=0, nullable=False)

    # Timestamps and tracking
    created_at = db.Column(TIMESTAMP, default=datetime.utcnow, nullable=False, index=True)
    updated_at = db.Column(TIMESTAMP, default=datetime.utcnow, onupdate=datetime.utcnow)
    analyzed_at = db.Column(TIMESTAMP)
    last_accessed = db.Column(TIMESTAMP)

    # User tracking
    created_by = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)
    analyzed_by = db.Column(db.Integer, db.ForeignKey('users.id'))

    # Analysis metadata
    analysis_extra_data = db.Column(JSON, default=dict)
    tags = db.Column(JSON, default=list)  # User-defined tags
    notes = db.Column(db.Text)

    # Performance metrics
    analysis_duration = db.Column(DOUBLE_PRECISION)  # seconds
    processing_cost = db.Column(DOUBLE_PRECISION)  # AI processing cost

    # Relationships
    content_entries = db.relationship('FileContent', backref='file', lazy='dynamic', cascade='all, delete-orphan')
    findings = db.relationship('Finding', backref='file', lazy='dynamic', cascade='all, delete-orphan')
    vectors = db.relationship('Vector', backref='file', lazy='dynamic', cascade='all, delete-orphan')
    child_files = db.relationship('AnalysisFile', backref=db.backref('parent_file', remote_side=[sha256_hash]),
                                  lazy='dynamic')
    extracted_relationships = db.relationship('ExtractionRelationship',
                                              foreign_keys='ExtractionRelationship.source_file_id',
                                              backref='source_file', lazy='dynamic')
    source_relationships = db.relationship('ExtractionRelationship',
                                           foreign_keys='ExtractionRelationship.extracted_file_id',
                                           backref='extracted_file', lazy='dynamic')
    graph_nodes = db.relationship('FileNode', foreign_keys='FileNode.file_id', backref='file', lazy='dynamic')
    combination_results = db.relationship('CombinationRelationship',
                                          foreign_keys='CombinationRelationship.result_file_id', backref='result_file',
                                          lazy='dynamic')
    combination_sources = db.relationship('CombinationSource', foreign_keys='CombinationSource.source_file_id',
                                          backref='source_file', lazy='dynamic')

    @classmethod
    def find_by_sha(cls, sha256: str) -> Optional['AnalysisFile']:
        """Find file by SHA256 hash"""
        return cls.query.filter_by(sha256_hash=sha256).first()

    @classmethod
    def find_by_public_id(cls, public_id: str) -> Optional['AnalysisFile']:
        """Find file by public ID"""
        try:
            return cls.query.filter_by(public_id=uuid.UUID(public_id)).first()
        except ValueError:
            return None

    @validates('filename')
    def validate_filename(self, key, filename):
        """Validate and sanitize filename"""
        if not filename or len(filename.strip()) == 0:
            raise ValueError("Filename cannot be empty")
        # Remove directory traversal attempts
        import os
        clean_name = os.path.basename(filename.strip())
        if len(clean_name) > 255:
            clean_name = clean_name[:255]
        return clean_name

    @validates('priority')
    def validate_priority(self, key, priority):
        """Validate priority range"""
        if not isinstance(priority, int) or priority < 1 or priority > 10:
            raise ValueError("Priority must be integer between 1-10")
        return priority

    def mark_as_analyzed(self, user_id: int, duration: float = None, cost: float = None):
        """Mark file as analyzed"""
        self.status = FileStatus.COMPLETE
        self.analyzed_at = datetime.utcnow()
        self.analyzed_by = user_id
        if duration:
            self.analysis_duration = duration
        if cost:
            self.processing_cost = cost

    def add_tag(self, tag: str):
        """Add tag to file"""
        if not self.tags:
            self.tags = []
        tag = tag.strip().lower()
        if tag and tag not in self.tags:
            self.tags.append(tag)

    def remove_tag(self, tag: str):
        """Remove tag from file"""
        if self.tags and tag in self.tags:
            self.tags.remove(tag)

    @hybrid_property
    def file_size_human(self):
        """Human readable file size"""
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if self.file_size < 1024.0:
                return f"{self.file_size:.1f} {unit}"
            self.file_size /= 1024.0
        return f"{self.file_size:.1f} PB"

    @hybrid_property
    def has_content(self):
        """Check if file has any content entries"""
        return self.content_entries.count() > 0

    @hybrid_property
    def has_findings(self):
        """Check if file has any findings"""
        return self.findings.count() > 0

    def to_dict(self) -> Dict[str, Any]:
        """Convert file to dictionary"""
        return {
            'id': self.public_id.hex,
            'filename': self.filename,
            'file_size': self.file_size,
            'file_size_human': self.file_size_human,
            'file_type': self.file_type,
            'mime_type': self.mime_type,
            'sha256_hash': self.sha256_hash,
            'status': self.status.value,
            'priority': self.priority,
            'confidence_score': self.confidence_score,
            'is_root_file': self.is_root_file,
            'is_encrypted': self.is_encrypted,
            'contains_crypto': self.contains_crypto,
            'created_at': self.created_at.isoformat(),
            'analyzed_at': self.analyzed_at.isoformat() if self.analyzed_at else None,
            'tags': self.tags or [],
            'notes': self.notes,
            'content_count': self.content_entries.count(),
            'findings_count': self.findings.count(),
            'creator': self.creator.username if self.creator else None
        }

    def __repr__(self):
        return f'<AnalysisFile {self.filename}({self.status.value})>'


class FileContent(db.Model):
    """File content storage with multiple content types"""
    __tablename__ = 'file_content'
    __table_args__ = (
        Index('idx_content_file_type', 'file_id', 'content_type'),
        Index('idx_content_extracted', 'extracted_at'),
        Index('idx_content_size', 'content_size'),
    )

    id = db.Column(db.Integer, primary_key=True)
    file_id = db.Column(db.Integer, db.ForeignKey('analysis_files.id'), nullable=False, index=True)

    # Content classification
    content_type = db.Column(db.String(50), nullable=False, index=True)  # text, binary, hex, etc.
    content_format = db.Column(db.String(20), default='text')  # text, json, binary
    encoding = db.Column(db.String(20), default='utf-8')

    # Content storage
    content_text = db.Column(db.Text)  # For text content
    content_bytes = db.Column(db.LargeBinary)  # For binary content
    content_json = db.Column(JSON)  # For structured content
    content_size = db.Column(db.Integer, nullable=False, index=True)

    # Content metadata
    checksum = db.Column(db.String(64))  # SHA256 of content
    compression_used = db.Column(db.Boolean, default=False)
    is_truncated = db.Column(db.Boolean, default=False)
    truncated_at = db.Column(db.Integer)  # Byte position where truncated

    # Extraction information
    extracted_at = db.Column(TIMESTAMP, default=datetime.utcnow, nullable=False, index=True)
    extracted_by = db.Column(db.Integer, db.ForeignKey('users.id'))
    extraction_method = db.Column(db.String(50))  # manual, auto, ai, etc.
    extraction_extra_data = db.Column(JSON, default=dict)

    # Quality metrics
    confidence_score = db.Column(db.Float, default=1.0)
    quality_score = db.Column(db.Float, default=1.0)

    # Relationships
    regions_of_interest = db.relationship('RegionOfInterest', backref='file_content', lazy='dynamic')

    @validates('content_type')
    def validate_content_type(self, key, content_type):
        """Validate content type"""
        valid_types = [
            'raw_binary', 'extracted_text', 'hex_dump', 'strings_output',
            'crypto_analysis', 'llm_analysis', 'metadata', 'exif_data',
            'archive_listing', 'disassembly', 'network_data', 'registry_data'
        ]
        # Allow advanced steganography and binwalk content types
        if (content_type.startswith('advanced_zsteg_') or 
            content_type.startswith('binwalk_') or 
            content_type in valid_types):
            return content_type
        raise ValueError(f"Invalid content type: {content_type}")

    def get_content(self) -> Union[str, bytes, dict]:
        """Get content in appropriate format"""
        if self.content_format == 'json' and self.content_json is not None:
            return self.content_json
        elif self.content_format == 'binary' and self.content_bytes is not None:
            return self.content_bytes
        else:
            return self.content_text or ""

    def set_content(self, content: Union[str, bytes, dict], content_format: str = None):
        """Set content with automatic format detection"""
        if isinstance(content, dict):
            self.content_json = content
            self.content_format = 'json'
            self.content_size = len(str(content))
        elif isinstance(content, bytes):
            self.content_bytes = content
            self.content_format = 'binary'
            self.content_size = len(content)
        else:
            self.content_text = str(content)
            self.content_format = 'text'
            self.content_size = len(self.content_text)

        # Generate checksum
        content_str = str(content).encode('utf-8') if not isinstance(content, bytes) else content
        self.checksum = hashlib.sha256(content_str).hexdigest()

    def __repr__(self):
        return f'<FileContent {self.content_type}({self.content_size} bytes)>'


class Finding(db.Model):
    """Analysis findings with classification and validation"""
    __tablename__ = 'findings'
    __table_args__ = (
        Index('idx_finding_file_type', 'file_id', 'finding_type'),
        Index('idx_finding_status_confidence', 'status', 'confidence_level'),
        Index('idx_finding_created', 'created_at'),
        Index('idx_finding_priority', 'priority'),
    )

    id = db.Column(db.Integer, primary_key=True)
    public_id = db.Column(UUID(as_uuid=True), default=uuid.uuid4, unique=True, nullable=False, index=True)

    file_id = db.Column(db.Integer, db.ForeignKey('analysis_files.id'), nullable=False, index=True)

    # Finding classification
    finding_type = db.Column(db.String(50), nullable=False, index=True)
    category = db.Column(db.String(50), index=True)
    title = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text)

    # Location information
    byte_offset = db.Column(db.BigInteger)
    byte_length = db.Column(db.Integer)
    line_number = db.Column(db.Integer)
    context = db.Column(db.Text)

    # Classification and validation
    status = db.Column(db.Enum(FindingStatus), default=FindingStatus.UNVERIFIED, nullable=False, index=True)
    confidence_level = db.Column(db.Integer, default=5, nullable=False, index=True)  # 1-10
    priority = db.Column(db.Integer, default=5, nullable=False, index=True)  # 1-10
    severity = db.Column(db.String(20), default='medium')  # low, medium, high, critical

    # Content and evidence
    evidence_data = db.Column(JSON, default=dict)
    raw_data = db.Column(db.Text)
    pattern_matched = db.Column(db.String(255))

    # Analysis metadata
    analysis_method = db.Column(db.String(50))  # regex, ai, manual, etc.
    analysis_extra_data = db.Column(JSON, default=dict)
    false_positive_reason = db.Column(db.Text)

    # Timestamps and tracking
    created_at = db.Column(TIMESTAMP, default=datetime.utcnow, nullable=False, index=True)
    updated_at = db.Column(TIMESTAMP, default=datetime.utcnow, onupdate=datetime.utcnow)
    validated_at = db.Column(TIMESTAMP)

    # User tracking
    created_by = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    validated_by = db.Column(db.Integer, db.ForeignKey('users.id'))

    # Quality metrics
    user_rating = db.Column(db.Integer)  # 1-5 user rating
    ai_confidence = db.Column(DOUBLE_PRECISION)  # AI model confidence

    @validates('confidence_level')
    def validate_confidence(self, key, confidence):
        """Validate confidence level"""
        if not isinstance(confidence, int) or confidence < 1 or confidence > 10:
            raise ValueError("Confidence level must be integer between 1-10")
        return confidence

    @validates('priority')
    def validate_priority(self, key, priority):
        """Validate priority"""
        if not isinstance(priority, int) or priority < 1 or priority > 10:
            raise ValueError("Priority must be integer between 1-10")
        return priority

    @validates('severity')
    def validate_severity(self, key, severity):
        """Validate severity"""
        valid_severities = ['low', 'medium', 'high', 'critical']
        if severity not in valid_severities:
            raise ValueError(f"Severity must be one of: {valid_severities}")
        return severity

    def mark_as_confirmed(self, user_id: int, notes: str = None):
        """Mark finding as confirmed"""
        self.status = FindingStatus.CONFIRMED
        self.validated_by = user_id
        self.validated_at = datetime.utcnow()
        if notes:
            self.description += f"\n\nValidation Notes: {notes}"

    def mark_as_false_positive(self, user_id: int, reason: str):
        """Mark finding as false positive"""
        self.status = FindingStatus.FALSE_POSITIVE
        self.validated_by = user_id
        self.validated_at = datetime.utcnow()
        self.false_positive_reason = reason

    def to_dict(self) -> Dict[str, Any]:
        """Convert finding to dictionary"""
        return {
            'id': self.public_id.hex,
            'finding_type': self.finding_type,
            'category': self.category,
            'title': self.title,
            'description': self.description,
            'status': self.status.value,
            'confidence_level': self.confidence_level,
            'priority': self.priority,
            'severity': self.severity,
            'byte_offset': self.byte_offset,
            'byte_length': self.byte_length,
            'context': self.context,
            'evidence_data': self.evidence_data,
            'analysis_method': self.analysis_method,
            'created_at': self.created_at.isoformat(),
            'validated_at': self.validated_at.isoformat() if self.validated_at else None,
            'creator': self.creator_user.username if self.creator_user else None
        }

    def __repr__(self):
        return f'<Finding {self.finding_type}({self.status.value})>'


class RegionOfInterest(db.Model):
    """Regions of interest within file content"""
    __tablename__ = 'regions_of_interest'

    id = db.Column(db.Integer, primary_key=True)
    public_id = db.Column(UUID(as_uuid=True), default=uuid.uuid4, unique=True, nullable=False)

    # File content reference
    file_content_id = db.Column(db.Integer, db.ForeignKey('file_content.id'), nullable=False)

    # Region boundaries
    start_offset = db.Column(db.BigInteger, nullable=False)
    end_offset = db.Column(db.BigInteger, nullable=False)

    # Region properties
    title = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text)
    region_type = db.Column(db.String(50), nullable=False)  # crypto, text, binary, etc.

    # Visual properties for UI
    color = db.Column(db.String(20), default='#yellow')
    highlight_style = db.Column(db.String(50), default='background')

    # Analysis properties
    confidence_score = db.Column(db.Float, default=0.0)
    importance_level = db.Column(db.Integer, default=1)  # 1-5 scale

    # Metadata
    extra_data = db.Column(JSON, default=dict)
    created_at = db.Column(TIMESTAMP, default=datetime.utcnow, nullable=False)
    created_by = db.Column(db.Integer, db.ForeignKey('users.id'))

    def __repr__(self):
        return f'<RegionOfInterest {self.title}>'


# PUZZLE MODELS
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
    steps = db.relationship('PuzzleStep', backref='session', lazy='dynamic', cascade='all, delete-orphan')
    collaborators = db.relationship('PuzzleCollaborator', backref='session', lazy='dynamic',
                                    cascade='all, delete-orphan')

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


# OTHER SUPPORTING MODELS
class Vector(db.Model):
    """Vector embeddings for semantic search"""
    __tablename__ = 'vectors'
    __table_args__ = (
        Index('idx_vector_file_type', 'file_id', 'vector_type'),
        Index('idx_vector_created', 'created_at'),
        Index('idx_vector_category', 'category'),
    )

    id = db.Column(db.Integer, primary_key=True)
    file_id = db.Column(db.Integer, db.ForeignKey('analysis_files.id'), nullable=False, index=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))

    # Vector information
    name = db.Column(db.String(100))  # Name of the vector
    vector_type = db.Column(db.String(50), nullable=False, index=True)  # content, filename, metadata
    embedding_model = db.Column(db.String(50), nullable=False)  # openai, sentence-transformers, etc.
    vector_data = db.Column(JSON, nullable=False)  # The actual vector
    dimension = db.Column(db.Integer, nullable=False)

    # Classification
    category = db.Column(db.String(50), index=True)  # steganography, forensics, cryptography, etc.

    # Source information
    source_text = db.Column(db.Text)
    source_extra_data = db.Column(JSON, default=dict)

    # Timestamps
    created_at = db.Column(TIMESTAMP, default=datetime.utcnow, nullable=False, index=True)
    updated_at = db.Column(TIMESTAMP, default=datetime.utcnow, onupdate=datetime.utcnow)

    def __repr__(self):
        return f'<Vector {self.vector_type}({self.dimension}D)>'


class ApiKey(db.Model):
    """API key management for users"""
    __tablename__ = 'api_keys'
    __table_args__ = (
        Index('idx_apikey_user_active', 'user_id', 'is_active'),
        Index('idx_apikey_hash', 'key_hash'),
    )

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)

    # Key information
    name = db.Column(db.String(100), nullable=False)
    key_hash = db.Column(db.String(255), nullable=False, unique=True, index=True)
    key_prefix = db.Column(db.String(8), nullable=False)  # First 8 chars for identification

    # Status and permissions
    is_active = db.Column(db.Boolean, default=True, nullable=False, index=True)
    permissions = db.Column(JSON, default=list)  # List of allowed endpoints/actions
    rate_limit = db.Column(db.Integer, default=1000)  # Requests per hour

    # Usage tracking
    last_used = db.Column(TIMESTAMP)
    usage_count = db.Column(db.Integer, default=0, nullable=False)

    # Timestamps
    created_at = db.Column(TIMESTAMP, default=datetime.utcnow, nullable=False)
    expires_at = db.Column(TIMESTAMP)

    def is_expired(self) -> bool:
        """Check if API key is expired"""
        return self.expires_at and self.expires_at < datetime.utcnow()

    def __repr__(self):
        return f'<ApiKey {self.name}({self.key_prefix}...)>'


class AuditLog(db.Model):
    """Audit log for security and compliance"""
    __tablename__ = 'audit_logs'
    __table_args__ = (
        Index('idx_audit_user_action', 'user_id', 'action'),
        Index('idx_audit_timestamp', 'timestamp'),
        Index('idx_audit_ip', 'ip_address'),
    )

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), index=True)

    # Action information
    action = db.Column(db.String(100), nullable=False, index=True)
    description = db.Column(db.Text)
    resource_type = db.Column(db.String(50))
    resource_id = db.Column(db.String(100))

    # Request context
    ip_address = db.Column(db.String(45), index=True)  # IPv6 compatible
    user_agent = db.Column(db.Text)
    request_id = db.Column(db.String(36))

    # Result information
    success = db.Column(db.Boolean, nullable=False, index=True)
    error_message = db.Column(db.Text)
    details = db.Column(JSON, default=dict)

    # Timestamp
    timestamp = db.Column(TIMESTAMP, default=datetime.utcnow, nullable=False, index=True)

    @classmethod
    def log_action(cls, user_id: int, action: str, description: str = None,
                   resource_type: str = None, resource_id: str = None,
                   success: bool = True, error_message: str = None,
                   ip_address: str = None, metadata: dict = None):
        """Create audit log entry"""
        log_entry = cls(
            user_id=user_id,
            action=action,
            description=description,
            resource_type=resource_type,
            resource_id=resource_id,
            success=success,
            error_message=error_message,
            ip_address=ip_address,
            details=metadata or {}
        )
        db.session.add(log_entry)
        return log_entry

    def __repr__(self):
        return f'<AuditLog {self.action}({self.timestamp})>'


class ExtractionRelationship(db.Model):
    """Relationship between files and their extracted content"""
    __tablename__ = 'extraction_relationships'

    id = db.Column(db.Integer, primary_key=True)
    public_id = db.Column(UUID(as_uuid=True), default=uuid.uuid4, unique=True, nullable=False)

    # Source file
    source_file_id = db.Column(db.Integer, db.ForeignKey('analysis_files.id'), nullable=False)
    source_file_sha = db.Column(db.String(64), db.ForeignKey('analysis_files.sha256_hash'))

    # Extracted content
    extracted_file_id = db.Column(db.Integer, db.ForeignKey('analysis_files.id'), nullable=False)
    extracted_file_sha = db.Column(db.String(64), db.ForeignKey('analysis_files.sha256_hash'))

    # Extraction details
    extraction_method = db.Column(db.String(50), nullable=False)  # zsteg, binwalk, etc.
    extraction_tool_version = db.Column(db.String(50))
    extraction_command = db.Column(db.Text)

    # Metadata
    confidence_score = db.Column(db.Float, default=0.0)
    extraction_depth = db.Column(db.Integer, default=1)
    extra_data = db.Column(JSON, default=dict)

    # Timestamps
    created_at = db.Column(TIMESTAMP, default=datetime.utcnow, nullable=False)


class FileNode(db.Model):
    """Graph node representation of files for visualization"""
    __tablename__ = 'file_nodes'
    __table_args__ = (
        db.UniqueConstraint('file_sha', name='uq_file_node_sha'),
    )

    id = db.Column(db.Integer, primary_key=True)
    public_id = db.Column(UUID(as_uuid=True), default=uuid.uuid4, unique=True, nullable=False)

    # File reference
    file_id = db.Column(db.Integer, db.ForeignKey('analysis_files.id'), nullable=False)
    file_sha = db.Column(db.String(64), db.ForeignKey('analysis_files.sha256_hash'))

    # Graph properties
    node_type = db.Column(db.String(50), nullable=False)  # root, extracted, related
    graph_level = db.Column(db.Integer, default=0)
    position_x = db.Column(db.Float)
    position_y = db.Column(db.Float)

    # Visual properties
    node_color = db.Column(db.String(20), default='#blue')
    node_size = db.Column(db.Integer, default=10)
    node_shape = db.Column(db.String(20), default='circle')

    # Metadata
    extra_data = db.Column(JSON, default=dict)
    created_at = db.Column(TIMESTAMP, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(TIMESTAMP, default=datetime.utcnow, onupdate=datetime.utcnow)


class GraphEdge(db.Model):
    """Graph edge representing relationships between files"""
    __tablename__ = 'graph_edges'

    id = db.Column(db.Integer, primary_key=True)
    public_id = db.Column(UUID(as_uuid=True), default=uuid.uuid4, unique=True, nullable=False)

    # Node connections
    source_node_id = db.Column(db.Integer, db.ForeignKey('file_nodes.id'), nullable=False)
    target_node_id = db.Column(db.Integer, db.ForeignKey('file_nodes.id'), nullable=False)

    # Edge properties
    edge_type = db.Column(db.String(50), nullable=False)  # extracted_from, similar_to, etc.
    weight = db.Column(db.Float, default=1.0)

    # Visual properties
    edge_color = db.Column(db.String(20), default='#gray')
    edge_width = db.Column(db.Integer, default=2)
    edge_style = db.Column(db.String(20), default='solid')  # solid, dashed, dotted

    # Metadata
    extra_data = db.Column(JSON, default=dict)
    created_at = db.Column(TIMESTAMP, default=datetime.utcnow, nullable=False)

    # Relationships
    source_node = db.relationship('FileNode', foreign_keys=[source_node_id])
    target_node = db.relationship('FileNode', foreign_keys=[target_node_id])


class FileDerivation(db.Model):
    """Model for file derivation relationships (one file derived from another)"""
    __tablename__ = 'file_derivations'

    id = db.Column(db.Integer, primary_key=True)
    parent_sha = db.Column(db.String(64), db.ForeignKey('file_nodes.file_sha'), nullable=False)
    child_sha = db.Column(db.String(64), db.ForeignKey('file_nodes.file_sha'), nullable=False)
    operation = db.Column(db.String(100), nullable=False)
    tool = db.Column(db.String(100))
    parameters = db.Column(db.Text)
    confidence = db.Column(db.Float, default=1.0)

    # Relationships
    parent = db.relationship('FileNode', foreign_keys=[parent_sha], backref='derived_children')
    child = db.relationship('FileNode', foreign_keys=[child_sha], backref='derived_from')

    created_at = db.Column(TIMESTAMP, default=datetime.utcnow)
    updated_at = db.Column(TIMESTAMP, default=datetime.utcnow, onupdate=datetime.utcnow)

    def __repr__(self):
        return f'<FileDerivation {self.parent_sha[:8]}...→{self.child_sha[:8]}... via {self.operation}>'


class CombinationRelationship(db.Model):
    """Model for file combinations (multiple sources -> one result)"""
    __tablename__ = 'combination_relationships'

    id = db.Column(db.Integer, primary_key=True)
    public_id = db.Column(UUID(as_uuid=True), default=uuid.uuid4, unique=True, nullable=False)
    result_file_id = db.Column(db.Integer, db.ForeignKey('analysis_files.id'), nullable=False)
    combination_method = db.Column(db.String(100), nullable=False)
    notes = db.Column(db.Text)
    discovered_by = db.Column(db.Integer, db.ForeignKey('users.id'))

    # Relationships
    sources = db.relationship('CombinationSource', backref='combination', cascade='all, delete-orphan')

    created_at = db.Column(TIMESTAMP, default=datetime.utcnow)
    updated_at = db.Column(TIMESTAMP, default=datetime.utcnow, onupdate=datetime.utcnow)

    def __repr__(self):
        return f'<CombinationRelationship {self.id}: {self.combination_method}>'


class CombinationSource(db.Model):
    """Model for sources in a combination relationship"""
    __tablename__ = 'combination_sources'

    id = db.Column(db.Integer, primary_key=True)
    public_id = db.Column(UUID(as_uuid=True), default=uuid.uuid4, unique=True, nullable=False)
    combination_id = db.Column(db.Integer, db.ForeignKey('combination_relationships.id'), nullable=False)
    source_file_id = db.Column(db.Integer, db.ForeignKey('analysis_files.id'), nullable=False)
    order_index = db.Column(db.Integer, default=0)

    created_at = db.Column(TIMESTAMP, default=datetime.utcnow)

    def __repr__(self):
        return f'<CombinationSource {self.combination_id}: {self.source_file_id} (order: {self.order_index})>'


class BulkImport(db.Model):
    """Model for tracking bulk import operations"""
    __tablename__ = 'bulk_imports'

    id = db.Column(db.Integer, primary_key=True)
    public_id = db.Column(UUID(as_uuid=True), default=uuid.uuid4, unique=True, nullable=False)

    # Import metadata
    import_type = db.Column(db.String(50), nullable=False)  # files, findings, etc.
    status = db.Column(db.String(20), default='pending')  # pending, processing, completed, failed
    total_items = db.Column(db.Integer, default=0)
    processed_items = db.Column(db.Integer, default=0)
    successful_items = db.Column(db.Integer, default=0)
    failed_items = db.Column(db.Integer, default=0)

    # Task tracking
    task_id = db.Column(db.String(36), index=True)  # Celery task ID

    # Error tracking
    error_message = db.Column(db.Text)
    error_details = db.Column(JSON, default=dict)

    # File information
    source_file = db.Column(db.String(255))
    file_size = db.Column(db.BigInteger)
    file_hash = db.Column(db.String(64))

    # User and timestamps
    created_by = db.Column(db.Integer, db.ForeignKey('users.id'))
    created_at = db.Column(TIMESTAMP, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(TIMESTAMP, default=datetime.utcnow, onupdate=datetime.utcnow)
    completed_at = db.Column(TIMESTAMP)

    # Relationships
    creator = db.relationship('User', backref='bulk_imports')

    def __repr__(self):
        return f'<BulkImport {self.id}: {self.import_type} ({self.status})>'


# Database event handlers for automatic updates
@event.listens_for(User, 'before_update')
def user_before_update(mapper, connection, target):
    """Update user timestamps and validation"""
    target.updated_at = datetime.utcnow()


@event.listens_for(AnalysisFile, 'before_update')
def file_before_update(mapper, connection, target):
    """Update file timestamps"""
    target.updated_at = datetime.utcnow()


@event.listens_for(Finding, 'before_update')
def finding_before_update(mapper, connection, target):
    """Update finding timestamps"""
    target.updated_at = datetime.utcnow()


@event.listens_for(PuzzleStep, 'before_insert')
def puzzle_step_before_insert(mapper, connection, target):
    """Set is_active to True for the first step in a session"""
    if target.session is None:
        # If session is None, set is_active to True by default
        target.is_active = True
    elif target.session.steps.count() == 0:
        target.is_active = True
    elif target.is_active:
        # If this step is active, deactivate all other steps
        for step in target.session.steps.filter(PuzzleStep.id != target.id).all():
            step.is_active = False


@event.listens_for(PuzzleStep, 'before_update')
def puzzle_step_before_update(mapper, connection, target):
    """Ensure only one step is active in a session"""
    if target.is_active and target.session is not None:
        # If this step is being activated, deactivate all other steps
        for step in target.session.steps.filter(PuzzleStep.id != target.id).all():
            step.is_active = False


# Create all indexes after model definitions
def create_indexes():
    """Create additional performance indexes"""
    try:
        # Full-text search indexes (PostgreSQL specific)
        db.engine.execute(text('''
                               CREATE INDEX IF NOT EXISTS idx_files_fulltext
                                   ON analysis_files USING gin(to_tsvector('english', filename || ' ' || COALESCE (notes, '')))
                               '''))

        db.engine.execute(text('''
                               CREATE INDEX IF NOT EXISTS idx_findings_fulltext
                                   ON findings USING gin(to_tsvector('english', title || ' ' || COALESCE (description, '')))
                               '''))
    except Exception as e:
        # Fallback for SQLite or other databases
        pass


def init_database():
    """Initialize database with required tables and initial data"""
    # Create all tables
    db.create_all()

    # Create indexes for better performance
    create_indexes()

    # Check if admin user exists, create if not
    admin = User.query.filter_by(username='admin').first()
    if not admin:
        admin = User(
            username='admin',
            email='admin@example.com',
            display_name='Administrator',
            is_admin=True,
            is_verified=True,
            level=UserLevel.MASTER
        )
        admin.set_password('admin123')
        db.session.add(admin)
        db.session.commit()

    return True


# Export all models
__all__ = [
    'User', 'AnalysisFile', 'FileContent', 'Finding', 'RegionOfInterest', 'Vector',
    'ApiKey', 'AuditLog', 'UserLevel', 'FileStatus', 'FindingStatus',
    'ExtractionRelationship', 'FileNode', 'GraphEdge', 'FileDerivation',
    'CombinationRelationship', 'CombinationSource', 'BulkImport',
    'PuzzleSession', 'PuzzleStep', 'PuzzleCollaborator',
    'PuzzleStepFile', 'PuzzleStepFinding', 'PuzzleStepRegion',
    'init_database'
]
