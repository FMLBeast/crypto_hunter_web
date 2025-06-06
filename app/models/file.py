"""
File and content analysis models
"""

import hashlib
import os
from datetime import datetime
from . import db

class AnalysisFile(db.Model):
    """Files from the massive dataset - SHA-based identification"""
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
    
    # Visual properties
    node_color = db.Column(db.String(7), default='#6366f1')
    node_shape = db.Column(db.String(32), default='circle')
    is_root_file = db.Column(db.Boolean, default=False)
    depth_level = db.Column(db.Integer, default=0)
    
    # Analysis status
    status = db.Column(db.String(32), default='pending')
    priority = db.Column(db.Integer, default=5)
    
    # File content metadata
    magic_signature = db.Column(db.String(256))
    entropy = db.Column(db.Float)
    is_encrypted = db.Column(db.Boolean, default=False)
    is_compressed = db.Column(db.Boolean, default=False)
    
    # Timestamps
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow)
    discovered_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationships
    discoverer = db.relationship('User', foreign_keys=[discovered_by])
    
    @staticmethod
    def calculate_sha256(file_path):
        """Calculate SHA256 hash of file"""
        sha256_hash = hashlib.sha256()
        try:
            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(chunk)
            return sha256_hash.hexdigest()
        except Exception:
            return None
    
    @classmethod
    def find_by_sha(cls, sha256_hash):
        """Find file by SHA256 hash"""
        return cls.query.filter_by(sha256_hash=sha256_hash).first()
    
    def get_children(self):
        """Get all files derived from this file"""
        from .relationship import ExtractionRelationship
        relationships = ExtractionRelationship.query.filter_by(source_file_id=self.id).all()
        return [rel.derived_file for rel in relationships]
    
    def get_parents(self):
        """Get all files this file was derived from"""
        from .relationship import ExtractionRelationship
        relationships = ExtractionRelationship.query.filter_by(derived_file_id=self.id).all()
        return [rel.source_file for rel in relationships]
    
    def get_similar_files(self, limit=5):
        """Find files with similar characteristics"""
        return AnalysisFile.query.filter(
            AnalysisFile.file_type == self.file_type,
            AnalysisFile.id != self.id
        ).limit(limit).all()
    
    def __repr__(self):
        return f'<AnalysisFile {self.filename}>'

class FileContent(db.Model):
    """Store file content analysis data"""
    id = db.Column(db.Integer, primary_key=True)
    file_id = db.Column(db.Integer, db.ForeignKey('analysis_file.id'), nullable=False)
    content_type = db.Column(db.String(32), nullable=False)
    content_data = db.Column(db.LargeBinary)
    content_text = db.Column(db.Text)
    content_preview = db.Column(db.Text)
    content_size = db.Column(db.BigInteger, default=0)
    encoding = db.Column(db.String(32), default='utf-8')
    
    # Analysis metadata
    strings_extracted = db.Column(db.Boolean, default=False)
    hex_analyzed = db.Column(db.Boolean, default=False)
    entropy_calculated = db.Column(db.Boolean, default=False)
    
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationships
    file = db.relationship('AnalysisFile', backref='content_analysis')
    
    def __repr__(self):
        return f'<FileContent {self.content_type} for {self.file.filename}>'
