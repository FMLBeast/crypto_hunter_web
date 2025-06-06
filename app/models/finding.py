"""
Analysis findings and region marking models
"""

from datetime import datetime
from . import db

class Vector(db.Model):
    """Analysis vectors with progress tracking"""
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(128), nullable=False, unique=True)
    description = db.Column(db.Text)
    color = db.Column(db.String(7), default='#6366f1')
    icon = db.Column(db.String(32), default='📁')
    status = db.Column(db.String(32), default='active')
    progress_percentage = db.Column(db.Integer, default=0)
    files_analyzed = db.Column(db.Integer, default=0)
    findings_count = db.Column(db.Integer, default=0)
    
    def __repr__(self):
        return f'<Vector {self.name}>'

class Finding(db.Model):
    """Analysis findings with full audit trail"""
    id = db.Column(db.Integer, primary_key=True)
    file_id = db.Column(db.Integer, db.ForeignKey('analysis_file.id'), nullable=False)
    vector_id = db.Column(db.Integer, db.ForeignKey('vector.id'), nullable=False)
    analyst_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    
    title = db.Column(db.String(256), nullable=False)
    description = db.Column(db.Text)
    finding_type = db.Column(db.String(64))
    confidence_level = db.Column(db.Integer, default=5)
    tools_used = db.Column(db.Text)
    
    # Technical details
    technical_details = db.Column(db.Text)
    extracted_data = db.Column(db.Text)
    cross_references = db.Column(db.Text)
    next_steps = db.Column(db.Text)
    
    # Verification and status
    status = db.Column(db.String(32), default='draft')
    verified_by = db.Column(db.Integer, db.ForeignKey('user.id'))
    verification_date = db.Column(db.DateTime)
    verification_notes = db.Column(db.Text)
    
    # Importance and impact
    impact_level = db.Column(db.String(32), default='low')
    is_breakthrough = db.Column(db.Boolean, default=False)
    
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationships
    file = db.relationship('AnalysisFile', backref='findings')
    vector = db.relationship('Vector', backref='findings')
    analyst = db.relationship('User', foreign_keys=[analyst_id])
    verifier = db.relationship('User', foreign_keys=[verified_by])
    
    @property
    def is_verified(self):
        return self.status == 'verified'
    
    def __repr__(self):
        return f'<Finding {self.title}>'

class RegionOfInterest(db.Model):
    """Mark specific regions in files as interesting"""
    id = db.Column(db.Integer, primary_key=True)
    file_content_id = db.Column(db.Integer, db.ForeignKey('file_content.id'), nullable=False)
    analyst_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    
    # Region boundaries
    start_offset = db.Column(db.BigInteger, nullable=False)
    end_offset = db.Column(db.BigInteger, nullable=False)
    start_line = db.Column(db.Integer)
    end_line = db.Column(db.Integer)
    
    # Visual coordinates for images
    x_start = db.Column(db.Integer)
    y_start = db.Column(db.Integer)
    x_end = db.Column(db.Integer)
    y_end = db.Column(db.Integer)
    
    # Region metadata
    title = db.Column(db.String(256), nullable=False)
    description = db.Column(db.Text)
    region_type = db.Column(db.String(64))
    color = db.Column(db.String(7), default='#ef4444')
    
    # Analysis context
    extraction_method = db.Column(db.String(128))
    related_finding_id = db.Column(db.Integer, db.ForeignKey('finding.id'))
    confidence_level = db.Column(db.Integer, default=5)
    
    # Status
    status = db.Column(db.String(32), default='active')
    verified_by = db.Column(db.Integer, db.ForeignKey('user.id'))
    verification_date = db.Column(db.DateTime)
    
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationships
    file_content = db.relationship('FileContent', backref='regions')
    analyst = db.relationship('User', foreign_keys=[analyst_id])
    verifier = db.relationship('User', foreign_keys=[verified_by])
    related_finding = db.relationship('Finding')
    
    def __repr__(self):
        return f'<RegionOfInterest {self.title}>'

class Attachment(db.Model):
    """File attachments for findings"""
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
    
    # Relationships
    finding = db.relationship('Finding', backref='attachments')
    uploader = db.relationship('User')
    
    def __repr__(self):
        return f'<Attachment {self.filename}>'
