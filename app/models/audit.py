"""
Audit trail and system tracking models
"""

from datetime import datetime
from . import db

class AuditLog(db.Model):
    """Comprehensive audit trail"""
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    action = db.Column(db.String(128), nullable=False)
    details = db.Column(db.Text)
    file_id = db.Column(db.Integer, db.ForeignKey('analysis_file.id'))
    ip_address = db.Column(db.String(45))
    user_agent = db.Column(db.Text)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationships
    user = db.relationship('User')
    file = db.relationship('AnalysisFile')
    
    def __repr__(self):
        return f'<AuditLog {self.action} by {self.user.username if self.user else "System"}>'

class BulkImport(db.Model):
    """Track bulk import operations"""
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
    
    # Relationships
    importer = db.relationship('User')
    
    def __repr__(self):
        return f'<BulkImport {self.filename} by {self.importer.username}>'

class FileAssignment(db.Model):
    """Track file assignments with time tracking"""
    id = db.Column(db.Integer, primary_key=True)
    file_id = db.Column(db.Integer, db.ForeignKey('analysis_file.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    vector_id = db.Column(db.Integer, db.ForeignKey('vector.id'), nullable=False)
    assigned_at = db.Column(db.DateTime, default=datetime.utcnow)
    assigned_by = db.Column(db.Integer, db.ForeignKey('user.id'))
    due_date = db.Column(db.DateTime)
    status = db.Column(db.String(32), default='active')
    notes = db.Column(db.Text)
    
    # Relationships
    file = db.relationship('AnalysisFile', backref='assignments')
    user = db.relationship('User', foreign_keys=[user_id])
    assigner = db.relationship('User', foreign_keys=[assigned_by])
    vector = db.relationship('Vector')
    
    def __repr__(self):
        return f'<FileAssignment {self.file.filename} to {self.user.username}>'
