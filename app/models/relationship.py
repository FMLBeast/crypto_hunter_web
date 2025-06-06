"""
File relationship models for tracking extraction chains
"""

from datetime import datetime
from . import db

class ExtractionRelationship(db.Model):
    """Track relationships between files through extraction methods"""
    id = db.Column(db.Integer, primary_key=True)
    source_file_id = db.Column(db.Integer, db.ForeignKey('analysis_file.id'), nullable=False)
    derived_file_id = db.Column(db.Integer, db.ForeignKey('analysis_file.id'), nullable=False)
    
    # Extraction details
    extraction_method = db.Column(db.String(128), nullable=False)
    extraction_parameters = db.Column(db.Text)
    tool_used = db.Column(db.String(64))
    command_line = db.Column(db.Text)
    
    # Visual properties
    edge_color = db.Column(db.String(7), default='#64748b')
    edge_style = db.Column(db.String(32), default='solid')
    edge_weight = db.Column(db.Float, default=1.0)
    
    # Metadata
    confidence_level = db.Column(db.Integer, default=5)
    notes = db.Column(db.Text)
    discovered_by = db.Column(db.Integer, db.ForeignKey('user.id'))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationships
    source_file = db.relationship('AnalysisFile', foreign_keys=[source_file_id], backref='extraction_relationships')
    derived_file = db.relationship('AnalysisFile', foreign_keys=[derived_file_id], backref='derived_relationships')
    discoverer = db.relationship('User', foreign_keys=[discovered_by])
    
    @property
    def method_display_name(self):
        """Human-readable extraction method name"""
        method_names = {
            'zsteg_bitplane': 'ZSteg Bitplane Analysis',
            'steghide': 'Steghide Extraction',
            'binwalk': 'Binwalk File Carving',
            'strings': 'String Extraction',
            'hexdump': 'Hexdump Analysis',
            'exiftool': 'EXIF Metadata',
            'foremost': 'Foremost Recovery',
            'dd': 'DD Block Copy',
            'manual': 'Manual Analysis'
        }
        return method_names.get(self.extraction_method.split('_')[0], self.extraction_method)
    
    def __repr__(self):
        return f'<ExtractionRelationship {self.source_file.filename} -> {self.derived_file.filename}>'

class CombinationRelationship(db.Model):
    """Track files created by combining multiple source files"""
    id = db.Column(db.Integer, primary_key=True)
    result_file_id = db.Column(db.Integer, db.ForeignKey('analysis_file.id'), nullable=False)
    combination_method = db.Column(db.String(128), nullable=False)
    notes = db.Column(db.Text)
    discovered_by = db.Column(db.Integer, db.ForeignKey('user.id'))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationships
    result_file = db.relationship('AnalysisFile', backref='combination_results')
    discoverer = db.relationship('User', foreign_keys=[discovered_by])
    
    def __repr__(self):
        return f'<CombinationRelationship -> {self.result_file.filename}>'

class CombinationSource(db.Model):
    """Source files for combination operations"""
    id = db.Column(db.Integer, primary_key=True)
    combination_id = db.Column(db.Integer, db.ForeignKey('combination_relationship.id'), nullable=False)
    source_file_id = db.Column(db.Integer, db.ForeignKey('analysis_file.id'), nullable=False)
    order_index = db.Column(db.Integer, default=0)
    
    # Relationships
    combination = db.relationship('CombinationRelationship', backref='source_files')
    source_file = db.relationship('AnalysisFile')
    
    def __repr__(self):
        return f'<CombinationSource {self.source_file.filename}>'
