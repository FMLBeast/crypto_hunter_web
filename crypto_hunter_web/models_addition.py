"""
Additional models for Crypto Hunter
"""

class CombinationRelationship(db.Model):
    """Model for file combinations (multiple sources -> one result)"""
    __tablename__ = 'combination_relationships'
    
    id = db.Column(db.Integer, primary_key=True)
    result_file_id = db.Column(db.Integer, db.ForeignKey('analysis_files.id'), nullable=False)
    combination_method = db.Column(db.String(100), nullable=False)
    notes = db.Column(db.Text)
    discovered_by = db.Column(db.Integer, db.ForeignKey('users.id'))
    
    # Relationships
    result_file = db.relationship('AnalysisFile', foreign_keys=[result_file_id], backref='combination_results')
    sources = db.relationship('CombinationSource', backref='combination', cascade='all, delete-orphan')
    
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    def __repr__(self):
        return f'<CombinationRelationship {self.id}: {self.combination_method}>'


class CombinationSource(db.Model):
    """Model for sources in a combination relationship"""
    __tablename__ = 'combination_sources'
    
    id = db.Column(db.Integer, primary_key=True)
    combination_id = db.Column(db.Integer, db.ForeignKey('combination_relationships.id'), nullable=False)
    source_file_id = db.Column(db.Integer, db.ForeignKey('analysis_files.id'), nullable=False)
    order_index = db.Column(db.Integer, default=0)
    
    # Relationships
    source_file = db.relationship('AnalysisFile', foreign_keys=[source_file_id], backref='combination_sources')
    
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def __repr__(self):
        return f'<CombinationSource {self.combination_id}: {self.source_file_id} (order: {self.order_index})>'