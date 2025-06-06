"""
Database models package
"""

from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

# Import all models to ensure they're registered
from .user import User
from .file import AnalysisFile, FileContent
from .relationship import ExtractionRelationship, CombinationRelationship, CombinationSource
from .finding import Finding, Vector, RegionOfInterest, Attachment
from .audit import AuditLog, BulkImport, FileAssignment

__all__ = [
    'db',
    'User', 
    'AnalysisFile', 'FileContent',
    'ExtractionRelationship', 'CombinationRelationship', 'CombinationSource',
    'Finding', 'Vector', 'RegionOfInterest', 'Attachment',
    'AuditLog', 'BulkImport', 'FileAssignment'
]
