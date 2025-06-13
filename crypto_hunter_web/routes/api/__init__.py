"""
API routes package initialization
"""
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

# Import all models to ensure they're registered with SQLAlchemy
from crypto_hunter_web.models import User, AnalysisFile, FileContent, Finding, AuditLog, PuzzleSession, PuzzleStep, PuzzleCollaborator

__all__ = [
    'db',
    'User', 
    'AnalysisFile', 
    'FileContent',
    'Finding', 
    'AuditLog',
    'PuzzleSession',
    'PuzzleStep', 
    'PuzzleCollaborator'
]
