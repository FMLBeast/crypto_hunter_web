"""
Base configuration settings
"""

import os
from pathlib import Path

class Config:
    """Base configuration"""
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'arweave-puzzle-11-dev-key'
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or 'sqlite:///arweave_tracker.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # File upload settings
    UPLOAD_FOLDER = os.environ.get('UPLOAD_FOLDER') or 'uploads'
    BULK_UPLOAD_FOLDER = 'bulk_uploads'
    MAX_CONTENT_LENGTH = int(os.environ.get('MAX_CONTENT_LENGTH', 500 * 1024 * 1024))
    
    # Session settings
    SESSION_TIMEOUT = int(os.environ.get('SESSION_TIMEOUT', 8 * 60 * 60))
    
    # Analysis settings
    MAX_FILE_SIZE_ANALYSIS = 10 * 1024 * 1024  # 10MB
    SUPPORTED_EXTRACTORS = ['zsteg', 'steghide', 'binwalk', 'strings', 'hexdump']
    
    @staticmethod
    def init_app(app):
        """Initialize app-specific configuration"""
        # Create upload directories
        upload_dirs = [
            Config.UPLOAD_FOLDER,
            Config.BULK_UPLOAD_FOLDER,
            f"{Config.BULK_UPLOAD_FOLDER}/screenshots",
            f"{Config.BULK_UPLOAD_FOLDER}/analysis_files", 
            f"{Config.BULK_UPLOAD_FOLDER}/discovered_files"
        ]
        
        for directory in upload_dirs:
            Path(directory).mkdir(parents=True, exist_ok=True)
