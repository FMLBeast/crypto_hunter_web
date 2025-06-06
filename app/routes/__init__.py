"""
Application routes package
"""

from .auth import auth_bp
from .files import files_bp
from .content import content_bp
from .graph import graph_bp
from .analysis import analysis_bp
from .api import api_bp

__all__ = [
    'auth_bp',
    'files_bp', 
    'content_bp',
    'graph_bp',
    'analysis_bp',
    'api_bp'
]
