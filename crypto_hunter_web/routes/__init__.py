# crypto_hunter_web/routes/__init__.py
"""
Route blueprints for the Crypto Hunter application.
This file ensures all route blueprints are properly registered.
"""

from crypto_hunter_web.routes.admin import admin_bp
from crypto_hunter_web.routes.analysis import analysis_bp
from crypto_hunter_web.routes.auth import auth_bp
from crypto_hunter_web.routes.content import content_bp
from crypto_hunter_web.routes.crypto_api import crypto_api_bp as legacy_crypto_api_bp
# Import all blueprints
from crypto_hunter_web.routes.dashboard_update import dashboard_bp
from crypto_hunter_web.routes.files import files_bp
from crypto_hunter_web.routes.graph import graph_bp
from crypto_hunter_web.routes.search_api import search_api_bp

# Export all blueprints
__all__ = [
    'dashboard_bp',
    'auth_bp',
    'files_bp',
    'analysis_bp',
    'graph_bp',
    'content_bp',
    'legacy_crypto_api_bp',
    'search_api_bp',
    'admin_bp'
]
