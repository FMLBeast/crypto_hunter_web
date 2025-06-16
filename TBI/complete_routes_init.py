# crypto_hunter_web/routes/__init__.py
"""
Complete route blueprints registration for the Crypto Hunter application.
This file ensures all route blueprints are properly registered and available.
"""

import logging
from flask import Flask

logger = logging.getLogger(__name__)

def register_all_blueprints(app: Flask):
    """Register all application blueprints"""
    try:
        # Import all blueprints
        from crypto_hunter_web.routes.main import main_bp
        from crypto_hunter_web.routes.auth import auth_bp
        from crypto_hunter_web.routes.dashboard import dashboard_bp
        from crypto_hunter_web.routes.files import files_bp
        from crypto_hunter_web.routes.analysis import analysis_bp
        from crypto_hunter_web.routes.graph import graph_bp
        from crypto_hunter_web.routes.puzzle_routes import puzzle_bp
        from crypto_hunter_web.routes.admin import admin_bp
        from crypto_hunter_web.routes.content import content_bp

        # Register main routes
        app.register_blueprint(main_bp)
        logger.info("Registered main blueprint")

        # Register authentication routes
        app.register_blueprint(auth_bp, url_prefix='/auth')
        logger.info("Registered auth blueprint")

        # Register dashboard routes
        app.register_blueprint(dashboard_bp, url_prefix='/dashboard')
        logger.info("Registered dashboard blueprint")

        # Register file management routes
        app.register_blueprint(files_bp, url_prefix='/files')
        logger.info("Registered files blueprint")

        # Register analysis routes
        app.register_blueprint(analysis_bp, url_prefix='/analysis')
        logger.info("Registered analysis blueprint")

        # Register graph visualization routes
        app.register_blueprint(graph_bp, url_prefix='/graph')
        logger.info("Registered graph blueprint")

        # Register puzzle solving routes
        app.register_blueprint(puzzle_bp, url_prefix='/puzzle')
        logger.info("Registered puzzle blueprint")

        # Register admin routes
        app.register_blueprint(admin_bp, url_prefix='/admin')
        logger.info("Registered admin blueprint")

        # Register content routes
        app.register_blueprint(content_bp, url_prefix='/content')
        logger.info("Registered content blueprint")

        # Register API routes
        try:
            from crypto_hunter_web.routes.api import api_bp
            app.register_blueprint(api_bp, url_prefix='/api')
            logger.info("Registered API blueprint")
        except ImportError as e:
            logger.warning(f"Could not import API blueprint: {e}")

        # Register search routes
        try:
            from crypto_hunter_web.routes.search import search_bp
            app.register_blueprint(search_bp, url_prefix='/search')
            logger.info("Registered search blueprint")
        except ImportError as e:
            logger.warning(f"Could not import search blueprint: {e}")

        logger.info("Successfully registered all blueprints")

    except Exception as e:
        logger.error(f"Error registering blueprints: {e}")
        raise


# Blueprint exports for backward compatibility
try:
    from crypto_hunter_web.routes.main import main_bp
    from crypto_hunter_web.routes.auth import auth_bp
    from crypto_hunter_web.routes.dashboard import dashboard_bp
    from crypto_hunter_web.routes.files import files_bp
    from crypto_hunter_web.routes.analysis import analysis_bp
    from crypto_hunter_web.routes.graph import graph_bp
    from crypto_hunter_web.routes.puzzle_routes import puzzle_bp
    from crypto_hunter_web.routes.admin import admin_bp
    from crypto_hunter_web.routes.content import content_bp

    __all__ = [
        'register_all_blueprints',
        'main_bp',
        'auth_bp', 
        'dashboard_bp',
        'files_bp',
        'analysis_bp',
        'graph_bp',
        'puzzle_bp',
        'admin_bp',
        'content_bp'
    ]

except ImportError as e:
    logger.warning(f"Some blueprints could not be imported: {e}")
    __all__ = ['register_all_blueprints']