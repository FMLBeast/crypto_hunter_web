#!/usr/bin/env python3
# run.py

from flask import Flask, jsonify
from crypto_hunter_web import create_app


def register_blueprints(app: Flask):
    """Register all application blueprints"""

    # Import all blueprints with error handling
    blueprints_to_register = []

    # Core UI blueprints
    try:
        from crypto_hunter_web.routes.dashboard import dashboard_bp
        blueprints_to_register.append((dashboard_bp, None))
    except ImportError as e:
        app.logger.warning(f"Dashboard blueprint not available: {e}")
        # Create minimal dashboard route
        from flask import Blueprint, render_template
        dashboard_bp = Blueprint('dashboard', __name__)

        @dashboard_bp.route('/')
        def index():
            return render_template('dashboard/index.html',
                                   total_files=0,
                                   complete_files=0,
                                   progress_percentage=0)

        blueprints_to_register.append((dashboard_bp, None))

    try:
        from crypto_hunter_web.routes.auth import auth_bp
        blueprints_to_register.append((auth_bp, None))
    except ImportError as e:
        app.logger.warning(f"Auth blueprint not available: {e}")

    try:
        from crypto_hunter_web.routes.files import files_bp
        blueprints_to_register.append((files_bp, None))
    except ImportError as e:
        app.logger.warning(f"Files blueprint not available: {e}")

    try:
        from crypto_hunter_web.routes.analysis import analysis_bp
        blueprints_to_register.append((analysis_bp, None))
    except ImportError as e:
        app.logger.warning(f"Analysis blueprint not available: {e}")

    try:
        from crypto_hunter_web.routes.graph import graph_bp
        blueprints_to_register.append((graph_bp, None))
    except ImportError as e:
        app.logger.warning(f"Graph blueprint not available: {e}")

    try:
        from crypto_hunter_web.routes.content import content_bp
        blueprints_to_register.append((content_bp, None))
    except ImportError as e:
        app.logger.warning(f"Content blueprint not available: {e}")

    # API blueprints
    try:
        from crypto_hunter_web.routes.crypto_api import crypto_api_bp
        blueprints_to_register.append((crypto_api_bp, '/api/crypto'))
    except ImportError as e:
        app.logger.warning(f"Crypto API blueprint not available: {e}")

    try:
        from crypto_hunter_web.routes.llm_crypto_api import llm_crypto_api_bp
        blueprints_to_register.append((llm_crypto_api_bp, '/api/llm'))
    except ImportError as e:
        app.logger.warning(f"LLM Crypto API blueprint not available: {e}")

    try:
        from crypto_hunter_web.routes.search_api import search_api_bp
        blueprints_to_register.append((search_api_bp, '/api/search'))
    except ImportError as e:
        app.logger.warning(f"Search API blueprint not available: {e}")

    try:
        from crypto_hunter_web.routes.background_api import background_api_bp
        blueprints_to_register.append((background_api_bp, '/background'))
    except ImportError as e:
        app.logger.warning(f"Background API blueprint not available: {e}")

    # Register all available blueprints
    for blueprint, url_prefix in blueprints_to_register:
        if url_prefix:
            app.register_blueprint(blueprint, url_prefix=url_prefix)
        else:
            app.register_blueprint(blueprint)
        app.logger.info(f"Registered blueprint: {blueprint.name}")


def main():
    """Main application entry point"""
    # Create the app via your existing factory
    app = create_app()

    # Register blueprints (UI + APIs)
    register_blueprints(app)

    # Public health check
    @app.route("/health")
    def health():
        return jsonify(status="ok"), 200

    # Additional route fallbacks for missing templates
    @app.route("/favicon.ico")
    def favicon():
        return "", 204

    # Error handlers
    @app.errorhandler(404)
    def not_found(error):
        return jsonify({'error': 'Resource not found'}), 404

    @app.errorhandler(500)
    def internal_error(error):
        return jsonify({'error': 'Internal server error'}), 500

    app.logger.info("Crypto Hunter application started successfully")

    # Run in debug if FLASK_ENV=development, else production
    app.run(host="0.0.0.0", port=8000, debug=app.config.get('DEBUG', False))


if __name__ == "__main__":
    main()