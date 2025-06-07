#!/usr/bin/env python3
# run.py

from flask import Flask, jsonify
from crypto_hunter_web import create_app
from crypto_hunter_web.routes.auth import auth_bp
from crypto_hunter_web.routes.files import files_bp
from crypto_hunter_web.routes.analysis import analysis_bp
from crypto_hunter_web.routes.crypto_api import crypto_api_bp
from crypto_hunter_web.routes.llm_crypto_api import llm_crypto_api_bp
from crypto_hunter_web.routes.search_api import search_api_bp
from crypto_hunter_web.routes.background_api import background_api_bp
from crypto_hunter_web.routes.graph import graph_bp
from crypto_hunter_web.routes.content import content_bp

def register_blueprints(app: Flask):
    # UI blueprints
    app.register_blueprint(auth_bp)
    app.register_blueprint(files_bp)
    app.register_blueprint(analysis_bp)
    app.register_blueprint(graph_bp)
    app.register_blueprint(content_bp)

    # API blueprints
    app.register_blueprint(crypto_api_bp,    url_prefix='/api/crypto')
    app.register_blueprint(llm_crypto_api_bp, url_prefix='/api/llm')
    app.register_blueprint(search_api_bp,     url_prefix='/api/search')

    # Background‐task API (protected routes)
    # These define /background/system/stats, /background/start, etc., and require login.
    app.register_blueprint(background_api_bp, url_prefix='/background')

def main():
    # Create the app via your existing factory
    app = create_app()

    # Register blueprints (UI + APIs)
    register_blueprints(app)

    # Public health check
    @app.route("/health")
    def health():
        return jsonify(status="ok"), 200

    # If you want /health returning JSON without auth, it’s here.

    # Run in debug if FLASK_ENV=development, else production
    app.run(host="0.0.0.0", port=8000)

if __name__ == "__main__":
    main()
