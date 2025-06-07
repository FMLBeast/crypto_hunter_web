# crypto_hunter_web/__init__.py

import os
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import LoginManager

# Extensions
db = SQLAlchemy()
migrate = Migrate()
login_manager = LoginManager()


def create_app():
    app = Flask(__name__, instance_relative_config=True)

    # Load config
    app.config.from_mapping(
        SECRET_KEY=os.getenv("SECRET_KEY", "dev-secret"),
        SQLALCHEMY_DATABASE_URI=os.getenv("DATABASE_URL", "sqlite:///instance/arweave_tracker.db"),
        SQLALCHEMY_TRACK_MODIFICATIONS=False,
        UPLOAD_FOLDER=os.getenv("UPLOAD_FOLDER", "uploads"),
        MAX_CONTENT_LENGTH=int(os.getenv("MAX_CONTENT_LENGTH", 524288000)),
        CELERY_BROKER_URL=os.getenv("CELERY_BROKER_URL"),
        CELERY_RESULT_BACKEND=os.getenv("CELERY_RESULT_BACKEND"),
        REDIS_URL=os.getenv("REDIS_URL"),
        OPENAI_API_KEY=os.getenv("OPENAI_API_KEY"),
        LLM_MODEL=os.getenv("LLM_MODEL", "gpt-4"),
        LLM_MAX_TOKENS=int(os.getenv("LLM_MAX_TOKENS", 2000)),
        LLM_TEMPERATURE=float(os.getenv("LLM_TEMPERATURE", 0.7)),
        LOG_LEVEL=os.getenv("LOG_LEVEL", "INFO"),
        LOG_FILE=os.getenv("LOG_FILE", "logs/crypto_hunter.log"),
    )

    # Ensure instance folder exists
    os.makedirs(app.instance_path, exist_ok=True)

    # Initialize extensions
    db.init_app(app)
    migrate.init_app(app, db)
    login_manager.init_app(app)
    login_manager.login_view = "auth.login"

    # Register UI blueprints
    from .routes.auth import auth_bp
    from .routes.files import files_bp
    from .routes.analysis import analysis_bp
    from .routes.graph import graph_bp
    from .routes.content import content_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(files_bp)
    app.register_blueprint(analysis_bp)
    app.register_blueprint(graph_bp)
    app.register_blueprint(content_bp)

    # Register API blueprints under /api/*
    from .routes.crypto_api import crypto_api_bp
    from .routes.llm_crypto_api import llm_crypto_api_bp
    from .routes.search_api import search_api_bp

    app.register_blueprint(crypto_api_bp,    url_prefix="/api/crypto")
    app.register_blueprint(llm_crypto_api_bp, url_prefix="/api/llm")
    app.register_blueprint(search_api_bp,     url_prefix="/api/search")

    # **Register background‐task API** with no prefix.
    # Its routes are defined in background_api.py as /background/...
    from .routes.background_api import background_api_bp
    app.register_blueprint(background_api_bp)

    return app
