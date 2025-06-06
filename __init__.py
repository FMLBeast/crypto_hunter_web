"""
Main Flask application factory and configuration
"""

from flask import Flask
from app.models import db
from app.routes import auth_bp, files_bp, content_bp, graph_bp, analysis_bp, api_bp
import os

def create_app(config_name='development'):
    """Create Flask application"""
    app = Flask(__name__)
    
    # Load configuration
    if config_name == 'development':
        from app.config.development import DevelopmentConfig
        app.config.from_object(DevelopmentConfig)
    elif config_name == 'production':
        from app.config.production import ProductionConfig
        app.config.from_object(ProductionConfig)
    elif config_name == 'testing':
        from app.config.testing import TestingConfig
        app.config.from_object(TestingConfig)
    else:
        from app.config.base import Config
        app.config.from_object(Config)
    
    # Initialize extensions
    db.init_app(app)
    
    # Register blueprints
    app.register_blueprint(auth_bp, url_prefix='/auth')
    app.register_blueprint(files_bp, url_prefix='/files')
    app.register_blueprint(content_bp, url_prefix='/content')
    app.register_blueprint(graph_bp, url_prefix='/graph')
    app.register_blueprint(analysis_bp, url_prefix='/analysis')
    app.register_blueprint(api_bp, url_prefix='/api')
    
    # Register main routes
    @app.route('/')
    def index():
        from app.routes.auth import index
        return index()
    
    # Create directories
    app.config['Config'].init_app(app)
    
    return app

if __name__ == '__main__':
    app = create_app()
    app.run(debug=True)