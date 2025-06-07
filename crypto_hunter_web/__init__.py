import os
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import LoginManager

# one shared instance
db = SQLAlchemy()
migrate = Migrate()
login_manager = LoginManager()

def create_app():
    app = Flask(__name__, instance_relative_config=True)

    # core config
    app.config.from_mapping(
        SECRET_KEY                    = os.getenv('SECRET_KEY', 'dev-secret'),
        SQLALCHEMY_DATABASE_URI       = os.getenv('DATABASE_URL', 'sqlite:///arweave_tracker.db'),
        SQLALCHEMY_TRACK_MODIFICATIONS= False,
        CELERY_BROKER_URL             = os.getenv('CELERY_BROKER_URL', 'redis://redis:6379/0'),
        CELERY_RESULT_BACKEND         = os.getenv('CELERY_RESULT_BACKEND', 'redis://redis:6379/0'),
    )
    app.config.from_pyfile('config.py', silent=True)

    # init extensions
    db.init_app(app)
    migrate.init_app(app, db)
    login_manager.init_app(app)

    # register blueprints
    from .routes.auth            import auth_bp
    from .routes.files           import files_bp
    from .routes.graph           import graph_bp
    from .routes.analysis        import analysis_bp
    from .routes.api             import api_bp
    from .routes.background_api  import background_api_bp
    from .routes.content         import content_bp
    from .routes.crypto_api      import crypto_api_bp
    from .routes.llm_crypto_api  import llm_crypto_api_bp
    from .routes.search_api      import search_api_bp

    app.register_blueprint(auth_bp,     url_prefix='/auth')
    app.register_blueprint(files_bp,    url_prefix='/files')
    app.register_blueprint(graph_bp,    url_prefix='/graph')
    app.register_blueprint(analysis_bp, url_prefix='/analysis')
    app.register_blueprint(api_bp,      url_prefix='/api')
    app.register_blueprint(background_api_bp, url_prefix='/background')
    app.register_blueprint(content_bp,  url_prefix='/content')
    app.register_blueprint(crypto_api_bp,    url_prefix='/crypto')
    app.register_blueprint(llm_crypto_api_bp, url_prefix='/llm')
    app.register_blueprint(search_api_bp, url_prefix='/search')

    # register CLI commands
    from .commands import register_commands
    register_commands(app)

    return app

# Flask-Login user loader
@login_manager.user_loader
def load_user(user_id):
    from .models import User
    return User.query.get(int(user_id))
