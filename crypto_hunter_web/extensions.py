#!/usr/bin/env python3
"""
Crypto Hunter Web Extensions
Centralized Flask extensions with proper error handling
"""
import logging
import os
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_wtf.csrf import CSRFProtect
from flask_migrate import Migrate
from flask_caching import Cache
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import redis

logger = logging.getLogger(__name__)

# Initialize extensions
db = SQLAlchemy()
login_manager = LoginManager()
csrf = CSRFProtect()
migrate = Migrate()
cache = Cache()
limiter = Limiter(key_func=get_remote_address)

# Redis client
redis_client = None

def init_redis():
    """Initialize Redis client"""
    global redis_client
    try:
        redis_url = os.environ.get('REDIS_URL', 'redis://localhost:6379/0')
        redis_client = redis.from_url(redis_url)
        redis_client.ping()
        logger.info("✅ Redis connected successfully")
        return True
    except Exception as e:
        logger.warning(f"⚠️ Redis connection failed: {e}")
        return False

def init_all_extensions(app):
    """Initialize all Flask extensions with the app"""
    try:
        # Initialize SQLAlchemy
        db.init_app(app)
        
        # Initialize Login Manager
        login_manager.init_app(app)
        login_manager.login_view = 'auth.login'
        login_manager.login_message = 'Please log in to access this page.'
        
        # Initialize CSRF protection
        csrf.init_app(app)
        
        # Initialize Migrate
        migrate.init_app(app, db)
        
        # Initialize Cache
        cache.init_app(app)
        
        # Initialize Rate Limiter
        limiter.init_app(app)
        
        # Initialize Redis
        init_redis()
        
        logger.info("✅ All extensions initialized")
        
    except Exception as e:
        logger.error(f"❌ Extension initialization failed: {e}")
        raise
