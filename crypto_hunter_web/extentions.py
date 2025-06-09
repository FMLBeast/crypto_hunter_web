#!/usr/bin/env python3
"""
Flask extensions initialization
Centralizes all Flask extension instances
"""

import os
import logging

logger = logging.getLogger(__name__)

# SQLAlchemy Database
try:
    from flask_sqlalchemy import SQLAlchemy
    db = SQLAlchemy()
except ImportError as e:
    logger.warning(f"SQLAlchemy not available: {e}")
    db = None

# Flask-Login
try:
    from flask_login import LoginManager
    login_manager = LoginManager()
    
    # Configure login manager
    login_manager.login_view = 'auth.login'
    login_manager.login_message = 'Please log in to access this page.'
    login_manager.login_message_category = 'info'
    
except ImportError as e:
    logger.warning(f"Flask-Login not available: {e}")
    login_manager = None

# Flask-WTF CSRF Protection
try:
    from flask_wtf.csrf import CSRFProtect
    csrf = CSRFProtect()
except ImportError as e:
    logger.warning(f"Flask-WTF CSRF not available: {e}")
    csrf = None

# Flask-Migrate
try:
    from flask_migrate import Migrate
    migrate = Migrate()
except ImportError as e:
    logger.warning(f"Flask-Migrate not available: {e}")
    migrate = None

# Redis Client
class RedisClient:
    """Simple Redis client wrapper"""
    
    def __init__(self, app=None):
        self.client = None
        if app:
            self.init_app(app)
    
    def init_app(self, app):
        """Initialize Redis with Flask app"""
        redis_url = app.config.get('REDIS_URL', 'redis://localhost:6379/0')
        
        try:
            import redis
            self.client = redis.from_url(redis_url, decode_responses=True)
            # Test connection
            self.client.ping()
            app.logger.info(f"Redis connected: {redis_url}")
        except ImportError:
            app.logger.warning("Redis library not available")
            self.client = None
        except Exception as e:
            app.logger.warning(f"Redis connection failed: {e}")
            self.client = None
    
    def get(self, key):
        """Get value from Redis"""
        if self.client:
            try:
                return self.client.get(key)
            except Exception as e:
                logger.warning(f"Redis GET failed: {e}")
        return None
    
    def set(self, key, value, ex=None):
        """Set value in Redis"""
        if self.client:
            try:
                return self.client.set(key, value, ex=ex)
            except Exception as e:
                logger.warning(f"Redis SET failed: {e}")
        return None
    
    def delete(self, key):
        """Delete key from Redis"""
        if self.client:
            try:
                return self.client.delete(key)
            except Exception as e:
                logger.warning(f"Redis DELETE failed: {e}")
        return None

# Initialize Redis client
redis_client = RedisClient()

# Flask-Caching
try:
    from flask_caching import Cache
    cache = Cache()
except ImportError as e:
    logger.warning(f"Flask-Caching not available: {e}")
    cache = None

# Flask-Limiter
try:
    from flask_limiter import Limiter
    from flask_limiter.util import get_remote_address
    
    limiter = Limiter(
        key_func=get_remote_address,
        default_limits=["1000 per hour", "100 per minute"]
    )
except ImportError as e:
    logger.warning(f"Flask-Limiter not available: {e}")
    limiter = None

# User loader for Flask-Login
if login_manager:
    @login_manager.user_loader
    def load_user(user_id):
        """Load user for Flask-Login"""
        try:
            from crypto_hunter_web.models import User
            return User.query.get(int(user_id))
        except ImportError:
            logger.warning("User model not available")
            return None
        except Exception as e:
            logger.warning(f"Error loading user: {e}")
            return None