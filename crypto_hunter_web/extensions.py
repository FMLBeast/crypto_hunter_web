#!/usr/bin/env python3
"""
Crypto Hunter Web Extensions
Centralized Flask extensions with proper error handling
"""

import logging
import os

logger = logging.getLogger(__name__)

# Initialize extensions with error handling
db = None
login_manager = None
csrf = None
redis_client = None
cache = None
limiter = None
migrate = None

# SQLAlchemy
try:
    from flask_sqlalchemy import SQLAlchemy

    db = SQLAlchemy()
    logger.info("SQLAlchemy extension loaded")
except ImportError as e:
    logger.error(f"Failed to load SQLAlchemy: {e}")

# Flask-Login
try:
    from flask_login import LoginManager

    login_manager = LoginManager()
    login_manager.login_view = 'auth.login'
    login_manager.login_message = 'Please log in to access this page.'
    login_manager.login_message_category = 'info'
    logger.info("Flask-Login extension loaded")
except ImportError as e:
    logger.error(f"Failed to load Flask-Login: {e}")

# CSRF Protection
try:
    from flask_wtf.csrf import CSRFProtect

    csrf = CSRFProtect()
    logger.info("CSRF protection loaded")
except ImportError as e:
    logger.warning(f"CSRF protection not available: {e}")

# Flask-Migrate
try:
    from flask_migrate import Migrate

    migrate = Migrate()
    logger.info("Flask-Migrate extension loaded")
except ImportError as e:
    logger.warning(f"Flask-Migrate not available: {e}")


# Redis Client
class RedisClient:
    """Redis client wrapper with graceful fallbacks"""

    def __init__(self):
        self.client = None
        self._connected = False

    def init_app(self, app):
        """Initialize Redis client"""
        try:
            import redis
            redis_url = app.config.get('REDIS_URL', 'redis://localhost:6379/0')
            self.client = redis.from_url(redis_url, decode_responses=True)

            # Test connection
            self.client.ping()
            self._connected = True
            app.logger.info(f"Redis connected: {redis_url}")

        except ImportError:
            app.logger.warning("Redis not installed, using memory fallback")
            self._setup_memory_fallback()
        except Exception as e:
            app.logger.warning(f"Redis connection failed: {e}, using memory fallback")
            self._setup_memory_fallback()

    def _setup_memory_fallback(self):
        """Setup in-memory fallback"""
        self._memory_store = {}
        self._connected = False

    @property
    def connected(self):
        return self._connected

    def get(self, key):
        """Get value from Redis or memory"""
        try:
            if self.client:
                return self.client.get(key)
            else:
                return self._memory_store.get(key)
        except Exception as e:
            logger.error(f"Redis GET error: {e}")
            return None

    def set(self, key, value, ex=None):
        """Set value in Redis or memory"""
        try:
            if self.client:
                return self.client.set(key, value, ex=ex)
            else:
                self._memory_store[key] = value
                return True
        except Exception as e:
            logger.error(f"Redis SET error: {e}")
            return False

    def delete(self, key):
        """Delete key from Redis or memory"""
        try:
            if self.client:
                return self.client.delete(key)
            else:
                return self._memory_store.pop(key, None) is not None
        except Exception as e:
            logger.error(f"Redis DELETE error: {e}")
            return False

    def exists(self, key):
        """Check if key exists"""
        try:
            if self.client:
                return self.client.exists(key)
            else:
                return key in self._memory_store
        except Exception as e:
            logger.error(f"Redis EXISTS error: {e}")
            return False

    def incr(self, key, amount=1):
        """Increment key value"""
        try:
            if self.client:
                return self.client.incr(key, amount)
            else:
                current = int(self._memory_store.get(key, 0))
                self._memory_store[key] = str(current + amount)
                return current + amount
        except Exception as e:
            logger.error(f"Redis INCR error: {e}")
            return None

    def expire(self, key, seconds):
        """Set key expiration (memory fallback ignores this)"""
        try:
            if self.client:
                return self.client.expire(key, seconds)
            else:
                return True  # Memory fallback doesn't support expiration
        except Exception as e:
            logger.error(f"Redis EXPIRE error: {e}")
            return False


# Initialize Redis client
redis_client = RedisClient()

# Flask-Caching
try:
    from flask_caching import Cache

    cache = Cache()
    logger.info("Flask-Caching loaded")
except ImportError as e:
    logger.warning(f"Flask-Caching not available: {e}")

# Flask-Limiter
try:
    from flask_limiter import Limiter
    from flask_limiter.util import get_remote_address

    limiter = Limiter(
        key_func=get_remote_address,
        default_limits=["1000 per hour"],
        storage_uri=os.getenv('REDIS_URL', 'memory://'),
        strategy="fixed-window",
    )
    logger.info("Flask-Limiter loaded")
except ImportError as e:
    logger.warning(f"Flask-Limiter not available: {e}")

# User loader for Flask-Login
if login_manager:
    @login_manager.user_loader
    def load_user(user_id):
        """Load user from database"""
        try:
            if db:
                from crypto_hunter_web.models import User
                return User.query.get(int(user_id))
        except Exception as e:
            logger.error(f"Error loading user {user_id}: {e}")
        return None


# Initialize all extensions
def init_all_extensions(app):
    """Initialize all available extensions"""

    # Database
    if db:
        db.init_app(app)
        app.logger.info("Database initialized")

    # Migrations
    if migrate and db:
        migrate.init_app(app, db)
        app.logger.info("Migrations initialized")

    # Login Manager
    if login_manager:
        login_manager.init_app(app)
        app.logger.info("Login manager initialized")

    # CSRF Protection
    if csrf and app.config.get('WTF_CSRF_ENABLED', True):
        csrf.init_app(app)
        app.logger.info("CSRF protection initialized")

    # Redis
    if redis_client:
        redis_client.init_app(app)

    # Cache
    if cache:
        cache_config = {
            'CACHE_TYPE': 'RedisCache' if redis_client.connected else 'SimpleCache',
            'CACHE_DEFAULT_TIMEOUT': 300,
        }
        if redis_client.connected:
            cache_config['CACHE_REDIS_URL'] = app.config.get('REDIS_URL')

        app.config.update(cache_config)
        cache.init_app(app)
        app.logger.info("Cache initialized")

    # Rate Limiter
    if limiter:
        try:
            limiter.init_app(app)
            app.logger.info("Rate limiter initialized")
        except Exception as e:
            app.logger.warning(f"Rate limiter failed to initialize: {e}")


# Export all extensions
__all__ = [
    'db',
    'login_manager',
    'csrf',
    'redis_client',
    'cache',
    'limiter',
    'migrate',
    'init_all_extensions'
]