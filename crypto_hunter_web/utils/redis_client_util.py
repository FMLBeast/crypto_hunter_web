# crypto_hunter_web/utils/redis_client.py - COMPLETE REDIS CLIENT IMPLEMENTATION

import os
import json
import logging
from typing import Any, Optional, List, Dict
from datetime import datetime, timedelta

try:
    import redis
    from redis.exceptions import ConnectionError, TimeoutError, RedisError
    REDIS_AVAILABLE = True
except ImportError:
    REDIS_AVAILABLE = False

logger = logging.getLogger(__name__)


class RedisClient:
    """Enhanced Redis client with fallback and error handling"""

    def __init__(self, url: str = None, decode_responses: bool = True):
        self._client = None
        self._available = False

        if not REDIS_AVAILABLE:
            logger.warning("Redis library not available, using fallback storage")
            self._fallback_storage = {}
            return

        try:
            redis_url = url or os.getenv('REDIS_URL', 'redis://localhost:6379/0')

            # Parse connection parameters
            self._client = redis.from_url(
                redis_url,
                decode_responses=decode_responses,
                socket_timeout=5,
                socket_connect_timeout=5,
                retry_on_timeout=True,
                health_check_interval=30
            )

            # Test connection
            self._client.ping()
            self._available = True
            logger.info("Redis client initialized successfully")

        except Exception as e:
            logger.error(f"Redis connection failed, using fallback: {e}")
            self._client = None
            self._available = False
            self._fallback_storage = {}

    @property
    def is_available(self) -> bool:
        """Check if Redis is available"""
        return self._available and self._client is not None

    def ping(self) -> bool:
        """Test Redis connection"""
        try:
            if self.is_available:
                return self._client.ping()
            return False
        except Exception:
            return False

    def get(self, key: str) -> Optional[str]:
        """Get value by key"""
        try:
            if self.is_available:
                return self._client.get(key)
            else:
                # Fallback to in-memory storage
                return self._fallback_storage.get(key)
        except Exception as e:
            logger.error(f"Redis GET error for key {key}: {e}")
            return None

    def set(self, key: str, value: Any, ex: int = None, px: int = None, nx: bool = False, xx: bool = False) -> bool:
        """Set key-value pair with optional expiration"""
        try:
            if self.is_available:
                return bool(self._client.set(key, value, ex=ex, px=px, nx=nx, xx=xx))
            else:
                # Fallback storage with expiration tracking
                self._fallback_storage[key] = value
                if ex:
                    # Set expiration time
                    self._fallback_storage[f"{key}:expires"] = datetime.utcnow() + timedelta(seconds=ex)
                return True
        except Exception as e:
            logger.error(f"Redis SET error for key {key}: {e}")
            return False

    def delete(self, *keys: str) -> int:
        """Delete one or more keys"""
        try:
            if self.is_available:
                return self._client.delete(*keys)
            else:
                count = 0
                for key in keys:
                    if key in self._fallback_storage:
                        del self._fallback_storage[key]
                        count += 1
                    # Also remove expiration tracking
                    exp_key = f"{key}:expires"
                    if exp_key in self._fallback_storage:
                        del self._fallback_storage[exp_key]
                return count
        except Exception as e:
            logger.error(f"Redis DELETE error for keys {keys}: {e}")
            return 0

    def exists(self, *keys: str) -> int:
        """Check if keys exist"""
        try:
            if self.is_available:
                return self._client.exists(*keys)
            else:
                count = 0
                for key in keys:
                    if self._is_key_valid(key):
                        count += 1
                return count
        except Exception as e:
            logger.error(f"Redis EXISTS error for keys {keys}: {e}")
            return 0

    def expire(self, key: str, time: int) -> bool:
        """Set expiration time for key"""
        try:
            if self.is_available:
                return bool(self._client.expire(key, time))
            else:
                if key in self._fallback_storage:
                    self._fallback_storage[f"{key}:expires"] = datetime.utcnow() + timedelta(seconds=time)
                    return True
                return False
        except Exception as e:
            logger.error(f"Redis EXPIRE error for key {key}: {e}")
            return False

    def ttl(self, key: str) -> int:
        """Get time to live for key"""
        try:
            if self.is_available:
                return self._client.ttl(key)
            else:
                exp_key = f"{key}:expires"
                if exp_key in self._fallback_storage:
                    expires_at = self._fallback_storage[exp_key]
                    remaining = (expires_at - datetime.utcnow()).total_seconds()
                    return int(remaining) if remaining > 0 else -2
                return -1 if key in self._fallback_storage else -2
        except Exception as e:
            logger.error(f"Redis TTL error for key {key}: {e}")
            return -2

    def incr(self, key: str, amount: int = 1) -> Optional[int]:
        """Increment value by amount"""
        try:
            if self.is_available:
                return self._client.incr(key, amount)
            else:
                current = int(self._fallback_storage.get(key, 0))
                new_value = current + amount
                self._fallback_storage[key] = str(new_value)
                return new_value
        except Exception as e:
            logger.error(f"Redis INCR error for key {key}: {e}")
            return None

    def decr(self, key: str, amount: int = 1) -> Optional[int]:
        """Decrement value by amount"""
        try:
            if self.is_available:
                return self._client.decr(key, amount)
            else:
                current = int(self._fallback_storage.get(key, 0))
                new_value = current - amount
                self._fallback_storage[key] = str(new_value)
                return new_value
        except Exception as e:
            logger.error(f"Redis DECR error for key {key}: {e}")
            return None

    # List operations
    def lpush(self, key: str, *values) -> Optional[int]:
        """Push values to left of list"""
        try:
            if self.is_available:
                return self._client.lpush(key, *values)
            else:
                if key not in self._fallback_storage:
                    self._fallback_storage[key] = []
                for value in reversed(values):
                    self._fallback_storage[key].insert(0, value)
                return len(self._fallback_storage[key])
        except Exception as e:
            logger.error(f"Redis LPUSH error for key {key}: {e}")
            return None

    def rpush(self, key: str, *values) -> Optional[int]:
        """Push values to right of list"""
        try:
            if self.is_available:
                return self._client.rpush(key, *values)
            else:
                if key not in self._fallback_storage:
                    self._fallback_storage[key] = []
                self._fallback_storage[key].extend(values)
                return len(self._fallback_storage[key])
        except Exception as e:
            logger.error(f"Redis RPUSH error for key {key}: {e}")
            return None

    def lrange(self, key: str, start: int, end: int) -> List[str]:
        """Get range of list elements"""
        try:
            if self.is_available:
                return self._client.lrange(key, start, end)
            else:
                if key in self._fallback_storage and isinstance(self._fallback_storage[key], list):
                    return self._fallback_storage[key][start:end+1 if end != -1 else None]
                return []
        except Exception as e:
            logger.error(f"Redis LRANGE error for key {key}: {e}")
            return []

    def llen(self, key: str) -> int:
        """Get length of list"""
        try:
            if self.is_available:
                return self._client.llen(key)
            else:
                if key in self._fallback_storage and isinstance(self._fallback_storage[key], list):
                    return len(self._fallback_storage[key])
                return 0
        except Exception as e:
            logger.error(f"Redis LLEN error for key {key}: {e}")
            return 0

    # Hash operations
    def hset(self, key: str, field: str, value: Any) -> bool:
        """Set hash field"""
        try:
            if self.is_available:
                return bool(self._client.hset(key, field, value))
            else:
                if key not in self._fallback_storage:
                    self._fallback_storage[key] = {}
                self._fallback_storage[key][field] = value
                return True
        except Exception as e:
            logger.error(f"Redis HSET error for key {key}, field {field}: {e}")
            return False

    def hget(self, key: str, field: str) -> Optional[str]:
        """Get hash field value"""
        try:
            if self.is_available:
                return self._client.hget(key, field)
            else:
                if key in self._fallback_storage and isinstance(self._fallback_storage[key], dict):
                    return self._fallback_storage[key].get(field)
                return None
        except Exception as e:
            logger.error(f"Redis HGET error for key {key}, field {field}: {e}")
            return None

    def hdel(self, key: str, *fields) -> int:
        """Delete hash fields"""
        try:
            if self.is_available:
                return self._client.hdel(key, *fields)
            else:
                if key in self._fallback_storage and isinstance(self._fallback_storage[key], dict):
                    count = 0
                    for field in fields:
                        if field in self._fallback_storage[key]:
                            del self._fallback_storage[key][field]
                            count += 1
                    return count
                return 0
        except Exception as e:
            logger.error(f"Redis HDEL error for key {key}, fields {fields}: {e}")
            return 0

    def hkeys(self, key: str) -> List[str]:
        """Get all hash field names"""
        try:
            if self.is_available:
                return self._client.hkeys(key)
            else:
                if key in self._fallback_storage and isinstance(self._fallback_storage[key], dict):
                    return list(self._fallback_storage[key].keys())
                return []
        except Exception as e:
            logger.error(f"Redis HKEYS error for key {key}: {e}")
            return []

    def hlen(self, key: str) -> int:
        """Get number of hash fields"""
        try:
            if self.is_available:
                return self._client.hlen(key)
            else:
                if key in self._fallback_storage and isinstance(self._fallback_storage[key], dict):
                    return len(self._fallback_storage[key])
                return 0
        except Exception as e:
            logger.error(f"Redis HLEN error for key {key}: {e}")
            return 0

    # Set operations
    def sadd(self, key: str, *values) -> int:
        """Add values to set"""
        try:
            if self.is_available:
                return self._client.sadd(key, *values)
            else:
                if key not in self._fallback_storage:
                    self._fallback_storage[key] = set()
                initial_size = len(self._fallback_storage[key])
                self._fallback_storage[key].update(values)
                return len(self._fallback_storage[key]) - initial_size
        except Exception as e:
            logger.error(f"Redis SADD error for key {key}: {e}")
            return 0

    def srem(self, key: str, *values) -> int:
        """Remove values from set"""
        try:
            if self.is_available:
                return self._client.srem(key, *values)
            else:
                if key in self._fallback_storage and isinstance(self._fallback_storage[key], set):
                    count = 0
                    for value in values:
                        if value in self._fallback_storage[key]:
                            self._fallback_storage[key].remove(value)
                            count += 1
                    return count
                return 0
        except Exception as e:
            logger.error(f"Redis SREM error for key {key}: {e}")
            return 0

    def smembers(self, key: str) -> set:
        """Get all set members"""
        try:
            if self.is_available:
                return self._client.smembers(key)
            else:
                if key in self._fallback_storage and isinstance(self._fallback_storage[key], set):
                    return self._fallback_storage[key].copy()
                return set()
        except Exception as e:
            logger.error(f"Redis SMEMBERS error for key {key}: {e}")
            return set()

    def scard(self, key: str) -> int:
        """Get set cardinality"""
        try:
            if self.is_available:
                return self._client.scard(key)
            else:
                if key in self._fallback_storage and isinstance(self._fallback_storage[key], set):
                    return len(self._fallback_storage[key])
                return 0
        except Exception as e:
            logger.error(f"Redis SCARD error for key {key}: {e}")
            return 0

    # JSON helper methods
    def set_json(self, key: str, value: Any, ex: int = None) -> bool:
        """Set JSON serialized value"""
        try:
            json_value = json.dumps(value, default=str)
            return self.set(key, json_value, ex=ex)
        except Exception as e:
            logger.error(f"JSON serialization error for key {key}: {e}")
            return False

    def get_json(self, key: str) -> Optional[Any]:
        """Get JSON deserialized value"""
        try:
            value = self.get(key)
            if value:
                return json.loads(value)
            return None
        except Exception as e:
            logger.error(f"JSON deserialization error for key {key}: {e}")
            return None

    def _is_key_valid(self, key: str) -> bool:
        """Check if key exists and hasn't expired (fallback mode)"""
        if key not in self._fallback_storage:
            return False

        # Check expiration
        exp_key = f"{key}:expires"
        if exp_key in self._fallback_storage:
            expires_at = self._fallback_storage[exp_key]
            if datetime.utcnow() >= expires_at:
                # Key has expired, remove it
                del self._fallback_storage[key]
                del self._fallback_storage[exp_key]
                return False

        return True

    def cleanup_expired_keys(self):
        """Clean up expired keys in fallback mode"""
        if self.is_available:
            return

        expired_keys = []
        for key, expires_at in self._fallback_storage.items():
            if key.endswith(':expires') and isinstance(expires_at, datetime):
                if datetime.utcnow() >= expires_at:
                    original_key = key[:-8]  # Remove ':expires'
                    expired_keys.extend([original_key, key])

        for key in expired_keys:
            self._fallback_storage.pop(key, None)

    def get_connection_info(self) -> Dict[str, Any]:
        """Get Redis connection information"""
        info = {
            'available': self.is_available,
            'fallback_mode': not self.is_available,
            'redis_library_available': REDIS_AVAILABLE
        }

        if self.is_available:
            try:
                redis_info = self._client.info()
                info.update({
                    'redis_version': redis_info.get('redis_version'),
                    'connected_clients': redis_info.get('connected_clients'),
                    'used_memory_human': redis_info.get('used_memory_human'),
                    'uptime_in_seconds': redis_info.get('uptime_in_seconds')
                })
            except Exception as e:
                info['error'] = str(e)
        else:
            info['fallback_keys_count'] = len(self._fallback_storage)

        return info


# Global Redis client instance
redis_client = RedisClient()


# Convenience functions
def get_redis_client() -> RedisClient:
    """Get the global Redis client instance"""
    return redis_client


def is_redis_available() -> bool:
    """Check if Redis is available"""
    return redis_client.is_available


# Cache version for handling schema changes
CACHE_VERSION = "v1"

# Cache prefixes for different types of data
class CachePrefix:
    FILE_ANALYSIS = "file_analysis"
    CRYPTO_ANALYSIS = "crypto_analysis"
    USER_DATA = "user_data"
    FINDING = "finding"
    REGION = "region"
    TASK = "task"
    SESSION = "session"
    STATS = "stats"


def get_cache_key(prefix: str, identifier: str, subtype: str = None) -> str:
    """
    Generate a standardized cache key with version and prefix

    Args:
        prefix: The cache prefix (use CachePrefix constants)
        identifier: The unique identifier for the cached item
        subtype: Optional subtype for more specific categorization

    Returns:
        Formatted cache key string
    """
    if subtype:
        return f"cache:{CACHE_VERSION}:{prefix}:{subtype}:{identifier}"
    return f"cache:{CACHE_VERSION}:{prefix}:{identifier}"


def cache_result(key: str, value: Any, ttl: int = 3600) -> bool:
    """
    Cache a result with TTL

    Args:
        key: Cache key
        value: Value to cache
        ttl: Time-to-live in seconds (default: 1 hour)

    Returns:
        True if caching was successful, False otherwise
    """
    # Track cache statistics
    increment_cache_stat("set_count")

    # Set cache with TTL
    return redis_client.set_json(key, value, ex=ttl)


def get_cached_result(key: str) -> Optional[Any]:
    """
    Get cached result

    Args:
        key: Cache key

    Returns:
        Cached value or None if not found
    """
    # Get value from cache
    value = redis_client.get_json(key)

    # Track cache statistics
    if value is not None:
        increment_cache_stat("hit_count")
    else:
        increment_cache_stat("miss_count")

    return value


def cache_file_analysis(file_hash: str, analysis_result: Dict, ttl: int = 3600) -> bool:
    """
    Cache file analysis result

    Args:
        file_hash: SHA256 hash of the file
        analysis_result: Analysis result to cache
        ttl: Time-to-live in seconds (default: 1 hour)

    Returns:
        True if caching was successful, False otherwise
    """
    key = get_cache_key(CachePrefix.FILE_ANALYSIS, file_hash)
    return cache_result(key, analysis_result, ttl)


def get_cached_file_analysis(file_hash: str) -> Optional[Dict]:
    """
    Get cached file analysis result

    Args:
        file_hash: SHA256 hash of the file

    Returns:
        Cached analysis result or None if not found
    """
    key = get_cache_key(CachePrefix.FILE_ANALYSIS, file_hash)
    return get_cached_result(key)


def cache_crypto_analysis(file_hash: str, crypto_analysis: Dict, ttl: int = 3600) -> bool:
    """
    Cache crypto analysis result

    Args:
        file_hash: SHA256 hash of the file
        crypto_analysis: Crypto analysis result to cache
        ttl: Time-to-live in seconds (default: 1 hour)

    Returns:
        True if caching was successful, False otherwise
    """
    key = get_cache_key(CachePrefix.CRYPTO_ANALYSIS, file_hash)
    return cache_result(key, crypto_analysis, ttl)


def get_cached_crypto_analysis(file_hash: str) -> Optional[Dict]:
    """
    Get cached crypto analysis result

    Args:
        file_hash: SHA256 hash of the file

    Returns:
        Cached crypto analysis result or None if not found
    """
    key = get_cache_key(CachePrefix.CRYPTO_ANALYSIS, file_hash)
    return get_cached_result(key)


def cache_session_data(session_id: str, session_data: Dict, ttl: int = 86400) -> bool:
    """
    Cache puzzle session data

    Args:
        session_id: Session ID
        session_data: Session data to cache
        ttl: Time-to-live in seconds (default: 24 hours)

    Returns:
        True if caching was successful, False otherwise
    """
    key = get_cache_key(CachePrefix.SESSION, session_id)
    return cache_result(key, session_data, ttl)


def get_cached_session_data(session_id: str) -> Optional[Dict]:
    """
    Get cached puzzle session data

    Args:
        session_id: Session ID

    Returns:
        Cached session data or None if not found
    """
    key = get_cache_key(CachePrefix.SESSION, session_id)
    return get_cached_result(key)


def invalidate_cache(pattern: str = None):
    """
    Invalidate cache entries matching pattern

    Args:
        pattern: Pattern to match cache keys (e.g., "file_analysis:*")
               If None, invalidates all cache entries
    """
    if not redis_client.is_available:
        logger.warning("Redis not available, cannot invalidate cache")
        return

    try:
        if pattern:
            # Format pattern with cache version prefix
            if not pattern.startswith("cache:"):
                pattern = f"cache:{CACHE_VERSION}:{pattern}"

            # Use SCAN to find matching keys
            cursor = 0
            while True:
                cursor, keys = redis_client._client.scan(cursor, match=pattern, count=100)
                if keys:
                    redis_client._client.delete(*keys)
                if cursor == 0:
                    break

            logger.info(f"Cache invalidated for pattern: {pattern}")
        else:
            # Find all cache keys
            cursor = 0
            all_keys = []
            while True:
                cursor, keys = redis_client._client.scan(cursor, match=f"cache:{CACHE_VERSION}:*", count=100)
                all_keys.extend(keys)
                if cursor == 0:
                    break

            # Delete all cache keys
            if all_keys:
                redis_client._client.delete(*all_keys)

            logger.info(f"Full cache invalidation completed, {len(all_keys)} keys removed")
    except Exception as e:
        logger.error(f"Error invalidating cache: {e}")


def invalidate_file_cache(file_hash: str):
    """
    Invalidate all cache entries for a specific file

    Args:
        file_hash: SHA256 hash of the file
    """
    pattern = f"*:{file_hash}"
    invalidate_cache(pattern)


def invalidate_session_cache(session_id: str):
    """
    Invalidate all cache entries for a specific session

    Args:
        session_id: Session ID
    """
    pattern = f"{CachePrefix.SESSION}:{session_id}"
    invalidate_cache(pattern)


def increment_cache_stat(stat_name: str, amount: int = 1):
    """
    Increment cache statistics counter

    Args:
        stat_name: Name of the statistic to increment
        amount: Amount to increment by (default: 1)
    """
    if not redis_client.is_available:
        return

    try:
        key = f"cache:{CACHE_VERSION}:{CachePrefix.STATS}:{stat_name}"
        redis_client._client.incrby(key, amount)
    except Exception as e:
        logger.debug(f"Error incrementing cache stat: {e}")


def get_cache_stats() -> Dict[str, int]:
    """
    Get cache statistics

    Returns:
        Dictionary of cache statistics
    """
    if not redis_client.is_available:
        return {
            "hit_count": 0,
            "miss_count": 0,
            "set_count": 0,
            "hit_ratio": 0.0
        }

    try:
        hit_count = int(redis_client.get(f"cache:{CACHE_VERSION}:{CachePrefix.STATS}:hit_count") or 0)
        miss_count = int(redis_client.get(f"cache:{CACHE_VERSION}:{CachePrefix.STATS}:miss_count") or 0)
        set_count = int(redis_client.get(f"cache:{CACHE_VERSION}:{CachePrefix.STATS}:set_count") or 0)

        total_requests = hit_count + miss_count
        hit_ratio = hit_count / total_requests if total_requests > 0 else 0.0

        return {
            "hit_count": hit_count,
            "miss_count": miss_count,
            "set_count": set_count,
            "hit_ratio": hit_ratio
        }
    except Exception as e:
        logger.error(f"Error getting cache stats: {e}")
        return {
            "hit_count": 0,
            "miss_count": 0,
            "set_count": 0,
            "hit_ratio": 0.0,
            "error": str(e)
        }


def warm_cache(file_hash: str, analysis_result: Dict):
    """
    Warm cache with analysis result

    Args:
        file_hash: SHA256 hash of the file
        analysis_result: Analysis result to cache
    """
    # Cache file analysis with longer TTL (4 hours)
    cache_file_analysis(file_hash, analysis_result, ttl=14400)

    # Cache crypto analysis separately if available
    if "crypto_analysis" in analysis_result:
        cache_crypto_analysis(file_hash, analysis_result["crypto_analysis"], ttl=14400)

    logger.info(f"Cache warmed for file: {file_hash}")
