"""
Custom decorators for enhanced functionality
"""

import functools
import time
import hashlib
from collections import defaultdict, deque
from datetime import datetime, timedelta
from flask import request, jsonify, session

# Rate limiting storage
rate_limit_storage = defaultdict(deque)

# Cache storage
cache_storage = {}

def rate_limit(max_requests=100, window_seconds=3600, per_user=True):
    """Rate limiting decorator"""
    def decorator(f):
        @functools.wraps(f)
        def decorated_function(*args, **kwargs):
            # Determine the key for rate limiting
            if per_user and 'user_id' in session:
                key = f"user_{session['user_id']}"
            else:
                key = request.remote_addr
            
            now = time.time()
            window_start = now - window_seconds
            
            # Clean old entries
            while rate_limit_storage[key] and rate_limit_storage[key][0] < window_start:
                rate_limit_storage[key].popleft()
            
            # Check if limit exceeded
            if len(rate_limit_storage[key]) >= max_requests:
                return jsonify({
                    'error': 'Rate limit exceeded',
                    'retry_after': int(rate_limit_storage[key][0] + window_seconds - now)
                }), 429
            
            # Add current request
            rate_limit_storage[key].append(now)
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def cache_result(timeout_seconds=300, key_func=None):
    """Cache function results"""
    def decorator(f):
        @functools.wraps(f)
        def decorated_function(*args, **kwargs):
            # Generate cache key
            if key_func:
                cache_key = key_func(*args, **kwargs)
            else:
                key_data = f"{f.__name__}_{str(args)}_{str(sorted(kwargs.items()))}"
                cache_key = hashlib.md5(key_data.encode()).hexdigest()
            
            # Check cache
            if cache_key in cache_storage:
                cached_result, timestamp = cache_storage[cache_key]
                if time.time() - timestamp < timeout_seconds:
                    return cached_result
            
            # Compute result and cache it
            result = f(*args, **kwargs)
            cache_storage[cache_key] = (result, time.time())
            
            # Clean old cache entries periodically
            if len(cache_storage) > 1000:
                _clean_cache()
            
            return result
        return decorated_function
    return decorator

def _clean_cache():
    """Clean expired cache entries"""
    current_time = time.time()
    expired_keys = []
    
    for key, (_, timestamp) in cache_storage.items():
        if current_time - timestamp > 3600:  # 1 hour max
            expired_keys.append(key)
    
    for key in expired_keys:
        del cache_storage[key]

def require_permission(permission):
    """Require specific permission for access"""
    def decorator(f):
        @functools.wraps(f)
        def decorated_function(*args, **kwargs):
            if 'user_id' not in session:
                return jsonify({'error': 'Authentication required'}), 401
            
            from app.models.user import User
            user = User.query.get(session['user_id'])
            
            if not user:
                return jsonify({'error': 'User not found'}), 401
            
            # Check permissions based on user role
            permissions = {
                'admin': ['read', 'write', 'delete', 'admin'],
                'expert': ['read', 'write', 'verify'],
                'analyst': ['read', 'write']
            }
            
            user_permissions = permissions.get(user.role, ['read'])
            
            if permission not in user_permissions:
                return jsonify({'error': 'Insufficient permissions'}), 403
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def log_activity(action_type):
    """Log user activity"""
    def decorator(f):
        @functools.wraps(f)
        def decorated_function(*args, **kwargs):
            from app.services.auth_service import AuthService
            
            start_time = time.time()
            
            try:
                result = f(*args, **kwargs)
                
                # Log successful action
                duration = time.time() - start_time
                AuthService.log_action(
                    action_type,
                    f"Action completed in {duration:.2f}s",
                    session.get('user_id')
                )
                
                return result
                
            except Exception as e:
                # Log failed action
                duration = time.time() - start_time
                AuthService.log_action(
                    f"{action_type}_failed",
                    f"Action failed after {duration:.2f}s: {str(e)}",
                    session.get('user_id')
                )
                raise
                
        return decorated_function
    return decorator

def validate_json_schema(schema):
    """Validate JSON request against schema"""
    def decorator(f):
        @functools.wraps(f)
        def decorated_function(*args, **kwargs):
            if not request.is_json:
                return jsonify({'error': 'Content-Type must be application/json'}), 400
            
            data = request.get_json()
            
            # Simple schema validation
            for field, field_type in schema.items():
                if field not in data:
                    return jsonify({'error': f'Missing required field: {field}'}), 400
                
                if not isinstance(data[field], field_type):
                    return jsonify({'error': f'Invalid type for field {field}'}), 400
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def compress_response(min_size=1000):
    """Compress large responses"""
    def decorator(f):
        @functools.wraps(f)
        def decorated_function(*args, **kwargs):
            response = f(*args, **kwargs)
            
            # Simple compression hint for large responses
            if hasattr(response, 'data') and len(response.data) > min_size:
                response.headers['Vary'] = 'Accept-Encoding'
            
            return response
        return decorated_function
    return decorator


def track_api_usage(f):
    """Decorator to track API usage"""

    @functools.wraps(f)
    def decorated_function(*args, **kwargs):
        start_time = time.time()

        try:
            result = f(*args, **kwargs)

            # Log successful API call
            execution_time = time.time() - start_time
            print(f"API: {f.__name__} completed in {execution_time:.3f}s")

            return result

        except Exception as e:
            # Log failed API call
            execution_time = time.time() - start_time
            print(f"API: {f.__name__} failed after {execution_time:.3f}s - {str(e)}")
            raise

    return decorated_function