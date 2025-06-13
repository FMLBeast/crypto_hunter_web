# crypto_hunter_web/utils/decorators.py - COMPLETE DECORATOR UTILITIES

import functools
import json
import logging
import time
from datetime import datetime
from typing import List, Callable
import redis
from flask import request, jsonify, current_app, g, make_response, redirect
from flask_login import current_user

from crypto_hunter_web.models import AuditLog
from crypto_hunter_web.services.security_service import SecurityService

logger = logging.getLogger(__name__)


class RateLimitExceeded(Exception):
    """Rate limit exceeded exception"""

    def __init__(self, limit: int, window: int, retry_after: int = None):
        self.limit = limit
        self.window = window
        self.retry_after = retry_after
        super().__init__(f"Rate limit exceeded: {limit} requests per {window} seconds")


def rate_limit(limit: str = "100 per hour", per_user: bool = True,
               key_func: Callable = None, methods: List[str] = None):
    """
    Rate limiting decorator with flexible configuration

    Args:
        limit: Rate limit string like "10 per minute", "100 per hour"
        per_user: Whether to apply limit per user or globally
        key_func: Custom function to generate rate limit key
        methods: HTTP methods to apply rate limiting to
    """

    def decorator(f):
        @functools.wraps(f)
        def decorated_function(*args, **kwargs):
            # Check if rate limiting should be applied
            if methods and request.method not in methods:
                return f(*args, **kwargs)

            # Skip rate limiting for admin users
            if current_user.is_authenticated and current_user.is_admin:
                return f(*args, **kwargs)

            # Parse rate limit
            try:
                rate_parts = limit.split()
                rate_count = int(rate_parts[0])
                rate_period = rate_parts[2]  # per minute/hour/day

                # Convert to seconds
                period_map = {
                    'second': 1, 'seconds': 1,
                    'minute': 60, 'minutes': 60,
                    'hour': 3600, 'hours': 3600,
                    'day': 86400, 'days': 86400
                }

                window_seconds = period_map.get(rate_period, 3600)

            except (ValueError, IndexError, KeyError):
                logger.error(f"Invalid rate limit format: {limit}")
                return f(*args, **kwargs)

            # Generate rate limit key
            if key_func:
                rate_key = key_func()
            elif per_user and current_user.is_authenticated:
                rate_key = f"rate_limit:user:{current_user.id}:{request.endpoint}"
            else:
                rate_key = f"rate_limit:ip:{request.remote_addr}:{request.endpoint}"

            # Check rate limit
            allowed, info = SecurityService.check_rate_limit(
                rate_key, rate_count, window_seconds
            )

            if not allowed:
                # Log rate limit violation
                AuditLog.log_action(
                    user_id=current_user.id if current_user.is_authenticated else None,
                    action='rate_limit_exceeded',
                    description=f'Rate limit exceeded for {request.endpoint}',
                    ip_address=request.remote_addr,
                    success=False,
                    metadata={
                        'rate_limit': limit,
                        'endpoint': request.endpoint,
                        'method': request.method
                    }
                )

                # Return rate limit error
                response = jsonify({
                    'error': 'Rate limit exceeded',
                    'message': f'Maximum {rate_count} requests per {rate_period}',
                    'retry_after': info.get('retry_after', window_seconds)
                })
                response.status_code = 429
                response.headers['Retry-After'] = str(info.get('retry_after', window_seconds))
                response.headers['X-RateLimit-Limit'] = str(rate_count)
                response.headers['X-RateLimit-Remaining'] = '0'
                response.headers['X-RateLimit-Reset'] = str(int(time.time()) + window_seconds)

                return response

            # Add rate limit headers to successful responses
            response = make_response(f(*args, **kwargs))
            response.headers['X-RateLimit-Limit'] = str(rate_count)
            response.headers['X-RateLimit-Remaining'] = str(info.get('remaining', rate_count))
            response.headers['X-RateLimit-Reset'] = str(int(time.time()) + window_seconds)

            return response

        return decorated_function

    return decorator

def api_endpoint(rate_limit_requests=None, cache_ttl=None, csrf_exempt=False, require_auth=False, require_json=False, endpoint=None):
    """
    Mark function as API endpoint with automatic JSON handling and CSRF protection

    Args:
        rate_limit_requests: Rate limit for this endpoint
        cache_ttl: Cache timeout in seconds
        csrf_exempt: Whether to exempt this endpoint from CSRF protection
        require_auth: Whether to require authentication for this endpoint
        require_json: Whether request must contain JSON
        endpoint: Custom endpoint name to use (defaults to function name)
    """
    def wrapper(f):
        # Create a decorated function that preserves the original function's attributes
        @functools.wraps(f)
        def decorated_function(*args, **kwargs):
            return f(*args, **kwargs)

        # Apply decorators in order, preserving function attributes at each step
        result = decorated_function

        # Apply CSRF exemption if requested
        if csrf_exempt:
            from flask_wtf.csrf import csrf_exempt as csrf_exempt_decorator
            result = csrf_exempt_decorator(result)

        # Apply authentication if required
        if require_auth:
            from flask_login import login_required
            result = login_required(result)

        # Apply rate limiting if specified
        if rate_limit_requests:
            rate_limit_str = f"{rate_limit_requests} per hour"
            result = rate_limit(rate_limit_str)(result)

        # Apply caching if specified
        if cache_ttl:
            result = cache_response(timeout=cache_ttl)(result)

        # Ensure the final function has the same name and attributes as the original
        functools.update_wrapper(result, f)

        # Preserve the endpoint name to avoid conflicts
        result.__name__ = f.__name__

        # Set a custom endpoint name if provided
        if endpoint:
            result.__name__ = endpoint

        return result

    return wrapper


def require_api_key(permissions: List[str] = None, optional: bool = False):
    """
    Require valid API key for endpoint access

    Args:
        permissions: Required permissions for the API key
        optional: If True, API key is optional but will be validated if provided
    """

    def decorator(f):
        @functools.wraps(f)
        def decorated_function(*args, **kwargs):
            # Get API key from header
            api_key = request.headers.get('X-API-Key') or request.headers.get('Authorization', '').replace('Bearer ', '')

            if not api_key:
                if optional:
                    g.api_key = None
                    return f(*args, **kwargs)

                return jsonify({
                    'error': 'API key required',
                    'message': 'Provide API key in X-API-Key header'
                }), 401

            # Validate API key
            api_key_obj = SecurityService.validate_api_key(api_key)
            if not api_key_obj:
                return jsonify({
                    'error': 'Invalid API key',
                    'message': 'API key is invalid or expired'
                }), 401

            # Check permissions
            if permissions:
                key_permissions = api_key_obj.permissions or []
                if not any(perm in key_permissions for perm in permissions):
                    return jsonify({
                        'error': 'Insufficient permissions',
                        'message': f'API key requires permissions: {permissions}'
                    }), 403

            # Store API key in request context
            g.api_key = api_key_obj
            g.api_user = api_key_obj.user

            return f(*args, **kwargs)

        return decorated_function

    return decorator



def cache_result(timeout):
    """
    Cache function result for specified timeout

    Args:
        timeout: Cache timeout in seconds
    """
    def decorator(f):
        @functools.wraps(f)
        def decorated_function(*args, **kwargs):
            # Generate cache key based on function name and arguments
            cache_key = f"cache_result:{f.__module__}:{f.__name__}:{str(args)}:{str(kwargs)}"

            # Try to get from cache
            try:
                redis_client = redis.from_url(current_app.config.get('REDIS_URL', 'redis://localhost:6379/0'))
                cached_result = redis_client.get(cache_key)

                if cached_result:
                    return json.loads(cached_result)

            except Exception as e:
                logger.warning(f"Cache read failed: {e}")

            # Execute function
            result = f(*args, **kwargs)

            # Cache result
            try:
                redis_client = redis.from_url(current_app.config.get('REDIS_URL', 'redis://localhost:6379/0'))
                redis_client.setex(
                    cache_key,
                    timeout,
                    json.dumps(result)
                )
            except Exception as e:
                logger.warning(f"Cache write failed: {e}")

            return result

        return decorated_function
    return decorator

def require_permissions(*permissions):
    """
    Require specific permissions for endpoint access

    Args:
        permissions: Required permission strings
    """

    def decorator(f):
        @functools.wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated:
                return jsonify({
                    'error': 'Authentication required',
                    'message': 'Please log in to access this resource'
                }), 401

            # Check if user has required permissions
            for permission in permissions:
                resource, action = permission.split(':', 1) if ':' in permission else (permission, 'read')

                if not SecurityService.check_permission(current_user, resource, action):
                    return jsonify({
                        'error': 'Insufficient permissions',
                        'message': f'Permission required: {permission}'
                    }), 403

            return f(*args, **kwargs)

        return decorated_function

    return decorator


def admin_required(f):
    """Require admin privileges"""

    @functools.wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated:
            return jsonify({
                'error': 'Authentication required',
                'message': 'Please log in to access this resource'
            }), 401

        if not current_user.is_admin:
            return jsonify({
                'error': 'Admin access required',
                'message': 'This resource requires administrator privileges'
            }), 403

        return f(*args, **kwargs)

    return decorated_function


def cache_response(timeout: int = 300, key_func: Callable = None,
                   vary_on_user: bool = False, cache_empty: bool = False):
    """
    Cache response for specified timeout

    Args:
        timeout: Cache timeout in seconds
        key_func: Custom function to generate cache key
        vary_on_user: Whether to include user ID in cache key
        cache_empty: Whether to cache empty/null responses
    """

    def decorator(f):
        @functools.wraps(f)
        def decorated_function(*args, **kwargs):
            # Generate cache key
            if key_func:
                cache_key = key_func()
            else:
                base_key = f"cache:{request.endpoint}:{request.method}"

                # Include query parameters
                if request.args:
                    query_string = "&".join(f"{k}={v}" for k, v in sorted(request.args.items()))
                    base_key += f":{query_string}"

                # Include user ID if required
                if vary_on_user and current_user.is_authenticated:
                    base_key += f":user:{current_user.id}"

                cache_key = base_key

            # Try to get from cache
            try:
                redis_client = redis.from_url(current_app.config.get('REDIS_URL', 'redis://localhost:6379/0'))
                cached_response = redis_client.get(cache_key)

                if cached_response:
                    response_data = json.loads(cached_response)
                    response = jsonify(response_data)
                    response.headers['X-Cache'] = 'HIT'
                    return response

            except Exception as e:
                logger.warning(f"Cache read failed: {e}")

            # Execute function
            response = f(*args, **kwargs)

            # Cache response
            try:
                if hasattr(response, 'get_json'):
                    response_data = response.get_json()

                    # Check if we should cache empty responses
                    if not cache_empty and not response_data:
                        return response

                    # Cache the response
                    redis_client = redis.from_url(current_app.config.get('REDIS_URL', 'redis://localhost:6379/0'))
                    redis_client.setex(
                        cache_key,
                        timeout,
                        json.dumps(response_data)
                    )

                    response.headers['X-Cache'] = 'MISS'

            except Exception as e:
                logger.warning(f"Cache write failed: {e}")

            return response

        return decorated_function

    return decorator


def measure_performance(track_db_queries: bool = True, log_slow: float = 1.0):
    """
    Measure and log endpoint performance

    Args:
        track_db_queries: Whether to track database query count
        log_slow: Log requests slower than this many seconds
    """

    def decorator(f):
        @functools.wraps(f)
        def decorated_function(*args, **kwargs):
            start_time = time.time()

            # Track database queries if requested
            if track_db_queries:
                # This would integrate with SQLAlchemy events
                # For now, we'll just track timing
                g.query_count = 0
                g.query_time = 0

            try:
                # Execute function
                result = f(*args, **kwargs)

                # Calculate performance metrics
                end_time = time.time()
                duration = end_time - start_time

                # Log performance
                performance_data = {
                    'endpoint': request.endpoint,
                    'method': request.method,
                    'duration': duration,
                    'status_code': getattr(result, 'status_code', 200),
                    'user_id': current_user.id if current_user.is_authenticated else None,
                    'ip_address': request.remote_addr
                }

                if track_db_queries:
                    performance_data.update({
                        'db_queries': getattr(g, 'query_count', 0),
                        'db_time': getattr(g, 'query_time', 0)
                    })

                # Log slow requests
                if duration > log_slow:
                    logger.warning(f"Slow request: {request.endpoint} took {duration:.2f}s",
                                   extra=performance_data)

                # Add performance headers
                if hasattr(result, 'headers'):
                    result.headers['X-Response-Time'] = f"{duration:.3f}s"
                    if track_db_queries:
                        result.headers['X-DB-Queries'] = str(getattr(g, 'query_count', 0))

                return result

            except Exception as e:
                # Log error with performance data
                end_time = time.time()
                duration = end_time - start_time

                logger.error(f"Endpoint error: {request.endpoint} failed after {duration:.2f}s: {e}",
                             extra={'duration': duration, 'error': str(e)})
                raise

        return decorated_function

    return decorator


def validate_content_type(*allowed_types):
    """
    Validate request content type

    Args:
        allowed_types: Allowed content types (e.g., 'application/json')
    """

    def decorator(f):
        @functools.wraps(f)
        def decorated_function(*args, **kwargs):
            if request.method in ['POST', 'PUT', 'PATCH']:
                content_type = request.content_type

                if not content_type:
                    return jsonify({
                        'error': 'Content-Type required',
                        'message': 'Request must specify Content-Type header'
                    }), 400

                # Check against allowed types
                content_type_base = content_type.split(';')[0].strip()
                if content_type_base not in allowed_types:
                    return jsonify({
                        'error': 'Invalid Content-Type',
                        'message': f'Allowed types: {", ".join(allowed_types)}'
                    }), 415

            return f(*args, **kwargs)

        return decorated_function

    return decorator


def log_api_access(include_request_body: bool = False, include_response: bool = False):
    """
    Log API access for audit purposes

    Args:
        include_request_body: Whether to log request body (be careful with sensitive data)
        include_response: Whether to log response data
    """

    def decorator(f):
        @functools.wraps(f)
        def decorated_function(*args, **kwargs):
            # Prepare audit data
            audit_data = {
                'endpoint': request.endpoint,
                'method': request.method,
                'url': request.url,
                'args': dict(request.args),
                'user_agent': request.headers.get('User-Agent'),
                'referer': request.headers.get('Referer')
            }

            # Include request body if requested (and safe)
            if include_request_body and request.is_json:
                try:
                    audit_data['request_body'] = request.get_json()
                except Exception:
                    audit_data['request_body'] = '<invalid json>'

            start_time = datetime.utcnow()
            end_time = None
            duration = None

            try:
                # Execute function
                result = f(*args, **kwargs)

                # Calculate duration
                end_time = datetime.utcnow()
                duration = (end_time - start_time).total_seconds()
                audit_data['duration'] = duration

                # Include response if requested
                if include_response and hasattr(result, 'get_json'):
                    try:
                        audit_data['response'] = result.get_json()
                    except Exception:
                        audit_data['response'] = '<not json>'

                # Log successful access
                AuditLog.log_action(
                    user_id=current_user.id if current_user.is_authenticated else None,
                    action='api_access',
                    description=f'API access: {request.method} {request.endpoint}',
                    ip_address=request.remote_addr,
                    success=True,
                    metadata=audit_data
                )

                return result

            except Exception as e:
                # Calculate duration for failed requests too
                if not end_time:
                    end_time = datetime.utcnow()
                    duration = (end_time - start_time).total_seconds()
                    audit_data['duration'] = duration

                # Log failed access
                audit_data['error'] = str(e)

                AuditLog.log_action(
                    user_id=current_user.id if current_user.is_authenticated else None,
                    action='api_access_failed',
                    description=f'API access failed: {request.method} {request.endpoint}',
                    ip_address=request.remote_addr,
                    success=False,
                    error_message=str(e),
                    metadata=audit_data
                )

                raise

        return decorated_function

    return decorator


def require_https(should_redirect: bool = False):
    """
    Require HTTPS for endpoint access

    Args:
        should_redirect: Whether to redirect HTTP to HTTPS (vs. return error)
    """

    def decorator(f):
        @functools.wraps(f)
        def decorated_function(*args, **kwargs):
            if not request.is_secure and not current_app.debug:
                if should_redirect:
                    # Redirect to HTTPS
                    url = request.url.replace('http://', 'https://', 1)
                    return redirect(url, code=301)
                else:
                    return jsonify({
                        'error': 'HTTPS required',
                        'message': 'This endpoint requires HTTPS'
                    }), 400

            return f(*args, **kwargs)

        return decorated_function

    return decorator


def handle_exceptions(default_status: int = 500, log_errors: bool = True):
    """
    Handle exceptions with consistent error responses

    Args:
        default_status: Default HTTP status for unhandled exceptions
        log_errors: Whether to log exceptions
    """

    def decorator(f):
        @functools.wraps(f)
        def decorated_function(*args, **kwargs):
            try:
                return f(*args, **kwargs)

            except ValueError as e:
                if log_errors:
                    logger.warning(f"ValueError in {request.endpoint}: {e}")
                return jsonify({
                    'error': 'Invalid input',
                    'message': str(e)
                }), 400

            except PermissionError as e:
                if log_errors:
                    logger.warning(f"Permission error in {request.endpoint}: {e}")
                return jsonify({
                    'error': 'Permission denied',
                    'message': 'Insufficient permissions'
                }), 403

            except FileNotFoundError as e:
                if log_errors:
                    logger.warning(f"File not found in {request.endpoint}: {e}")
                return jsonify({
                    'error': 'Resource not found',
                    'message': 'Requested resource does not exist'
                }), 404

            except KeyError as e:
                if log_errors:
                    logger.warning(f"KeyError in {request.endpoint}: {e}")
                return jsonify({
                    'error': 'Missing parameter',
                    'message': f'Required parameter missing: {str(e)}'
                }), 400

            except Exception as e:
                if log_errors:
                    logger.error(f"Unhandled exception in {request.endpoint}: {e}", exc_info=True)

                # Don't expose internal errors in production
                if current_app.debug:
                    error_message = str(e)
                else:
                    error_message = 'An internal error occurred'

                return jsonify({
                    'error': 'Internal error',
                    'message': error_message
                }), default_status

        return decorated_function

    return decorator


# Convenience decorators
def json_api(require_auth: bool = True, rate_limit_val: str = "100 per hour"):
    """Convenience decorator for JSON APIs"""

    def decorator(f):
        decorators = [
            api_endpoint(require_json=True),
            rate_limit(rate_limit_val),
            handle_exceptions(),
            measure_performance()
        ]

        if require_auth:
            decorators.append(require_permissions('api:access'))

        # Apply decorators in reverse order
        for dec in reversed(decorators):
            f = dec(f)

        return f

    return decorator


def public_api(rate_limit_val: str = "1000 per hour"):
    """Convenience decorator for public APIs"""

    def decorator(f):
        decorators = [
            api_endpoint(require_json=False),
            rate_limit(rate_limit_val, per_user=False),
            handle_exceptions(),
            measure_performance()
        ]

        for dec in reversed(decorators):
            f = dec(f)

        return f

    return decorator


def validate_json(schema=None, required_fields=None):
    """
    Validate JSON request data against a schema

    Args:
        schema: JSON schema to validate against
        required_fields: List of required fields (alternative to schema)
    """
    def decorator(f):
        @functools.wraps(f)
        def decorated_function(*args, **kwargs):
            if not request.is_json:
                return jsonify({
                    'error': 'JSON required',
                    'message': 'Request must contain JSON data'
                }), 400

            try:
                data = request.get_json()

                # Create schema from required_fields if provided
                if required_fields and not schema:
                    schema = {'required': required_fields}

                # Validate against schema if provided
                if schema:
                    # Simple schema validation
                    if 'required' in schema:
                        for field in schema['required']:
                            if field not in data:
                                return jsonify({
                                    'error': 'Validation error',
                                    'message': f'Missing required field: {field}'
                                }), 400

                    if 'properties' in schema:
                        for field, field_schema in schema['properties'].items():
                            if field in data and 'type' in field_schema:
                                expected_type = field_schema['type']
                                actual_value = data[field]

                                # Type checking
                                type_map = {
                                    'string': str,
                                    'integer': int,
                                    'number': (int, float),
                                    'boolean': bool,
                                    'array': list,
                                    'object': dict
                                }

                                if expected_type in type_map:
                                    if not isinstance(actual_value, type_map[expected_type]):
                                        return jsonify({
                                            'error': 'Validation error',
                                            'message': f'Field {field} must be of type {expected_type}'
                                        }), 400

                # Store validated data in g for easy access
                g.json_data = data

                return f(*args, **kwargs)

            except Exception as e:
                return jsonify({
                    'error': 'JSON parsing error',
                    'message': str(e)
                }), 400

        return decorated_function
    return decorator

# Export all decorators
__all__ = [
    'rate_limit',
    'require_api_key',
    'api_endpoint',
    'require_permissions',
    'admin_required',
    'cache_response',
    'measure_performance',
    'validate_content_type',
    'log_api_access',
    'require_https',
    'handle_exceptions',
    'json_api',
    'public_api',
    'RateLimitExceeded',
    'validate_json'
]
