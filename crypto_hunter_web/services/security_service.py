# crypto_hunter_web/services/security_service.py - COMPLETE SECURITY SERVICE

import logging
import hashlib
import secrets
import time
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple
from urllib.parse import urlparse
from collections import defaultdict
import redis
from flask import current_app, request, session

from crypto_hunter_web.models import db, User, AuditLog, ApiKey

logger = logging.getLogger(__name__)


class SecurityService:
    """Comprehensive security service for authentication, authorization, and threat detection"""

    # Rate limiting and blocking configuration
    MAX_LOGIN_ATTEMPTS = 5
    LOCKOUT_DURATION = 30  # minutes
    RATE_LIMIT_WINDOW = 3600  # 1 hour
    MAX_REQUESTS_PER_HOUR = 1000

    # IP blocking configuration
    SUSPICIOUS_THRESHOLD = 10  # suspicious events before blocking
    BLOCK_DURATION = 3600  # 1 hour

    # Session security
    SESSION_TIMEOUT = 3600  # 1 hour
    MAX_CONCURRENT_SESSIONS = 5

    def __init__(self):
        """Initialize security service"""
        self.redis_client = None
        try:
            if current_app.config.get('REDIS_URL'):
                self.redis_client = redis.from_url(current_app.config['REDIS_URL'])
        except Exception as e:
            logger.warning(f"Redis not available for security service: {e}")

    @classmethod
    def log_failed_login(cls, username: str, ip_address: str, reason: str):
        """Log failed login attempt and apply security measures"""
        try:
            # Log to audit log
            AuditLog.log_action(
                user_id=None,
                action='login_failed',
                description=f'Failed login attempt for {username}',
                ip_address=ip_address,
                success=False,
                error_message=reason,
                metadata={
                    'username': username,
                    'reason': reason,
                    'timestamp': datetime.utcnow().isoformat()
                }
            )

            # Track suspicious activity
            cls._track_suspicious_activity(ip_address, 'failed_login', username)

            # Check if IP should be blocked
            cls._check_and_block_ip(ip_address)

        except Exception as e:
            logger.error(f"Failed to log failed login: {e}")

    @classmethod
    def is_ip_blocked(cls, ip_address: str) -> bool:
        """Check if IP address is currently blocked"""
        try:
            service = cls()
            if not service.redis_client:
                return False

            block_key = f"blocked_ip:{ip_address}"
            return service.redis_client.exists(block_key)

        except Exception as e:
            logger.error(f"Error checking IP block status: {e}")
            return False

    @classmethod
    def block_ip(cls, ip_address: str, duration: int = None, reason: str = 'Suspicious activity'):
        """Block IP address for specified duration"""
        try:
            service = cls()
            if not service.redis_client:
                return

            if duration is None:
                duration = cls.BLOCK_DURATION

            block_key = f"blocked_ip:{ip_address}"
            block_data = {
                'blocked_at': datetime.utcnow().isoformat(),
                'reason': reason,
                'duration': duration
            }

            service.redis_client.setex(block_key, duration, str(block_data))

            # Log the block
            AuditLog.log_action(
                user_id=None,
                action='ip_blocked',
                description=f'IP {ip_address} blocked for {reason}',
                ip_address=ip_address,
                metadata={
                    'reason': reason,
                    'duration': duration,
                    'blocked_until': (datetime.utcnow() + timedelta(seconds=duration)).isoformat()
                }
            )

            logger.warning(f"Blocked IP {ip_address} for {duration} seconds: {reason}")

        except Exception as e:
            logger.error(f"Failed to block IP: {e}")

    @classmethod
    def unblock_ip(cls, ip_address: str):
        """Manually unblock an IP address"""
        try:
            service = cls()
            if not service.redis_client:
                return

            block_key = f"blocked_ip:{ip_address}"
            service.redis_client.delete(block_key)

            # Log the unblock
            AuditLog.log_action(
                user_id=None,
                action='ip_unblocked',
                description=f'IP {ip_address} manually unblocked',
                ip_address=ip_address
            )

            logger.info(f"Manually unblocked IP {ip_address}")

        except Exception as e:
            logger.error(f"Failed to unblock IP: {e}")

    @classmethod
    def _track_suspicious_activity(cls, ip_address: str, activity_type: str, details: str = ''):
        """Track suspicious activity for IP addresses"""
        try:
            service = cls()
            if not service.redis_client:
                return

            activity_key = f"suspicious_activity:{ip_address}"
            activity_data = {
                'timestamp': datetime.utcnow().isoformat(),
                'type': activity_type,
                'details': details
            }

            # Add to list of activities
            service.redis_client.lpush(activity_key, str(activity_data))
            service.redis_client.ltrim(activity_key, 0, 99)  # Keep last 100 activities
            service.redis_client.expire(activity_key, 86400)  # Expire after 24 hours

        except Exception as e:
            logger.error(f"Failed to track suspicious activity: {e}")

    @classmethod
    def _check_and_block_ip(cls, ip_address: str):
        """Check if IP should be blocked based on suspicious activity"""
        try:
            service = cls()
            if not service.redis_client:
                return

            # Count recent failed attempts
            activity_key = f"suspicious_activity:{ip_address}"
            recent_activities = service.redis_client.lrange(activity_key, 0, -1)

            # Count activities in last hour
            cutoff_time = datetime.utcnow() - timedelta(hours=1)
            recent_count = 0

            for activity_str in recent_activities:
                try:
                    activity_data = eval(activity_str.decode())
                    activity_time = datetime.fromisoformat(activity_data['timestamp'])
                    if activity_time > cutoff_time:
                        recent_count += 1
                except Exception:
                    continue

            # Block if threshold exceeded
            if recent_count >= cls.SUSPICIOUS_THRESHOLD:
                cls.block_ip(ip_address, cls.BLOCK_DURATION,
                             f'Exceeded suspicious activity threshold ({recent_count} events)')

        except Exception as e:
            logger.error(f"Failed to check IP for blocking: {e}")

    @classmethod
    def is_safe_url(cls, target: str) -> bool:
        """Check if redirect URL is safe"""
        try:
            if not target:
                return False

            # Parse the URL
            parsed = urlparse(target)

            # Only allow relative URLs or same host
            if parsed.netloc and parsed.netloc != request.host:
                return False

            # Block potentially dangerous schemes
            if parsed.scheme and parsed.scheme not in ['http', 'https', '']:
                return False

            # Block path traversal attempts
            if '..' in target or '//' in target:
                return False

            return True

        except Exception:
            return False

    @classmethod
    def validate_api_key(cls, api_key: str) -> Optional[ApiKey]:
        """Validate API key and return ApiKey object if valid"""
        try:
            if not api_key or len(api_key) < 32:
                return None

            # Hash the provided key
            key_hash = hashlib.sha256(api_key.encode()).hexdigest()

            # Find matching API key
            api_key_obj = ApiKey.query.filter_by(
                key_hash=key_hash,
                is_active=True
            ).first()

            if not api_key_obj:
                return None

            # Check if expired
            if api_key_obj.is_expired():
                return None

            # Update usage tracking
            api_key_obj.last_used = datetime.utcnow()
            api_key_obj.usage_count += 1
            db.session.commit()

            return api_key_obj

        except Exception as e:
            logger.error(f"API key validation failed: {e}")
            return None

    @classmethod
    def check_rate_limit(cls, identifier: str, limit: int = None, window: int = None) -> Tuple[bool, Dict[str, Any]]:
        """Check rate limit for given identifier"""
        try:
            service = cls()
            if not service.redis_client:
                return True, {}  # Allow if Redis not available

            if limit is None:
                limit = cls.MAX_REQUESTS_PER_HOUR
            if window is None:
                window = cls.RATE_LIMIT_WINDOW

            rate_key = f"rate_limit:{identifier}"
            current_time = int(time.time())
            window_start = current_time - window

            # Remove old entries
            service.redis_client.zremrangebyscore(rate_key, 0, window_start)

            # Count current requests
            current_count = service.redis_client.zcard(rate_key)

            if current_count >= limit:
                # Rate limit exceeded
                ttl = service.redis_client.ttl(rate_key)
                return False, {
                    'limit': limit,
                    'current': current_count,
                    'window': window,
                    'retry_after': ttl
                }

            # Add current request
            service.redis_client.zadd(rate_key, {str(current_time): current_time})
            service.redis_client.expire(rate_key, window)

            return True, {
                'limit': limit,
                'current': current_count + 1,
                'window': window,
                'remaining': limit - current_count - 1
            }

        except Exception as e:
            logger.error(f"Rate limit check failed: {e}")
            return True, {}  # Allow if check fails

    @classmethod
    def generate_secure_token(cls, length: int = 32) -> str:
        """Generate cryptographically secure token"""
        return secrets.token_urlsafe(length)

    @classmethod
    def hash_password(cls, password: str, salt: str = None) -> Tuple[str, str]:
        """Hash password with salt"""
        if salt is None:
            salt = secrets.token_hex(16)

        # Use PBKDF2 with SHA-256
        import hashlib
        import os

        key = hashlib.pbkdf2_hmac(
            'sha256',
            password.encode('utf-8'),
            salt.encode('utf-8'),
            100000  # iterations
        )

        return key.hex(), salt

    @classmethod
    def verify_password(cls, password: str, hashed: str, salt: str) -> bool:
        """Verify password against hash"""
        try:
            key, _ = cls.hash_password(password, salt)
            return secrets.compare_digest(key, hashed)
        except Exception:
            return False

    @classmethod
    def create_session_token(cls, user_id: int) -> str:
        """Create secure session token"""
        try:
            service = cls()
            if not service.redis_client:
                return secrets.token_urlsafe(32)

            # Generate token
            token = secrets.token_urlsafe(32)

            # Store session data
            session_key = f"session:{token}"
            session_data = {
                'user_id': user_id,
                'created_at': datetime.utcnow().isoformat(),
                'last_activity': datetime.utcnow().isoformat(),
                'ip_address': request.remote_addr if request else None,
                'user_agent': request.headers.get('User-Agent') if request else None
            }

            service.redis_client.setex(session_key, cls.SESSION_TIMEOUT, str(session_data))

            # Track user sessions
            user_sessions_key = f"user_sessions:{user_id}"
            service.redis_client.sadd(user_sessions_key, token)
            service.redis_client.expire(user_sessions_key, cls.SESSION_TIMEOUT)

            # Limit concurrent sessions
            cls._enforce_session_limit(user_id)

            return token

        except Exception as e:
            logger.error(f"Session token creation failed: {e}")
            return secrets.token_urlsafe(32)

    @classmethod
    def validate_session_token(cls, token: str) -> Optional[Dict[str, Any]]:
        """Validate session token and return session data"""
        try:
            service = cls()
            if not service.redis_client:
                return None

            session_key = f"session:{token}"
            session_data_str = service.redis_client.get(session_key)

            if not session_data_str:
                return None

            session_data = eval(session_data_str.decode())

            # Update last activity
            session_data['last_activity'] = datetime.utcnow().isoformat()
            service.redis_client.setex(session_key, cls.SESSION_TIMEOUT, str(session_data))

            return session_data

        except Exception as e:
            logger.error(f"Session validation failed: {e}")
            return None

    @classmethod
    def invalidate_session(cls, token: str):
        """Invalidate session token"""
        try:
            service = cls()
            if not service.redis_client:
                return

            # Get session data first
            session_data = cls.validate_session_token(token)

            # Remove session
            session_key = f"session:{token}"
            service.redis_client.delete(session_key)

            # Remove from user sessions
            if session_data:
                user_sessions_key = f"user_sessions:{session_data['user_id']}"
                service.redis_client.srem(user_sessions_key, token)

        except Exception as e:
            logger.error(f"Session invalidation failed: {e}")

    @classmethod
    def _enforce_session_limit(cls, user_id: int):
        """Enforce maximum concurrent sessions per user"""
        try:
            service = cls()
            if not service.redis_client:
                return

            user_sessions_key = f"user_sessions:{user_id}"
            session_tokens = service.redis_client.smembers(user_sessions_key)

            if len(session_tokens) > cls.MAX_CONCURRENT_SESSIONS:
                # Remove oldest sessions
                valid_sessions = []

                for token in session_tokens:
                    session_key = f"session:{token.decode()}"
                    if service.redis_client.exists(session_key):
                        session_data_str = service.redis_client.get(session_key)
                        session_data = eval(session_data_str.decode())
                        valid_sessions.append((token.decode(), session_data['last_activity']))

                # Sort by last activity and remove oldest
                valid_sessions.sort(key=lambda x: x[1])
                sessions_to_remove = len(valid_sessions) - cls.MAX_CONCURRENT_SESSIONS

                for i in range(sessions_to_remove):
                    token_to_remove = valid_sessions[i][0]
                    cls.invalidate_session(token_to_remove)

        except Exception as e:
            logger.error(f"Session limit enforcement failed: {e}")

    @classmethod
    def check_permission(cls, user: User, resource: str, action: str) -> bool:
        """Check if user has permission for action on resource"""
        try:
            # Admin users have all permissions
            if user.is_admin:
                return True

            # Check if user is active
            if not user.is_active:
                return False

            # Define permission matrix
            permissions = {
                'file': {
                    'read': True,  # All users can read files
                    'write': True,  # All users can upload files
                    'delete': lambda u, resource_id: cls._check_file_ownership(u, resource_id),
                    'admin': False  # Only admins
                },
                'analysis': {
                    'read': True,
                    'write': True,
                    'delete': lambda u, resource_id: cls._check_analysis_ownership(u, resource_id),
                    'admin': False
                },
                'system': {
                    'read': False,
                    'write': False,
                    'delete': False,
                    'admin': False
                }
            }

            if resource not in permissions:
                return False

            permission = permissions[resource].get(action, False)

            if callable(permission):
                return permission(user, None)  # Pass resource_id if available

            return bool(permission)

        except Exception as e:
            logger.error(f"Permission check failed: {e}")
            return False

    @classmethod
    def _check_file_ownership(cls, user: User, file_id: str = None) -> bool:
        """Check if user owns the file"""
        try:
            if not file_id:
                return True  # Can't check ownership without file_id

            from crypto_hunter_web.models import AnalysisFile
            file_obj = AnalysisFile.find_by_sha(file_id)

            if not file_obj:
                return False

            return file_obj.created_by == user.id

        except Exception:
            return False

    @classmethod
    def _check_analysis_ownership(cls, user: User, analysis_id: str = None) -> bool:
        """Check if user owns the analysis"""
        try:
            if not analysis_id:
                return True

            from crypto_hunter_web.models import Finding
            finding = Finding.query.filter_by(public_id=analysis_id).first()

            if not finding:
                return False

            return finding.created_by == user.id

        except Exception:
            return False

    @classmethod
    def log_security_event(cls, event_type: str, description: str,
                           user_id: int = None, severity: str = 'medium',
                           metadata: Dict[str, Any] = None):
        """Log security event"""
        try:
            AuditLog.log_action(
                user_id=user_id,
                action=f"security_{event_type}",
                description=description,
                ip_address=request.remote_addr if request else None,
                metadata={
                    **(metadata or {}),
                    'severity': severity,
                    'event_type': event_type,
                    'user_agent': request.headers.get('User-Agent') if request else None
                }
            )

            # Alert on high severity events
            if severity == 'high':
                logger.warning(f"HIGH SEVERITY SECURITY EVENT: {description}")

        except Exception as e:
            logger.error(f"Security event logging failed: {e}")

    @classmethod
    def get_security_metrics(cls) -> Dict[str, Any]:
        """Get security metrics for monitoring"""
        try:
            # Get recent security events
            recent_events = AuditLog.query.filter(
                AuditLog.action.like('security_%'),
                AuditLog.timestamp >= datetime.utcnow() - timedelta(hours=24)
            ).count()

            # Get blocked IPs
            service = cls()
            blocked_ips = 0
            if service.redis_client:
                blocked_ips = len(service.redis_client.keys("blocked_ip:*"))

            # Get failed logins in last hour
            failed_logins = AuditLog.query.filter(
                AuditLog.action == 'login_failed',
                AuditLog.timestamp >= datetime.utcnow() - timedelta(hours=1)
            ).count()

            # Get active sessions
            active_sessions = 0
            if service.redis_client:
                active_sessions = len(service.redis_client.keys("session:*"))

            return {
                'security_events_24h': recent_events,
                'blocked_ips': blocked_ips,
                'failed_logins_1h': failed_logins,
                'active_sessions': active_sessions,
                'last_updated': datetime.utcnow().isoformat()
            }

        except Exception as e:
            logger.error(f"Security metrics collection failed: {e}")
            return {}

    @classmethod
    def sanitize_input(cls, input_str: str, max_length: int = 1000) -> str:
        """Sanitize user input to prevent XSS and injection attacks"""
        try:
            if not input_str:
                return ''

            # Remove potential XSS patterns
            import re

            # Remove HTML tags
            clean = re.sub(r'<[^>]*>', '', str(input_str))

            # Remove JavaScript event handlers
            clean = re.sub(r'on\w+\s*=', '', clean, flags=re.IGNORECASE)

            # Remove script tags content
            clean = re.sub(r'<script.*?</script>', '', clean, flags=re.IGNORECASE | re.DOTALL)

            # Limit length
            if len(clean) > max_length:
                clean = clean[:max_length]

            return clean.strip()

        except Exception:
            return ''


# Global security service instance
security_service = SecurityService()