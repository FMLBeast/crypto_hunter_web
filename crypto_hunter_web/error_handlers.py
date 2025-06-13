# crypto_hunter_web/error_handlers.py - COMPLETE ERROR HANDLING

import logging
import traceback
from datetime import datetime
from flask import request, jsonify, render_template, current_app, g
from werkzeug.exceptions import HTTPException, RequestEntityTooLarge, NotFound, Forbidden, Unauthorized, BadRequest, InternalServerError
from werkzeug.http import HTTP_STATUS_CODES
from sqlalchemy.exc import SQLAlchemyError, IntegrityError
from flask_login import current_user

from crypto_hunter_web.models import db, AuditLog
from crypto_hunter_web.services.security_service import SecurityService

logger = logging.getLogger(__name__)


class ErrorHandler:
    """Centralized error handling with logging and user-friendly responses"""

    def __init__(self, app=None):
        self.app = app
        if app is not None:
            self.init_app(app)

    def init_app(self, app):
        """Initialize error handlers with Flask app"""
        self.app = app

        # Register HTTP error handlers
        app.register_error_handler(400, self.handle_bad_request)
        app.register_error_handler(401, self.handle_unauthorized)
        app.register_error_handler(403, self.handle_forbidden)
        app.register_error_handler(404, self.handle_not_found)
        app.register_error_handler(405, self.handle_method_not_allowed)
        app.register_error_handler(413, self.handle_request_too_large)
        app.register_error_handler(429, self.handle_rate_limit_exceeded)
        app.register_error_handler(500, self.handle_internal_error)
        app.register_error_handler(502, self.handle_bad_gateway)
        app.register_error_handler(503, self.handle_service_unavailable)

        # Register exception handlers
        app.register_error_handler(SQLAlchemyError, self.handle_database_error)
        app.register_error_handler(IntegrityError, self.handle_integrity_error)
        app.register_error_handler(ValueError, self.handle_value_error)
        app.register_error_handler(FileNotFoundError, self.handle_file_not_found)
        app.register_error_handler(PermissionError, self.handle_permission_error)
        app.register_error_handler(Exception, self.handle_generic_exception)

        # Setup error logging
        self._setup_error_logging(app)

    def _setup_error_logging(self, app):
        """Setup comprehensive error logging"""
        if not app.debug:
            # Email handler for critical errors (if configured)
            if app.config.get('MAIL_SERVER'):
                self._setup_mail_handler(app)

            # File handler for all errors
            self._setup_file_handler(app)

            # Sentry handler for error tracking (if configured)
            if app.config.get('SENTRY_DSN'):
                self._setup_sentry_handler(app)

    def _setup_mail_handler(self, app):
        """Setup email notifications for critical errors"""
        try:
            from logging.handlers import SMTPHandler

            mail_handler = SMTPHandler(
                mailhost=(app.config['MAIL_SERVER'], app.config.get('MAIL_PORT', 587)),
                fromaddr=app.config.get('MAIL_DEFAULT_SENDER'),
                toaddrs=app.config.get('ADMIN_EMAILS', []),
                subject='Crypto Hunter Application Error',
                credentials=(app.config.get('MAIL_USERNAME'), app.config.get('MAIL_PASSWORD')),
                secure=() if app.config.get('MAIL_USE_TLS') else None
            )

            mail_handler.setLevel(logging.ERROR)
            mail_handler.setFormatter(logging.Formatter('''
Message type:       %(levelname)s
Location:           %(pathname)s:%(lineno)d
Module:             %(module)s
Function:           %(funcName)s
Time:               %(asctime)s

Message:

%(message)s
            '''))

            app.logger.addHandler(mail_handler)

        except Exception as e:
            app.logger.warning(f"Failed to setup email error handler: {e}")

    def _setup_file_handler(self, app):
        """Setup file handler for error logging"""
        try:
            import logging.handlers

            error_log_file = app.config.get('ERROR_LOG_FILE', 'logs/errors.log')

            # Ensure log directory exists
            import os
            os.makedirs(os.path.dirname(error_log_file), exist_ok=True)

            file_handler = logging.handlers.RotatingFileHandler(
                error_log_file,
                maxBytes=10485760,  # 10MB
                backupCount=10
            )

            file_handler.setLevel(logging.ERROR)
            file_handler.setFormatter(logging.Formatter(
                '[%(asctime)s] %(levelname)s [%(name)s.%(funcName)s:%(lineno)d] %(message)s'
            ))

            app.logger.addHandler(file_handler)

        except Exception as e:
            app.logger.warning(f"Failed to setup file error handler: {e}")

    def _setup_sentry_handler(self, app):
        """Setup Sentry error tracking"""
        try:
            import sentry_sdk
            from sentry_sdk.integrations.flask import FlaskIntegration
            from sentry_sdk.integrations.logging import LoggingIntegration

            sentry_logging = LoggingIntegration(
                level=logging.INFO,        # Capture info and above as breadcrumbs
                event_level=logging.ERROR  # Send errors as events
            )

            sentry_sdk.init(
                dsn=app.config['SENTRY_DSN'],
                integrations=[FlaskIntegration(), sentry_logging],
                traces_sample_rate=0.1,
                environment=app.config.get('FLASK_ENV', 'production'),
                release=app.config.get('APPLICATION_VERSION', '2.0.0')
            )

        except ImportError:
            app.logger.warning("Sentry SDK not installed")
        except Exception as e:
            app.logger.warning(f"Failed to setup Sentry: {e}")

    def _log_error(self, error, extra_context=None):
        """Log error with comprehensive context"""
        try:
            # Gather request context
            context = {
                'url': request.url if request else 'N/A',
                'method': request.method if request else 'N/A',
                'ip_address': request.remote_addr if request else 'N/A',
                'user_agent': request.headers.get('User-Agent') if request else 'N/A',
                'user_id': current_user.id if current_user.is_authenticated else None,
                'timestamp': datetime.utcnow().isoformat(),
                'request_id': getattr(g, 'request_id', 'unknown')
            }

            if extra_context:
                context.update(extra_context)

            # Log to application logger
            logger.error(
                f"Error occurred: {error}",
                extra=context,
                exc_info=True
            )

            # Create audit log entry for security-related errors
            if isinstance(error, (Unauthorized, Forbidden)):
                try:
                    AuditLog.log_action(
                        user_id=current_user.id if current_user.is_authenticated else None,
                        action='security_error',
                        description=f'Security error: {error}',
                        ip_address=request.remote_addr if request else None,
                        success=False,
                        error_message=str(error),
                        metadata=context
                    )
                except Exception:
                    pass  # Don't fail on audit log errors

        except Exception as log_error:
            # Fallback logging if main logging fails
            print(f"Error logging failed: {log_error}")
            print(f"Original error: {error}")

    def _is_api_request(self):
        """Check if request is an API request"""
        return (
            request.path.startswith('/api/') or
            request.headers.get('Content-Type') == 'application/json' or
            request.headers.get('Accept') == 'application/json'
        )

    def _create_error_response(self, error, status_code, message=None, details=None):
        """Create standardized error response"""

        # Default message from HTTP status code
        if not message:
            message = HTTP_STATUS_CODES.get(status_code, 'Unknown Error')

        error_data = {
            'error': True,
            'status_code': status_code,
            'message': message,
            'timestamp': datetime.utcnow().isoformat(),
            'request_id': getattr(g, 'request_id', 'unknown')
        }

        # Add details in debug mode or for API requests
        if current_app.debug or self._is_api_request():
            if details:
                error_data['details'] = details

            if hasattr(error, '__class__'):
                error_data['error_type'] = error.__class__.__name__

        # Add support information for production
        if not current_app.debug:
            error_data['support'] = {
                'contact': 'support@cryptohunter.local',
                'documentation': 'https://docs.cryptohunter.local'
            }

        # Return JSON for API requests
        if self._is_api_request():
            response = jsonify(error_data)
            response.status_code = status_code
            return response

        # Return HTML for web requests
        try:
            return render_template(
                f'errors/{status_code}.html',
                error=error_data
            ), status_code
        except Exception:
            # Fallback if template doesn't exist
            return render_template(
                'errors/generic.html',
                error=error_data
            ), status_code

    # HTTP Error Handlers

    def handle_bad_request(self, error):
        """Handle 400 Bad Request errors"""
        self._log_error(error, {'error_type': 'bad_request'})

        message = "The request could not be understood by the server"
        details = str(error.description) if hasattr(error, 'description') else None

        return self._create_error_response(error, 400, message, details)

    def handle_unauthorized(self, error):
        """Handle 401 Unauthorized errors"""
        self._log_error(error, {'error_type': 'unauthorized'})

        # Track failed authentication attempts
        SecurityService.log_security_event(
            'unauthorized_access',
            f'Unauthorized access attempt to {request.path}',
            severity='medium'
        )

        message = "Authentication required"
        return self._create_error_response(error, 401, message)

    def handle_forbidden(self, error):
        """Handle 403 Forbidden errors"""
        self._log_error(error, {'error_type': 'forbidden'})

        # Track permission violations
        SecurityService.log_security_event(
            'permission_denied',
            f'Permission denied for {request.path}',
            user_id=current_user.id if current_user.is_authenticated else None,
            severity='medium'
        )

        message = "You do not have permission to access this resource"
        return self._create_error_response(error, 403, message)

    def handle_not_found(self, error):
        """Handle 404 Not Found errors"""
        # Don't log 404s for static files or common paths
        if not any(request.path.startswith(path) for path in ['/static/', '/favicon', '/robots']):
            self._log_error(error, {'error_type': 'not_found'})

        message = "The requested resource was not found"
        return self._create_error_response(error, 404, message)

    def handle_method_not_allowed(self, error):
        """Handle 405 Method Not Allowed errors"""
        self._log_error(error, {'error_type': 'method_not_allowed'})

        allowed_methods = getattr(error, 'valid_methods', [])
        message = f"Method {request.method} not allowed"
        details = f"Allowed methods: {', '.join(allowed_methods)}" if allowed_methods else None

        response = self._create_error_response(error, 405, message, details)
        if allowed_methods:
            response.headers['Allow'] = ', '.join(allowed_methods)

        return response

    def handle_request_too_large(self, error):
        """Handle 413 Request Entity Too Large errors"""
        self._log_error(error, {'error_type': 'request_too_large'})

        max_size = current_app.config.get('MAX_CONTENT_LENGTH', 0)
        max_size_mb = max_size / (1024 * 1024) if max_size else 'unknown'

        message = f"Request too large. Maximum size is {max_size_mb:.1f} MB"
        return self._create_error_response(error, 413, message)

    def handle_rate_limit_exceeded(self, error):
        """Handle 429 Rate Limit Exceeded errors"""
        self._log_error(error, {'error_type': 'rate_limit_exceeded'})

        # Track rate limit violations for potential abuse
        SecurityService.log_security_event(
            'rate_limit_exceeded',
            f'Rate limit exceeded for {request.path}',
            user_id=current_user.id if current_user.is_authenticated else None,
            severity='low'
        )

        message = "Maximum 5 requests per hour"
        retry_after = getattr(error, 'retry_after', 60)

        # For API requests, use the format from the issue description
        if self._is_api_request():
            response = jsonify({
                'error': 'Rate limit exceeded',
                'message': message,
                'retry_after': retry_after
            })
            response.status_code = 429
        else:
            response = self._create_error_response(error, 429, message)

        response.headers['Retry-After'] = str(retry_after)

        return response

    def handle_internal_error(self, error):
        """Handle 500 Internal Server errors"""
        # Always log internal errors
        self._log_error(error, {
            'error_type': 'internal_server_error',
            'traceback': traceback.format_exc()
        })

        # Rollback database session
        try:
            db.session.rollback()
        except Exception:
            pass

        message = "An internal server error occurred"
        details = str(error) if current_app.debug else None

        return self._create_error_response(error, 500, message, details)

    def handle_bad_gateway(self, error):
        """Handle 502 Bad Gateway errors"""
        self._log_error(error, {'error_type': 'bad_gateway'})

        message = "Bad gateway - upstream server error"
        return self._create_error_response(error, 502, message)

    def handle_service_unavailable(self, error):
        """Handle 503 Service Unavailable errors"""
        self._log_error(error, {'error_type': 'service_unavailable'})

        message = "Service temporarily unavailable"
        return self._create_error_response(error, 503, message)

    # Exception Handlers

    def handle_database_error(self, error):
        """Handle SQLAlchemy database errors"""
        self._log_error(error, {
            'error_type': 'database_error',
            'sql_error': str(error)
        })

        # Rollback transaction
        try:
            db.session.rollback()
        except Exception:
            pass

        message = "Database error occurred"
        details = str(error) if current_app.debug else None

        return self._create_error_response(error, 500, message, details)

    def handle_integrity_error(self, error):
        """Handle database integrity errors (duplicates, constraints)"""
        self._log_error(error, {
            'error_type': 'integrity_error',
            'constraint_error': str(error)
        })

        # Rollback transaction
        try:
            db.session.rollback()
        except Exception:
            pass

        # Parse common integrity errors
        error_str = str(error).lower()
        if 'unique constraint' in error_str or 'duplicate' in error_str:
            message = "Duplicate entry - resource already exists"
        elif 'foreign key constraint' in error_str:
            message = "Invalid reference - related resource not found"
        elif 'not null constraint' in error_str:
            message = "Missing required field"
        else:
            message = "Data integrity error"

        details = str(error) if current_app.debug else None

        return self._create_error_response(error, 400, message, details)

    def handle_value_error(self, error):
        """Handle ValueError exceptions"""
        self._log_error(error, {'error_type': 'value_error'})

        message = "Invalid input value"
        details = str(error) if current_app.debug else None

        return self._create_error_response(error, 400, message, details)

    def handle_file_not_found(self, error):
        """Handle FileNotFoundError exceptions"""
        self._log_error(error, {'error_type': 'file_not_found'})

        message = "File not found"
        details = str(error) if current_app.debug else None

        return self._create_error_response(error, 404, message, details)

    def handle_permission_error(self, error):
        """Handle PermissionError exceptions"""
        self._log_error(error, {'error_type': 'permission_error'})

        message = "Permission denied"
        details = str(error) if current_app.debug else None

        return self._create_error_response(error, 403, message, details)

    def handle_generic_exception(self, error):
        """Handle all other unhandled exceptions"""
        # Skip if already handled by specific handlers
        if isinstance(error, HTTPException):
            return

        self._log_error(error, {
            'error_type': 'unhandled_exception',
            'exception_class': error.__class__.__name__,
            'traceback': traceback.format_exc()
        })

        # Rollback database session
        try:
            db.session.rollback()
        except Exception:
            pass

        message = "An unexpected error occurred"
        details = str(error) if current_app.debug else None

        return self._create_error_response(error, 500, message, details)


# Global error handler instance
error_handler = ErrorHandler()


def init_error_handlers(app):
    """Initialize error handlers with Flask app"""
    error_handler.init_app(app)

    # Add before request handler to generate request IDs
    @app.before_request
    def before_request():
        """Generate unique request ID for tracking"""
        import uuid
        g.request_id = str(uuid.uuid4())[:8]

    # Add after request handler for error tracking
    @app.after_request
    def after_request(response):
        """Track response for monitoring"""
        # Log 4xx and 5xx responses
        if response.status_code >= 400:
            logger.info(
                f"Error response: {response.status_code} for {request.method} {request.path}",
                extra={
                    'status_code': response.status_code,
                    'method': request.method,
                    'path': request.path,
                    'request_id': getattr(g, 'request_id', 'unknown')
                }
            )

        return response


# Export for easy import
__all__ = ['ErrorHandler', 'error_handler', 'init_error_handlers']
