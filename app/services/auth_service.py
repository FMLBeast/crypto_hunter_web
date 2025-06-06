"""
Authentication and user management service
"""

from flask import session, request
from datetime import datetime, timedelta
import functools
import logging

from app.models import db, User
from app.models.audit import AuditLog

audit_logger = logging.getLogger('audit')

class AuthService:
    """Handle authentication and authorization"""
    
    @staticmethod
    def login_required(f):
        """Decorator for routes requiring authentication"""
        @functools.wraps(f)
        def decorated_function(*args, **kwargs):
            if 'user_id' not in session:
                return {'error': 'Authentication required'}, 401
            
            # Check session timeout
            if 'last_activity' in session:
                last_activity = datetime.fromisoformat(session['last_activity'])
                timeout = timedelta(seconds=28800)  # 8 hours
                if datetime.now() - last_activity > timeout:
                    session.clear()
                    return {'error': 'Session expired'}, 401
            
            session['last_activity'] = datetime.now().isoformat()
            return f(*args, **kwargs)
        return decorated_function
    
    @staticmethod
    def admin_required(f):
        """Decorator for routes requiring admin access"""
        @functools.wraps(f)
        def decorated_function(*args, **kwargs):
            if 'user_id' not in session:
                return {'error': 'Authentication required'}, 401
            
            user = User.query.get(session['user_id'])
            if not user or not user.can_access_admin():
                return {'error': 'Admin access required'}, 403
            
            return f(*args, **kwargs)
        return decorated_function
    
    @staticmethod
    def get_current_user():
        """Get the current logged-in user"""
        if 'user_id' in session:
            return User.query.get(session['user_id'])
        return None
    
    @staticmethod
    def login_user(username, password):
        """Authenticate user and create session"""
        user = User.query.filter_by(username=username, is_active=True).first()
        
        if user and user.check_password(password):
            session['user_id'] = user.id
            session['username'] = user.username
            session['role'] = user.role
            session['last_activity'] = datetime.now().isoformat()
            
            user.last_login = datetime.utcnow()
            user.last_activity = datetime.utcnow()
            db.session.commit()
            
            AuthService.log_action('user_login', f'Successful login', user.id)
            return user
        else:
            AuthService.log_action('login_failed', f'Failed login attempt for username: {username}')
            return None
    
    @staticmethod
    def logout_user():
        """Clear user session"""
        user_id = session.get('user_id')
        AuthService.log_action('user_logout', 'User logged out', user_id)
        session.clear()
    
    @staticmethod
    def log_action(action, details, user_id=None, file_id=None):
        """Log user actions for audit trail"""
        if not user_id and 'user_id' in session:
            user_id = session['user_id']
        
        audit_entry = AuditLog(
            user_id=user_id,
            action=action,
            details=details,
            file_id=file_id,
            ip_address=request.remote_addr,
            user_agent=request.headers.get('User-Agent', '')
        )
        db.session.add(audit_entry)
        db.session.commit()
        
        audit_logger.info(f"User {user_id}: {action} - {details}")

def create_default_admin():
    """Create default admin user if none exists"""
    if User.query.count() == 0:
        admin = User(
            username='admin',
            email='admin@arweave-puzzle.local',
            display_name='Administrator',
            role='admin'
        )
        admin.set_password('admin123')
        db.session.add(admin)
        db.session.commit()
        print("Created default admin user: admin / admin123")
