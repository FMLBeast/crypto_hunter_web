from flask import session, current_app, request
from werkzeug.security import check_password_hash
from crypto_hunter_web.models import db, User, AuditLog
from flask_login import current_user

class AuthService:
    @staticmethod
    def login_user(username, password):
        user = User.query.filter_by(username=username).first()
        if not user or not check_password_hash(user.password_hash, password):
            return False
        session['user_id'] = user.id
        # optionally session['role'] = user.role
        # record audit
        db.session.add(AuditLog(
            user_id=user.id,
            action='login',
            details=f'User {username} logged in'
        ))
        db.session.commit()
        return user

    @staticmethod
    def logout_user():
        user_id = session.pop('user_id', None)
        if user_id:
            db.session.add(AuditLog(
                user_id=user_id,
                action='logout',
                details='User logged out'
            ))
            db.session.commit()

    @staticmethod
    def login_required(fn):
        from functools import wraps
        from flask import redirect, url_for, session
        @wraps(fn)
        def wrapper(*args, **kwargs):
            if 'user_id' not in session:
                return redirect(url_for('auth.login'))
            return fn(*args, **kwargs)
        return wrapper

    @staticmethod
    def admin_required(fn):
        from functools import wraps
        from flask import redirect, url_for, session, flash
        from crypto_hunter_web.models import User

        @wraps(fn)
        def wrapper(*args, **kwargs):
            if 'user_id' not in session:
                return redirect(url_for('auth.login'))

            user = User.query.get(session['user_id'])
            if not user or not user.is_admin:
                flash('Admin privileges required for this action', 'error')
                return redirect(url_for('main.index'))

            return fn(*args, **kwargs)
        return wrapper

    @staticmethod
    def log_action(action, description=None, metadata=None):
        """Log user action to audit log

        Args:
            action (str): The action being performed
            description (str, optional): Description of the action
            metadata (dict, optional): Additional metadata for the action
        """
        try:
            # Get user ID from current_user if authenticated, otherwise from session
            user_id = None
            if hasattr(current_user, 'is_authenticated') and current_user.is_authenticated:
                user_id = current_user.id
            elif 'user_id' in session:
                user_id = session['user_id']

            # Get IP address if available
            ip_address = request.remote_addr if request and hasattr(request, 'remote_addr') else None

            # Create audit log entry
            log_entry = AuditLog.log_action(
                user_id=user_id,
                action=action,
                description=description,
                success=True,
                ip_address=ip_address,
                metadata=metadata
            )

            # Commit the transaction
            db.session.commit()
            return log_entry
        except Exception as e:
            # Log error but don't raise exception to prevent disrupting main flow
            if current_app:
                current_app.logger.error(f"Error logging action {action}: {str(e)}")
            return None
