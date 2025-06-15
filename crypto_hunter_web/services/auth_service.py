from flask import session, current_app, request
from werkzeug.security import check_password_hash
from crypto_hunter_web.models import db, User, AuditLog
from flask_login import current_user, login_user, logout_user

class AuthService:
    @staticmethod
    def login_user(username, password, remember=False, duration=None):
        user = User.query.filter_by(username=username).first()
        if not user or not check_password_hash(user.password_hash, password):
            return False

        # Use Flask-Login's login_user instead of directly manipulating session
        login_user(user, remember=remember, duration=duration)

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
        if current_user.is_authenticated:
            user_id = current_user.id
            # Use Flask-Login's logout_user
            logout_user()

            db.session.add(AuditLog(
                user_id=user_id,
                action='logout',
                details='User logged out'
            ))
            db.session.commit()

    @staticmethod
    def login_required(fn):
        from functools import wraps
        from flask import redirect, url_for
        from flask_login import current_user

        @wraps(fn)
        def wrapper(*args, **kwargs):
            if not current_user.is_authenticated:
                return redirect(url_for('auth.login'))
            return fn(*args, **kwargs)
        return wrapper

    @staticmethod
    def admin_required(fn):
        from functools import wraps
        from flask import redirect, url_for, flash
        from flask_login import current_user

        @wraps(fn)
        def wrapper(*args, **kwargs):
            if not current_user.is_authenticated:
                return redirect(url_for('auth.login'))

            if not current_user.is_admin:
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
            # Rollback the transaction to prevent database inconsistency
            db.session.rollback()
            return None
