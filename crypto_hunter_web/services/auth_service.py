from flask import session
from werkzeug.security import check_password_hash
from crypto_hunter_web.models import db, User, AuditLog

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
