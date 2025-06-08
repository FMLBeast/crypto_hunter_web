# crypto_hunter_web/routes/auth.py - COMPLETE AUTHENTICATION SYSTEM

from flask import Blueprint, render_template, request, flash, redirect, url_for, session, jsonify, current_app
from flask_login import login_user, logout_user, current_user, login_required
from flask_limiter import Limiter
from werkzeug.security import check_password_hash
from datetime import datetime, timedelta
import secrets
import re

from crypto_hunter_web.models import db, User, AuditLog
from crypto_hunter_web.services.auth_service import AuthService
from crypto_hunter_web.services.security_service import SecurityService
from crypto_hunter_web.utils.validators import validate_email, validate_password_strength
from crypto_hunter_web.utils.decorators import rate_limit

auth_bp = Blueprint('auth', __name__, url_prefix='/auth')


@auth_bp.route('/login', methods=['GET', 'POST'])
@rate_limit("10 per minute")
def login():
    """Enhanced user login with security features"""
    if current_user.is_authenticated:
        return redirect(url_for('files.dashboard'))

    if request.method == 'POST':
        username = request.form.get('username', '').strip().lower()
        password = request.form.get('password', '').strip()
        remember_me = request.form.get('remember_me', False)

        # Input validation
        if not username or not password:
            flash('Please enter both username and password', 'error')
            return render_template('auth/login.html')

        # Rate limiting check
        if SecurityService.is_ip_blocked(request.remote_addr):
            flash('Too many failed attempts. Please try again later.', 'error')
            return render_template('auth/login.html'), 429

        # Attempt authentication
        user = User.query.filter_by(username=username).first()

        if not user:
            # Log failed attempt
            SecurityService.log_failed_login(username, request.remote_addr, 'user_not_found')
            flash('Invalid username or password', 'error')
            return render_template('auth/login.html')

        # Check if account is locked
        if user.is_locked():
            flash(f'Account is locked until {user.locked_until.strftime("%Y-%m-%d %H:%M")}', 'error')
            return render_template('auth/login.html')

        # Check if account is suspended
        if user.is_suspended:
            flash('Account has been suspended. Please contact administrator.', 'error')
            return render_template('auth/login.html')

        # Verify password
        if not user.check_password(password):
            # Handle failed login
            user.failed_login_attempts += 1

            # Lock account after 5 failed attempts
            if user.failed_login_attempts >= 5:
                user.lock_account(30)  # Lock for 30 minutes
                flash('Account locked due to too many failed attempts. Try again in 30 minutes.', 'error')
            else:
                remaining = 5 - user.failed_login_attempts
                flash(f'Invalid password. {remaining} attempts remaining.', 'error')

            SecurityService.log_failed_login(username, request.remote_addr, 'invalid_password')
            db.session.commit()
            return render_template('auth/login.html')

        # Successful login
        user.unlock_account()  # Reset failed attempts
        user.last_login = datetime.utcnow()
        user.login_count += 1
        user.last_active = datetime.utcnow()

        # Login user with Flask-Login
        login_user(user, remember=remember_me, duration=timedelta(days=30 if remember_me else 1))

        # Create audit log
        AuditLog.log_action(
            user_id=user.id,
            action='login_success',
            description=f'User {username} logged in successfully',
            ip_address=request.remote_addr,
            metadata={
                'user_agent': request.headers.get('User-Agent', ''),
                'remember_me': remember_me
            }
        )

        db.session.commit()

        # Success message
        display_name = user.display_name or user.username
        flash(f'Welcome back, {display_name}!', 'success')

        # Redirect to intended page or dashboard
        next_page = request.args.get('next')
        if next_page and SecurityService.is_safe_url(next_page):
            return redirect(next_page)

        return redirect(url_for('files.dashboard'))

    return render_template('auth/login.html')


@auth_bp.route('/register', methods=['GET', 'POST'])
@rate_limit("5 per minute")
def register():
    """User registration with validation and security"""
    if not current_app.config.get('ENABLE_REGISTRATION', True):
        flash('Registration is currently disabled.', 'error')
        return redirect(url_for('auth.login'))

    if current_user.is_authenticated:
        return redirect(url_for('files.dashboard'))

    if request.method == 'POST':
        # Get form data
        username = request.form.get('username', '').strip().lower()
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '').strip()
        confirm_password = request.form.get('confirm_password', '').strip()
        display_name = request.form.get('display_name', '').strip()
        terms_accepted = request.form.get('terms_accepted', False)

        # Validation
        errors = []

        # Username validation
        if not username:
            errors.append('Username is required')
        elif len(username) < 3:
            errors.append('Username must be at least 3 characters')
        elif len(username) > 80:
            errors.append('Username must be less than 80 characters')
        elif not re.match(r'^[a-zA-Z0-9_-]+$', username):
            errors.append('Username can only contain letters, numbers, underscore, and hyphen')
        elif User.query.filter_by(username=username).first():
            errors.append('Username already exists')

        # Email validation
        if not email:
            errors.append('Email is required')
        elif not validate_email(email):
            errors.append('Invalid email format')
        elif User.query.filter_by(email=email).first():
            errors.append('Email already registered')

        # Password validation
        password_validation = validate_password_strength(password)
        if not password_validation['valid']:
            errors.extend(password_validation['errors'])

        if password != confirm_password:
            errors.append('Passwords do not match')

        # Display name validation
        if display_name and len(display_name) > 100:
            errors.append('Display name must be less than 100 characters')

        # Terms validation
        if not terms_accepted:
            errors.append('You must accept the terms of service')

        # If there are errors, show them
        if errors:
            for error in errors:
                flash(error, 'error')
            return render_template('auth/register.html')

        try:
            # Create new user
            user = User(
                username=username,
                email=email,
                display_name=display_name or username.title(),
                is_verified=False,  # Email verification required
                preferences={
                    'email_notifications': True,
                    'security_alerts': True
                }
            )
            user.set_password(password)

            db.session.add(user)
            db.session.commit()

            # Create audit log
            AuditLog.log_action(
                user_id=user.id,
                action='user_registered',
                description=f'New user {username} registered',
                ip_address=request.remote_addr,
                metadata={
                    'email': email,
                    'user_agent': request.headers.get('User-Agent', '')
                }
            )

            # Send verification email (if email service is configured)
            if current_app.config.get('MAIL_SERVER'):
                AuthService.send_verification_email(user)
                flash('Registration successful! Please check your email to verify your account.', 'success')
            else:
                # Auto-verify if email service not configured
                user.is_verified = True
                db.session.commit()
                flash('Registration successful! You can now log in.', 'success')

            return redirect(url_for('auth.login'))

        except Exception as e:
            db.session.rollback()
            current_app.logger.error(f"Registration failed for {username}: {e}")
            flash('Registration failed. Please try again.', 'error')
            return render_template('auth/register.html')

    return render_template('auth/register.html')


@auth_bp.route('/logout')
@login_required
def logout():
    """User logout with audit logging"""
    if current_user.is_authenticated:
        # Create audit log
        AuditLog.log_action(
            user_id=current_user.id,
            action='logout',
            description=f'User {current_user.username} logged out',
            ip_address=request.remote_addr
        )

        # Update last active time
        current_user.last_active = datetime.utcnow()
        db.session.commit()

        username = current_user.username
        logout_user()

        flash(f'Goodbye, {username}!', 'info')

    return redirect(url_for('auth.login'))


@auth_bp.route('/profile')
@login_required
def profile():
    """User profile page"""
    # Get user statistics
    user_stats = {
        'files_uploaded': current_user.created_files.count(),
        'findings_created': current_user.created_findings.count(),
        'account_age_days': (datetime.utcnow() - current_user.created_at).days,
        'login_streak': current_user.streak_days,
        'total_points': current_user.points,
        'current_level': current_user.level.value
    }

    # Get recent activity
    recent_activity = AuditLog.query.filter_by(user_id=current_user.id) \
        .order_by(AuditLog.timestamp.desc()) \
        .limit(10).all()

    return render_template('auth/profile.html',
                           user_stats=user_stats,
                           recent_activity=recent_activity)


@auth_bp.route('/profile/edit', methods=['GET', 'POST'])
@login_required
def edit_profile():
    """Edit user profile"""
    if request.method == 'POST':
        # Get form data
        display_name = request.form.get('display_name', '').strip()
        first_name = request.form.get('first_name', '').strip()
        last_name = request.form.get('last_name', '').strip()
        bio = request.form.get('bio', '').strip()
        timezone = request.form.get('timezone', 'UTC')

        # Email notification preferences
        email_notifications = request.form.get('email_notifications', False)
        security_alerts = request.form.get('security_alerts', False)

        # Validation
        errors = []

        if display_name and len(display_name) > 100:
            errors.append('Display name must be less than 100 characters')

        if first_name and len(first_name) > 50:
            errors.append('First name must be less than 50 characters')

        if last_name and len(last_name) > 50:
            errors.append('Last name must be less than 50 characters')

        if bio and len(bio) > 500:
            errors.append('Bio must be less than 500 characters')

        if errors:
            for error in errors:
                flash(error, 'error')
            return render_template('auth/edit_profile.html')

        try:
            # Update user profile
            current_user.display_name = display_name
            current_user.first_name = first_name
            current_user.last_name = last_name
            current_user.bio = bio
            current_user.timezone = timezone

            # Update preferences
            current_user.preferences.update({
                'email_notifications': bool(email_notifications),
                'security_alerts': bool(security_alerts)
            })

            db.session.commit()

            # Create audit log
            AuditLog.log_action(
                user_id=current_user.id,
                action='profile_updated',
                description='User profile updated',
                ip_address=request.remote_addr
            )

            flash('Profile updated successfully!', 'success')
            return redirect(url_for('auth.profile'))

        except Exception as e:
            db.session.rollback()
            current_app.logger.error(f"Profile update failed for {current_user.username}: {e}")
            flash('Failed to update profile. Please try again.', 'error')

    return render_template('auth/edit_profile.html')


@auth_bp.route('/change-password', methods=['GET', 'POST'])
@login_required
@rate_limit("3 per minute")
def change_password():
    """Change user password"""
    if request.method == 'POST':
        current_password = request.form.get('current_password', '').strip()
        new_password = request.form.get('new_password', '').strip()
        confirm_password = request.form.get('confirm_password', '').strip()

        # Validation
        errors = []

        if not current_password:
            errors.append('Current password is required')
        elif not current_user.check_password(current_password):
            errors.append('Current password is incorrect')

        # New password validation
        password_validation = validate_password_strength(new_password)
        if not password_validation['valid']:
            errors.extend(password_validation['errors'])

        if new_password != confirm_password:
            errors.append('New passwords do not match')

        if current_password == new_password:
            errors.append('New password must be different from current password')

        if errors:
            for error in errors:
                flash(error, 'error')
            return render_template('auth/change_password.html')

        try:
            # Update password
            current_user.set_password(new_password)
            current_user.password_changed_at = datetime.utcnow()
            db.session.commit()

            # Create audit log
            AuditLog.log_action(
                user_id=current_user.id,
                action='password_changed',
                description='User changed password',
                ip_address=request.remote_addr
            )

            flash('Password changed successfully!', 'success')
            return redirect(url_for('auth.profile'))

        except Exception as e:
            db.session.rollback()
            current_app.logger.error(f"Password change failed for {current_user.username}: {e}")
            flash('Failed to change password. Please try again.', 'error')

    return render_template('auth/change_password.html')


@auth_bp.route('/forgot-password', methods=['GET', 'POST'])
@rate_limit("3 per hour")
def forgot_password():
    """Password reset request"""
    if current_user.is_authenticated:
        return redirect(url_for('files.dashboard'))

    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()

        if not email:
            flash('Email is required', 'error')
            return render_template('auth/forgot_password.html')

        user = User.query.filter_by(email=email).first()

        if user:
            # Generate reset token
            reset_token = secrets.token_urlsafe(32)

            # Store token in session with expiration (1 hour)
            session[f'reset_token_{user.id}'] = {
                'token': reset_token,
                'expires': (datetime.utcnow() + timedelta(hours=1)).isoformat()
            }

            # Send reset email (if email service configured)
            if current_app.config.get('MAIL_SERVER'):
                AuthService.send_password_reset_email(user, reset_token)

            # Create audit log
            AuditLog.log_action(
                user_id=user.id,
                action='password_reset_requested',
                description='Password reset requested',
                ip_address=request.remote_addr,
                metadata={'email': email}
            )

        # Always show success message (don't reveal if email exists)
        flash('If the email exists in our system, you will receive password reset instructions.', 'info')
        return redirect(url_for('auth.login'))

    return render_template('auth/forgot_password.html')


@auth_bp.route('/reset-password/<int:user_id>/<token>')
@rate_limit("5 per hour")
def reset_password(user_id, token):
    """Password reset form"""
    if current_user.is_authenticated:
        return redirect(url_for('files.dashboard'))

    # Validate token
    session_key = f'reset_token_{user_id}'
    if session_key not in session:
        flash('Invalid or expired reset link', 'error')
        return redirect(url_for('auth.forgot_password'))

    token_data = session[session_key]
    if (token_data['token'] != token or
            datetime.fromisoformat(token_data['expires']) < datetime.utcnow()):
        flash('Invalid or expired reset link', 'error')
        session.pop(session_key, None)
        return redirect(url_for('auth.forgot_password'))

    user = User.query.get_or_404(user_id)

    if request.method == 'POST':
        new_password = request.form.get('new_password', '').strip()
        confirm_password = request.form.get('confirm_password', '').strip()

        # Validation
        errors = []

        password_validation = validate_password_strength(new_password)
        if not password_validation['valid']:
            errors.extend(password_validation['errors'])

        if new_password != confirm_password:
            errors.append('Passwords do not match')

        if errors:
            for error in errors:
                flash(error, 'error')
            return render_template('auth/reset_password.html', user_id=user_id, token=token)

        try:
            # Update password
            user.set_password(new_password)
            user.unlock_account()  # Clear any locks
            db.session.commit()

            # Remove reset token
            session.pop(session_key, None)

            # Create audit log
            AuditLog.log_action(
                user_id=user.id,
                action='password_reset_completed',
                description='Password reset completed',
                ip_address=request.remote_addr
            )

            flash('Password reset successfully! You can now log in.', 'success')
            return redirect(url_for('auth.login'))

        except Exception as e:
            db.session.rollback()
            current_app.logger.error(f"Password reset failed for user {user_id}: {e}")
            flash('Failed to reset password. Please try again.', 'error')

    return render_template('auth/reset_password.html', user_id=user_id, token=token)


@auth_bp.route('/verify-email/<int:user_id>/<token>')
def verify_email(user_id, token):
    """Email verification"""
    user = User.query.get_or_404(user_id)

    # Simple token validation (in production, use proper JWT or signed tokens)
    expected_token = hashlib.sha256(f"{user.email}{user.created_at}".encode()).hexdigest()[:32]

    if token != expected_token:
        flash('Invalid verification link', 'error')
        return redirect(url_for('auth.login'))

    if user.is_verified:
        flash('Email already verified', 'info')
        return redirect(url_for('auth.login'))

    try:
        user.is_verified = True
        db.session.commit()

        # Create audit log
        AuditLog.log_action(
            user_id=user.id,
            action='email_verified',
            description='Email verification completed',
            ip_address=request.remote_addr
        )

        flash('Email verified successfully! You can now log in.', 'success')

    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Email verification failed for user {user_id}: {e}")
        flash('Email verification failed. Please try again.', 'error')

    return redirect(url_for('auth.login'))


@auth_bp.route('/api-keys')
@login_required
def api_keys():
    """Manage API keys"""
    user_api_keys = current_user.api_keys.filter_by(is_active=True).all()
    return render_template('auth/api_keys.html', api_keys=user_api_keys)


@auth_bp.route('/api-keys/create', methods=['POST'])
@login_required
@rate_limit("5 per hour")
def create_api_key():
    """Create new API key"""
    from crypto_hunter_web.models import ApiKey

    name = request.form.get('name', '').strip()
    permissions = request.form.getlist('permissions')

    if not name:
        flash('API key name is required', 'error')
        return redirect(url_for('auth.api_keys'))

    if len(name) > 100:
        flash('API key name must be less than 100 characters', 'error')
        return redirect(url_for('auth.api_keys'))

    try:
        # Generate API key
        api_key = secrets.token_urlsafe(32)
        key_hash = hashlib.sha256(api_key.encode()).hexdigest()

        # Create API key record
        api_key_record = ApiKey(
            user_id=current_user.id,
            name=name,
            key_hash=key_hash,
            key_prefix=api_key[:8],
            permissions=permissions or [],
            rate_limit=1000  # Default rate limit
        )

        db.session.add(api_key_record)
        db.session.commit()

        # Create audit log
        AuditLog.log_action(
            user_id=current_user.id,
            action='api_key_created',
            description=f'API key "{name}" created',
            ip_address=request.remote_addr
        )

        flash(f'API key created successfully: {api_key}', 'success')
        flash('Please save this key securely - it will not be shown again!', 'warning')

    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"API key creation failed: {e}")
        flash('Failed to create API key. Please try again.', 'error')

    return redirect(url_for('auth.api_keys'))


@auth_bp.route('/api-keys/<int:key_id>/revoke', methods=['POST'])
@login_required
def revoke_api_key(key_id):
    """Revoke API key"""
    from crypto_hunter_web.models import ApiKey

    api_key = ApiKey.query.filter_by(id=key_id, user_id=current_user.id).first_or_404()

    try:
        api_key.is_active = False
        db.session.commit()

        # Create audit log
        AuditLog.log_action(
            user_id=current_user.id,
            action='api_key_revoked',
            description=f'API key "{api_key.name}" revoked',
            ip_address=request.remote_addr
        )

        flash('API key revoked successfully', 'success')

    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"API key revocation failed: {e}")
        flash('Failed to revoke API key. Please try again.', 'error')

    return redirect(url_for('auth.api_keys'))


# Error handlers for auth blueprint
@auth_bp.errorhandler(429)
def ratelimit_handler(e):
    """Handle rate limit errors"""
    flash('Too many requests. Please slow down and try again later.', 'error')
    return render_template('auth/login.html'), 429


# Template context processors
@auth_bp.context_processor
def inject_auth_context():
    """Inject authentication context into templates"""
    return {
        'registration_enabled': current_app.config.get('ENABLE_REGISTRATION', True),
        'email_verification_enabled': bool(current_app.config.get('MAIL_SERVER')),
    }