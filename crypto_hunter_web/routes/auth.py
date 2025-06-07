# crypto_hunter_web/routes/auth.py - COMPLETE FIXED VERSION

from flask import Blueprint, render_template, request, flash, redirect, url_for
from crypto_hunter_web.services.auth_service import AuthService

auth_bp = Blueprint('auth', __name__, url_prefix='/auth')


@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()

        user = AuthService.login_user(username, password)
        if not user:
            flash('Invalid username or password', 'danger')
            return redirect(url_for('auth.login'))

        # FIXED: Safe access to display_name attribute
        display_name = getattr(user, 'display_name', None) or user.username
        flash(f'Welcome back, {display_name}!', 'success')
        return redirect(url_for('files.dashboard'))

    return render_template('auth/login.html')


@auth_bp.route('/logout')
def logout():
    AuthService.logout()
    flash('You have been logged out.', 'info')
    return redirect(url_for('auth.login'))


@auth_bp.route('/profile')
@AuthService.login_required
def profile():
    """User profile page"""
    from flask_login import current_user
    return render_template('auth/profile.html', user=current_user)


@auth_bp.route('/change-password', methods=['GET', 'POST'])
@AuthService.login_required
def change_password():
    """Change user password"""
    from flask_login import current_user
    from crypto_hunter_web import db

    if request.method == 'POST':
        current_password = request.form.get('current_password')
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')

        # Validate current password
        if not current_user.check_password(current_password):
            flash('Current password is incorrect', 'error')
            return render_template('auth/change_password.html')

        # Validate new password
        if len(new_password) < 6:
            flash('New password must be at least 6 characters', 'error')
            return render_template('auth/change_password.html')

        if new_password != confirm_password:
            flash('New passwords do not match', 'error')
            return render_template('auth/change_password.html')

        # Update password
        try:
            current_user.set_password(new_password)
            db.session.commit()

            flash('Password changed successfully!', 'success')
            AuthService.log_action('password_changed', 'User changed password')
            return redirect(url_for('auth.profile'))

        except Exception as e:
            db.session.rollback()
            flash(f'Error changing password: {str(e)}', 'error')

    return render_template('auth/change_password.html')