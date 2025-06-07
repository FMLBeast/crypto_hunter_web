"""
Authentication routes
"""

from flask import Blueprint, render_template, request, redirect, url_for, flash, session
from crypto_hunter_web.services.auth_service import AuthService

auth_bp = Blueprint('auth', __name__)

@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    """User login"""
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        if not username or not password:
            flash('Username and password are required', 'error')
            return render_template('auth/login.html')
        
        user = AuthService.login_user(username, password)
        
        if user:
            flash(f'Welcome back, {user.display_name or user.username}!', 'success')
            return redirect(url_for('files.dashboard'))
        else:
            flash('Invalid username or password', 'error')
    
    return render_template('auth/login.html')

@auth_bp.route('/logout')
def logout():
    """User logout"""
    AuthService.logout_user()
    flash('You have been logged out', 'info')
    return redirect(url_for('auth.login'))

@auth_bp.route('/')
def index():
    """Redirect to dashboard or login"""
    if 'user_id' in session:
        return redirect(url_for('files.dashboard'))
    return redirect(url_for('auth.login'))
