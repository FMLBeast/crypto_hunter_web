# crypto_hunter_web/routes/main.py
"""
Main application routes - Landing page and general navigation
"""
import logging
from flask import Blueprint, render_template, redirect, url_for, request, current_app
from flask_login import current_user

logger = logging.getLogger(__name__)

# Create main blueprint
main_bp = Blueprint('main', __name__)


@main_bp.route('/')
def index():
    """Main landing page"""
    if current_user.is_authenticated:
        return redirect(url_for('dashboard.index'))
    
    return render_template('main/landing.html')


@main_bp.route('/health')
def health_check():
    """Health check endpoint"""
    try:
        # Basic health checks
        from crypto_hunter_web.extensions import db
        db.session.execute('SELECT 1')
        
        return {
            'status': 'healthy',
            'message': 'Crypto Hunter is running',
            'version': '2.0.0'
        }
    except Exception as e:
        logger.error(f"Health check failed: {e}")
        return {
            'status': 'unhealthy',
            'message': str(e)
        }, 500


@main_bp.route('/about')
def about():
    """About page"""
    return render_template('main/about.html')


@main_bp.route('/help')
def help_page():
    """Help documentation page"""
    return render_template('main/help.html')


@main_bp.route('/terms')
def terms():
    """Terms of service"""
    return render_template('main/terms.html')


@main_bp.route('/privacy')
def privacy():
    """Privacy policy"""
    return render_template('main/privacy.html')


# Error handlers specific to main blueprint
@main_bp.errorhandler(404)
def not_found_error(error):
    return render_template('errors/404.html'), 404


@main_bp.errorhandler(500)
def internal_error(error):
    return render_template('errors/500.html'), 500


@main_bp.errorhandler(403)
def forbidden_error(error):
    return render_template('errors/403.html'), 403