"""
Main routes for Crypto Hunter - BETA VERSION
"""
from flask import Blueprint, jsonify, current_app

main_bp = Blueprint('main', __name__)


@main_bp.route('/')
def index():
    """Main landing page"""
    return jsonify({
        'message': 'Crypto Hunter Beta',
        'version': '2.0.0-beta',
        'status': 'running',
        'features': {
            'file_upload': True,
            'crypto_analysis': True,
            'user_auth': True,
            'api_access': True
        }
    })


@main_bp.route('/health')
def health():
    """Health check endpoint"""
    try:
        return jsonify({
            'status': 'healthy',
            'version': '2.0.0-beta',
            'environment': current_app.config.get('FLASK_ENV', 'production')
        })
    except Exception as e:
        return jsonify({
            'status': 'unhealthy',
            'error': str(e)
        }), 503


@main_bp.route('/status')
def status():
    """System status endpoint"""
    return jsonify({
        'app': 'Crypto Hunter',
        'version': '2.0.0-beta',
        'status': 'operational',
        'uptime': 'unknown',
        'features': {
            'authentication': True,
            'file_analysis': True,
            'crypto_detection': True,
            'background_tasks': True,
            'api': True
        }
    })


@main_bp.route('/about')
def about():
    """About page"""
    return jsonify({
        'name': 'Crypto Hunter',
        'version': '2.0.0-beta',
        'description': 'Advanced Cryptocurrency and Cryptographic Analysis Platform',
        'author': 'Crypto Hunter Team',
        'license': 'Proprietary'
    })


@main_bp.errorhandler(404)
def not_found(error):
    """Handle 404 errors"""
    return jsonify({
        'error': 'Not Found',
        'message': 'The requested resource was not found',
        'status_code': 404
    }), 404


@main_bp.errorhandler(500)
def internal_error(error):
    """Handle 500 errors"""
    return jsonify({
        'error': 'Internal Server Error',
        'message': 'An unexpected error occurred',
        'status_code': 500
    }), 500