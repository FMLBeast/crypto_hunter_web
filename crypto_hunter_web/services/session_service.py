# crypto_hunter_web/services/session_service.py

from flask_login import login_user as flask_login_user, logout_user as flask_logout_user

def login_user(user):
    """Wrapper around flask-login’s login_user."""
    return flask_login_user(user)

def logout_user():
    """Wrapper around flask-login’s logout_user."""
    return flask_logout_user()
