# crypto_hunter_web/models/__init__.py

# Import everything from the main models.py file
from crypto_hunter_web.models import *

# Functions for setup script
def init_database():
    """Initialize database - basic version"""
    from crypto_hunter_web.extensions import db
    db.create_all()
    print("Database initialized")

def create_agent_tables():
    """Create agent tables - will add later"""
    print("Agent tables will be created later")