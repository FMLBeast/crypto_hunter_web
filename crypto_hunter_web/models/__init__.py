# crypto_hunter_web/models/__init__.py

# Import db from extensions first
from crypto_hunter_web.extensions import db

# Load the models.py file directly to avoid circular imports
import os

# Get the path to the models.py file
models_file = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'models.py')

# Create a namespace to execute the models.py file in
models_namespace = {
    '__file__': models_file,
    '__name__': 'crypto_hunter_web.models',
    'db': db  # Provide db to the models.py execution context
}

# Execute the models.py file to get all the classes
with open(models_file, 'r') as f:
    exec(f.read(), models_namespace)

# Export ALL classes and functions from models.py (except private ones)
for name, obj in models_namespace.items():
    if not name.startswith('_') and name not in ['os', 'sys']:
        globals()[name] = obj

def init_database():
    """Initialize database"""
    db.create_all()
    print("Database initialized")

def create_agent_tables():
    """Create agent tables - will add later"""  
    print("Agent tables will be created later")

# Add these functions to exports
globals()['init_database'] = init_database
globals()['create_agent_tables'] = create_agent_tables
