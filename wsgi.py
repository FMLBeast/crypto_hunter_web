import os
from crypto_hunter_web import create_app

# Create Flask application
config_name = os.environ.get('FLASK_ENV', 'development')
app = create_app(config_name)

# Export for WSGI servers
application = app
