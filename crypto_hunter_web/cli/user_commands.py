# crypto_hunter_web/cli/user_commands.py

import click
from flask.cli import with_appcontext
from crypto_hunter_web.extensions import db

@click.command('init-db')
@with_appcontext
def init_db():
    """Initialize database tables."""
    db.create_all()
    click.echo('Database initialized.')

def register_commands(app):
    app.cli.add_command(init_db)
