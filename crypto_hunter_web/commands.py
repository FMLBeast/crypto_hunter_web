# crypto_hunter_web/commands.py

import click
from flask.cli import with_appcontext
from .importer import import_from_csv

def register_commands(app):
    @app.cli.command('import-files')
    @click.argument('csv_path', type=click.Path(exists=True))
    @with_appcontext
    def import_files(csv_path):
        """Bulk-import FileNode records from CSV."""
        from . import db
        count = import_from_csv(csv_path)
        click.echo(f"✅ Imported {count} files from {csv_path}")
