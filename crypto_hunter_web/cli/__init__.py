"""
crypto_hunter_web/cli/__init__.py
CLI commands for Crypto Hunter management
"""

from .analysis_commands import analysis_cli
from .forensics_commands import forensics_cli
from .system_commands import system_cli
from .user_commands import user_cli


def register_commands(app):
    """Register all CLI commands with the Flask app"""
    app.cli.add_command(user_cli)
    app.cli.add_command(forensics_cli)
    app.cli.add_command(analysis_cli)
    app.cli.add_command(system_cli)
