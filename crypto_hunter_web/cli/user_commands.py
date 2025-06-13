# crypto_hunter_web/cli/user_commands.py
# User management commands

import click
from flask.cli import with_appcontext
from werkzeug.security import generate_password_hash
from crypto_hunter_web.models import User, db


@click.group()
def user_cli():
    """User management commands"""
    pass


@user_cli.command()
@click.option('--username', prompt=True, help='Username for the new user')
@click.option('--email', prompt=True, help='Email for the new user')
@click.option('--password', prompt=True, hide_input=True, confirmation_prompt=True, help='Password for the new user')
@click.option('--admin', is_flag=True, help='Make user an admin')
@with_appcontext
def create(username, email, password, admin):
    """Create a new user"""
    # Check if user already exists
    if User.query.filter_by(username=username).first():
        click.echo(f"Error: User '{username}' already exists")
        return

    if User.query.filter_by(email=email).first():
        click.echo(f"Error: Email '{email}' already exists")
        return

    # Create new user
    user = User(
        username=username,
        email=email,
        password_hash=generate_password_hash(password),
        is_admin=admin,
        is_active=True
    )

    db.session.add(user)
    db.session.commit()

    role = "admin" if admin else "user"
    click.echo(f"✅ Created {role} user: {username} ({email})")


@user_cli.command()
@click.argument('username')
@with_appcontext
def delete(username):
    """Delete a user"""
    user = User.query.filter_by(username=username).first()
    if not user:
        click.echo(f"Error: User '{username}' not found")
        return

    if click.confirm(f"Are you sure you want to delete user '{username}'?"):
        db.session.delete(user)
        db.session.commit()
        click.echo(f"✅ Deleted user: {username}")


@user_cli.command()
@click.argument('username')
@with_appcontext
def make_admin(username):
    """Make a user an admin"""
    user = User.query.filter_by(username=username).first()
    if not user:
        click.echo(f"Error: User '{username}' not found")
        return

    user.is_admin = True
    db.session.commit()
    click.echo(f"✅ Made user '{username}' an admin")


@user_cli.command()
@with_appcontext
def list():
    """List all users"""
    users = User.query.all()

    if not users:
        click.echo("No users found")
        return

    click.echo("Users:")
    for user in users:
        role = "admin" if user.is_admin else "user"
        status = "active" if user.is_active else "inactive"
        click.echo(f"  {user.username} ({user.email}) - {role}, {status}")
