"""
Extensions and CLI commands for Crypto Hunter - BETA VERSION
"""
import click
from flask import current_app
from flask.cli import with_appcontext


@click.group()
def user():
    """User management commands"""
    pass


@user.command()
@click.option('--username', prompt=True, help='Admin username')
@click.option('--email', prompt=True, help='Admin email')
@click.option('--password', prompt=True, hide_input=True, help='Admin password')
@with_appcontext
def create_admin(username, email, password):
    """Create an admin user"""
    try:
        from crypto_hunter_web.models import User, db

        # Check if user already exists
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            click.echo(f'User {username} already exists')
            return

        # Create admin user
        admin = User(
            username=username,
            email=email,
            is_admin=True,
            is_active=True,
            is_verified=True
        )
        admin.set_password(password)

        db.session.add(admin)
        db.session.commit()

        click.echo(f'✅ Admin user created: {username}')

    except Exception as e:
        click.echo(f'❌ Error creating admin user: {e}')


@user.command()
@with_appcontext
def list_users():
    """List all users"""
    try:
        from crypto_hunter_web.models import User

        users = User.query.all()

        click.echo('Users:')
        for user in users:
            status = '✅' if user.is_active else '❌'
            admin = '👑' if user.is_admin else '👤'
            click.echo(f'{status} {admin} {user.username} ({user.email})')

    except Exception as e:
        click.echo(f'❌ Error listing users: {e}')


@click.group()
def db_commands():
    """Database management commands"""
    pass


@db_commands.command()
@with_appcontext
def init_db():
    """Initialize the database"""
    try:
        from crypto_hunter_web.models import db
        db.create_all()
        click.echo('✅ Database initialized')
    except Exception as e:
        click.echo(f'❌ Error initializing database: {e}')


@db_commands.command()
@with_appcontext
def reset_db():
    """Reset the database (WARNING: Destroys all data)"""
    if click.confirm('This will destroy all data. Are you sure?'):
        try:
            from crypto_hunter_web.models import db
            db.drop_all()
            db.create_all()
            click.echo('✅ Database reset')
        except Exception as e:
            click.echo(f'❌ Error resetting database: {e}')


@click.command()
@with_appcontext
def test_redis():
    """Test Redis connection"""
    try:
        import redis
        redis_client = redis.from_url(current_app.config['REDIS_URL'])
        redis_client.ping()
        click.echo('✅ Redis connection successful')
    except Exception as e:
        click.echo(f'❌ Redis connection failed: {e}')


@click.command()
@with_appcontext
def test_celery():
    """Test Celery connection"""
    try:
        from crypto_hunter_web.services.celery_app import celery_app

        # Try to get worker stats
        inspector = celery_app.control.inspect()
        stats = inspector.stats()

        if stats:
            click.echo('✅ Celery workers active')
            for worker, info in stats.items():
                click.echo(f'  Worker: {worker}')
        else:
            click.echo('⚠️ No active Celery workers found')

    except Exception as e:
        click.echo(f'❌ Celery connection failed: {e}')


def register_commands(app):
    """Register CLI commands with the Flask app"""
    app.cli.add_command(user)
    app.cli.add_command(db_commands, name='db-admin')
    app.cli.add_command(test_redis)
    app.cli.add_command(test_celery)