# crypto_hunter_web/cli/system_commands.py
# System management commands

import click
import subprocess
from flask.cli import with_appcontext
from crypto_hunter_web.models import db
from crypto_hunter_web.services.background_service import BackgroundService
from crypto_hunter_web.services.extractors.forensics_extractor import ForensicsToolkit


@click.group()
def system_cli():
    """System management commands"""
    pass


@system_cli.command()
@with_appcontext
def init():
    """Initialize the system"""
    click.echo("🚀 Initializing Crypto Hunter...")

    # Create database tables
    click.echo("📊 Creating database tables...")
    try:
        db.create_all()
        click.echo("✅ Database tables created")
    except Exception as e:
        click.echo(f"❌ Database initialization failed: {e}")
        return

    # Check dependencies
    click.echo("🔍 Checking dependencies...")
    _check_system_dependencies()

    click.echo("✅ System initialization complete!")
    click.echo("💡 Next steps:")
    click.echo("  1. Create an admin user: crypto-hunter user create --admin")
    click.echo("  2. Check forensics tools: crypto-hunter forensics check")
    click.echo("  3. Start the application: python run.py")


def _check_system_dependencies():
    """Check system dependencies"""
    dependencies = [
        ('Python', ['python', '--version']),
        ('Pip', ['pip', '--version']),
        ('Redis', ['redis-cli', '--version']),
        ('PostgreSQL', ['psql', '--version']),
    ]

    for name, command in dependencies:
        try:
            subprocess.run(command, check=True, capture_output=True)
            click.echo(f"  ✅ {name}")
        except (subprocess.CalledProcessError, FileNotFoundError):
            click.echo(f"  ⚠️  {name} - not available")


@system_cli.command()
@with_appcontext
def health():
    """Check system health"""
    click.echo("🏥 System Health Check")

    # Database check
    try:
        db.session.execute('SELECT 1')
        click.echo("✅ Database: Connected")
    except Exception as e:
        click.echo(f"❌ Database: {e}")

    # Redis check
    try:
        import redis
        r = redis.from_url('redis://localhost:6379/0')
        r.ping()
        click.echo("✅ Redis: Connected")
    except Exception as e:
        click.echo(f"❌ Redis: {e}")

    # Background tasks check
    try:
        system_status = BackgroundService.get_system_status()
        click.echo("✅ Background Tasks: Available")

        if system_status.get('workers', {}).get('active_tasks'):
            active_count = sum(len(tasks) for tasks in system_status['workers']['active_tasks'].values())
            click.echo(f"   Active tasks: {active_count}")
    except Exception as e:
        click.echo(f"❌ Background Tasks: {e}")

    # Forensics tools check
    click.echo("\n🔧 Forensics Tools:")
    toolkit = ForensicsToolkit()

    available_tools = 0
    total_tools = len(toolkit.tools)

    for tool_name in toolkit.tools.keys():
        # noinspection PyProtectedMember
        if toolkit._is_tool_available(tool_name):
            available_tools += 1
            click.echo(f"   ✅ {tool_name}")
        else:
            click.echo(f"   ❌ {tool_name}")

    click.echo(f"\n📊 Summary: {available_tools}/{total_tools} forensics tools available")


@system_cli.command()
@with_appcontext
def stats():
    """Show system statistics"""
    from crypto_hunter_web.models import AnalysisFile, Finding, User, FileContent

    click.echo("📊 System Statistics")

    # File statistics
    total_files = AnalysisFile.query.count()
    analyzed_files = AnalysisFile.query.filter_by(status='complete').count()
    processing_files = AnalysisFile.query.filter_by(status='processing').count()

    click.echo(f"\n📁 Files:")
    click.echo(f"   Total: {total_files}")
    click.echo(f"   Analyzed: {analyzed_files}")
    click.echo(f"   Processing: {processing_files}")

    # User statistics
    total_users = User.query.count()
    admin_users = User.query.filter_by(is_admin=True).count()

    click.echo(f"\n👥 Users:")
    click.echo(f"   Total: {total_users}")
    click.echo(f"   Admins: {admin_users}")

    # Finding statistics
    total_findings = Finding.query.count()

    click.echo(f"\n🔍 Findings:")
    click.echo(f"   Total: {total_findings}")

    if analyzed_files > 0:
        avg_findings = total_findings / analyzed_files
        click.echo(f"   Average per file: {avg_findings:.1f}")

    # Content statistics
    content_entries = FileContent.query.count()
    click.echo(f"\n📋 Content Entries: {content_entries}")


@system_cli.command()
@click.confirmation_option(prompt="Are you sure you want to reset the database?")
@with_appcontext
def reset():
    """Reset the database (destructive operation)"""
    click.echo("🗑️  Resetting database...")

    try:
        db.drop_all()
        db.create_all()
        click.echo("✅ Database reset complete")
        click.echo("💡 Don't forget to create a new admin user!")
    except Exception as e:
        click.echo(f"❌ Database reset failed: {e}")


@system_cli.command()
@click.option('--output', default='backup.sql', help='Output file for backup')
@with_appcontext
def backup(output):
    """Backup the database"""
    click.echo(f"💾 Creating database backup: {output}")

    try:
        # This is a simple example - in production, use proper backup tools
        subprocess.run([
            'pg_dump',
            '--no-password',
            '--verbose',
            '--file', output,
            'crypto_hunter'
        ], check=True)
        click.echo(f"✅ Backup created: {output}")
    except subprocess.CalledProcessError as e:
        click.echo(f"❌ Backup failed: {e}")
    except FileNotFoundError:
        click.echo("❌ pg_dump not found. Make sure PostgreSQL client tools are installed.")
