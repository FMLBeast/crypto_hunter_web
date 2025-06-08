"""
crypto_hunter_web/cli/__init__.py
CLI commands for Crypto Hunter management
"""

import click
from flask.cli import with_appcontext
from .user_commands import user_cli
from .forensics_commands import forensics_cli
from .analysis_commands import analysis_cli
from .system_commands import system_cli


def register_commands(app):
    """Register all CLI commands with the Flask app"""
    app.cli.add_command(user_cli)
    app.cli.add_command(forensics_cli)
    app.cli.add_command(analysis_cli)
    app.cli.add_command(system_cli)


# ===================================================================
# crypto_hunter_web/cli/user_commands.py
# User management commands
# ===================================================================

import click
from flask.cli import with_appcontext
from werkzeug.security import generate_password_hash
from crypto_hunter_web.models import db, User


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


# ===================================================================
# crypto_hunter_web/cli/forensics_commands.py
# Forensics tools management commands
# ===================================================================

import click
import subprocess
import os
from flask.cli import with_appcontext
from crypto_hunter_web.services.background_service import ForensicsToolkit


@click.group()
def forensics_cli():
    """Forensics tools management"""
    pass


@forensics_cli.command()
@with_appcontext
def check():
    """Check status of forensics tools"""
    click.echo("🔧 Checking forensics tools...")

    toolkit = ForensicsToolkit()
    tools_status = {}

    for tool_name in toolkit.tools.keys():
        available = toolkit._is_tool_available(tool_name)
        tools_status[tool_name] = available

        status_icon = "✅" if available else "❌"
        click.echo(f"  {status_icon} {tool_name}")

    # Summary
    available_count = sum(tools_status.values())
    total_count = len(tools_status)

    click.echo(f"\n📊 Summary: {available_count}/{total_count} tools available")

    if available_count < total_count:
        click.echo("\n💡 To install missing tools, run: crypto-hunter forensics install")


@forensics_cli.command()
@click.option('--tool', help='Install specific tool')
@click.option('--all', 'install_all', is_flag=True, help='Install all tools')
@with_appcontext
def install(tool, install_all):
    """Install forensics tools"""
    if not tool and not install_all:
        click.echo("Please specify --tool NAME or --all")
        return

    if install_all:
        click.echo("🚀 Installing all forensics tools...")
        _install_all_tools()
    else:
        click.echo(f"🔧 Installing {tool}...")
        _install_single_tool(tool)


def _install_all_tools():
    """Install all forensics tools"""
    tools_to_install = {
        'system_packages': [
            'binutils',  # strings, objdump, nm, readelf
            'bsdmainutils',  # hexdump
            'file',  # file command
            'exiftool',  # metadata extraction
            'foremost',  # file carving
            'steghide',  # steganography
            'sox',  # audio processing
            'ffmpeg',  # video/audio processing
            'wireshark',  # network analysis
            'tcpdump',  # packet capture
            'hashcat',  # password cracking
            'john',  # password cracking
            'radare2',  # reverse engineering
            'build-essential',  # compilation tools
        ],
        'pip_packages': [
            'binwalk',  # binary analysis
        ],
        'gem_packages': [
            'zsteg',  # image steganography
        ]
    }

    # Install system packages
    click.echo("📦 Installing system packages...")
    system_packages = ' '.join(tools_to_install['system_packages'])
    try:
        subprocess.run(['sudo', 'apt-get', 'update'], check=True)
        subprocess.run(['sudo', 'apt-get', 'install', '-y'] + tools_to_install['system_packages'], check=True)
        click.echo("✅ System packages installed")
    except subprocess.CalledProcessError:
        click.echo("❌ Failed to install system packages")

    # Install pip packages
    click.echo("🐍 Installing Python packages...")
    for package in tools_to_install['pip_packages']:
        try:
            subprocess.run(['pip', 'install', package], check=True)
            click.echo(f"✅ Installed {package}")
        except subprocess.CalledProcessError:
            click.echo(f"❌ Failed to install {package}")

    # Install gem packages
    click.echo("💎 Installing Ruby gems...")
    for package in tools_to_install['gem_packages']:
        try:
            subprocess.run(['gem', 'install', package], check=True)
            click.echo(f"✅ Installed {package}")
        except subprocess.CalledProcessError:
            click.echo(f"❌ Failed to install {package}")

    # Install special tools
    _install_special_tools()


def _install_special_tools():
    """Install tools that require special handling"""
    # StegSeek
    click.echo("🔍 Installing StegSeek...")
    try:
        subprocess.run([
            'wget', '-O', '/tmp/stegseek.deb',
            'https://github.com/RickdeJager/stegseek/releases/latest/download/stegseek_1.6_amd64.deb'
        ], check=True)
        subprocess.run(['sudo', 'dpkg', '-i', '/tmp/stegseek.deb'], check=True)
        click.echo("✅ StegSeek installed")
    except subprocess.CalledProcessError:
        click.echo("❌ Failed to install StegSeek")

    # Bulk Extractor
    click.echo("🔍 Installing Bulk Extractor...")
    try:
        subprocess.run(['sudo', 'apt-get', 'install', '-y', 'bulk-extractor'], check=True)
        click.echo("✅ Bulk Extractor installed")
    except subprocess.CalledProcessError:
        click.echo("❌ Failed to install Bulk Extractor")


def _install_single_tool(tool_name):
    """Install a specific tool"""
    installation_commands = {
        'binwalk': ['pip', 'install', 'binwalk'],
        'zsteg': ['gem', 'install', 'zsteg'],
        'steghide': ['sudo', 'apt-get', 'install', '-y', 'steghide'],
        'foremost': ['sudo', 'apt-get', 'install', '-y', 'foremost'],
        'exiftool': ['sudo', 'apt-get', 'install', '-y', 'exiftool'],
        'strings': ['sudo', 'apt-get', 'install', '-y', 'binutils'],
        'hexdump': ['sudo', 'apt-get', 'install', '-y', 'bsdmainutils'],
        'sox': ['sudo', 'apt-get', 'install', '-y', 'sox'],
        'ffmpeg': ['sudo', 'apt-get', 'install', '-y', 'ffmpeg'],
        'wireshark': ['sudo', 'apt-get', 'install', '-y', 'wireshark'],
        'tcpdump': ['sudo', 'apt-get', 'install', '-y', 'tcpdump'],
        'hashcat': ['sudo', 'apt-get', 'install', '-y', 'hashcat'],
        'john': ['sudo', 'apt-get', 'install', '-y', 'john'],
        'radare2': ['sudo', 'apt-get', 'install', '-y', 'radare2'],
    }

    if tool_name not in installation_commands:
        click.echo(f"❌ Unknown tool: {tool_name}")
        return

    try:
        subprocess.run(installation_commands[tool_name], check=True)
        click.echo(f"✅ Installed {tool_name}")
    except subprocess.CalledProcessError:
        click.echo(f"❌ Failed to install {tool_name}")


@forensics_cli.command()
@with_appcontext
def test():
    """Test forensics tools with sample files"""
    click.echo("🧪 Testing forensics tools...")

    # Create test files
    test_dir = "/tmp/crypto_hunter_test"
    os.makedirs(test_dir, exist_ok=True)

    # Create a simple test file
    test_file = os.path.join(test_dir, "test.txt")
    with open(test_file, 'w') as f:
        f.write("This is a test file for Crypto Hunter forensics tools.\nflag{test_flag_12345}")

    click.echo(f"📁 Created test file: {test_file}")

    # Test each tool
    toolkit = ForensicsToolkit()

    test_results = {}
    for tool_name in ['strings', 'hexdump', 'binwalk']:
        if toolkit._is_tool_available(tool_name):
            click.echo(f"🔧 Testing {tool_name}...")
            try:
                result = toolkit._run_tool_analysis(tool_name, test_file, 'text/plain')
                test_results[tool_name] = result.success if result else False
                status = "✅ PASS" if test_results[tool_name] else "❌ FAIL"
                click.echo(f"  {status}")
            except Exception as e:
                test_results[tool_name] = False
                click.echo(f"  ❌ FAIL: {e}")
        else:
            test_results[tool_name] = False
            click.echo(f"🔧 {tool_name}: ⚠️ NOT AVAILABLE")

    # Cleanup
    import shutil
    shutil.rmtree(test_dir, ignore_errors=True)

    # Summary
    passed = sum(test_results.values())
    total = len(test_results)
    click.echo(f"\n📊 Test Results: {passed}/{total} tools passed")


# ===================================================================
# crypto_hunter_web/cli/analysis_commands.py
# Analysis management commands
# ===================================================================

import click
import json
from flask.cli import with_appcontext
from crypto_hunter_web.models import db, AnalysisFile, FileContent, Finding
from crypto_hunter_web.services.background_service import BackgroundService


@click.group()
def analysis_cli():
    """Analysis management commands"""
    pass


@analysis_cli.command()
@click.argument('file_hash')
@click.option('--type', 'analysis_type', default='comprehensive',
              type=click.Choice(['comprehensive', 'steganography', 'crypto', 'ai']),
              help='Type of analysis to run')
@with_appcontext
def run(file_hash, analysis_type):
    """Run analysis on a file"""
    file_obj = AnalysisFile.query.filter_by(sha256_hash=file_hash).first()
    if not file_obj:
        click.echo(f"❌ File not found: {file_hash}")
        return

    click.echo(f"🔍 Starting {analysis_type} analysis for {file_obj.filename}...")

    try:
        if analysis_type == 'comprehensive':
            task_id = BackgroundService.queue_comprehensive_analysis(
                file_id=file_obj.id,
                analysis_types=['steganography', 'binary_analysis', 'crypto_patterns', 'strings'],
                user_id=1  # System user
            )
        elif analysis_type == 'steganography':
            task_id = BackgroundService.queue_steganography_analysis(
                file_id=file_obj.id,
                user_id=1
            )
        elif analysis_type == 'crypto':
            task_id = BackgroundService.queue_crypto_analysis(
                file_id=file_obj.id,
                analysis_options={'deep_scan': True},
                user_id=1
            )
        else:
            click.echo(f"❌ Analysis type '{analysis_type}' not implemented")
            return

        click.echo(f"✅ Analysis queued with task ID: {task_id}")
        click.echo(f"💡 Check status with: crypto-hunter analysis status {task_id}")

    except Exception as e:
        click.echo(f"❌ Failed to queue analysis: {e}")


@analysis_cli.command()
@click.argument('task_id')
@with_appcontext
def status(task_id):
    """Check analysis status"""
    try:
        status_info = BackgroundService.get_task_status(task_id)

        if 'error' in status_info:
            click.echo(f"❌ Error: {status_info['error']}")
            return

        state = status_info.get('state', 'UNKNOWN')
        click.echo(f"📊 Task {task_id}: {state}")

        if state == 'PROGRESS':
            meta = status_info.get('meta', {})
            progress = meta.get('progress', 0)
            stage = meta.get('stage', 'Processing...')
            click.echo(f"⏳ Progress: {progress}% - {stage}")
        elif state == 'SUCCESS':
            result = status_info.get('result', {})
            click.echo(f"✅ Analysis complete!")
            if 'findings_count' in result:
                click.echo(f"🔍 Findings: {result['findings_count']}")
            if 'execution_time' in result:
                click.echo(f"⏱️  Time: {result['execution_time']:.2f}s")
        elif state == 'FAILURE':
            meta = status_info.get('meta', {})
            error = meta.get('error', 'Unknown error')
            click.echo(f"❌ Analysis failed: {error}")

    except Exception as e:
        click.echo(f"❌ Error checking status: {e}")


@analysis_cli.command()
@click.option('--limit', default=10, help='Number of recent analyses to show')
@with_appcontext
def list(limit):
    """List recent analyses"""
    files = AnalysisFile.query.order_by(AnalysisFile.created_at.desc()).limit(limit).all()

    if not files:
        click.echo("No analyses found")
        return

    click.echo("Recent analyses:")
    for file in files:
        status_icon = {
            'complete': '✅',
            'processing': '⏳',
            'failed': '❌',
            'pending': '📋'
        }.get(file.status, '❓')

        findings_count = Finding.query.filter_by(file_id=file.id).count()

        click.echo(f"  {status_icon} {file.filename[:50]} - {file.status}")
        click.echo(f"     Hash: {file.sha256_hash}")
        click.echo(f"     Findings: {findings_count}")
        if file.analyzed_at:
            click.echo(f"     Analyzed: {file.analyzed_at}")
        click.echo()


@analysis_cli.command()
@click.argument('file_hash')
@click.option('--format', 'output_format', default='text',
              type=click.Choice(['text', 'json']),
              help='Output format')
@with_appcontext
def results(file_hash, output_format):
    """Show analysis results for a file"""
    file_obj = AnalysisFile.query.filter_by(sha256_hash=file_hash).first()
    if not file_obj:
        click.echo(f"❌ File not found: {file_hash}")
        return

    # Get findings
    findings = Finding.query.filter_by(file_id=file_obj.id).all()

    # Get analysis content
    content_entries = FileContent.query.filter_by(file_id=file_obj.id).all()

    if output_format == 'json':
        results_data = {
            'file': {
                'filename': file_obj.filename,
                'hash': file_obj.sha256_hash,
                'status': file_obj.status,
                'analyzed_at': file_obj.analyzed_at.isoformat() if file_obj.analyzed_at else None
            },
            'findings': [
                {
                    'type': f.finding_type,
                    'confidence': f.confidence,
                    'description': f.description,
                    'created_at': f.created_at.isoformat()
                }
                for f in findings
            ],
            'content_entries': [
                {
                    'type': c.content_type,
                    'method': c.extraction_method,
                    'size': c.content_size
                }
                for c in content_entries
            ]
        }
        click.echo(json.dumps(results_data, indent=2))
    else:
        click.echo(f"📄 Analysis Results for {file_obj.filename}")
        click.echo(f"🆔 Hash: {file_obj.sha256_hash}")
        click.echo(f"📊 Status: {file_obj.status}")

        if findings:
            click.echo(f"\n🔍 Findings ({len(findings)}):")
            for finding in findings:
                confidence_bar = "█" * int(finding.confidence * 10)
                click.echo(f"  • {finding.finding_type}")
                click.echo(f"    Confidence: {confidence_bar} {finding.confidence:.2f}")
                click.echo(f"    {finding.description}")
                click.echo()
        else:
            click.echo("\n🔍 No findings")

        if content_entries:
            click.echo(f"📋 Content Entries ({len(content_entries)}):")
            for content in content_entries:
                click.echo(f"  • {content.content_type} ({content.extraction_method})")
                click.echo(f"    Size: {content.content_size} bytes")
            click.echo()


# ===================================================================
# crypto_hunter_web/cli/system_commands.py
# System management commands
# ===================================================================

import click
import subprocess
from flask.cli import with_appcontext
from crypto_hunter_web.models import db
from crypto_hunter_web.services.background_service import BackgroundService


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
        queue_status = BackgroundService.get_queue_status()
        click.echo("✅ Background Tasks: Available")

        if queue_status.get('active_tasks'):
            active_count = sum(len(tasks) for tasks in queue_status['active_tasks'].values())
            click.echo(f"   Active tasks: {active_count}")
    except Exception as e:
        click.echo(f"❌ Background Tasks: {e}")

    # Forensics tools check
    click.echo("\n🔧 Forensics Tools:")
    from crypto_hunter_web.services.background_service import ForensicsToolkit
    toolkit = ForensicsToolkit()

    available_tools = 0
    total_tools = len(toolkit.tools)

    for tool_name in toolkit.tools.keys():
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
        import subprocess
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