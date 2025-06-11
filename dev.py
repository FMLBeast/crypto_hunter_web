
#!/usr/bin/env python3
"""
dev.py - Crypto Hunter Development Automation
Best-in-class development experience with comprehensive tooling
"""

import os
import sys
import subprocess
import time
import signal
import threading
import json
import shutil
from pathlib import Path
from typing import List, Dict, Optional
import argparse
import platform


class Colors:
    """ANSI color codes for terminal output"""
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


class DevEnvironment:
    """Development environment manager for Crypto Hunter"""

    def __init__(self):
        self.root_dir = Path(__file__).parent
        self.processes = []
        self.setup_signal_handlers()
        self.system = platform.system().lower()

    def setup_signal_handlers(self):
        """Setup graceful shutdown"""
        signal.signal(signal.SIGINT, self.signal_handler)
        signal.signal(signal.SIGTERM, self.signal_handler)

    def signal_handler(self, signum, frame):
        """Handle shutdown signals"""
        self.print_colored("\n🛑 Shutting down services...", Colors.YELLOW)
        self.stop_all_services()
        sys.exit(0)

    def print_colored(self, message: str, color: str = Colors.ENDC):
        """Print colored message"""
        print(f"{color}{message}{Colors.ENDC}")

    def run_command(self, cmd: List[str], cwd: str = None, capture_output: bool = False) -> subprocess.CompletedProcess:
        """Run command with proper error handling"""
        if isinstance(cmd, str):
            cmd = cmd.split()

        self.print_colored(f"🔨 Running: {' '.join(cmd)}", Colors.BLUE)
        try:
            return subprocess.run(cmd, check=True, cwd=cwd or self.root_dir,
                                  capture_output=capture_output, text=True)
        except subprocess.CalledProcessError as e:
            self.print_colored(f"❌ Command failed: {e}", Colors.RED)
            if not capture_output:
                sys.exit(1)
            return e

    def check_dependencies(self):
        """Check required dependencies"""
        self.print_colored("🔍 Checking dependencies...", Colors.HEADER)

        required = {
            'python': 'python --version',
            'pip': 'pip --version',
            'docker': 'docker --version',
            'docker-compose': 'docker-compose --version'
        }

        optional = {
            'redis-cli': 'redis-cli --version',
            'psql': 'psql --version',
            'node': 'node --version',
            'npm': 'npm --version'
        }

        missing_required = []
        missing_optional = []

        for dep, cmd in required.items():
            try:
                result = subprocess.run(cmd.split(), check=True, capture_output=True)
                self.print_colored(f"✅ {dep}", Colors.GREEN)
            except (subprocess.CalledProcessError, FileNotFoundError):
                self.print_colored(f"❌ {dep} - REQUIRED", Colors.RED)
                missing_required.append(dep)

        for dep, cmd in optional.items():
            try:
                result = subprocess.run(cmd.split(), check=True, capture_output=True)
                self.print_colored(f"✅ {dep}", Colors.GREEN)
            except (subprocess.CalledProcessError, FileNotFoundError):
                self.print_colored(f"⚠️  {dep} - optional", Colors.YELLOW)
                missing_optional.append(dep)

        if missing_required:
            self.print_colored(f"\n❌ Missing required dependencies: {', '.join(missing_required)}", Colors.RED)
            self.print_colored("Please install missing tools before continuing.", Colors.RED)
            return False

        if missing_optional:
            self.print_colored(f"\n⚠️  Missing optional dependencies: {', '.join(missing_optional)}", Colors.YELLOW)
            self.print_colored("Some features may not be available.", Colors.YELLOW)

        return True

    def setup_environment(self):
        """Setup development environment"""
        self.print_colored("🚀 Setting up development environment...", Colors.HEADER)

        # Create necessary directories
        directories = ['logs', 'uploads', 'instance', 'backups', 'temp', '.pytest_cache']
        for directory in directories:
            Path(directory).mkdir(exist_ok=True)
            self.print_colored(f"📁 Created directory: {directory}", Colors.CYAN)

        # Copy environment file if it doesn't exist
        env_file = Path('.env')
        env_example = Path('.env.example')

        if not env_file.exists():
            if env_example.exists():
                shutil.copy(env_example, env_file)
                self.print_colored("📋 Created .env from .env.example", Colors.GREEN)
            else:
                self.create_default_env()

        # Install Python dependencies
        self.print_colored("📦 Installing Python dependencies...", Colors.BLUE)
        self.run_command(['pip', 'install', '-r', 'requirements.txt'])

        # Install development dependencies if available
        dev_requirements = Path('requirements-dev.txt')
        if dev_requirements.exists():
            self.run_command(['pip', 'install', '-r', 'requirements-dev.txt'])

        self.print_colored("✅ Environment setup complete!", Colors.GREEN)

    def create_default_env(self):
        """Create default .env file"""
        default_env = """# Crypto Hunter Development Environment
SECRET_KEY=dev-secret-key-change-in-production
FLASK_ENV=development
DEBUG=true

# Database
DATABASE_URL=postgresql://crypto_hunter:dev_password@localhost:5432/crypto_hunter_dev

# Redis
REDIS_URL=redis://localhost:6379/0
CELERY_BROKER_URL=redis://localhost:6379/2
CELERY_RESULT_BACKEND=redis://localhost:6379/3

# AI Services (Optional)
OPENAI_API_KEY=
ANTHROPIC_API_KEY=

# Features
ENABLE_REGISTRATION=true
ENABLE_AI_ANALYSIS=true
ENABLE_BACKGROUND_TASKS=true
ENABLE_API=true

# Development
WTF_CSRF_ENABLED=false
LOG_LEVEL=DEBUG
MAX_CONTENT_LENGTH=104857600

# Forensics Tools
FORENSICS_TOOLS_PATH=/opt/forensics-tools
WORDLISTS_PATH=/opt/wordlists
"""
        with open('.env', 'w') as f:
            f.write(default_env)
        self.print_colored("📋 Created default .env file", Colors.GREEN)

    def start_infrastructure(self, services: List[str] = None):
        """Start infrastructure services"""
        if services is None:
            services = ['redis', 'postgres']

        self.print_colored("🔧 Starting infrastructure services...", Colors.HEADER)

        # Check if Docker is running
        try:
            subprocess.run(['docker', 'info'], check=True, capture_output=True)
        except subprocess.CalledProcessError:
            self.print_colored("❌ Docker is not running. Please start Docker first.", Colors.RED)
            return False

        # Start services based on what's requested
        if 'redis' in services:
            self.start_redis()

        if 'postgres' in services:
            self.start_postgres()

        if 'full' in services:
            self.start_full_stack()

        return True

    def start_redis(self):
        """Start Redis container"""
        self.print_colored("🔴 Starting Redis...", Colors.RED)

        try:
            # Check if redis container already exists
            result = subprocess.run(
                ['docker', 'ps', '-a', '--filter', 'name=crypto-hunter-redis', '--format', '{{.Names}}'],
                capture_output=True, text=True)

            if 'crypto-hunter-redis' in result.stdout:
                # Container exists, start it
                subprocess.run(['docker', 'start', 'crypto-hunter-redis'], check=True)
            else:
                # Create new container
                subprocess.run([
                    'docker', 'run', '-d',
                    '--name', 'crypto-hunter-redis',
                    '-p', '6379:6379',
                    '--restart', 'unless-stopped',
                    'redis:7-alpine',
                    'redis-server', '--appendonly', 'yes'
                ], check=True)

            self.print_colored("✅ Redis started on port 6379", Colors.GREEN)

        except subprocess.CalledProcessError as e:
            self.print_colored(f"❌ Failed to start Redis: {e}", Colors.RED)

    def start_postgres(self):
        """Start PostgreSQL container"""
        self.print_colored("🐘 Starting PostgreSQL...", Colors.BLUE)

        try:
            # Check if postgres container already exists
            result = subprocess.run(
                ['docker', 'ps', '-a', '--filter', 'name=crypto-hunter-postgres', '--format', '{{.Names}}'],
                capture_output=True, text=True)

            if 'crypto-hunter-postgres' in result.stdout:
                # Container exists, start it
                subprocess.run(['docker', 'start', 'crypto-hunter-postgres'], check=True)
            else:
                # Create new container
                subprocess.run([
                    'docker', 'run', '-d',
                    '--name', 'crypto-hunter-postgres',
                    '-p', '5432:5432',
                    '-e', 'POSTGRES_DB=crypto_hunter_dev',
                    '-e', 'POSTGRES_USER=crypto_hunter',
                    '-e', 'POSTGRES_PASSWORD=dev_password',
                    '--restart', 'unless-stopped',
                    'postgres:15-alpine'
                ], check=True)

                # Wait a moment for postgres to start
                time.sleep(3)

            self.print_colored("✅ PostgreSQL started on port 5432", Colors.GREEN)

        except subprocess.CalledProcessError as e:
            self.print_colored(f"❌ Failed to start PostgreSQL: {e}", Colors.RED)

    def start_full_stack(self):
        """Start full development stack with docker-compose"""
        self.print_colored("🚀 Starting full development stack...", Colors.HEADER)

        try:
            self.run_command(
                ['docker-compose', '-f', 'docker-compose.yml', '-f', 'docker-compose.override.yml', 'up', '-d'])
            self.print_colored("✅ Full stack started", Colors.GREEN)
        except subprocess.CalledProcessError as e:
            self.print_colored(f"❌ Failed to start full stack: {e}", Colors.RED)

    def setup_database(self):
        """Initialize database"""
        self.print_colored("🗄️ Setting up database...", Colors.HEADER)

        # Wait for database to be ready
        self.print_colored("⏳ Waiting for database to be ready...", Colors.YELLOW)
        time.sleep(5)

        try:
            # Initialize database
            self.run_command(['flask', 'db', 'init'])
        except subprocess.CalledProcessError:
            self.print_colored("ℹ️ Database already initialized", Colors.CYAN)

        try:
            # Create migration
            self.run_command(['flask', 'db', 'migrate', '-m', 'Initial migration'])
        except subprocess.CalledProcessError:
            self.print_colored("ℹ️ No new migrations needed", Colors.CYAN)

        # Apply migrations
        self.run_command(['flask', 'db', 'upgrade'])

        self.print_colored("✅ Database setup complete", Colors.GREEN)

    def create_admin_user(self):
        """Create admin user"""
        self.print_colored("👤 Creating admin user...", Colors.HEADER)

        try:
            self.run_command([
                'flask', 'user', 'create',
                '--username', 'admin',
                '--email', 'admin@crypto-hunter.local',
                '--password', 'admin123',
                '--admin'
            ])
            self.print_colored("✅ Admin user created (admin/admin123)", Colors.GREEN)
        except subprocess.CalledProcessError:
            self.print_colored("ℹ️ Admin user already exists", Colors.CYAN)

    def install_forensics_tools(self):
        """Install forensics tools"""
        self.print_colored("🔧 Installing forensics tools...", Colors.HEADER)

        if self.system == 'linux':
            self._install_linux_tools()
        elif self.system == 'darwin':
            self._install_macos_tools()
        else:
            self.print_colored("⚠️ Forensics tools installation not supported on this platform", Colors.YELLOW)
            self.print_colored("Consider using Docker for full forensics support", Colors.YELLOW)

    def _install_linux_tools(self):
        """Install forensics tools on Linux"""
        tools = {
            'binwalk': 'pip3 install binwalk',
            'zsteg': 'gem install zsteg',
            'steghide': 'apt-get install -y steghide',
            'foremost': 'apt-get install -y foremost',
            'exiftool': 'apt-get install -y exiftool',
            'strings': 'apt-get install -y binutils',
            'hexdump': 'apt-get install -y bsdmainutils'
        }

        for tool, install_cmd in tools.items():
            self.print_colored(f"📦 Installing {tool}...", Colors.BLUE)
            try:
                if install_cmd.startswith('apt-get'):
                    subprocess.run(['sudo'] + install_cmd.split(), check=True, capture_output=True)
                else:
                    subprocess.run(install_cmd.split(), check=True, capture_output=True)
                self.print_colored(f"✅ {tool} installed", Colors.GREEN)
            except subprocess.CalledProcessError:
                self.print_colored(f"⚠️ Failed to install {tool}", Colors.YELLOW)

    def _install_macos_tools(self):
        """Install forensics tools on macOS"""
        tools = {
            'binwalk': 'pip3 install binwalk',
            'exiftool': 'brew install exiftool',
            'foremost': 'brew install foremost'
        }

        for tool, install_cmd in tools.items():
            self.print_colored(f"📦 Installing {tool}...", Colors.BLUE)
            try:
                subprocess.run(install_cmd.split(), check=True, capture_output=True)
                self.print_colored(f"✅ {tool} installed", Colors.GREEN)
            except subprocess.CalledProcessError:
                self.print_colored(f"⚠️ Failed to install {tool}", Colors.YELLOW)

    def start_celery_worker(self):
        """Start Celery worker"""
        self.print_colored("👷 Starting Celery worker...", Colors.HEADER)

        cmd = [
            'celery', '-A', 'crypto_hunter_web.services.background_service',
            'worker', '--loglevel=info', '--concurrency=2'
        ]

        process = subprocess.Popen(cmd, cwd=self.root_dir)
        self.processes.append(('celery-worker', process))

        self.print_colored("✅ Celery worker started", Colors.GREEN)

    def start_celery_beat(self):
        """Start Celery beat scheduler"""
        self.print_colored("⏰ Starting Celery beat...", Colors.HEADER)

        cmd = [
            'celery', '-A', 'crypto_hunter_web.services.background_service',
            'beat', '--loglevel=info'
        ]

        process = subprocess.Popen(cmd, cwd=self.root_dir)
        self.processes.append(('celery-beat', process))

        self.print_colored("✅ Celery beat started", Colors.GREEN)

    def start_flask_app(self):
        """Start Flask development server"""
        self.print_colored("🌶️ Starting Flask development server...", Colors.HEADER)

        cmd = ['python', 'run.py']

        process = subprocess.Popen(cmd, cwd=self.root_dir)
        self.processes.append(('flask-app', process))

        self.print_colored("✅ Flask app started on http://localhost:8000", Colors.GREEN)

    def run_tests(self, test_path: str = None, coverage: bool = False):
        """Run tests"""
        self.print_colored("🧪 Running tests...", Colors.HEADER)

        cmd = ['python', '-m', 'pytest']

        if test_path:
            cmd.append(test_path)

        if coverage:
            cmd.extend(['--cov=crypto_hunter_web', '--cov-report=html', '--cov-report=term'])

        cmd.extend(['-v', '--tb=short'])

        try:
            self.run_command(cmd)
            self.print_colored("✅ Tests completed", Colors.GREEN)
        except subprocess.CalledProcessError:
            self.print_colored("❌ Some tests failed", Colors.RED)

    def format_code(self):
        """Format code with black and isort"""
        self.print_colored("🎨 Formatting code...", Colors.HEADER)

        try:
            self.run_command(['black', 'crypto_hunter_web/', '--line-length', '100'])
            self.run_command(['isort', 'crypto_hunter_web/'])
            self.print_colored("✅ Code formatted", Colors.GREEN)
        except subprocess.CalledProcessError:
            self.print_colored("⚠️ Code formatting tools not available", Colors.YELLOW)

    def lint_code(self):
        """Lint code with flake8"""
        self.print_colored("🔍 Linting code...", Colors.HEADER)

        try:
            result = subprocess.run(['flake8', 'crypto_hunter_web/', '--max-line-length=100'],
                                    capture_output=True, text=True)
            if result.returncode == 0:
                self.print_colored("✅ No linting issues found", Colors.GREEN)
            else:
                self.print_colored("⚠️ Linting issues found:", Colors.YELLOW)
                print(result.stdout)
        except subprocess.CalledProcessError:
            self.print_colored("⚠️ Flake8 not available", Colors.YELLOW)

    def build_docker_image(self, tag: str = 'crypto-hunter:latest'):
        """Build Docker image"""
        self.print_colored(f"🐳 Building Docker image: {tag}", Colors.HEADER)

        try:
            self.run_command(['docker', 'build', '-t', tag, '.'])
            self.print_colored(f"✅ Docker image built: {tag}", Colors.GREEN)
        except subprocess.CalledProcessError:
            self.print_colored("❌ Docker build failed", Colors.RED)

    def stop_all_services(self):
        """Stop all running services"""
        self.print_colored("🛑 Stopping services...", Colors.YELLOW)

        # Stop processes started by this script
        for name, process in self.processes:
            try:
                process.terminate()
                process.wait(timeout=10)
                self.print_colored(f"✅ Stopped {name}", Colors.GREEN)
            except subprocess.TimeoutExpired:
                process.kill()
                self.print_colored(f"⚠️ Force killed {name}", Colors.YELLOW)
            except Exception as e:
                self.print_colored(f"❌ Error stopping {name}: {e}", Colors.RED)

        # Stop Docker containers
        containers = ['crypto-hunter-redis', 'crypto-hunter-postgres']
        for container in containers:
            try:
                subprocess.run(['docker', 'stop', container], check=True, capture_output=True)
                self.print_colored(f"✅ Stopped {container}", Colors.GREEN)
            except subprocess.CalledProcessError:
                pass  # Container might not exist

    def show_status(self):
        """Show status of all services"""
        self.print_colored("📊 Service Status", Colors.HEADER)

        # Check Docker containers
        containers = ['crypto-hunter-redis', 'crypto-hunter-postgres']
        for container in containers:
            try:
                result = subprocess.run(['docker', 'ps', '--filter', f'name={container}', '--format', '{{.Status}}'],
                                        capture_output=True, text=True)
                if result.stdout.strip():
                    self.print_colored(f"✅ {container}: {result.stdout.strip()}", Colors.GREEN)
                else:
                    self.print_colored(f"❌ {container}: Not running", Colors.RED)
            except subprocess.CalledProcessError:
                self.print_colored(f"❌ {container}: Error checking status", Colors.RED)

        # Check processes
        for name, process in self.processes:
            if process.poll() is None:
                self.print_colored(f"✅ {name}: Running (PID: {process.pid})", Colors.GREEN)
            else:
                self.print_colored(f"❌ {name}: Stopped", Colors.RED)

        # Check ports
        ports = [('Flask App', 8000), ('Redis', 6379), ('PostgreSQL', 5432)]
        for service, port in ports:
            try:
                import socket
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                result = sock.connect_ex(('localhost', port))
                sock.close()
                if result == 0:
                    self.print_colored(f"✅ {service}: Port {port} open", Colors.GREEN)
                else:
                    self.print_colored(f"❌ {service}: Port {port} closed", Colors.RED)
            except Exception:
                self.print_colored(f"❌ {service}: Cannot check port {port}", Colors.RED)

    def full_setup(self):
        """Run complete development setup"""
        self.print_colored("🚀 Running full development setup...", Colors.HEADER)

        if not self.check_dependencies():
            return

        self.setup_environment()
        self.start_infrastructure(['redis', 'postgres'])
        time.sleep(5)  # Wait for services to be ready
        self.setup_database()
        self.create_admin_user()

        self.print_colored("\n🎉 Development environment ready!", Colors.GREEN)
        self.print_colored("Next steps:", Colors.CYAN)
        self.print_colored("  python dev.py run    - Start all services", Colors.CYAN)
        self.print_colored("  python dev.py test   - Run tests", Colors.CYAN)
        self.print_colored("  python dev.py status - Check service status", Colors.CYAN)

    def run_development_stack(self):
        """Run full development stack"""
        self.print_colored("🚀 Starting development stack...", Colors.HEADER)

        if not self.start_infrastructure(['redis', 'postgres']):
            return

        time.sleep(3)  # Wait for infrastructure

        self.start_celery_worker()
        self.start_celery_beat()
        self.start_flask_app()

        self.print_colored("\n🎉 All services started!", Colors.GREEN)
        self.print_colored("Access your application at: http://localhost:8000", Colors.CYAN)
        self.print_colored("Admin login: admin / admin123", Colors.CYAN)
        self.print_colored("\nPress Ctrl+C to stop all services", Colors.YELLOW)

        # Wait for interrupt
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            pass


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(description='Crypto Hunter Development Tools')
    parser.add_argument('command', nargs='?', default='help',
                        choices=['setup', 'run', 'test', 'format', 'lint', 'build', 'stop', 'status', 'tools', 'help'],
                        help='Command to run')
    parser.add_argument('--coverage', action='store_true', help='Run tests with coverage')
    parser.add_argument('--test-path', help='Specific test path to run')
    parser.add_argument('--tag', default='crypto-hunter:latest', help='Docker image tag')

    args = parser.parse_args()

    dev = DevEnvironment()

    if args.command == 'setup':
        dev.full_setup()
    elif args.command == 'run':
        dev.run_development_stack()
    elif args.command == 'test':
        dev.run_tests(args.test_path, args.coverage)
    elif args.command == 'format':
        dev.format_code()
    elif args.command == 'lint':
        dev.lint_code()
    elif args.command == 'build':
        dev.build_docker_image(args.tag)
    elif args.command == 'stop':
        dev.stop_all_services()
    elif args.command == 'status':
        dev.show_status()
    elif args.command == 'tools':
        dev.install_forensics_tools()
    else:
        print(f"""
{Colors.HEADER}🔍 Crypto Hunter Development Tools{Colors.ENDC}

{Colors.BOLD}Commands:{Colors.ENDC}
  {Colors.GREEN}setup{Colors.ENDC}    - Complete development environment setup
  {Colors.GREEN}run{Colors.ENDC}      - Start all development services
  {Colors.GREEN}test{Colors.ENDC}     - Run test suite
  {Colors.GREEN}format{Colors.ENDC}   - Format code with black and isort
  {Colors.GREEN}lint{Colors.ENDC}     - Lint code with flake8
  {Colors.GREEN}build{Colors.ENDC}    - Build Docker image
  {Colors.GREEN}stop{Colors.ENDC}     - Stop all services
  {Colors.GREEN}status{Colors.ENDC}   - Show service status
  {Colors.GREEN}tools{Colors.ENDC}    - Install forensics tools

{Colors.BOLD}Examples:{Colors.ENDC}
  {Colors.CYAN}python dev.py setup{Colors.ENDC}              - One-time setup
  {Colors.CYAN}python dev.py run{Colors.ENDC}                - Start development
  {Colors.CYAN}python dev.py test --coverage{Colors.ENDC}    - Run tests with coverage
  {Colors.CYAN}python dev.py build --tag my-tag{Colors.ENDC} - Build custom Docker image

{Colors.BOLD}Quick Start:{Colors.ENDC}
  1. {Colors.CYAN}python dev.py setup{Colors.ENDC}    - Setup everything
  2. {Colors.CYAN}python dev.py run{Colors.ENDC}      - Start developing
  3. Open http://localhost:8000
        """)


if __name__ == "__main__":
    main()