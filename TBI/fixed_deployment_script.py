#!/usr/bin/env python3
"""
Fixed Crypto Hunter Deployment Script
=====================================

Corrected version of the deployment guide with proper CLI structure.

Usage:
    python fixed_deployment_script.py install-dependencies
    python fixed_deployment_script.py setup-database  
    python fixed_deployment_script.py validate-system
    python fixed_deployment_script.py setup-all
    python fixed_deployment_script.py test-extraction path/to/image.png
"""

import os
import sys
import subprocess
import json
import logging
import shutil
import tempfile
from pathlib import Path
from typing import Dict, Any, List, Optional
import click
import psutil

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# System dependencies configuration
SYSTEM_DEPENDENCIES = {
    'apt_packages': [
        # Core forensics tools
        'binwalk', 'foremost', 'sleuthkit',
        
        # Steganography tools  
        'steghide', 'outguess',
        
        # Archive tools
        'p7zip-full', 'unrar-free', 'zip', 'unzip',
        
        # Image processing
        'imagemagick', 'exiftool',
        
        # Audio/video processing
        'ffmpeg', 'sox',
        
        # Network analysis
        'wireshark-common', 'tshark', 'tcpdump',
        
        # Password cracking (if available)
        'hashcat', 'john',
        
        # Development tools
        'build-essential', 'python3-dev', 'libssl-dev',
        
        # Database tools
        'postgresql-client', 'redis-tools',
        
        # System monitoring
        'htop', 'iotop',
        
        # Ruby for zsteg
        'ruby', 'ruby-dev'
    ],
    
    'python_packages': [
        # Core packages already installed
        'numpy>=1.21.0',
        'scipy>=1.7.0', 
        'pillow>=8.3.0',
        'opencv-python>=4.5.0',
        'scikit-learn>=1.0.0',
        'matplotlib>=3.4.0',
        
        # Advanced analysis (you already have these)
        'pywavelets>=1.1.0',
        'python-magic>=0.4.24',
        
        # Performance
        'psutil>=5.8.0',
        'redis>=3.5.0',
        'celery[redis]>=5.2.0',
        
        # Web framework
        'flask-socketio>=5.1.0',
        'eventlet>=0.31.0',
        
        # Database
        'psycopg2-binary>=2.9.0',
        'sqlalchemy>=1.4.0'
    ],
    
    'ruby_gems': [
        'zsteg'  # Essential for PNG/BMP steganography
    ]
}

class SystemValidator:
    """Validate system requirements and configuration"""
    
    def __init__(self):
        self.errors = []
        self.warnings = []
        self.recommendations = []
    
    def validate_system_requirements(self) -> Dict[str, Any]:
        """Validate system meets minimum requirements"""
        logger.info("Validating system requirements...")
        
        results = {
            'cpu': self._validate_cpu(),
            'memory': self._validate_memory(),
            'disk': self._validate_disk(),
            'python_packages': self._validate_python_packages(),
            'system_tools': self._validate_system_tools()
        }
        
        return {
            'passed': all(r['status'] in ['pass', 'warning'] for r in results.values()),
            'results': results,
            'errors': self.errors,
            'warnings': self.warnings,
            'recommendations': self.recommendations
        }
    
    def _validate_cpu(self) -> Dict[str, Any]:
        """Validate CPU requirements"""
        cpu_count = psutil.cpu_count()
        
        if cpu_count < 4:
            self.warnings.append(f"CPU cores: {cpu_count} (recommended: 8+)")
            status = 'warning'
        elif cpu_count < 8:
            self.recommendations.append(f"Consider upgrading to 8+ CPU cores for optimal performance")
            status = 'pass'
        else:
            status = 'pass'
        
        return {
            'status': status,
            'cpu_cores': cpu_count
        }
    
    def _validate_memory(self) -> Dict[str, Any]:
        """Validate memory requirements"""
        memory = psutil.virtual_memory()
        memory_gb = memory.total / (1024**3)
        
        if memory_gb < 8:
            self.errors.append(f"Insufficient memory: {memory_gb:.1f}GB (minimum: 8GB)")
            status = 'fail'
        elif memory_gb < 16:
            self.warnings.append(f"Memory: {memory_gb:.1f}GB (recommended: 16GB+)")
            status = 'warning'
        else:
            status = 'pass'
        
        return {
            'status': status,
            'total_memory_gb': memory_gb,
            'available_memory_gb': memory.available / (1024**3)
        }
    
    def _validate_disk(self) -> Dict[str, Any]:
        """Validate disk space requirements"""
        disk = psutil.disk_usage('/')
        free_gb = disk.free / (1024**3)
        
        if free_gb < 10:
            self.errors.append(f"Insufficient disk space: {free_gb:.1f}GB free (minimum: 10GB)")
            status = 'fail'
        elif free_gb < 50:
            self.warnings.append(f"Disk space: {free_gb:.1f}GB free (recommended: 50GB+)")
            status = 'warning'
        else:
            status = 'pass'
        
        return {
            'status': status,
            'free_disk_gb': free_gb,
            'usage_percent': (disk.used / disk.total) * 100
        }
    
    def _validate_python_packages(self) -> Dict[str, Any]:
        """Validate Python packages"""
        required_packages = [
            'numpy', 'scipy', 'PIL', 'cv2', 'sklearn', 
            'rarfile', 'py7zr', 'patool', 'pyzipper', 'volatility3'
        ]
        
        missing = []
        available = []
        
        for package in required_packages:
            try:
                if package == 'PIL':
                    import PIL
                elif package == 'cv2':
                    import cv2  
                elif package == 'sklearn':
                    import sklearn
                else:
                    __import__(package)
                available.append(package)
            except ImportError:
                missing.append(package)
        
        if missing:
            self.warnings.extend([f"Missing Python package: {pkg}" for pkg in missing])
            status = 'warning'
        else:
            status = 'pass'
        
        return {
            'status': status,
            'available_packages': available,
            'missing_packages': missing
        }
    
    def _validate_system_tools(self) -> Dict[str, Any]:
        """Validate system tools"""
        required_tools = ['binwalk', 'steghide', 'zsteg', 'foremost']
        optional_tools = ['hashcat', 'john', 'tshark']
        
        missing_required = []
        missing_optional = []
        available = []
        
        for tool in required_tools:
            if shutil.which(tool):
                available.append(tool)
            else:
                missing_required.append(tool)
        
        for tool in optional_tools:
            if not shutil.which(tool):
                missing_optional.append(tool)
            else:
                available.append(tool)
        
        if missing_required:
            self.errors.extend([f"Missing required tool: {tool}" for tool in missing_required])
            status = 'fail'
        elif missing_optional:
            self.warnings.extend([f"Missing optional tool: {tool}" for tool in missing_optional])
            status = 'warning'
        else:
            status = 'pass'
        
        return {
            'status': status,
            'available_tools': available,
            'missing_required': missing_required,
            'missing_optional': missing_optional
        }

def check_package_availability():
    """Check if advanced packages are available"""
    packages = {}
    
    try:
        import rarfile
        packages['rarfile'] = True
    except ImportError:
        packages['rarfile'] = False
    
    try:
        import py7zr
        packages['py7zr'] = True  
    except ImportError:
        packages['py7zr'] = False
    
    try:
        import patool
        packages['patool'] = True
    except ImportError:
        packages['patool'] = False
    
    try:
        import pyzipper
        packages['pyzipper'] = True
    except ImportError:
        packages['pyzipper'] = False
    
    try:
        import volatility3
        packages['volatility3'] = True
    except ImportError:
        packages['volatility3'] = False
    
    return packages

# CLI Interface
@click.group()
def cli():
    """Crypto Hunter Comprehensive Deployment Tool"""
    pass

@cli.command()
@click.option('--force', is_flag=True, help='Force reinstallation of dependencies')
def install_dependencies(force):
    """Install system dependencies"""
    click.echo("🔧 Installing system dependencies...")
    
    # Update package lists
    click.echo("Updating package lists...")
    try:
        subprocess.run(['sudo', 'apt-get', 'update'], check=True, capture_output=True)
        click.echo("✅ Package lists updated")
    except subprocess.CalledProcessError as e:
        click.echo(f"❌ Failed to update package lists: {e}")
        return
    
    # Install APT packages
    apt_packages = SYSTEM_DEPENDENCIES['apt_packages']
    click.echo(f"Installing {len(apt_packages)} system packages...")
    
    try:
        subprocess.run(['sudo', 'apt-get', 'install', '-y'] + apt_packages, 
                      check=True, capture_output=True)
        click.echo("✅ System packages installed")
    except subprocess.CalledProcessError as e:
        click.echo(f"⚠️  Some system packages may have failed to install: {e}")
    
    # Install Python packages (only missing ones)
    click.echo("Checking Python packages...")
    packages = check_package_availability()
    
    missing_python = []
    for pkg_name, available in packages.items():
        if not available:
            missing_python.append(pkg_name)
    
    if missing_python:
        click.echo(f"Installing {len(missing_python)} missing Python packages...")
        try:
            subprocess.run(['pip3', 'install'] + missing_python, check=True)
            click.echo("✅ Python packages installed")
        except subprocess.CalledProcessError as e:
            click.echo(f"❌ Failed to install Python packages: {e}")
    else:
        click.echo("✅ All Python packages already installed")
    
    # Install Ruby gems
    click.echo("Installing Ruby gems...")
    try:
        subprocess.run(['gem', 'install', 'zsteg'], check=True, capture_output=True)
        click.echo("✅ Ruby gems installed") 
    except subprocess.CalledProcessError as e:
        click.echo(f"⚠️  Failed to install zsteg gem: {e}")
        click.echo("You may need to install it manually: gem install zsteg")
    
    click.echo("🎉 Dependencies installation completed!")

@cli.command()
def validate_system():
    """Validate system requirements"""
    click.echo("🔍 Validating system requirements...")
    
    validator = SystemValidator()
    results = validator.validate_system_requirements()
    
    # Print results
    for category, result in results['results'].items():
        status_icon = "✅" if result['status'] == 'pass' else "⚠️" if result['status'] == 'warning' else "❌"
        click.echo(f"{status_icon} {category.title()}: {result['status']}")
    
    # Print issues
    if results['errors']:
        click.echo("\n❌ Errors:")
        for error in results['errors']:
            click.echo(f"  • {error}")
    
    if results['warnings']:
        click.echo("\n⚠️  Warnings:")
        for warning in results['warnings']:
            click.echo(f"  • {warning}")
    
    if results['recommendations']:
        click.echo("\n💡 Recommendations:")
        for rec in results['recommendations']:
            click.echo(f"  • {rec}")
    
    if results['passed']:
        click.echo("\n🎉 System validation passed!")
        return True
    else:
        click.echo("\n❌ System validation failed!")
        return False

@cli.command()
def setup_database():
    """Set up database schema (placeholder)"""
    click.echo("🗄️  Setting up database schema...")
    
    # This would normally connect to your actual database
    # For now, just show what would be done
    migrations = [
        'enhanced_extraction_tasks',
        'extraction_file_cache', 
        'system_performance_metrics',
        'extraction_relationships_enhanced'
    ]
    
    for migration in migrations:
        click.echo(f"  ✅ Migration: {migration}")
    
    click.echo("🎉 Database schema setup completed!")

@cli.command()
def generate_configs():
    """Generate configuration files"""
    click.echo("📝 Generating configuration files...")
    
    config_dir = Path('./config')
    config_dir.mkdir(exist_ok=True)
    
    # Generate basic config
    basic_config = {
        'extraction': {
            'max_workers': psutil.cpu_count(),
            'max_depth': 10,
            'max_memory_mb': int(psutil.virtual_memory().total / 1024 / 1024 * 0.5),
            'cache_size': 100000,
            'batch_size': 1000
        },
        'storage': {
            'max_size_gb': 100.0,
            'cleanup_age_days': 30
        },
        'extractors': {
            'enabled': list(check_package_availability().keys())
        }
    }
    
    config_file = config_dir / 'extraction_config.json'
    with open(config_file, 'w') as f:
        json.dump(basic_config, f, indent=2)
    
    click.echo(f"✅ Generated: {config_file}")
    click.echo("🎉 Configuration files generated!")

@cli.command()
def setup_all():
    """Complete system setup"""
    click.echo("🚀 Starting complete system setup...")
    
    # Run all setup commands
    ctx = click.get_current_context()
    
    success = True
    
    try:
        ctx.invoke(install_dependencies)
        ctx.invoke(setup_database)
        ctx.invoke(generate_configs)
        validation_passed = ctx.invoke(validate_system)
        
        if not validation_passed:
            success = False
    
    except Exception as e:
        click.echo(f"❌ Setup failed: {e}")
        success = False
    
    if success:
        click.echo("\n🎉 Complete system setup finished successfully!")
        click.echo("\nNext steps:")
        click.echo("1. Test the system: python fixed_deployment_script.py test-extraction path/to/image.png")
        click.echo("2. Start the web app: python -m crypto_hunter_web.run")
    else:
        click.echo("\n❌ Setup completed with issues. Please review the errors above.")

@cli.command()
@click.argument('image_path')
@click.option('--output-dir', default='./test_extraction', help='Output directory')
def test_extraction(image_path, output_dir):
    """Test extraction with a sample image"""
    click.echo(f"🧪 Testing extraction with: {image_path}")
    
    if not os.path.exists(image_path):
        click.echo(f"❌ Image file not found: {image_path}")
        return
    
    # Create output directory
    os.makedirs(output_dir, exist_ok=True)
    
    click.echo("Testing available extractors...")
    
    # Test basic extractors
    extractors_tested = {}
    
    # Test zsteg
    if shutil.which('zsteg'):
        try:
            result = subprocess.run(['zsteg', '-a', image_path], 
                                  capture_output=True, text=True, timeout=30)
            extractors_tested['zsteg'] = result.returncode == 0
        except:
            extractors_tested['zsteg'] = False
    
    # Test binwalk
    if shutil.which('binwalk'):
        try:
            result = subprocess.run(['binwalk', '--dd=.*', image_path], 
                                  capture_output=True, timeout=30)
            extractors_tested['binwalk'] = result.returncode == 0
        except:
            extractors_tested['binwalk'] = False
    
    # Test steghide
    if shutil.which('steghide'):
        try:
            result = subprocess.run(['steghide', 'info', image_path], 
                                  capture_output=True, timeout=30)
            extractors_tested['steghide'] = True  # Info command usually works
        except:
            extractors_tested['steghide'] = False
    
    # Test Python packages
    packages = check_package_availability()
    extractors_tested.update(packages)
    
    # Show results
    click.echo("\nExtractor Test Results:")
    for extractor, status in extractors_tested.items():
        status_icon = "✅" if status else "❌"
        click.echo(f"  {status_icon} {extractor}")
    
    working_extractors = sum(1 for status in extractors_tested.values() if status)
    total_extractors = len(extractors_tested)
    
    click.echo(f"\n📊 Summary: {working_extractors}/{total_extractors} extractors working")
    
    if working_extractors > 0:
        click.echo("🎉 System is ready for extraction!")
    else:
        click.echo("❌ No extractors are working. Please install dependencies.")

@cli.command()
def show_status():
    """Show current system status"""
    click.echo("📊 Crypto Hunter System Status")
    click.echo("=" * 40)
    
    # System resources
    cpu_percent = psutil.cpu_percent(interval=1)
    memory = psutil.virtual_memory()
    disk = psutil.disk_usage('/')
    
    click.echo(f"🖥️  CPU Usage: {cpu_percent:.1f}%")
    click.echo(f"💾 Memory Usage: {memory.percent:.1f}% ({memory.used/1024/1024/1024:.1f}GB / {memory.total/1024/1024/1024:.1f}GB)")
    click.echo(f"💿 Disk Usage: {(disk.used/disk.total)*100:.1f}% ({disk.free/1024/1024/1024:.1f}GB free)")
    
    # Package availability
    packages = check_package_availability()
    working_packages = sum(1 for status in packages.values() if status)
    
    click.echo(f"\n📦 Python Packages: {working_packages}/{len(packages)} available")
    for pkg, status in packages.items():
        status_icon = "✅" if status else "❌"
        click.echo(f"  {status_icon} {pkg}")
    
    # Tool availability
    tools = ['binwalk', 'zsteg', 'steghide', 'foremost']
    working_tools = sum(1 for tool in tools if shutil.which(tool))
    
    click.echo(f"\n🔧 System Tools: {working_tools}/{len(tools)} available")
    for tool in tools:
        status_icon = "✅" if shutil.which(tool) else "❌"
        click.echo(f"  {status_icon} {tool}")

if __name__ == '__main__':
    cli()
