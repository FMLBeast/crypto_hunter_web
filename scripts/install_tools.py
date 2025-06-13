#!/usr/bin/env python3
"""
Script to install required tools for crypto_hunter extraction
"""

import os
import sys
import subprocess
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def run_command(command, check=True):
    """Run a shell command and log output"""
    logger.info(f"Running: {' '.join(command)}")
    try:
        result = subprocess.run(command, check=check, capture_output=True, text=True)
        if result.stdout:
            logger.info(result.stdout)
        if result.stderr:
            logger.warning(result.stderr)
        return result.returncode == 0
    except subprocess.CalledProcessError as e:
        logger.error(f"Command failed: {e}")
        if e.stdout:
            logger.info(e.stdout)
        if e.stderr:
            logger.error(e.stderr)
        return False
    except Exception as e:
        logger.error(f"Error running command: {e}")
        return False

def check_tool_installed(tool_name):
    """Check if a tool is installed and available in PATH"""
    try:
        result = subprocess.run(['which', tool_name], capture_output=True, text=True)
        return result.returncode == 0
    except:
        return False

def install_apt_package(package_name):
    """Install a package using apt-get"""
    logger.info(f"Installing {package_name} using apt-get...")
    return run_command(['apt-get', 'update']) and run_command(['apt-get', 'install', '-y', package_name])

def install_pip_package(package_name):
    """Install a package using pip"""
    logger.info(f"Installing {package_name} using pip...")
    return run_command([sys.executable, '-m', 'pip', 'install', package_name])

def install_gem_package(package_name):
    """Install a package using gem"""
    logger.info(f"Installing {package_name} using gem...")
    return run_command(['gem', 'install', package_name])

def install_steghide():
    """Install steghide"""
    if check_tool_installed('steghide'):
        logger.info("steghide is already installed")
        return True
    
    return install_apt_package('steghide')

def install_foremost():
    """Install foremost"""
    if check_tool_installed('foremost'):
        logger.info("foremost is already installed")
        return True
    
    return install_apt_package('foremost')

def install_zsteg():
    """Install zsteg"""
    if check_tool_installed('zsteg'):
        logger.info("zsteg is already installed")
        return True
    
    # Install Ruby if needed
    if not check_tool_installed('ruby'):
        install_apt_package('ruby')
        install_apt_package('ruby-dev')
    
    return install_gem_package('zsteg')

def install_binwalk():
    """Install binwalk"""
    if check_tool_installed('binwalk'):
        logger.info("binwalk is already installed")
        return True
    
    # Try pip first
    if install_pip_package('binwalk'):
        return True
    
    # If pip fails, try apt
    return install_apt_package('binwalk')

def install_exiftool():
    """Install exiftool"""
    if check_tool_installed('exiftool'):
        logger.info("exiftool is already installed")
        return True
    
    return install_apt_package('libimage-exiftool-perl')

def main():
    """Install all required tools"""
    logger.info("Starting installation of required tools for crypto_hunter extraction")
    
    # Check if running as root
    if os.geteuid() != 0:
        logger.error("This script must be run as root to install system packages")
        logger.info("Please run with: sudo python3 install_tools.py")
        return False
    
    # Install tools
    tools = {
        'steghide': install_steghide,
        'foremost': install_foremost,
        'zsteg': install_zsteg,
        'binwalk': install_binwalk,
        'exiftool': install_exiftool
    }
    
    success = True
    for tool_name, install_func in tools.items():
        logger.info(f"Checking/installing {tool_name}...")
        if not install_func():
            logger.error(f"Failed to install {tool_name}")
            success = False
    
    if success:
        logger.info("All tools installed successfully!")
    else:
        logger.warning("Some tools failed to install. Check the log for details.")
    
    return success

if __name__ == "__main__":
    sys.exit(0 if main() else 1)