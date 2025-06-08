#!/usr/bin/env python3
"""
scripts/setup_forensics_tools.py
Automated installation and setup of best-in-class forensics tools
"""

import os
import sys
import subprocess
import platform
import shutil
import urllib.request
import tempfile
import json
from pathlib import Path
from typing import Dict, List, Optional

class ForensicsToolsInstaller:
    """Automated installer for forensics and analysis tools"""
    
    def __init__(self):
        self.system = platform.system().lower()
        self.arch = platform.machine().lower()
        self.distro = self._detect_linux_distro()
        self.tools_dir = Path("/opt/forensics-tools")
        self.wordlists_dir = Path("/opt/wordlists")
        self.installation_log = []
        
    def _detect_linux_distro(self):
        """Detect Linux distribution"""
        try:
            with open('/etc/os-release', 'r') as f:
                for line in f:
                    if line.startswith('ID='):
                        return line.split('=')[1].strip().strip('"')
        except:
            return 'unknown'
        return 'unknown'
    
    def install_all_tools(self):
        """Install all forensics tools"""
        print("🔧 Starting forensics tools installation...")
        print(f"System: {self.system} ({self.arch})")
        print(f"Distribution: {self.distro}")
        
        # Create directories
        self._create_directories()
        
        # Install by category
        self.install_steganography_tools()
        self.install_binary_analysis_tools()
        self.install_reverse_engineering_tools()
        self.install_vm_emulation_tools()
        self.install_audio_video_tools()
        self.install_network_tools()
        self.install_cryptographic_tools()
        self.install_wordlists()
        
        # Generate report
        self._generate_installation_report()
        
    def _create_directories(self):
        """Create necessary directories"""
        directories = [
            self.tools_dir,
            self.wordlists_dir,
            Path("/opt/stegsolve"),
            Path("/usr/local/bin"),
            Path("/opt/ghidra"),
            Path("/opt/ida"),
            Path("/opt/vm-tools")
        ]
        
        for directory in directories:
            try:
                directory.mkdir(parents=True, exist_ok=True)
                print(f"📁 Created directory: {directory}")
            except PermissionError:
                print(f"⚠️  Permission denied creating {directory} - run as root")
    
    def install_steganography_tools(self):
        """Install steganography analysis tools"""
        print("\n🔍 Installing Steganography Tools...")
        
        tools = {
            'zsteg': {
                'type': 'gem',
                'command': ['gem', 'install', 'zsteg'],
                'verify': ['zsteg', '--version']
            },
            'steghide': {
                'type': 'package',
                'ubuntu': ['apt', 'install', '-y', 'steghide'],
                'centos': ['yum', 'install', '-y', 'steghide'],
                'arch': ['pacman', '-S', '--noconfirm', 'steghide'],
                'verify': ['steghide', '--version']
            },
            'stegseek': {
                'type': 'github',
                'url': 'https://github.com/RickdeJager/stegseek/releases/latest/download/stegseek_1.6_amd64.deb',
                'install_method': 'deb',
                'verify': ['stegseek', '--version']
            },
            'outguess': {
                'type': 'package',
                'ubuntu': ['apt', 'install', '-y', 'outguess'],
                'centos': ['yum', 'install', '-y', 'outguess'],
                'verify': ['outguess', '-h']
            },
            'stegsolve': {
                'type': 'jar',
                'url': 'http://www.caesum.com/handbook/Stegsolve.jar',
                'target': '/opt/stegsolve/stegsolve.jar',
                'verify': ['java', '-jar', '/opt/stegsolve/stegsolve.jar', '--help']
            },
            'jphide': {
                'type': 'source',
                'url': 'https://linux01.gwdg.de/~alatham/stego/jphide/jphide-0.5.tar.gz',
                'verify': ['jphide', '--version']
            }
        }
        
        self._install_tools_category(tools, "Steganography")
    
    def install_binary_analysis_tools(self):
        """Install binary analysis and file carving tools"""
        print("\n🔧 Installing Binary Analysis Tools...")
        
        tools = {
            'binwalk': {
                'type': 'pip',
                'command': ['pip3', 'install', 'binwalk'],
                'verify': ['binwalk', '--version']
            },
            'foremost': {
                'type': 'package',
                'ubuntu': ['apt', 'install', '-y', 'foremost'],
                'centos': ['yum', 'install', '-y', 'foremost'],
                'verify': ['foremost', '-V']
            },
            'scalpel': {
                'type': 'package',
                'ubuntu': ['apt', 'install', '-y', 'scalpel'],
                'centos': ['yum', 'install', '-y', 'scalpel'],
                'verify': ['scalpel', '-V']
            },
            'bulk_extractor': {
                'type': 'package',
                'ubuntu': ['apt', 'install', '-y', 'bulk-extractor'],
                'centos': ['yum', 'install', '-y', 'bulk-extractor'],
                'verify': ['bulk_extractor', '-V']
            },
            'photorec': {
                'type': 'package',
                'ubuntu': ['apt', 'install', '-y', 'testdisk'],
                'centos': ['yum', 'install', '-y', 'testdisk'],
                'verify': ['photorec', '/version']
            },
            'exiftool': {
                'type': 'package',
                'ubuntu': ['apt', 'install', '-y', 'exiftool'],
                'centos': ['yum', 'install', '-y', 'perl-Image-ExifTool'],
                'verify': ['exiftool', '-ver']
            }
        }
        
        self._install_tools_category(tools, "Binary Analysis")
    
    def install_reverse_engineering_tools(self):
        """Install reverse engineering tools"""
        print("\n⚙️ Installing Reverse Engineering Tools...")
        
        tools = {
            'radare2': {
                'type': 'script',
                'url': 'https://github.com/radareorg/radare2/releases/latest/download/radare2_5.8.8_amd64.deb',
                'install_method': 'deb',
                'verify': ['radare2', '-version']
            },
            'ghidra': {
                'type': 'ghidra_install',
                'verify': ['ghidra', '--version']
            },
            'objdump': {
                'type': 'package',
                'ubuntu': ['apt', 'install', '-y', 'binutils'],
                'centos': ['yum', 'install', '-y', 'binutils'],
                'verify': ['objdump', '--version']
            },
            'readelf': {
                'type': 'package',
                'ubuntu': ['apt', 'install', '-y', 'binutils'],
                'centos': ['yum', 'install', '-y', 'binutils'],
                'verify': ['readelf', '--version']
            },
            'nm': {
                'type': 'package',
                'ubuntu': ['apt', 'install', '-y', 'binutils'],
                'centos': ['yum', 'install', '-y', 'binutils'],
                'verify': ['nm', '--version']
            }
        }
        
        self._install_tools_category(tools, "Reverse Engineering")
    
    def install_vm_emulation_tools(self):
        """Install VM and emulation tools"""
        print("\n🖥️ Installing VM & Emulation Tools...")
        
        tools = {
            'qemu': {
                'type': 'package',
                'ubuntu': ['apt', 'install', '-y', 'qemu-system', 'qemu-utils'],
                'centos': ['yum', 'install', '-y', 'qemu-kvm', 'qemu-img'],
                'verify': ['qemu-system-x86_64', '--version']
            },
            'unicorn': {
                'type': 'pip',
                'command': ['pip3', 'install', 'unicorn'],
                'verify': ['python3', '-c', 'import unicorn; print("Unicorn installed")']
            },
            'keystone': {
                'type': 'pip',
                'command': ['pip3', 'install', 'keystone-engine'],
                'verify': ['python3', '-c', 'import keystone; print("Keystone installed")']
            },
            'capstone': {
                'type': 'pip',
                'command': ['pip3', 'install', 'capstone'],
                'verify': ['python3', '-c', 'import capstone; print("Capstone installed")']
            }
        }
        
        self._install_tools_category(tools, "VM & Emulation")
    
    def install_audio_video_tools(self):
        """Install audio/video steganography tools"""
        print("\n🎵 Installing Audio/Video Tools...")
        
        tools = {
            'sox': {
                'type': 'package',
                'ubuntu': ['apt', 'install', '-y', 'sox'],
                'centos': ['yum', 'install', '-y', 'sox'],
                'verify': ['sox', '--version']
            },
            'ffmpeg': {
                'type': 'package',
                'ubuntu': ['apt', 'install', '-y', 'ffmpeg'],
                'centos': ['yum', 'install', '-y', 'ffmpeg'],
                'verify': ['ffmpeg', '-version']
            },
            'audacity': {
                'type': 'package',
                'ubuntu': ['apt', 'install', '-y', 'audacity'],
                'centos': ['yum', 'install', '-y', 'audacity'],
                'verify': ['audacity', '--version']
            },
            'sonic-visualiser': {
                'type': 'package',
                'ubuntu': ['apt', 'install', '-y', 'sonic-visualiser'],
                'verify': ['sonic-visualiser', '--version']
            }
        }
        
        self._install_tools_category(tools, "Audio/Video")
    
    def install_network_tools(self):
        """Install network analysis tools"""
        print("\n🌐 Installing Network Analysis Tools...")
        
        tools = {
            'wireshark': {
                'type': 'package',
                'ubuntu': ['apt', 'install', '-y', 'wireshark-common', 'tshark'],
                'centos': ['yum', 'install', '-y', 'wireshark'],
                'verify': ['tshark', '--version']
            },
            'tcpdump': {
                'type': 'package',
                'ubuntu': ['apt', 'install', '-y', 'tcpdump'],
                'centos': ['yum', 'install', '-y', 'tcpdump'],
                'verify': ['tcpdump', '--version']
            },
            'nmap': {
                'type': 'package',
                'ubuntu': ['apt', 'install', '-y', 'nmap'],
                'centos': ['yum', 'install', '-y', 'nmap'],
                'verify': ['nmap', '--version']
            }
        }
        
        self._install_tools_category(tools, "Network Analysis")
    
    def install_cryptographic_tools(self):
        """Install cryptographic analysis tools"""
        print("\n🔐 Installing Cryptographic Tools...")
        
        tools = {
            'openssl': {
                'type': 'package',
                'ubuntu': ['apt', 'install', '-y', 'openssl'],
                'centos': ['yum', 'install', '-y', 'openssl'],
                'verify': ['openssl', 'version']
            },
            'hashcat': {
                'type': 'package',
                'ubuntu': ['apt', 'install', '-y', 'hashcat'],
                'centos': ['yum', 'install', '-y', 'hashcat'],
                'verify': ['hashcat', '--version']
            },
            'john': {
                'type': 'package',
                'ubuntu': ['apt', 'install', '-y', 'john'],
                'centos': ['yum', 'install', '-y', 'john'],
                'verify': ['john', '--version']
            },
            'gpg': {
                'type': 'package',
                'ubuntu': ['apt', 'install', '-y', 'gnupg'],
                'centos': ['yum', 'install', '-y', 'gnupg2'],
                'verify': ['gpg', '--version']
            }
        }
        
        self._install_tools_category(tools, "Cryptographic")
    
    def install_wordlists(self):
        """Install common wordlists for cracking"""
        print("\n📋 Installing Wordlists...")
        
        wordlists = {
            'rockyou': {
                'url': 'https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt',
                'target': self.wordlists_dir / 'rockyou.txt'
            },
            'common': {
                'url': 'https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/10-million-password-list-top-1000000.txt',
                'target': self.wordlists_dir / 'common.txt'
            },
            'steganography': {
                'url': 'https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/top-20-common-SSH-passwords.txt',
                'target': self.wordlists_dir / 'steganography.txt'
            }
        }
        
        for name, config in wordlists.items():
            try:
                print(f"📥 Downloading {name} wordlist...")
                urllib.request.urlretrieve(config['url'], config['target'])
                print(f"✅ {name} wordlist installed")
                self.installation_log.append(f"✅ {name} wordlist: Success")
            except Exception as e:
                print(f"❌ Failed to install {name} wordlist: {e}")
                self.installation_log.append(f"❌ {name} wordlist: {e}")
    
    def _install_tools_category(self, tools: Dict, category: str):
        """Install a category of tools"""
        for tool_name, config in tools.items():
            success = self._install_single_tool(tool_name, config)
            status = "✅ Success" if success else "❌ Failed"
            self.installation_log.append(f"{status} {category} - {tool_name}")
    
    def _install_single_tool(self, tool_name: str, config: Dict) -> bool:
        """Install a single tool"""
        print(f"  📦 Installing {tool_name}...")
        
        try:
            install_type = config.get('type')
            
            if install_type == 'package':
                return self._install_package(tool_name, config)
            elif install_type == 'pip':
                return self._install_pip_package(config)
            elif install_type == 'gem':
                return self._install_gem_package(config)
            elif install_type == 'github':
                return self._install_github_release(config)
            elif install_type == 'jar':
                return self._install_jar_file(config)
            elif install_type == 'source':
                return self._install_from_source(config)
            elif install_type == 'ghidra_install':
                return self._install_ghidra()
            elif install_type == 'script':
                return self._install_with_script(config)
            else:
                print(f"    ⚠️  Unknown install type: {install_type}")
                return False
                
        except Exception as e:
            print(f"    ❌ Installation failed: {e}")
            return False
    
    def _install_package(self, tool_name: str, config: Dict) -> bool:
        """Install using system package manager"""
        if self.system == 'linux':
            if self.distro in ['ubuntu', 'debian'] and 'ubuntu' in config:
                cmd = config['ubuntu']
            elif self.distro in ['centos', 'rhel', 'fedora'] and 'centos' in config:
                cmd = config['centos']
            elif self.distro == 'arch' and 'arch' in config:
                cmd = config['arch']
            else:
                print(f"    ⚠️  No package definition for {self.distro}")
                return False
            
            result = subprocess.run(cmd, capture_output=True)
            success = result.returncode == 0
            
            if success:
                # Verify installation
                if 'verify' in config:
                    verify_result = subprocess.run(config['verify'], capture_output=True)
                    success = verify_result.returncode == 0
                    
            return success
        
        return False
    
    def _install_pip_package(self, config: Dict) -> bool:
        """Install Python package via pip"""
        cmd = config.get('command', ['pip3', 'install', config.get('package')])
        result = subprocess.run(cmd, capture_output=True)
        
        if result.returncode == 0 and 'verify' in config:
            verify_result = subprocess.run(config['verify'], capture_output=True)
            return verify_result.returncode == 0
            
        return result.returncode == 0
    
    def _install_gem_package(self, config: Dict) -> bool:
        """Install Ruby gem"""
        cmd = config.get('command')
        result = subprocess.run(cmd, capture_output=True)
        return result.returncode == 0
    
    def _install_github_release(self, config: Dict) -> bool:
        """Install from GitHub release"""
        url = config.get('url')
        method = config.get('install_method')
        
        with tempfile.NamedTemporaryFile(suffix=f'.{method}') as tmp:
            urllib.request.urlretrieve(url, tmp.name)
            
            if method == 'deb':
                cmd = ['dpkg', '-i', tmp.name]
            elif method == 'rpm':
                cmd = ['rpm', '-i', tmp.name]
            else:
                return False
                
            result = subprocess.run(cmd, capture_output=True)
            return result.returncode == 0
    
    def _install_jar_file(self, config: Dict) -> bool:
        """Install JAR file"""
        url = config.get('url')
        target = Path(config.get('target'))
        
        target.parent.mkdir(parents=True, exist_ok=True)
        urllib.request.urlretrieve(url, target)
        
        return target.exists()
    
    def _install_from_source(self, config: Dict) -> bool:
        """Install from source code"""
        # This would require more complex logic for each tool
        print(f"    ⚠️  Source installation not implemented")
        return False
    
    def _install_ghidra(self) -> bool:
        """Install Ghidra reverse engineering tool"""
        # Download and install Ghidra
        ghidra_url = "https://github.com/NationalSecurityAgency/ghidra/releases/latest/download/ghidra_10.4_PUBLIC_20230928.zip"
        
        try:
            with tempfile.NamedTemporaryFile(suffix='.zip') as tmp:
                urllib.request.urlretrieve(ghidra_url, tmp.name)
                
                # Extract to /opt/ghidra
                import zipfile
                with zipfile.ZipFile(tmp.name, 'r') as zip_ref:
                    zip_ref.extractall('/opt/')
                    
                # Create symlink
                ghidra_dir = Path('/opt/ghidra_10.4_PUBLIC')
                if ghidra_dir.exists():
                    symlink = Path('/usr/local/bin/ghidra')
                    symlink.symlink_to(ghidra_dir / 'ghidraRun')
                    return True
                    
        except Exception as e:
            print(f"    ❌ Ghidra installation failed: {e}")
            
        return False
    
    def _install_with_script(self, config: Dict) -> bool:
        """Install using custom script"""
        # Implementation for script-based installations
        return self._install_github_release(config)
    
    def verify_installations(self) -> Dict[str, bool]:
        """Verify all tool installations"""
        print("\n🔍 Verifying tool installations...")
        
        tools_to_verify = [
            ('binwalk', ['binwalk', '--version']),
            ('zsteg', ['zsteg', '--version']),
            ('steghide', ['steghide', '--version']),
            ('stegseek', ['stegseek', '--version']),
            ('foremost', ['foremost', '-V']),
            ('strings', ['strings', '--version']),
            ('exiftool', ['exiftool', '-ver']),
            ('radare2', ['radare2', '-version']),
            ('sox', ['sox', '--version']),
            ('ffmpeg', ['ffmpeg', '-version']),
            ('wireshark', ['tshark', '--version']),
            ('hashcat', ['hashcat', '--version']),
            ('john', ['john', '--version'])
        ]
        
        verification_results = {}
        
        for tool_name, verify_cmd in tools_to_verify:
            try:
                result = subprocess.run(verify_cmd, capture_output=True, timeout=10)
                success = result.returncode == 0
                verification_results[tool_name] = success
                status = "✅" if success else "❌"
                print(f"  {status} {tool_name}")
            except Exception:
                verification_results[tool_name] = False
                print(f"  ❌ {tool_name}")
        
        return verification_results
    
    def _generate_installation_report(self):
        """Generate installation report"""
        print("\n📊 Installation Report")
        print("=" * 50)
        
        for log_entry in self.installation_log:
            print(log_entry)
        
        # Verify installations
        verification_results = self.verify_installations()
        
        # Summary
        total_tools = len(verification_results)
        successful_tools = sum(verification_results.values())
        
        print(f"\n📈 Summary: {successful_tools}/{total_tools} tools installed successfully")
        print(f"Success rate: {successful_tools/total_tools*100:.1f}%")
        
        # Save detailed report
        report_file = Path("/opt/forensics-installation-report.json")
        report_data = {
            'installation_log': self.installation_log,
            'verification_results': verification_results,
            'system_info': {
                'system': self.system,
                'arch': self.arch,
                'distro': self.distro
            },
            'summary': {
                'total_tools': total_tools,
                'successful_tools': successful_tools,
                'success_rate': successful_tools/total_tools*100
            }
        }
        
        with open(report_file, 'w') as f:
            json.dump(report_data, f, indent=2)
        
        print(f"📄 Detailed report saved to: {report_file}")
    
    def create_docker_setup(self):
        """Create Docker setup for forensics tools"""
        dockerfile_content = '''
FROM ubuntu:22.04

# Install system dependencies
RUN apt-get update && apt-get install -y \\
    python3 python3-pip ruby gem \\
    binutils build-essential \\
    wget curl git unzip \\
    openjdk-11-jdk \\
    && rm -rf /var/lib/apt/lists/*

# Install forensics tools
COPY scripts/setup_forensics_tools.py /tmp/
RUN python3 /tmp/setup_forensics_tools.py

# Set up working directory
WORKDIR /forensics
VOLUME ["/forensics/data"]

CMD ["/bin/bash"]
'''
        
        with open('Dockerfile.forensics', 'w') as f:
            f.write(dockerfile_content)
        
        print("🐳 Created Dockerfile.forensics for containerized forensics environment")


def main():
    """Main installation function"""
    if os.geteuid() != 0:
        print("⚠️  Warning: Running without root privileges. Some tools may not install correctly.")
        print("Consider running with sudo for complete installation.")
    
    installer = ForensicsToolsInstaller()
    
    print("🚀 Crypto Hunter Forensics Tools Installer")
    print("=" * 50)
    
    try:
        installer.install_all_tools()
        installer.create_docker_setup()
        print("\n🎉 Installation complete!")
        print("Use the advanced forensics toolkit in your Crypto Hunter application.")
        
    except KeyboardInterrupt:
        print("\n🛑 Installation cancelled by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Installation failed: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
