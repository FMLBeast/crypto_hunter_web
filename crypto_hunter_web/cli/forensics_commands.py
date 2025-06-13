# crypto_hunter_web/cli/forensics_commands.py
# Forensics tools management commands

import click
import os
import subprocess
from flask.cli import with_appcontext
from crypto_hunter_web.services.extractors.forensics_extractor import ForensicsToolkit


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
        # noinspection PyProtectedMember
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
        'stegseek': ['_install_special_tools'],
        'bulk-extractor': ['sudo', 'apt-get', 'install', '-y', 'bulk-extractor'],
    }

    if tool_name not in installation_commands:
        click.echo(f"❌ Unknown tool: {tool_name}")
        return

    if tool_name == 'stegseek':
        _install_special_tools()
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