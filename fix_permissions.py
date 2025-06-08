# fix_permissions.py - FIX DIRECTORY PERMISSIONS AND SETUP

"""
Fix permissions and create necessary directories for Crypto Hunter
Run this script to resolve permission issues
"""

import os
import stat
import subprocess
from pathlib import Path


def create_directories():
    """Create all necessary directories with proper permissions"""
    directories = [
        'logs',
        'uploads',
        'instance',
        'temp',
        'backups',
        '.pytest_cache'
    ]

    print("📁 Creating directories...")

    for directory in directories:
        dir_path = Path(directory)
        try:
            dir_path.mkdir(exist_ok=True, parents=True)

            # Set proper permissions (readable/writable by owner, readable by group)
            os.chmod(dir_path, stat.S_IRWXU | stat.S_IRGRP | stat.S_IXGRP)

            print(f"✅ Created/fixed {directory}")

            # Create a test file to verify write permissions
            test_file = dir_path / '.test_write'
            try:
                test_file.write_text('test')
                test_file.unlink()  # Clean up
                print(f"   ✅ Write permissions OK")
            except PermissionError:
                print(f"   ❌ Write permissions FAILED")
                return False

        except PermissionError as e:
            print(f"❌ Failed to create {directory}: {e}")
            return False
        except Exception as e:
            print(f"❌ Unexpected error with {directory}: {e}")
            return False

    return True


def fix_log_file_permissions():
    """Fix specific log file permissions"""
    log_files = [
        'logs/crypto_hunter.log',
        'logs/development.log',
        'logs/celery.log'
    ]

    print("\n📝 Fixing log file permissions...")

    for log_file_str in log_files:
        log_file = Path(log_file_str)

        # Create parent directory if it doesn't exist
        log_file.parent.mkdir(exist_ok=True, parents=True)

        # Create empty log file if it doesn't exist
        if not log_file.exists():
            try:
                log_file.touch()
                print(f"✅ Created {log_file}")
            except PermissionError as e:
                print(f"❌ Cannot create {log_file}: {e}")
                return False

        # Set proper permissions
        try:
            os.chmod(log_file, stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP)
            print(f"✅ Fixed permissions for {log_file}")
        except PermissionError as e:
            print(f"❌ Cannot fix permissions for {log_file}: {e}")
            return False

    return True


def check_current_permissions():
    """Check current directory permissions"""
    print("\n🔍 Checking current permissions...")

    current_dir = Path('.')

    try:
        # Check if we can read the current directory
        list(current_dir.iterdir())
        print("✅ Can read current directory")

        # Check if we can write to current directory
        test_file = current_dir / '.test_write_permission'
        test_file.write_text('test')
        test_file.unlink()
        print("✅ Can write to current directory")

        return True

    except PermissionError as e:
        print(f"❌ Permission issue with current directory: {e}")
        return False


def fix_ownership():
    """Fix ownership of project files (if running as root or with sudo)"""
    if os.geteuid() == 0:  # Running as root
        print("\n⚠️  Running as root - fixing ownership...")

        # Get the original user from SUDO_USER environment variable
        original_user = os.environ.get('SUDO_USER')
        if original_user:
            try:
                import pwd
                user_info = pwd.getpwnam(original_user)
                uid = user_info.pw_uid
                gid = user_info.pw_gid

                # Fix ownership of key directories
                for directory in ['logs', 'uploads', 'instance', 'temp']:
                    if Path(directory).exists():
                        os.chown(directory, uid, gid)
                        # Fix ownership of all files in directory
                        for root, dirs, files in os.walk(directory):
                            for d in dirs:
                                os.chown(os.path.join(root, d), uid, gid)
                            for f in files:
                                os.chown(os.path.join(root, f), uid, gid)

                print(f"✅ Fixed ownership to user: {original_user}")
                return True

            except Exception as e:
                print(f"❌ Failed to fix ownership: {e}")
                return False

    return True


def suggest_permission_fixes():
    """Suggest manual permission fixes if automated fixes fail"""
    print("\n💡 Manual permission fix suggestions:")
    print("   sudo chown -R $USER:$USER .")
    print("   chmod -R 755 .")
    print("   chmod -R 766 logs/ uploads/ instance/ temp/")
    print("   mkdir -p logs uploads instance temp")
    print("   touch logs/crypto_hunter.log")
    print("   chmod 664 logs/*.log")


def main():
    """Main permission fixing function"""
    print("🔧 Crypto Hunter Permission Fixer")
    print("=" * 35)

    success = True

    # Step 1: Check current permissions
    if not check_current_permissions():
        print("❌ Basic permission issues detected")
        suggest_permission_fixes()
        return False

    # Step 2: Create directories
    if not create_directories():
        print("❌ Failed to create directories")
        success = False

    # Step 3: Fix log files
    if not fix_log_file_permissions():
        print("❌ Failed to fix log file permissions")
        success = False

    # Step 4: Fix ownership if needed
    if not fix_ownership():
        print("❌ Failed to fix ownership")
        success = False

    if success:
        print("\n🎉 All permissions fixed successfully!")
        print("   You can now run: python test_integration.py")
    else:
        print("\n❌ Some permission issues remain")
        suggest_permission_fixes()

    return success


if __name__ == "__main__":
    success = main()
    exit(0 if success else 1)