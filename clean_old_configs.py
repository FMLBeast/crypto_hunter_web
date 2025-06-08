# cleanup_old_configs.py - REMOVE CONFLICTING FILES

"""
Cleanup script to remove old conflicting Celery configurations
Run this after implementing the unified configuration
"""

import os
import shutil
from pathlib import Path


def backup_file(file_path):
    """Create backup of file before deletion"""
    if file_path.exists():
        backup_path = file_path.with_suffix(file_path.suffix + '.backup')
        shutil.copy2(file_path, backup_path)
        print(f"📁 Backed up {file_path} to {backup_path}")
        return True
    return False


def remove_conflicting_configs():
    """Remove old conflicting Celery configurations"""
    print("🧹 Cleaning up old Celery configurations...")

    # Files to remove (they conflict with unified config)
    files_to_remove = [
        'crypto_hunter_web/services/celery_config.py',  # Old separate config
        # Note: We keep background_service.py but it's been rewritten
    ]

    # Directories to check for old configs
    directories_to_check = [
        'crypto_hunter_web/services/',
        'crypto_hunter_web/',
    ]

    removed_count = 0

    for file_path_str in files_to_remove:
        file_path = Path(file_path_str)
        if file_path.exists():
            # Create backup first
            backup_file(file_path)

            # Remove the file
            file_path.unlink()
            print(f"🗑️  Removed {file_path}")
            removed_count += 1
        else:
            print(f"ℹ️  {file_path} already removed or doesn't exist")

    # Check for other potential conflicts
    potential_conflicts = []
    for dir_path_str in directories_to_check:
        dir_path = Path(dir_path_str)
        if dir_path.exists():
            for file_path in dir_path.glob('*celery*'):
                if file_path.name not in ['celery_app.py']:  # Keep our new unified file
                    potential_conflicts.append(file_path)

    if potential_conflicts:
        print(f"\n⚠️  Found {len(potential_conflicts)} potential conflicts:")
        for conflict in potential_conflicts:
            print(f"   • {conflict}")
        print("   Review these files manually to ensure they don't conflict")

    return removed_count


def check_unified_config():
    """Check that unified configuration is in place"""
    print("\n🔍 Checking unified configuration...")

    required_files = [
        'crypto_hunter_web/celery_app.py',
        'celery_worker_entrypoint.py',
        'crypto_hunter_web/services/background_service.py',
    ]

    all_present = True
    for file_path_str in required_files:
        file_path = Path(file_path_str)
        if file_path.exists():
            print(f"✅ {file_path}")
        else:
            print(f"❌ {file_path} - MISSING")
            all_present = False

    return all_present


def update_imports():
    """Check for files that might still import old configurations"""
    print("\n🔍 Checking for import updates needed...")

    files_to_check = [
        'crypto_hunter_web/__init__.py',
        'crypto_hunter_web/services/__init__.py',
        'run_local.py',
    ]

    imports_to_find = [
        'from .celery_config import',
        'from crypto_hunter_web.services.celery_config import',
        'celery_config.celery_app',
    ]

    files_needing_update = []

    for file_path_str in files_to_check:
        file_path = Path(file_path_str)
        if file_path.exists():
            content = file_path.read_text()
            for import_pattern in imports_to_find:
                if import_pattern in content:
                    files_needing_update.append((file_path, import_pattern))

    if files_needing_update:
        print("⚠️  Files with old imports found:")
        for file_path, pattern in files_needing_update:
            print(f"   • {file_path}: contains '{pattern}'")
        print("   These should be updated to use 'crypto_hunter_web.celery_app'")
    else:
        print("✅ No old imports found")

    return len(files_needing_update) == 0


def main():
    """Main cleanup function"""
    print("🧹 Crypto Hunter Configuration Cleanup")
    print("=" * 40)

    # Step 1: Remove conflicting files
    removed_count = remove_conflicting_configs()

    # Step 2: Check unified configuration
    config_ok = check_unified_config()

    # Step 3: Check for import updates
    imports_ok = update_imports()

    # Summary
    print(f"\n📊 Cleanup Summary:")
    print(f"   • Removed {removed_count} conflicting files")
    print(f"   • Unified config present: {'✅' if config_ok else '❌'}")
    print(f"   • Import updates needed: {'❌' if not imports_ok else '✅'}")

    if config_ok and imports_ok:
        print("\n🎉 Cleanup complete! Your project should now have:")
        print("   • Single unified Celery configuration")
        print("   • No conflicting import statements")
        print("   • Proper worker entrypoint")
        print("\nNext steps:")
        print("   1. Run: python test_integration.py")
        print("   2. Test locally: python run_local.py")
        print("   3. Deploy with confidence!")
    else:
        print("\n⚠️  Manual intervention required:")
        if not config_ok:
            print("   • Ensure all unified config files are in place")
        if not imports_ok:
            print("   • Update remaining old import statements")

    return config_ok and imports_ok


if __name__ == "__main__":
    success = main()
    exit(0 if success else 1)