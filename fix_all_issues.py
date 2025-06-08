# fix_all_issues_skip_perms.py - SKIP PERMISSION CHECKS AND FOCUS ON INTEGRATION

"""
Modified version that skips permission checks and focuses on integration testing
Use this if you can't fix permissions but want to test the integration
"""

import sys
from pathlib import Path


class CryptoHunterFixer:
    """Crypto Hunter fixer that skips permission checks"""

    def __init__(self):
        self.issues_found = []
        self.fixes_applied = []
        self.project_root = Path.cwd()

    def log_issue(self, issue):
        """Log an issue found"""
        self.issues_found.append(issue)
        print(f"❌ ISSUE: {issue}")

    def log_fix(self, fix):
        """Log a fix applied"""
        self.fixes_applied.append(fix)
        print(f"✅ FIXED: {fix}")

    def log_info(self, info):
        """Log informational message"""
        print(f"ℹ️  {info}")

    def skip_permissions(self):
        """Skip permission checks and ensure basic directories exist"""
        print("\n⏭️  Skipping permission checks, ensuring directories exist...")

        required_dirs = ['logs', 'uploads', 'instance', 'temp', 'backups']

        for dir_name in required_dirs:
            dir_path = self.project_root / dir_name
            try:
                dir_path.mkdir(exist_ok=True, parents=True)
                self.log_fix(f"Directory {dir_name} exists")
            except Exception as e:
                self.log_info(f"Cannot create {dir_name}: {e} (continuing anyway)")

        return True

    def apply_configuration_fixes(self):
        """Apply all configuration fixes"""
        print("\n⚙️  Checking configuration files...")

        required_files = {
            'crypto_hunter_web/celery_app.py': 'Unified Celery configuration',
            'crypto_hunter_web/__init__.py': 'Fixed Flask app with robust logging',
            'crypto_hunter_web/services/__init__.py': 'Clean service imports',
            'celery_worker_entrypoint.py': 'Unified worker entrypoint',
        }

        for file_path_str, description in required_files.items():
            file_path = self.project_root / file_path_str
            if file_path.exists():
                self.log_fix(f"{description} in place")
            else:
                self.log_issue(f"Missing required file: {file_path}")

        # Create celery_app.py if it doesn't exist
        celery_app_path = self.project_root / 'crypto_hunter_web' / 'celery_app.py'
        if not celery_app_path.exists():
            self.log_issue("crypto_hunter_web/celery_app.py is missing - please create this file!")
            return False

        return True

    def test_imports(self):
        """Test that all imports work"""
        print("\n🧪 Testing imports...")

        import_tests = [
            ('Flask app creation', 'from crypto_hunter_web import create_app; create_app("testing")'),
            ('Database models', 'from crypto_hunter_web.models import db'),
            ('Core services', 'from crypto_hunter_web.services import AuthService'),
            ('Unified Celery app', 'from crypto_hunter_web.celery_app import celery_app'),
        ]

        all_passed = True

        for test_name, import_code in import_tests:
            try:
                # Add current directory to Python path
                original_path = sys.path.copy()
                sys.path.insert(0, str(self.project_root))

                exec(import_code)
                self.log_fix(f"Import test passed: {test_name}")

                # Restore original path
                sys.path = original_path

            except Exception as e:
                self.log_issue(f"Import test failed - {test_name}: {e}")
                all_passed = False

                # Restore original path even on error
                sys.path = original_path

        return all_passed

    def test_celery_configuration(self):
        """Test Celery configuration"""
        print("\n🔄 Testing Celery configuration...")

        try:
            # Add current directory to Python path
            sys.path.insert(0, str(self.project_root))

            # Test unified Celery app import
            from crypto_hunter_web.services.celery_app import celery_app

            # Check task discovery
            tasks = celery_app.tasks
            crypto_hunter_tasks = [t for t in tasks.keys() if 'crypto_hunter_web' in t]

            if len(crypto_hunter_tasks) > 0:
                self.log_fix(f"Celery app loaded with {len(crypto_hunter_tasks)} tasks")

                # Check for key tasks
                expected_tasks = [
                    'crypto_hunter_web.services.background_service.analyze_file_comprehensive',
                    'crypto_hunter_web.services.background_service.cleanup_old_tasks'
                ]

                for task_name in expected_tasks:
                    if task_name in tasks:
                        self.log_fix(f"Required task found: {task_name}")
                    else:
                        self.log_issue(f"Required task missing: {task_name}")

                return True
            else:
                self.log_issue("No Crypto Hunter tasks found in Celery app")
                return False

        except Exception as e:
            self.log_issue(f"Celery configuration test failed: {e}")
            return False

    def test_flask_app_context(self):
        """Test Flask app context"""
        print("\n🌐 Testing Flask app context...")

        try:
            sys.path.insert(0, str(self.project_root))

            from crypto_hunter_web import create_app

            app = create_app('testing')

            with app.app_context():
                # Test basic configuration
                if app.config.get('CELERY_BROKER_URL'):
                    self.log_fix("Flask app context works with Celery config")
                    return True
                else:
                    self.log_issue("Flask app missing Celery configuration")
                    return False

        except Exception as e:
            self.log_issue(f"Flask app context test failed: {e}")
            return False

    def provide_next_steps(self):
        """Provide next steps based on results"""
        print("\n📋 Next Steps:")

        if len(self.issues_found) == 0:
            print("🎉 All integration issues resolved!")
            print("\n✅ You can now:")
            print("   1. Start development server: python run_local.py")
            print("   2. Run with Docker: docker-compose up")
            print("   3. Test integration: python test_integration.py")
            print("\n⚠️  Note: Permission issues with logs directory remain")
            print("   • Application may log to console instead of files")
            print("   • Consider fixing permissions with: sudo chown -R $USER:$USER .")
        else:
            print(f"⚠️  {len(self.issues_found)} integration issues still need attention:")
            for i, issue in enumerate(self.issues_found, 1):
                print(f"   {i}. {issue}")

    def run_comprehensive_fix(self):
        """Run all fixes in sequence, skipping permissions"""
        print("🚀 Crypto Hunter Integration Fix (Skipping Permissions)")
        print("=" * 60)

        # Step 1: Skip permissions but ensure directories exist
        self.skip_permissions()

        # Step 2: Apply configuration fixes
        if not self.apply_configuration_fixes():
            print("❌ Configuration issues detected. Please ensure all files are in place.")
            return False

        # Step 3: Test imports
        if not self.test_imports():
            print("❌ Import issues detected. Please check dependencies.")
            return False

        # Step 4: Test Celery configuration
        if not self.test_celery_configuration():
            print("❌ Celery configuration issues detected.")
            return False

        # Step 5: Test Flask app context
        if not self.test_flask_app_context():
            print("❌ Flask app context issues detected.")
            return False

        # Step 6: Provide next steps
        self.provide_next_steps()

        return len(self.issues_found) == 0


def main():
    """Main entry point"""
    fixer = CryptoHunterFixer()
    success = fixer.run_comprehensive_fix()
    return 0 if success else 1


if __name__ == "__main__":
    exit(main())