# test_integration.py - INTEGRATION VALIDATION SCRIPT

"""
Test script to validate all integration fixes
Run this to ensure Celery and import issues are resolved
"""

import sys
import traceback
from pathlib import Path


def test_basic_imports():
    """Test that core modules can be imported"""
    print("🔍 Testing basic imports...")

    try:
        from crypto_hunter_web import create_app
        print("✅ Flask app creation")
    except Exception as e:
        print(f"❌ Flask app creation: {e}")
        return False

    try:
        from crypto_hunter_web.models import db, User, AnalysisFile
        print("✅ Database models")
    except Exception as e:
        print(f"❌ Database models: {e}")
        return False

    try:
        from crypto_hunter_web.services import AuthService, SearchService, FileAnalyzer
        print("✅ Core services")
    except Exception as e:
        print(f"❌ Core services: {e}")
        return False

    return True


def test_celery_integration():
    """Test Celery configuration and task discovery"""
    print("\n🔍 Testing Celery integration...")

    try:
        from crypto_hunter_web.services.celery_app import celery_app
        print("✅ Unified Celery app import")
    except Exception as e:
        print(f"❌ Unified Celery app import: {e}")
        return False

    try:
        # Check task registration
        tasks = celery_app.tasks
        crypto_hunter_tasks = [t for t in tasks.keys() if 'crypto_hunter_web' in t]

        print(f"✅ Task discovery: {len(crypto_hunter_tasks)} tasks found")

        # Check for key tasks
        expected_tasks = [
            'crypto_hunter_web.services.background_service.analyze_file_comprehensive',
            'crypto_hunter_web.services.background_service.analyze_crypto_patterns',
            'crypto_hunter_web.services.background_service.process_ai_analysis',
            'crypto_hunter_web.services.background_service.cleanup_old_tasks'
        ]

        for task_name in expected_tasks:
            if task_name in tasks:
                print(f"  ✅ {task_name}")
            else:
                print(f"  ❌ {task_name} - NOT FOUND")

    except Exception as e:
        print(f"❌ Task discovery: {e}")
        return False

    return True


def test_worker_entrypoint():
    """Test worker entrypoint can be imported"""
    print("\n🔍 Testing worker entrypoint...")

    try:
        # Add current directory to path for import
        sys.path.insert(0, str(Path.cwd()))

        import celery_worker_entrypoint
        print("✅ Worker entrypoint import")

        # Check if celery_app is accessible
        if hasattr(celery_worker_entrypoint, 'celery_app'):
            print("✅ Celery app accessible from entrypoint")
        else:
            print("❌ Celery app not accessible from entrypoint")
            return False

    except Exception as e:
        print(f"❌ Worker entrypoint: {e}")
        traceback.print_exc()
        return False

    return True


def test_flask_app_context():
    """Test Flask app context integration with Celery"""
    print("\n🔍 Testing Flask app context...")

    try:
        from crypto_hunter_web import create_app
        from crypto_hunter_web.services.celery_app import celery_app

        app = create_app('testing')

        with app.app_context():
            # Test that we can access Flask app config
            broker_url = app.config.get('CELERY_BROKER_URL')
            if broker_url:
                print("✅ Flask config accessible in app context")
            else:
                print("❌ Flask config not accessible")
                return False

            # Test database connection
            from crypto_hunter_web.models import db
            db.session.execute('SELECT 1')
            print("✅ Database accessible in app context")

    except Exception as e:
        print(f"❌ Flask app context: {e}")
        return False

    return True


def test_services_package():
    """Test services package imports work correctly"""
    print("\n🔍 Testing services package...")

    try:
        from crypto_hunter_web.services import is_service_available, get_available_services

        available_services = get_available_services()
        print(f"✅ Services package: {len(available_services)} services available")

        # Check core services
        required_services = ['AuthService', 'SearchService', 'FileAnalyzer', 'celery_app']
        for service in required_services:
            if is_service_available(service):
                print(f"  ✅ {service}")
            else:
                print(f"  ❌ {service} - NOT AVAILABLE")

        # Show optional services
        optional_services = [s for s in available_services if s not in required_services]
        if optional_services:
            print(f"  📋 Optional services: {', '.join(optional_services[:3])}...")

    except Exception as e:
        print(f"❌ Services package: {e}")
        return False

    return True


def test_task_execution():
    """Test that tasks can be executed (eager mode)"""
    print("\n🔍 Testing task execution...")

    try:
        from crypto_hunter_web import create_app
        from crypto_hunter_web.services.celery_app import celery_app

        app = create_app('testing')

        # Enable eager mode for testing
        celery_app.conf.task_always_eager = True
        celery_app.conf.task_eager_propagates = True

        with app.app_context():
            # Test health check task
            from celery_worker_entrypoint import worker_health_check

            result = worker_health_check.apply()
            if result.successful():
                print("✅ Task execution (health check)")
                task_result = result.get()
                if task_result.get('status') == 'ok':
                    print("  ✅ Task returned expected result")
                else:
                    print(f"  ❌ Unexpected task result: {task_result}")
            else:
                print("❌ Task execution failed")
                return False

    except Exception as e:
        print(f"❌ Task execution: {e}")
        traceback.print_exc()
        return False

    return True


def test_docker_compatibility():
    """Test Docker-related configurations"""
    print("\n🔍 Testing Docker compatibility...")

    try:
        # Check if docker-compose.yml exists and worker command is correct
        docker_compose_file = Path('docker-compose.yml')
        if docker_compose_file.exists():
            content = docker_compose_file.read_text()
            if 'celery_worker_entrypoint.celery_app' in content:
                print("✅ Docker Compose uses unified Celery app")
            else:
                print("❌ Docker Compose may use old Celery configuration")
                return False
        else:
            print("⚠️  docker-compose.yml not found")

        # Check worker entrypoint exists
        entrypoint_file = Path('celery_worker_entrypoint.py')
        if entrypoint_file.exists():
            print("✅ Worker entrypoint file exists")
        else:
            print("❌ Worker entrypoint file missing")
            return False

    except Exception as e:
        print(f"❌ Docker compatibility: {e}")
        return False

    return True


def run_all_tests():
    """Run all integration tests"""
    print("🚀 Crypto Hunter Integration Test Suite")
    print("=" * 50)

    tests = [
        ("Basic Imports", test_basic_imports),
        ("Celery Integration", test_celery_integration),
        ("Worker Entrypoint", test_worker_entrypoint),
        ("Flask App Context", test_flask_app_context),
        ("Services Package", test_services_package),
        ("Task Execution", test_task_execution),
        ("Docker Compatibility", test_docker_compatibility),
    ]

    passed = 0
    failed = 0

    for test_name, test_func in tests:
        try:
            if test_func():
                passed += 1
            else:
                failed += 1
        except Exception as e:
            print(f"❌ {test_name}: Unexpected error - {e}")
            failed += 1

    print(f"\n📊 Test Results: {passed} passed, {failed} failed")

    if failed == 0:
        print("🎉 All integration tests passed! Your project is ready to run.")
        print("\nNext steps:")
        print("  1. Start services: python run_local.py")
        print("  2. Or use Docker: docker-compose up")
        print("  3. Or deploy to production")
        return True
    else:
        print("❌ Some tests failed. Please fix the issues before deploying.")
        return False


if __name__ == "__main__":
    success = run_all_tests()
    sys.exit(0 if success else 1)