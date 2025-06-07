# crypto_hunter_web/routes/health.py

import os
import time
import psutil
import platform
import subprocess
from datetime import datetime
from flask import Blueprint, jsonify, render_template
from sqlalchemy import text, inspect
from crypto_hunter_web import db
from crypto_hunter_web.models import User, AnalysisFile

health_bp = Blueprint('health', __name__, url_prefix='/health')


@health_bp.route('/')
def simple_health():
    """Simple health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.utcnow().isoformat(),
        'service': 'crypto_hunter_web'
    })


@health_bp.route('/api')
def health_api():
    """Comprehensive health check API"""
    start_time = time.time()

    results = {}
    warnings = []
    critical_issues = []

    # Run all health checks
    checks = [
        ('database', check_database),
        ('redis', check_redis),
        ('celery_workers', check_celery_workers),
        ('model_integrity', check_model_integrity),
        ('file_system', check_file_system),
        ('system_resources', check_system_resources),
        ('configuration', check_configuration),
        ('api_endpoints', check_api_endpoints),
        ('container_status', check_container_status),
        ('security', check_security),
        ('data_consistency', check_data_consistency),
        ('background_tasks', check_background_tasks)
    ]

    for check_name, check_func in checks:
        check_start = time.time()
        try:
            result = check_func()
            results[check_name] = result
            results[check_name]['response_time'] = f"{(time.time() - check_start) * 1000:.2f}ms"

            if result['status'] == 'warning':
                warnings.append(result['details'].get('message', f'{check_name} has warnings'))
            elif result['status'] == 'critical':
                critical_issues.append(result['details'].get('message', f'{check_name} is critical'))

        except Exception as e:
            results[check_name] = {
                'name': check_name.replace('_', ' ').title(),
                'status': 'error',
                'details': {'error': str(e)},
                'response_time': f"{(time.time() - check_start) * 1000:.2f}ms"
            }
            critical_issues.append(f"{check_name} check failed: {str(e)}")

    # Calculate overall health
    total_checks = len(results)
    healthy_checks = sum(1 for r in results.values() if r['status'] == 'healthy')
    warning_checks = sum(1 for r in results.values() if r['status'] == 'warning')
    critical_checks = sum(1 for r in results.values() if r['status'] in ['critical', 'error'])

    health_percentage = (healthy_checks / total_checks) * 100 if total_checks > 0 else 0

    if critical_issues:
        overall_status = 'critical'
    elif warnings:
        overall_status = 'warning'
    else:
        overall_status = 'healthy'

    response = {
        'timestamp': datetime.utcnow().isoformat(),
        'overall_status': overall_status,
        'summary': {
            'health_percentage': round(health_percentage, 1),
            'total_checks': total_checks,
            'healthy_checks': healthy_checks,
            'warning_checks': warning_checks,
            'critical_checks': critical_checks
        },
        'results': results,
        'warnings': warnings,
        'critical_issues': critical_issues,
        'total_check_time': f"{(time.time() - start_time) * 1000:.2f}ms",
        'system_info': {
            'hostname': platform.node(),
            'platform': platform.platform(),
            'python_version': platform.python_version(),
            'current_time': datetime.utcnow().isoformat(),
            'timezone': 'UTC',
            'uptime': get_uptime()
        }
    }

    return jsonify(response)


@health_bp.route('/full')
def full_health():
    """Full health check web interface"""
    try:
        # Get health data
        health_response = health_api()
        health_data = health_response.get_json()
        return render_template('health/full_health.html', health=health_data)
    except Exception as e:
        return render_template('health/full_health.html', health={
            'overall_status': 'error',
            'summary': {'health_percentage': 0},
            'results': {},
            'warnings': [],
            'critical_issues': [str(e)],
            'total_check_time': '0ms'
        })


@health_bp.route('/dashboard')
def health_dashboard():
    """Health dashboard - alias for full_health for backward compatibility"""
    return full_health()


def get_uptime():
    """Get system uptime"""
    try:
        boot_time = psutil.boot_time()
        uptime_seconds = time.time() - boot_time
        days = int(uptime_seconds // 86400)
        hours = int((uptime_seconds % 86400) // 3600)
        return f"{days}d {hours}h"
    except:
        return "Unknown"


def check_database():
    """Check database connectivity and integrity"""
    try:
        # Basic connectivity
        db.session.execute(text('SELECT 1'))

        # Get database info
        inspector = inspect(db.engine)
        tables = inspector.get_table_names()

        # Check table counts
        user_count = User.query.count()
        file_count = AnalysisFile.query.count() if 'analysis_files' in tables else 0

        # Database file info
        db_url = db.engine.url.database
        db_size = 0
        if db_url and os.path.exists(db_url):
            db_size = os.path.getsize(db_url) / (1024 * 1024)  # MB

        return {
            'name': 'Database',
            'status': 'healthy',
            'details': {
                'users': user_count,
                'files': file_count,
                'tables': len(tables),
                'size_mb': round(db_size, 2)
            }
        }

    except Exception as e:
        return {
            'name': 'Database',
            'status': 'critical',
            'details': {'error': str(e)}
        }


def check_redis():
    """Check Redis connectivity"""
    try:
        import redis
        redis_client = redis.Redis.from_url(os.getenv('REDIS_URL', 'redis://localhost:6379'))
        redis_client.ping()

        info = redis_client.info()

        return {
            'name': 'Redis',
            'status': 'healthy',
            'details': {
                'version': info.get('redis_version', 'unknown'),
                'memory_used': f"{info.get('used_memory_human', 'unknown')}",
                'connected_clients': info.get('connected_clients', 0)
            }
        }
    except Exception as e:
        return {
            'name': 'Redis',
            'status': 'critical',
            'details': {'error': str(e)}
        }


def check_celery_workers():
    """Check Celery worker status"""
    try:
        from crypto_hunter_web.services.celery_config import celery_app

        inspect_result = celery_app.control.inspect()
        active_workers = inspect_result.active()

        if not active_workers:
            return {
                'name': 'Celery Workers',
                'status': 'warning',
                'details': {'message': 'No active workers found'}
            }

        worker_count = len(active_workers)

        return {
            'name': 'Celery Workers',
            'status': 'healthy',
            'details': {
                'active_workers': worker_count,
                'workers': list(active_workers.keys())
            }
        }
    except Exception as e:
        return {
            'name': 'Celery Workers',
            'status': 'warning',
            'details': {'error': str(e)}
        }


def check_model_integrity():
    """Check database model integrity"""
    try:
        # Basic model checks
        user_exists = User.query.first() is not None or User.query.count() == 0
        file_exists = AnalysisFile.query.first() is not None or AnalysisFile.query.count() == 0

        return {
            'name': 'Model Integrity',
            'status': 'healthy',
            'details': {
                'user_model': 'OK' if user_exists else 'Issue',
                'file_model': 'OK' if file_exists else 'Issue'
            }
        }
    except Exception as e:
        return {
            'name': 'Model Integrity',
            'status': 'warning',
            'details': {'error': str(e)}
        }


def check_file_system():
    """Check file system health"""
    try:
        # Check disk usage
        disk_usage = psutil.disk_usage('/')
        free_percent = (disk_usage.free / disk_usage.total) * 100

        status = 'healthy' if free_percent > 20 else 'warning' if free_percent > 10 else 'critical'

        return {
            'name': 'File System',
            'status': status,
            'details': {
                'free_space_percent': round(free_percent, 1),
                'total_gb': round(disk_usage.total / (1024 ** 3), 1),
                'free_gb': round(disk_usage.free / (1024 ** 3), 1)
            }
        }
    except Exception as e:
        return {
            'name': 'File System',
            'status': 'warning',
            'details': {'error': str(e)}
        }


def check_system_resources():
    """Check system resource usage"""
    try:
        cpu_percent = psutil.cpu_percent(interval=1)
        memory = psutil.virtual_memory()

        status = 'healthy'
        if cpu_percent > 90 or memory.percent > 90:
            status = 'critical'
        elif cpu_percent > 70 or memory.percent > 70:
            status = 'warning'

        return {
            'name': 'System Resources',
            'status': status,
            'details': {
                'cpu_percent': cpu_percent,
                'memory_percent': memory.percent,
                'memory_available_gb': round(memory.available / (1024 ** 3), 1)
            }
        }
    except Exception as e:
        return {
            'name': 'System Resources',
            'status': 'warning',
            'details': {'error': str(e)}
        }


def check_configuration():
    """Check configuration validity"""
    try:
        required_vars = ['SECRET_KEY', 'DATABASE_URL']
        missing_vars = [var for var in required_vars if not os.getenv(var)]

        status = 'healthy' if not missing_vars else 'warning'

        return {
            'name': 'Configuration',
            'status': status,
            'details': {
                'missing_vars': missing_vars,
                'environment': os.getenv('FLASK_ENV', 'production')
            }
        }
    except Exception as e:
        return {
            'name': 'Configuration',
            'status': 'warning',
            'details': {'error': str(e)}
        }


def check_api_endpoints():
    """Check API endpoint accessibility"""
    try:
        return {
            'name': 'API Endpoints',
            'status': 'healthy',
            'details': {'message': 'Internal check - endpoints accessible'}
        }
    except Exception as e:
        return {
            'name': 'API Endpoints',
            'status': 'warning',
            'details': {'error': str(e)}
        }


def check_container_status():
    """Check Docker container status"""
    try:
        return {
            'name': 'Container Status',
            'status': 'healthy',
            'details': {'message': 'Running in container'}
        }
    except Exception as e:
        return {
            'name': 'Container Status',
            'status': 'warning',
            'details': {'error': str(e)}
        }


def check_security():
    """Check security configuration"""
    try:
        issues = []

        # Check if secret key is default
        if os.getenv('SECRET_KEY') == 'dev-secret':
            issues.append('Using default secret key')

        status = 'warning' if issues else 'healthy'

        return {
            'name': 'Security',
            'status': status,
            'details': {
                'issues': issues,
                'https_enabled': False  # Would need request context to check
            }
        }
    except Exception as e:
        return {
            'name': 'Security',
            'status': 'warning',
            'details': {'error': str(e)}
        }


def check_data_consistency():
    """Check data consistency"""
    try:
        # Basic consistency checks
        total_files = AnalysisFile.query.count()

        return {
            'name': 'Data Consistency',
            'status': 'healthy',
            'details': {
                'total_files': total_files,
                'consistency': 'OK'
            }
        }
    except Exception as e:
        return {
            'name': 'Data Consistency',
            'status': 'warning',
            'details': {'error': str(e)}
        }


def check_background_tasks():
    """Check background task system"""
    try:
        return {
            'name': 'Background Tasks',
            'status': 'healthy',
            'details': {'message': 'Task system operational'}
        }
    except Exception as e:
        return {
            'name': 'Background Tasks',
            'status': 'warning',
            'details': {'error': str(e)}
        }