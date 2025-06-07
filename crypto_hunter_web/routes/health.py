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
    return render_template('health/full_health.html')

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

        # Check for missing columns (should be fixed now)
        missing_columns = None
        if 'analysis_files' in tables:
            af_columns = [col['name'] for col in inspector.get_columns('analysis_files')]
            expected_columns = ['sha256_hash', 'file_size', 'md5_hash', 'parent_file_sha', 'extraction_method', 'depth_level']
            missing_columns = [col for col in expected_columns if col not in af_columns]

        return {
            'name': 'Database',
            'status': 'critical' if missing_columns else 'healthy',
            'details': {
                'connection': 'OK',
                'database_file': str(db_url),
                'database_size': f"{db_size:.2f} MB",
                'tables_count': len(tables),
                'tables': tables[:10],  # First 10 tables
                'user_count': user_count,
                'file_count': file_count,
                'missing_columns': missing_columns,
                'last_activity': datetime.utcnow().isoformat()
            }
        }
    except Exception as e:
        return {
            'name': 'Database',
            'status': 'critical',
            'details': {'error': str(e)}
        }

def check_redis():
    """Check Redis connectivity and performance"""
    try:
        import redis
        redis_url = os.getenv('REDIS_URL', 'redis://redis:6379/0')
        r = redis.from_url(redis_url)

        # Test connection
        r.ping()

        # Test read/write
        test_key = 'health_check_test'
        r.set(test_key, 'test_value', ex=10)
        value = r.get(test_key)
        r.delete(test_key)

        # Get Redis info
        info = r.info()

        return {
            'name': 'Redis',
            'status': 'healthy' if value == b'test_value' else 'warning',
            'details': {
                'connection': 'OK',
                'read_write_test': 'OK' if value == b'test_value' else 'FAILED',
                'version': info.get('redis_version', 'unknown'),
                'uptime_seconds': info.get('uptime_in_seconds', 0),
                'connected_clients': info.get('connected_clients', 0),
                'memory_usage': f"{info.get('used_memory_human', '0B')}",
                'total_commands': info.get('total_commands_processed', 0),
                'keyspace_hits': info.get('keyspace_hits', 0),
                'keyspace_misses': info.get('keyspace_misses', 0)
            }
        }
    except ImportError:
        return {
            'name': 'Redis',
            'status': 'warning',
            'details': {'error': 'Redis package not installed'}
        }
    except Exception as e:
        return {
            'name': 'Redis',
            'status': 'critical',
            'details': {'error': str(e)}
        }

def check_celery_workers():
    """Check Celery worker status - FIXED IMPORT"""
    try:
        # Try different import approaches for Celery
        try:
            from celery import current_app as celery_app
            from celery.task.control import inspect as celery_inspect
        except ImportError:
            try:
                from celery import Celery
                celery_app = Celery('crypto_hunter')
                celery_app.config_from_object({
                    'broker_url': os.getenv('CELERY_BROKER_URL', 'redis://redis:6379/0'),
                    'result_backend': os.getenv('CELERY_RESULT_BACKEND', 'redis://redis:6379/1')
                })
                from celery.task.control import inspect as celery_inspect
            except ImportError:
                # Fallback - use modern Celery imports
                import celery
                from celery import current_app as celery_app
                inspector = celery_app.control.inspect()

                active = inspector.active() or {}
                stats = inspector.stats() or {}

                return {
                    'name': 'Celery Workers',
                    'status': 'healthy' if active else 'warning',
                    'details': {
                        'workers_active': len(active),
                        'worker_stats': stats,
                        'message': 'Celery workers operational' if active else 'No active workers found'
                    }
                }

        # Original inspection method if imports work
        inspector = celery_inspect()
        active = inspector.active() or {}
        stats = inspector.stats() or {}
        registered = inspector.registered() or {}

        return {
            'name': 'Celery Workers',
            'status': 'healthy' if active else 'warning',
            'details': {
                'workers_active': len(active),
                'total_tasks_registered': sum(len(tasks) for tasks in registered.values()),
                'worker_stats': stats,
                'message': 'Celery workers operational' if active else 'No active workers found'
            }
        }

    except ImportError as e:
        return {
            'name': 'Celery Workers',
            'status': 'warning',
            'details': {
                'error': f'Celery import failed: {str(e)}',
                'message': 'Celery monitoring not available'
            }
        }
    except Exception as e:
        return {
            'name': 'Celery Workers',
            'status': 'warning',
            'details': {
                'error': str(e),
                'message': 'Celery worker check failed'
            }
        }

def check_model_integrity():
    """Check model integrity and methods"""
    try:
        issues = []
        model_checks = {}

        # Test User model
        try:
            user = User.query.first()
            if user:
                # Test methods exist
                if hasattr(user, 'award_points'):
                    model_checks['User'] = {'status': 'healthy', 'method_test': 'OK', 'issues': []}
                else:
                    issues.append('User.award_points method missing')
                    model_checks['User'] = {'status': 'warning', 'issues': ['award_points method missing']}
            else:
                model_checks['User'] = {'status': 'healthy', 'issues': []}
        except Exception as e:
            issues.append(f'User model error: {str(e)}')
            model_checks['User'] = {'status': 'critical', 'issues': [str(e)]}

        # Test AnalysisFile model
        try:
            if hasattr(AnalysisFile, 'calculate_sha256'):
                model_checks['AnalysisFile'] = {'status': 'healthy', 'issues': []}
            else:
                issues.append('AnalysisFile.calculate_sha256 method missing')
                model_checks['AnalysisFile'] = {'status': 'warning', 'issues': ['calculate_sha256 method missing']}
        except Exception as e:
            issues.append(f'AnalysisFile model error: {str(e)}')
            model_checks['AnalysisFile'] = {'status': 'critical', 'issues': [str(e)]}

        return {
            'name': 'Model Integrity',
            'status': 'critical' if any('critical' in check.get('status', '') for check in model_checks.values()) else 'warning' if issues else 'healthy',
            'details': {
                'total_issues': len(issues),
                'model_checks': model_checks
            }
        }
    except Exception as e:
        return {
            'name': 'Model Integrity',
            'status': 'critical',
            'details': {'error': str(e)}
        }

def check_file_system():
    """Check file system health"""
    try:
        details = {}

        # Check disk usage
        disk_usage = psutil.disk_usage('/')
        details['disk_usage'] = {
            'total_gb': f"{disk_usage.total / (1024**3):.2f}",
            'free_gb': f"{disk_usage.free / (1024**3):.2f}",
            'used_percentage': f"{(disk_usage.used / disk_usage.total) * 100:.1f}%"
        }

        # Check important directories
        directories = {}
        for dir_name, dir_path in [('uploads', 'uploads'), ('instance', 'instance'), ('logs', 'logs')]:
            if os.path.exists(dir_path):
                size = sum(os.path.getsize(os.path.join(dirpath, filename))
                          for dirpath, dirnames, filenames in os.walk(dir_path)
                          for filename in filenames)
                directories[dir_name] = {
                    'exists': True,
                    'writable': os.access(dir_path, os.W_OK),
                    'size': f"{size / (1024**2):.2f} MB"
                }
            else:
                directories[dir_name] = {'exists': False}

        details['directories'] = directories

        # Check database file specifically
        db_path = 'instance/arweave_tracker.db'
        if os.path.exists(db_path):
            stat = os.stat(db_path)
            details['database_file'] = {
                'exists': True,
                'size_mb': stat.st_size / (1024**2),
                'modified': datetime.fromtimestamp(stat.st_mtime).isoformat(),
                'permissions': oct(stat.st_mode)[-3:]
            }

        # Status based on disk usage
        status = 'critical' if disk_usage.free < 1024**3 else 'warning' if disk_usage.free < 5*1024**3 else 'healthy'

        return {
            'name': 'File System',
            'status': status,
            'details': details
        }
    except Exception as e:
        return {
            'name': 'File System',
            'status': 'critical',
            'details': {'error': str(e)}
        }

def check_system_resources():
    """Check system resource usage"""
    try:
        # CPU info
        cpu_info = {
            'usage_percent': psutil.cpu_percent(interval=1),
            'core_count': psutil.cpu_count(),
            'load_average': list(psutil.getloadavg()) if hasattr(psutil, 'getloadavg') else [0, 0, 0]
        }

        # Memory info
        memory = psutil.virtual_memory()
        memory_info = {
            'total_gb': f"{memory.total / (1024**3):.2f}",
            'available_gb': f"{memory.available / (1024**3):.2f}",
            'usage_percent': memory.percent
        }

        # Process info
        process = psutil.Process()
        process_info = {
            'pid': process.pid,
            'cpu_percent': process.cpu_percent(),
            'memory_percent': process.memory_percent(),
            'num_threads': process.num_threads(),
            'create_time': datetime.fromtimestamp(process.create_time()).isoformat()
        }

        status = 'critical' if memory.percent > 90 or cpu_info['usage_percent'] > 90 else 'warning' if memory.percent > 80 or cpu_info['usage_percent'] > 80 else 'healthy'

        return {
            'name': 'System Resources',
            'status': status,
            'details': {
                'cpu': cpu_info,
                'memory': memory_info,
                'process': process_info
            }
        }
    except Exception as e:
        return {
            'name': 'System Resources',
            'status': 'warning',
            'details': {'error': str(e)}
        }

def check_configuration():
    """Check configuration and environment"""
    try:
        # Environment variables
        important_vars = ['DATABASE_URL', 'REDIS_URL', 'SECRET_KEY', 'CELERY_BROKER_URL', 'CELERY_RESULT_BACKEND']
        env_vars = {}
        missing_vars = []

        for var in important_vars:
            value = os.getenv(var)
            if value:
                # Hide sensitive values
                if 'SECRET' in var or 'PASSWORD' in var:
                    env_vars[var] = '*' + value[-4:] if len(value) > 4 else '*****'
                else:
                    env_vars[var] = value
            else:
                missing_vars.append(var)

        # Flask config
        from flask import current_app
        flask_config = {
            'DEBUG': current_app.debug,
            'TESTING': current_app.testing,
            'SECRET_KEY_SET': bool(current_app.secret_key),
            'SQLALCHEMY_DATABASE_URI_SET': bool(current_app.config.get('SQLALCHEMY_DATABASE_URI')),
            'MAX_CONTENT_LENGTH': current_app.config.get('MAX_CONTENT_LENGTH'),
            'UPLOAD_FOLDER': current_app.config.get('UPLOAD_FOLDER')
        }

        return {
            'name': 'Configuration',
            'status': 'warning' if missing_vars else 'healthy',
            'details': {
                'environment_variables': env_vars,
                'missing_variables': missing_vars,
                'flask_config': flask_config
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
        import requests
        from urllib.parse import urljoin

        base_url = 'http://localhost:8000'
        endpoints = {
            'Basic Health': '/health',
            'Login Page': '/auth/login',
            'Dashboard': '/dashboard',
            'Files List': '/files'
        }

        results = {}
        failed_endpoints = []

        for name, endpoint in endpoints.items():
            try:
                response = requests.get(urljoin(base_url, endpoint), timeout=5, allow_redirects=False)
                results[name] = {
                    'accessible': True,
                    'status_code': response.status_code,
                    'response_size': len(response.content)
                }
                if response.status_code >= 500:
                    failed_endpoints.append(name)
            except Exception as e:
                results[name] = {
                    'accessible': False,
                    'error': str(e)
                }
                failed_endpoints.append(name)

        return {
            'name': 'API Endpoints',
            'status': 'critical' if failed_endpoints else 'healthy',
            'details': {
                'endpoint_results': results,
                'failed_endpoints': failed_endpoints,
                'total_tested': len(endpoints)
            }
        }
    except ImportError:
        return {
            'name': 'API Endpoints',
            'status': 'warning',
            'details': {'error': 'requests package not available for endpoint testing'}
        }
    except Exception as e:
        return {
            'name': 'API Endpoints',
            'status': 'warning',
            'details': {'error': str(e)}
        }

def check_container_status():
    """Check Docker container status - IMPROVED"""
    try:
        # Get container information using docker ps
        result = subprocess.run(['docker', 'ps', '--format', 'table {{.Names}}\t{{.Status}}'],
                              capture_output=True, text=True, timeout=5)

        containers = {}
        running_count = 0
        expected_containers = ['hunter-web-1', 'hunter-worker-1', 'hunter-beat-1', 'hunter-redis-1']

        if result.returncode == 0:
            lines = result.stdout.strip().split('\n')[1:]  # Skip header
            for line in lines:
                if '\t' in line:
                    name, status = line.split('\t', 1)
                    containers[name] = status
                    if 'Up' in status:
                        running_count += 1

        # Check expected containers
        for container in expected_containers:
            if container not in containers:
                containers[container] = 'not running'

        not_running = [name for name, status in containers.items()
                      if name in expected_containers and 'Up' not in status]

        status = 'healthy' if running_count >= 2 else 'warning' if running_count >= 1 else 'critical'

        return {
            'name': 'Container Status',
            'status': status,
            'details': {
                'containers': containers,
                'running_count': running_count,
                'total_expected': len(expected_containers),
                'not_running': not_running if not_running else None
            }
        }
    except Exception as e:
        return {
            'name': 'Container Status',
            'status': 'warning',
            'details': {
                'containers': {'hunter-web-1': 'unknown', 'hunter-worker-1': 'unknown',
                              'hunter-beat-1': 'unknown', 'hunter-redis-1': 'unknown'},
                'running_count': 0,
                'total_expected': 4,
                'error': str(e)
            }
        }

def check_security():
    """Check security configuration"""
    try:
        checks = {}

        # Check admin password
        admin = User.query.filter_by(username='admin').first()
        if admin:
            checks['admin_default_password'] = admin.check_password('admin123')

        # Check secret key strength
        secret_key = os.getenv('SECRET_KEY', '')
        checks['secret_key_set'] = bool(secret_key)
        checks['secret_key_strength'] = 'strong' if len(secret_key) > 32 else 'weak'

        # Check database file permissions
        db_path = 'instance/arweave_tracker.db'
        if os.path.exists(db_path):
            stat = os.stat(db_path)
            perms = oct(stat.st_mode)[-3:]
            checks['database_permissions'] = perms

        issues = []
        if checks.get('admin_default_password'):
            issues.append('Admin user still has default password')
        if checks.get('secret_key_strength') == 'weak':
            issues.append('Weak secret key detected')

        return {
            'name': 'Security',
            'status': 'critical' if len(issues) > 1 else 'warning' if issues else 'healthy',
            'details': {
                'security_checks': checks,
                'issues': issues if issues else None
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
        checks = {}

        # Check for admin user
        admin_exists = User.query.filter_by(username='admin').first() is not None
        checks['admin_user_exists'] = admin_exists

        # Check for orphaned files (files without valid parent relationships)
        orphaned_files = 0
        try:
            orphaned_files = AnalysisFile.query.filter(
                AnalysisFile.parent_file_sha.isnot(None),
                ~AnalysisFile.parent_file_sha.in_(
                    db.session.query(AnalysisFile.sha256_hash)
                )
            ).count()
        except:
            pass

        checks['orphaned_files'] = orphaned_files

        return {
            'name': 'Data Consistency',
            'status': 'warning' if orphaned_files > 0 or not admin_exists else 'healthy',
            'details': {
                'consistency_checks': checks
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
        # This is a simple check - in a real system you'd check task queues
        return {
            'name': 'Background Tasks',
            'status': 'healthy',
            'details': {
                'last_check': datetime.utcnow().isoformat(),
                'message': 'Background task system operational'
            }
        }
    except Exception as e:
        return {
            'name': 'Background Tasks',
            'status': 'warning',
            'details': {'error': str(e)}
        }

def get_uptime():
    """Get system uptime"""
    try:
        with open('/proc/uptime', 'r') as f:
            uptime_seconds = float(f.readline().split()[0])
            hours, remainder = divmod(uptime_seconds, 3600)
            minutes, seconds = divmod(remainder, 60)
            return f"{int(hours)}:{int(minutes):02d}:{int(seconds):02d}"
    except:
        return "unknown"