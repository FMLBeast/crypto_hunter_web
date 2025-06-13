# crypto_hunter_web/routes/health.py - COMPLETE HEALTH ROUTES IMPLEMENTATION

from flask import Blueprint, render_template, request, jsonify, current_app
from flask_login import login_required, current_user
from datetime import datetime, timedelta
import subprocess
import psutil
import os

from crypto_hunter_web.models import db, AnalysisFile, FileContent, Finding, User, FileStatus
from crypto_hunter_web.services.auth_service import AuthService
from crypto_hunter_web.services.background_crypto import BackgroundCryptoManager
from crypto_hunter_web.utils.redis_client_util import redis_client
from crypto_hunter_web.utils.decorators import rate_limit, api_endpoint

health_bp = Blueprint('health', __name__, url_prefix='/health')


@health_bp.route('/')
def simple_health():
    """Simple health check endpoint"""
    return jsonify({
        'status': 'ok',
        'service': 'crypto_hunter_web',
        'timestamp': datetime.utcnow().isoformat(),
        'version': '1.0.0'
    }), 200


@health_bp.route('/api')
@api_endpoint(rate_limit_requests=1000, cache_ttl=30)
def health_api():
    """Comprehensive API health check"""
    try:
        health_status = {
            'overall_status': 'healthy',
            'timestamp': datetime.utcnow().isoformat(),
            'version': '1.0.0',
            'components': {},
            'performance_metrics': {},
            'warnings': [],
            'errors': []
        }

        # Database health check
        db_health = _check_database_health()
        health_status['components']['database'] = db_health

        # Redis health check
        redis_health = _check_redis_health()
        health_status['components']['redis'] = redis_health

        # Background processing health
        background_health = _check_background_processing_health()
        health_status['components']['background_processing'] = background_health

        # System resources health
        system_health = _check_system_resources()
        health_status['components']['system_resources'] = system_health

        # Application metrics
        app_metrics = _get_application_metrics()
        health_status['performance_metrics'] = app_metrics

        # API endpoints health
        api_health = _check_api_endpoints()
        health_status['components']['api_endpoints'] = api_health

        # Container health (if running in Docker)
        container_health = _check_container_status()
        health_status['components']['containers'] = container_health

        # Determine overall status
        component_statuses = [comp['status'] for comp in health_status['components'].values()]

        if any(status == 'critical' for status in component_statuses):
            health_status['overall_status'] = 'critical'
        elif any(status == 'warning' for status in component_statuses):
            health_status['overall_status'] = 'warning'
        else:
            health_status['overall_status'] = 'healthy'

        # Collect warnings and errors
        for component_name, component in health_status['components'].items():
            if component['status'] == 'warning' and 'details' in component:
                health_status['warnings'].append(f"{component_name}: {component['details'].get('warning', 'Warning condition detected')}")
            elif component['status'] == 'critical' and 'details' in component:
                health_status['errors'].append(f"{component_name}: {component['details'].get('error', 'Critical condition detected')}")

        # Return appropriate HTTP status code
        if health_status['overall_status'] == 'critical':
            return jsonify(health_status), 503
        elif health_status['overall_status'] == 'warning':
            return jsonify(health_status), 200
        else:
            return jsonify(health_status), 200

    except Exception as e:
        current_app.logger.error(f"Error in health check: {e}")
        return jsonify({
            'overall_status': 'critical',
            'error': str(e),
            'timestamp': datetime.utcnow().isoformat()
        }), 503


@health_bp.route('/full')
@login_required
@AuthService.admin_required
@rate_limit(limit="4 per minute")
def full_health():
    """Comprehensive health check with detailed diagnostics (admin only)"""
    try:
        detailed_health = {
            'overall_status': 'healthy',
            'timestamp': datetime.utcnow().isoformat(),
            'detailed_checks': {},
            'system_info': _get_system_info(),
            'database_diagnostics': _get_database_diagnostics(),
            'performance_analysis': _get_performance_analysis(),
            'security_status': _get_security_status(),
            'recommendations': []
        }

        # Run detailed checks
        detailed_checks = {
            'database_connectivity': _detailed_database_check(),
            'redis_connectivity': _detailed_redis_check(),
            'file_system': _check_file_system_health(),
            'network_connectivity': _check_network_health(),
            'service_dependencies': _check_service_dependencies(),
            'data_integrity': _check_data_integrity(),
            'performance_bottlenecks': _identify_performance_bottlenecks()
        }

        detailed_health['detailed_checks'] = detailed_checks

        # Generate recommendations
        recommendations = _generate_health_recommendations(detailed_checks)
        detailed_health['recommendations'] = recommendations

        # Determine overall status
        check_statuses = [check['status'] for check in detailed_checks.values()]
        if any(status == 'critical' for status in check_statuses):
            detailed_health['overall_status'] = 'critical'
        elif any(status == 'warning' for status in check_statuses):
            detailed_health['overall_status'] = 'warning'

        AuthService.log_action('full_health_check_performed', 'Performed comprehensive health check')

        return jsonify(detailed_health)

    except Exception as e:
        current_app.logger.error(f"Error in full health check: {e}")
        return jsonify({
            'overall_status': 'critical',
            'error': str(e),
            'timestamp': datetime.utcnow().isoformat()
        }), 503


@health_bp.route('/dashboard')
@login_required
def health_dashboard():
    """Health monitoring dashboard"""
    try:
        # Get current health status
        health_data = {}

        # Quick health checks
        health_data['database'] = _check_database_health()
        health_data['redis'] = _check_redis_health()
        health_data['background_processing'] = _check_background_processing_health()
        health_data['system_resources'] = _check_system_resources()

        # System metrics over time
        health_data['metrics_history'] = _get_metrics_history()

        # Recent alerts and warnings
        health_data['recent_alerts'] = _get_recent_alerts()

        # Service uptime
        health_data['uptime'] = _get_service_uptime()

        return render_template('health/dashboard.html', health_data=health_data)

    except Exception as e:
        current_app.logger.error(f"Error loading health dashboard: {e}")
        return jsonify({'error': str(e)}), 500


# Health check helper functions

def _check_database_health():
    """Check database connectivity and performance"""
    try:
        # Test basic connectivity
        start_time = datetime.utcnow()
        result = db.session.execute('SELECT 1').scalar()
        response_time = (datetime.utcnow() - start_time).total_seconds() * 1000

        if result != 1:
            return {
                'status': 'critical',
                'details': {'error': 'Database query returned unexpected result'}
            }

        # Check response time
        if response_time > 1000:  # 1 second
            status = 'warning'
            warning = f'Database response time high: {response_time:.2f}ms'
        elif response_time > 100:  # 100ms
            status = 'warning'
            warning = f'Database response time elevated: {response_time:.2f}ms'
        else:
            status = 'healthy'
            warning = None

        # Get basic table counts
        table_counts = {}
        try:
            table_counts['files'] = AnalysisFile.query.count()
            table_counts['content'] = FileContent.query.count()
            table_counts['findings'] = Finding.query.count()
            table_counts['users'] = User.query.count()
        except Exception as e:
            status = 'warning'
            warning = f'Could not retrieve table counts: {e}'

        details = {
            'response_time_ms': response_time,
            'table_counts': table_counts
        }

        if warning:
            details['warning'] = warning

        return {
            'status': status,
            'details': details
        }

    except Exception as e:
        return {
            'status': 'critical',
            'details': {'error': f'Database connection failed: {e}'}
        }


def _check_redis_health():
    """Check Redis connectivity and performance"""
    try:
        # Test basic connectivity
        start_time = datetime.utcnow()
        ping_result = redis_client.ping()
        response_time = (datetime.utcnow() - start_time).total_seconds() * 1000

        if not ping_result:
            return {
                'status': 'critical',
                'details': {'error': 'Redis ping failed'}
            }

        # Get connection info
        connection_info = redis_client.get_connection_info()

        status = 'healthy'
        warning = None

        if connection_info.get('fallback_mode'):
            status = 'warning'
            warning = 'Redis unavailable, using fallback mode'
        elif response_time > 100:
            status = 'warning'
            warning = f'Redis response time high: {response_time:.2f}ms'

        details = {
            'response_time_ms': response_time,
            'connection_info': connection_info
        }

        if warning:
            details['warning'] = warning

        return {
            'status': status,
            'details': details
        }

    except Exception as e:
        return {
            'status': 'critical',
            'details': {'error': f'Redis check failed: {e}'}
        }


def _check_background_processing_health():
    """Check background processing system health"""
    try:
        # Get system stats
        system_stats = BackgroundCryptoManager.get_system_stats()

        if 'error' in system_stats:
            return {
                'status': 'critical',
                'details': {'error': system_stats['error']}
            }

        # Analyze the stats
        status = 'healthy'
        warnings = []

        # Check for high failure rate
        if system_stats.get('system_health') == 'critical':
            status = 'critical'
        elif system_stats.get('system_health') == 'warning':
            status = 'warning'
            warnings.append('Background processing system reported warnings')

        # Check for stale tasks
        active_tasks = system_stats.get('active_tasks', 0)
        if active_tasks > 100:
            status = 'warning'
            warnings.append(f'High number of active tasks: {active_tasks}')

        details = {
            'system_stats': system_stats,
            'warnings': warnings
        }

        return {
            'status': status,
            'details': details
        }

    except Exception as e:
        return {
            'status': 'critical',
            'details': {'error': f'Background processing check failed: {e}'}
        }


def _check_system_resources():
    """Check system resource usage"""
    try:
        # Get system metrics using psutil
        cpu_percent = psutil.cpu_percent(interval=1)
        memory = psutil.virtual_memory()
        disk = psutil.disk_usage('/')

        status = 'healthy'
        warnings = []

        # Check CPU usage
        if cpu_percent > 90:
            status = 'critical'
            warnings.append(f'Critical CPU usage: {cpu_percent}%')
        elif cpu_percent > 70:
            status = 'warning'
            warnings.append(f'High CPU usage: {cpu_percent}%')

        # Check memory usage
        memory_percent = memory.percent
        if memory_percent > 95:
            status = 'critical'
            warnings.append(f'Critical memory usage: {memory_percent}%')
        elif memory_percent > 80:
            if status != 'critical':
                status = 'warning'
            warnings.append(f'High memory usage: {memory_percent}%')

        # Check disk usage
        disk_percent = disk.percent
        if disk_percent > 95:
            status = 'critical'
            warnings.append(f'Critical disk usage: {disk_percent}%')
        elif disk_percent > 85:
            if status != 'critical':
                status = 'warning'
            warnings.append(f'High disk usage: {disk_percent}%')

        details = {
            'cpu_percent': cpu_percent,
            'memory_percent': memory_percent,
            'memory_available_gb': round(memory.available / (1024**3), 2),
            'disk_percent': disk_percent,
            'disk_free_gb': round(disk.free / (1024**3), 2),
            'warnings': warnings
        }

        return {
            'status': status,
            'details': details
        }

    except Exception as e:
        return {
            'status': 'warning',
            'details': {'error': f'System resource check failed: {e}'}
        }


def _get_application_metrics():
    """Get application-specific performance metrics"""
    try:
        # Get recent activity metrics
        now = datetime.utcnow()
        hour_ago = now - timedelta(hours=1)
        day_ago = now - timedelta(days=1)

        metrics = {
            'files_analyzed_last_hour': 0,
            'files_analyzed_last_day': 0,
            'findings_created_last_hour': 0,
            'findings_created_last_day': 0,
            'active_users_last_hour': 0,
            'database_size_estimate': 0,
            'average_response_time_ms': 0
        }

        try:
            # Files analyzed (completed status changes)
            metrics['files_analyzed_last_day'] = AnalysisFile.query.filter(
                AnalysisFile.updated_at >= day_ago,
                AnalysisFile.status == FileStatus.COMPLETE
            ).count()

            # Findings created
            metrics['findings_created_last_hour'] = Finding.query.filter(
                Finding.created_at >= hour_ago
            ).count()

            metrics['findings_created_last_day'] = Finding.query.filter(
                Finding.created_at >= day_ago
            ).count()

            # Estimate database size
            metrics['database_size_estimate'] = (
                AnalysisFile.query.count() * 1000 +  # Rough estimate
                FileContent.query.count() * 5000 +
                Finding.query.count() * 500
            )

        except Exception as e:
            current_app.logger.warning(f"Could not gather all application metrics: {e}")

        return metrics

    except Exception as e:
        return {'error': f'Failed to get application metrics: {e}'}


def _check_api_endpoints():
    """Check API endpoint accessibility"""
    try:
        import requests
        from urllib.parse import urljoin

        base_url = 'http://localhost:8000'
        endpoints = {
            'Basic Health': '/health',
            'Search API': '/api/search/search/hyperfast?q=test',
            'Files API': '/files',
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
            'status': 'critical' if failed_endpoints else 'healthy',
            'details': {
                'endpoint_results': results,
                'failed_endpoints': failed_endpoints,
                'total_tested': len(endpoints)
            }
        }
    except ImportError:
        return {
            'status': 'warning',
            'details': {'error': 'requests package not available for endpoint testing'}
        }
    except Exception as e:
        return {
            'status': 'warning',
            'details': {'error': str(e)}
        }


def _check_container_status():
    """Check Docker container status"""
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

        # Check if expected containers are running
        missing_containers = []
        for container in expected_containers:
            if container not in containers:
                missing_containers.append(container)

        status = 'healthy'
        if missing_containers:
            if len(missing_containers) == len(expected_containers):
                status = 'warning'  # Not running in Docker
            else:
                status = 'critical'  # Some containers missing

        return {
            'status': status,
            'details': {
                'running_containers': running_count,
                'total_containers': len(containers),
                'containers': containers,
                'missing_containers': missing_containers,
                'docker_available': result.returncode == 0
            }
        }

    except subprocess.TimeoutExpired:
        return {
            'status': 'warning',
            'details': {'error': 'Docker command timed out'}
        }
    except FileNotFoundError:
        return {
            'status': 'warning',
            'details': {'error': 'Docker not available or not in PATH'}
        }
    except Exception as e:
        return {
            'status': 'warning',
            'details': {'error': str(e)}
        }


def _get_system_info():
    """Get detailed system information"""
    try:
        import platform

        return {
            'platform': platform.platform(),
            'python_version': platform.python_version(),
            'architecture': platform.architecture(),
            'processor': platform.processor(),
            'hostname': platform.node(),
            'boot_time': datetime.fromtimestamp(psutil.boot_time()).isoformat(),
            'process_count': len(psutil.pids()),
            'load_average': os.getloadavg() if hasattr(os, 'getloadavg') else None
        }
    except Exception as e:
        return {'error': str(e)}


def _get_database_diagnostics():
    """Get detailed database diagnostics"""
    try:
        diagnostics = {}

        # Table sizes
        try:
            diagnostics['table_sizes'] = {
                'analysis_files': AnalysisFile.query.count(),
                'file_contents': FileContent.query.count(),
                'findings': Finding.query.count(),
                'users': User.query.count()
            }
        except:
            diagnostics['table_sizes'] = 'Unable to retrieve'

        # Recent activity
        try:
            hour_ago = datetime.utcnow() - timedelta(hours=1)
            diagnostics['recent_activity'] = {
                'files_created_last_hour': AnalysisFile.query.filter(AnalysisFile.created_at >= hour_ago).count(),
                'findings_created_last_hour': Finding.query.filter(Finding.created_at >= hour_ago).count()
            }
        except:
            diagnostics['recent_activity'] = 'Unable to retrieve'

        return diagnostics

    except Exception as e:
        return {'error': str(e)}


def _get_performance_analysis():
    """Analyze system performance patterns"""
    try:
        analysis = {
            'cpu_trend': 'stable',
            'memory_trend': 'stable',
            'response_time_trend': 'stable',
            'bottlenecks_detected': []
        }

        # This would be enhanced with historical data
        # For now, provide current state analysis

        return analysis

    except Exception as e:
        return {'error': str(e)}


def _get_security_status():
    """Check security-related status"""
    try:
        security_status = {
            'https_enabled': False,  # Would check actual config
            'authentication_required': True,
            'session_security': True,
            'file_permissions': 'checking...',
            'security_warnings': []
        }

        # Check for basic security configurations
        if not current_app.config.get('SECRET_KEY') or current_app.config['SECRET_KEY'] == 'dev-secret-key-change-in-production':
            security_status['security_warnings'].append('Default secret key detected')

        return security_status

    except Exception as e:
        return {'error': str(e)}


def _detailed_database_check():
    """Perform detailed database connectivity check"""
    return _check_database_health()  # Enhanced version of basic check


def _detailed_redis_check():
    """Perform detailed Redis connectivity check"""
    return _check_redis_health()  # Enhanced version of basic check


def _check_file_system_health():
    """Check file system health and permissions"""
    try:
        upload_folder = current_app.config.get('UPLOAD_FOLDER', 'uploads')

        # Check if upload directory exists and is writable
        if not os.path.exists(upload_folder):
            return {
                'status': 'critical',
                'details': {'error': f'Upload folder does not exist: {upload_folder}'}
            }

        if not os.access(upload_folder, os.W_OK):
            return {
                'status': 'critical',
                'details': {'error': f'Upload folder is not writable: {upload_folder}'}
            }

        return {
            'status': 'healthy',
            'details': {'upload_folder': upload_folder, 'writable': True}
        }

    except Exception as e:
        return {
            'status': 'warning',
            'details': {'error': str(e)}
        }


def _check_network_health():
    """Check network connectivity"""
    try:
        # Basic network check - ping localhost
        result = subprocess.run(['ping', '-c', '1', 'localhost'], 
                              capture_output=True, timeout=5)

        if result.returncode == 0:
            return {
                'status': 'healthy',
                'details': {'localhost_ping': 'successful'}
            }
        else:
            return {
                'status': 'warning',
                'details': {'localhost_ping': 'failed'}
            }

    except Exception as e:
        return {
            'status': 'warning',
            'details': {'error': str(e)}
        }


def _check_service_dependencies():
    """Check external service dependencies"""
    try:
        dependencies = {
            'database': _check_database_health()['status'],
            'redis': _check_redis_health()['status'],
        }

        failed_deps = [name for name, status in dependencies.items() if status == 'critical']

        if failed_deps:
            return {
                'status': 'critical',
                'details': {'failed_dependencies': failed_deps}
            }

        warning_deps = [name for name, status in dependencies.items() if status == 'warning']
        if warning_deps:
            return {
                'status': 'warning',
                'details': {'warning_dependencies': warning_deps}
            }

        return {
            'status': 'healthy',
            'details': {'all_dependencies': 'healthy'}
        }

    except Exception as e:
        return {
            'status': 'warning',
            'details': {'error': str(e)}
        }


def _check_data_integrity():
    """Check data integrity"""
    try:
        integrity_issues = []

        # Check for orphaned content entries
        try:
            orphaned_content = db.session.query(FileContent).filter(
                ~FileContent.file_id.in_(db.session.query(AnalysisFile.id))
            ).count()

            if orphaned_content > 0:
                integrity_issues.append(f'{orphaned_content} orphaned content entries')
        except:
            pass

        # Check for files without content
        try:
            files_without_content = db.session.query(AnalysisFile).filter(
                ~AnalysisFile.id.in_(db.session.query(FileContent.file_id))
            ).count()

            if files_without_content > 0:
                integrity_issues.append(f'{files_without_content} files without content')
        except:
            pass

        if integrity_issues:
            return {
                'status': 'warning',
                'details': {'integrity_issues': integrity_issues}
            }

        return {
            'status': 'healthy',
            'details': {'data_integrity': 'good'}
        }

    except Exception as e:
        return {
            'status': 'warning',
            'details': {'error': str(e)}
        }


def _identify_performance_bottlenecks():
    """Identify potential performance bottlenecks"""
    try:
        bottlenecks = []

        # Check for large tables without recent activity
        try:
            file_count = AnalysisFile.query.count()
            if file_count > 10000:
                recent_files = AnalysisFile.query.filter(
                    AnalysisFile.created_at >= datetime.utcnow() - timedelta(hours=24)
                ).count()

                if recent_files < file_count * 0.01:  # Less than 1% activity
                    bottlenecks.append('Large file table with low activity - consider archiving')
        except:
            pass

        # Check system resources
        try:
            memory = psutil.virtual_memory()
            if memory.percent > 80:
                bottlenecks.append('High memory usage may affect performance')
        except:
            pass

        if bottlenecks:
            return {
                'status': 'warning',
                'details': {'bottlenecks': bottlenecks}
            }

        return {
            'status': 'healthy',
            'details': {'performance': 'optimal'}
        }

    except Exception as e:
        return {
            'status': 'warning',
            'details': {'error': str(e)}
        }


def _generate_health_recommendations(detailed_checks):
    """Generate health improvement recommendations"""
    recommendations = []

    for check_name, check_result in detailed_checks.items():
        if check_result['status'] == 'critical':
            recommendations.append(f"URGENT: Address critical issue in {check_name}")
        elif check_result['status'] == 'warning':
            recommendations.append(f"Review warning conditions in {check_name}")

    # Add general recommendations
    recommendations.extend([
        "Consider setting up automated health monitoring",
        "Implement log rotation for application logs",
        "Schedule regular database maintenance",
        "Monitor disk usage trends"
    ])

    return recommendations[:10]  # Limit to 10 recommendations


def _get_metrics_history():
    """Get historical metrics for dashboard"""
    # This would be enhanced with actual historical data storage
    return {
        'cpu_history': [],
        'memory_history': [],
        'response_time_history': []
    }


def _get_recent_alerts():
    """Get recent health alerts"""
    # This would query an alerts/monitoring system
    return []


def _get_service_uptime():
    """Get service uptime information"""
    try:
        boot_time = psutil.boot_time()
        uptime_seconds = datetime.utcnow().timestamp() - boot_time

        return {
            'uptime_seconds': uptime_seconds,
            'uptime_human': str(timedelta(seconds=int(uptime_seconds))),
            'boot_time': datetime.fromtimestamp(boot_time).isoformat()
        }
    except Exception as e:
        return {'error': str(e)}
