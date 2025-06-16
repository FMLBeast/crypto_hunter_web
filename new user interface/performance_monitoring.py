"""
crypto_hunter_web/monitoring/performance_metrics.py
Comprehensive performance monitoring and metrics collection system
"""

import time
import psutil
import logging
import threading
from typing import Dict, List, Optional, Any, Callable
from datetime import datetime, timedelta
from dataclasses import dataclass, field
from collections import defaultdict, deque
from functools import wraps
import json

from prometheus_client import (
    Counter, Histogram, Gauge, Summary, Info,
    CollectorRegistry, generate_latest, CONTENT_TYPE_LATEST
)
from flask import Flask, Response, request
import redis

logger = logging.getLogger(__name__)


@dataclass
class MetricPoint:
    """Individual metric data point"""
    timestamp: datetime
    value: float
    labels: Dict[str, str] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'timestamp': self.timestamp.isoformat(),
            'value': self.value,
            'labels': self.labels
        }


@dataclass
class PerformanceAlert:
    """Performance alert definition"""
    metric_name: str
    threshold: float
    operator: str  # 'gt', 'lt', 'eq'
    duration_seconds: int
    severity: str  # 'warning', 'critical'
    message: str
    webhook_url: Optional[str] = None
    last_triggered: Optional[datetime] = None
    is_active: bool = False


class AgentMetricsCollector:
    """Collect metrics specific to agent operations"""
    
    def __init__(self, registry: CollectorRegistry = None):
        self.registry = registry or CollectorRegistry()
        
        # Agent execution metrics
        self.agent_executions_total = Counter(
            'crypto_hunter_agent_executions_total',
            'Total number of agent executions',
            ['agent_type', 'task_type', 'status'],
            registry=self.registry
        )
        
        self.agent_execution_duration = Histogram(
            'crypto_hunter_agent_execution_duration_seconds',
            'Time spent executing agent tasks',
            ['agent_type', 'task_type'],
            registry=self.registry
        )
        
        self.agent_queue_size = Gauge(
            'crypto_hunter_agent_queue_size',
            'Number of tasks in agent queue',
            ['priority'],
            registry=self.registry
        )
        
        self.workflow_executions_total = Counter(
            'crypto_hunter_workflow_executions_total',
            'Total number of workflow executions',
            ['workflow_name', 'status'],
            registry=self.registry
        )
        
        self.workflow_duration = Histogram(
            'crypto_hunter_workflow_duration_seconds',
            'Time spent executing workflows',
            ['workflow_name'],
            registry=self.registry
        )
        
        self.active_agents = Gauge(
            'crypto_hunter_active_agents',
            'Number of active agents',
            ['agent_type'],
            registry=self.registry
        )
        
        self.agent_utilization = Gauge(
            'crypto_hunter_agent_utilization_percent',
            'Agent utilization percentage',
            ['agent_type'],
            registry=self.registry
        )
        
        # File processing metrics
        self.files_processed_total = Counter(
            'crypto_hunter_files_processed_total',
            'Total number of files processed',
            ['file_type', 'status'],
            registry=self.registry
        )
        
        self.file_processing_duration = Histogram(
            'crypto_hunter_file_processing_duration_seconds',
            'Time spent processing files',
            ['file_type'],
            registry=self.registry
        )
        
        self.file_size_bytes = Histogram(
            'crypto_hunter_file_size_bytes',
            'Size of processed files in bytes',
            ['file_type'],
            registry=self.registry
        )
        
        # Finding and extraction metrics
        self.findings_generated_total = Counter(
            'crypto_hunter_findings_generated_total',
            'Total number of findings generated',
            ['finding_type', 'agent_type'],
            registry=self.registry
        )
        
        self.extractions_successful_total = Counter(
            'crypto_hunter_extractions_successful_total',
            'Total number of successful extractions',
            ['extractor_type'],
            registry=self.registry
        )
        
        self.cipher_solutions_total = Counter(
            'crypto_hunter_cipher_solutions_total',
            'Total number of cipher solutions',
            ['cipher_type', 'status'],
            registry=self.registry
        )
        
        # Collaboration metrics
        self.active_sessions = Gauge(
            'crypto_hunter_active_sessions',
            'Number of active collaboration sessions',
            registry=self.registry
        )
        
        self.session_users = Gauge(
            'crypto_hunter_session_users',
            'Number of users in collaboration sessions',
            ['session_id'],
            registry=self.registry
        )
        
        self.collaboration_events_total = Counter(
            'crypto_hunter_collaboration_events_total',
            'Total number of collaboration events',
            ['event_type'],
            registry=self.registry
        )


class SystemMetricsCollector:
    """Collect system-level metrics"""
    
    def __init__(self, registry: CollectorRegistry = None):
        self.registry = registry or CollectorRegistry()
        
        # System resource metrics
        self.cpu_usage_percent = Gauge(
            'crypto_hunter_cpu_usage_percent',
            'CPU usage percentage',
            registry=self.registry
        )
        
        self.memory_usage_bytes = Gauge(
            'crypto_hunter_memory_usage_bytes',
            'Memory usage in bytes',
            ['type'],  # 'used', 'available', 'total'
            registry=self.registry
        )
        
        self.disk_usage_bytes = Gauge(
            'crypto_hunter_disk_usage_bytes',
            'Disk usage in bytes',
            ['path', 'type'],  # type: 'used', 'free', 'total'
            registry=self.registry
        )
        
        self.network_bytes = Counter(
            'crypto_hunter_network_bytes_total',
            'Network bytes transferred',
            ['direction'],  # 'sent', 'received'
            registry=self.registry
        )
        
        # Application metrics
        self.http_requests_total = Counter(
            'crypto_hunter_http_requests_total',
            'Total number of HTTP requests',
            ['method', 'endpoint', 'status'],
            registry=self.registry
        )
        
        self.http_request_duration = Histogram(
            'crypto_hunter_http_request_duration_seconds',
            'Time spent processing HTTP requests',
            ['method', 'endpoint'],
            registry=self.registry
        )
        
        self.database_connections = Gauge(
            'crypto_hunter_database_connections',
            'Number of database connections',
            ['state'],  # 'active', 'idle'
            registry=self.registry
        )
        
        self.redis_operations_total = Counter(
            'crypto_hunter_redis_operations_total',
            'Total number of Redis operations',
            ['operation', 'status'],
            registry=self.registry
        )
        
        # Error tracking
        self.errors_total = Counter(
            'crypto_hunter_errors_total',
            'Total number of errors',
            ['error_type', 'component'],
            registry=self.registry
        )
        
        self.exceptions_total = Counter(
            'crypto_hunter_exceptions_total',
            'Total number of exceptions',
            ['exception_type', 'module'],
            registry=self.registry
        )


class PerformanceMonitor:
    """Main performance monitoring system"""
    
    def __init__(self, app: Flask = None, redis_client=None):
        self.app = app
        self.redis_client = redis_client or redis.Redis()
        
        # Metric collectors
        self.agent_metrics = AgentMetricsCollector()
        self.system_metrics = SystemMetricsCollector()
        
        # Performance data storage
        self.metrics_history = defaultdict(lambda: deque(maxlen=1000))
        self.alerts = []
        self.alert_history = deque(maxlen=100)
        
        # Monitoring state
        self.monitoring_enabled = True
        self.collection_interval = 15  # seconds
        self.retention_days = 7
        
        # Background monitoring thread
        self._monitoring_thread = None
        self._stop_monitoring = threading.Event()
        
        if app:
            self.init_app(app)
    
    def init_app(self, app: Flask):
        """Initialize monitoring with Flask app"""
        self.app = app
        
        # Register routes
        self._register_routes()
        
        # Register request middleware
        self._register_middleware()
        
        # Start background monitoring
        self.start_monitoring()
        
        logger.info("✅ Performance monitoring initialized")
    
    def _register_routes(self):
        """Register monitoring routes"""
        
        @self.app.route('/metrics')
        def metrics():
            """Prometheus metrics endpoint"""
            registry = CollectorRegistry()
            registry._names_to_collectors.update(self.agent_metrics.registry._names_to_collectors)
            registry._names_to_collectors.update(self.system_metrics.registry._names_to_collectors)
            
            return Response(
                generate_latest(registry),
                mimetype=CONTENT_TYPE_LATEST
            )
        
        @self.app.route('/api/monitoring/health')
        def health_check():
            """Comprehensive health check endpoint"""
            health_status = self.get_health_status()
            status_code = 200 if health_status['overall_status'] == 'healthy' else 503
            return health_status, status_code
        
        @self.app.route('/api/monitoring/performance')
        def performance_dashboard():
            """Performance dashboard data"""
            return {
                'success': True,
                'data': self.get_performance_dashboard_data()
            }
        
        @self.app.route('/api/monitoring/alerts')
        def get_alerts():
            """Get current alerts"""
            return {
                'success': True,
                'alerts': [self._alert_to_dict(alert) for alert in self.alerts],
                'alert_history': list(self.alert_history)
            }
    
    def _register_middleware(self):
        """Register request monitoring middleware"""
        
        @self.app.before_request
        def before_request():
            """Track request start time"""
            request.start_time = time.time()
        
        @self.app.after_request
        def after_request(response):
            """Track request completion and metrics"""
            if hasattr(request, 'start_time'):
                duration = time.time() - request.start_time
                
                # Record HTTP metrics
                self.system_metrics.http_requests_total.labels(
                    method=request.method,
                    endpoint=request.endpoint or 'unknown',
                    status=response.status_code
                ).inc()
                
                self.system_metrics.http_request_duration.labels(
                    method=request.method,
                    endpoint=request.endpoint or 'unknown'
                ).observe(duration)
            
            return response
    
    def start_monitoring(self):
        """Start background monitoring thread"""
        if self._monitoring_thread and self._monitoring_thread.is_alive():
            return
        
        self._stop_monitoring.clear()
        self._monitoring_thread = threading.Thread(
            target=self._monitoring_loop,
            daemon=True,
            name='PerformanceMonitor'
        )
        self._monitoring_thread.start()
        
        logger.info("📊 Performance monitoring started")
    
    def stop_monitoring(self):
        """Stop background monitoring"""
        self._stop_monitoring.set()
        if self._monitoring_thread:
            self._monitoring_thread.join(timeout=5)
        
        logger.info("🛑 Performance monitoring stopped")
    
    def _monitoring_loop(self):
        """Main monitoring loop"""
        while not self._stop_monitoring.is_set():
            try:
                self._collect_system_metrics()
                self._check_alerts()
                self._cleanup_old_data()
                
                # Wait for next collection interval
                if self._stop_monitoring.wait(self.collection_interval):
                    break
                    
            except Exception as e:
                logger.exception(f"Error in monitoring loop: {e}")
                time.sleep(5)  # Brief pause before retrying
    
    def _collect_system_metrics(self):
        """Collect system-level metrics"""
        try:
            # CPU metrics
            cpu_percent = psutil.cpu_percent()
            self.system_metrics.cpu_usage_percent.set(cpu_percent)
            
            # Memory metrics
            memory = psutil.virtual_memory()
            self.system_metrics.memory_usage_bytes.labels(type='used').set(memory.used)
            self.system_metrics.memory_usage_bytes.labels(type='available').set(memory.available)
            self.system_metrics.memory_usage_bytes.labels(type='total').set(memory.total)
            
            # Disk metrics
            disk = psutil.disk_usage('/')
            self.system_metrics.disk_usage_bytes.labels(path='/', type='used').set(disk.used)
            self.system_metrics.disk_usage_bytes.labels(path='/', type='free').set(disk.free)
            self.system_metrics.disk_usage_bytes.labels(path='/', type='total').set(disk.total)
            
            # Network metrics
            network = psutil.net_io_counters()
            self.system_metrics.network_bytes.labels(direction='sent')._value._value = network.bytes_sent
            self.system_metrics.network_bytes.labels(direction='received')._value._value = network.bytes_recv
            
            # Store in history
            timestamp = datetime.utcnow()
            self.metrics_history['cpu_percent'].append(
                MetricPoint(timestamp, cpu_percent)
            )
            self.metrics_history['memory_percent'].append(
                MetricPoint(timestamp, (memory.used / memory.total) * 100)
            )
            self.metrics_history['disk_percent'].append(
                MetricPoint(timestamp, (disk.used / disk.total) * 100)
            )
            
        except Exception as e:
            logger.error(f"Failed to collect system metrics: {e}")
    
    def _check_alerts(self):
        """Check alert conditions"""
        current_time = datetime.utcnow()
        
        for alert in self.alerts:
            try:
                # Get current metric value
                metric_value = self._get_current_metric_value(alert.metric_name)
                if metric_value is None:
                    continue
                
                # Check threshold
                threshold_exceeded = False
                if alert.operator == 'gt' and metric_value > alert.threshold:
                    threshold_exceeded = True
                elif alert.operator == 'lt' and metric_value < alert.threshold:
                    threshold_exceeded = True
                elif alert.operator == 'eq' and abs(metric_value - alert.threshold) < 0.001:
                    threshold_exceeded = True
                
                # Check duration
                if threshold_exceeded:
                    if not alert.is_active:
                        # Start tracking this alert
                        alert.last_triggered = current_time
                        alert.is_active = True
                    elif (current_time - alert.last_triggered).total_seconds() >= alert.duration_seconds:
                        # Alert condition met, trigger notification
                        self._trigger_alert(alert, metric_value)
                else:
                    # Reset alert state
                    alert.is_active = False
                    alert.last_triggered = None
                    
            except Exception as e:
                logger.error(f"Error checking alert {alert.metric_name}: {e}")
    
    def _get_current_metric_value(self, metric_name: str) -> Optional[float]:
        """Get current value for a metric"""
        # Map metric names to actual values
        metric_mapping = {
            'cpu_percent': lambda: psutil.cpu_percent(),
            'memory_percent': lambda: psutil.virtual_memory().percent,
            'disk_percent': lambda: psutil.disk_usage('/').percent,
            'agent_queue_size': lambda: len(self.metrics_history.get('agent_queue', [])),
            'error_rate': lambda: self._calculate_error_rate(),
        }
        
        getter = metric_mapping.get(metric_name)
        if getter:
            try:
                return getter()
            except Exception as e:
                logger.error(f"Failed to get metric {metric_name}: {e}")
        
        return None
    
    def _calculate_error_rate(self) -> float:
        """Calculate recent error rate"""
        # This is a simplified calculation
        # In production, you'd want more sophisticated error rate calculation
        recent_errors = len([
            point for point in self.metrics_history.get('errors', [])
            if (datetime.utcnow() - point.timestamp).total_seconds() < 300  # Last 5 minutes
        ])
        return recent_errors
    
    def _trigger_alert(self, alert: PerformanceAlert, current_value: float):
        """Trigger an alert notification"""
        alert_data = {
            'alert_id': id(alert),
            'metric_name': alert.metric_name,
            'threshold': alert.threshold,
            'current_value': current_value,
            'severity': alert.severity,
            'message': alert.message.format(
                metric=alert.metric_name,
                value=current_value,
                threshold=alert.threshold
            ),
            'timestamp': datetime.utcnow().isoformat()
        }
        
        # Store in alert history
        self.alert_history.appendleft(alert_data)
        
        # Send webhook notification if configured
        if alert.webhook_url:
            self._send_webhook_alert(alert.webhook_url, alert_data)
        
        logger.warning(
            f"Alert triggered: {alert.metric_name} = {current_value} "
            f"(threshold: {alert.threshold}, severity: {alert.severity})"
        )
    
    def _send_webhook_alert(self, webhook_url: str, alert_data: Dict[str, Any]):
        """Send alert to webhook"""
        try:
            import requests
            
            payload = {
                'type': 'crypto_hunter_alert',
                'alert': alert_data,
                'timestamp': datetime.utcnow().isoformat()
            }
            
            response = requests.post(
                webhook_url,
                json=payload,
                timeout=10,
                headers={'Content-Type': 'application/json'}
            )
            
            if response.status_code == 200:
                logger.info(f"Alert webhook sent successfully to {webhook_url}")
            else:
                logger.error(f"Alert webhook failed: {response.status_code}")
                
        except Exception as e:
            logger.error(f"Failed to send alert webhook: {e}")
    
    def _cleanup_old_data(self):
        """Clean up old metric data"""
        cutoff_time = datetime.utcnow() - timedelta(days=self.retention_days)
        
        for metric_name, points in self.metrics_history.items():
            # Remove old points
            while points and points[0].timestamp < cutoff_time:
                points.popleft()
    
    def get_health_status(self) -> Dict[str, Any]:
        """Get comprehensive health status"""
        try:
            # System health checks
            cpu_percent = psutil.cpu_percent()
            memory = psutil.virtual_memory()
            disk = psutil.disk_usage('/')
            
            # Application health checks
            db_healthy = self._check_database_health()
            redis_healthy = self._check_redis_health()
            agent_system_healthy = self._check_agent_system_health()
            
            # Determine overall status
            critical_issues = []
            warnings = []
            
            if cpu_percent > 90:
                critical_issues.append(f"High CPU usage: {cpu_percent}%")
            elif cpu_percent > 75:
                warnings.append(f"Elevated CPU usage: {cpu_percent}%")
            
            if memory.percent > 90:
                critical_issues.append(f"High memory usage: {memory.percent}%")
            elif memory.percent > 75:
                warnings.append(f"Elevated memory usage: {memory.percent}%")
            
            if (disk.used / disk.total) * 100 > 90:
                critical_issues.append(f"High disk usage: {(disk.used / disk.total) * 100:.1f}%")
            
            if not db_healthy:
                critical_issues.append("Database connection failed")
            
            if not redis_healthy:
                warnings.append("Redis connection issues")
            
            if not agent_system_healthy:
                warnings.append("Agent system issues detected")
            
            # Overall status
            if critical_issues:
                overall_status = "critical"
            elif warnings:
                overall_status = "warning"
            else:
                overall_status = "healthy"
            
            return {
                'overall_status': overall_status,
                'timestamp': datetime.utcnow().isoformat(),
                'system': {
                    'cpu_percent': cpu_percent,
                    'memory_percent': memory.percent,
                    'disk_percent': (disk.used / disk.total) * 100,
                    'uptime_seconds': time.time() - psutil.boot_time()
                },
                'services': {
                    'database': 'healthy' if db_healthy else 'unhealthy',
                    'redis': 'healthy' if redis_healthy else 'unhealthy',
                    'agent_system': 'healthy' if agent_system_healthy else 'unhealthy'
                },
                'issues': {
                    'critical': critical_issues,
                    'warnings': warnings
                },
                'active_alerts': len([a for a in self.alerts if a.is_active])
            }
            
        except Exception as e:
            logger.exception(f"Failed to get health status: {e}")
            return {
                'overall_status': 'unknown',
                'error': str(e),
                'timestamp': datetime.utcnow().isoformat()
            }
    
    def _check_database_health(self) -> bool:
        """Check database connectivity"""
        try:
            from crypto_hunter_web.extensions import db
            # Simple query to test connectivity
            db.session.execute('SELECT 1')
            return True
        except Exception:
            return False
    
    def _check_redis_health(self) -> bool:
        """Check Redis connectivity"""
        try:
            self.redis_client.ping()
            return True
        except Exception:
            return False
    
    def _check_agent_system_health(self) -> bool:
        """Check agent system health"""
        try:
            from crypto_hunter_web.services.complete_agent_system import complete_agent_system
            status = complete_agent_system.get_system_status()
            return status.get('initialized', False)
        except Exception:
            return False
    
    def get_performance_dashboard_data(self) -> Dict[str, Any]:
        """Get data for performance dashboard"""
        try:
            # Recent metrics (last hour)
            recent_cpu = [
                point.to_dict() for point in self.metrics_history['cpu_percent']
                if (datetime.utcnow() - point.timestamp).total_seconds() < 3600
            ]
            
            recent_memory = [
                point.to_dict() for point in self.metrics_history['memory_percent']
                if (datetime.utcnow() - point.timestamp).total_seconds() < 3600
            ]
            
            # Agent metrics
            agent_stats = self._get_agent_performance_stats()
            
            # System summary
            system_summary = {
                'cpu_current': psutil.cpu_percent(),
                'memory_current': psutil.virtual_memory().percent,
                'disk_current': psutil.disk_usage('/').percent,
                'active_agents': agent_stats.get('active_agents', 0),
                'running_workflows': agent_stats.get('running_workflows', 0),
                'queued_tasks': agent_stats.get('queued_tasks', 0)
            }
            
            return {
                'timestamp': datetime.utcnow().isoformat(),
                'system_summary': system_summary,
                'metrics_history': {
                    'cpu_percent': recent_cpu,
                    'memory_percent': recent_memory
                },
                'agent_performance': agent_stats,
                'alerts': {
                    'active': len([a for a in self.alerts if a.is_active]),
                    'total': len(self.alerts)
                }
            }
            
        except Exception as e:
            logger.exception(f"Failed to get dashboard data: {e}")
            return {'error': str(e)}
    
    def _get_agent_performance_stats(self) -> Dict[str, Any]:
        """Get agent system performance statistics"""
        try:
            from crypto_hunter_web.services.complete_agent_system import complete_agent_system
            
            if not complete_agent_system.initialized:
                return {}
            
            status = complete_agent_system.get_system_status()
            
            return {
                'active_agents': len(status.get('agents', {})),
                'running_workflows': status.get('orchestrator', {}).get('active_workflows', 0),
                'queued_tasks': status.get('task_queue', {}).get('pending_tasks', 0),
                'agent_types': list(status.get('agents', {}).keys()),
                'database_records': status.get('database', {})
            }
            
        except Exception as e:
            logger.error(f"Failed to get agent performance stats: {e}")
            return {}
    
    def add_alert(self, metric_name: str, threshold: float, operator: str = 'gt',
                  duration_seconds: int = 300, severity: str = 'warning',
                  message: str = None, webhook_url: str = None):
        """Add a performance alert"""
        if message is None:
            message = f"Alert: {metric_name} {operator} {threshold}"
        
        alert = PerformanceAlert(
            metric_name=metric_name,
            threshold=threshold,
            operator=operator,
            duration_seconds=duration_seconds,
            severity=severity,
            message=message,
            webhook_url=webhook_url
        )
        
        self.alerts.append(alert)
        logger.info(f"Added alert: {metric_name} {operator} {threshold}")
    
    def _alert_to_dict(self, alert: PerformanceAlert) -> Dict[str, Any]:
        """Convert alert to dictionary"""
        return {
            'metric_name': alert.metric_name,
            'threshold': alert.threshold,
            'operator': alert.operator,
            'duration_seconds': alert.duration_seconds,
            'severity': alert.severity,
            'message': alert.message,
            'is_active': alert.is_active,
            'last_triggered': alert.last_triggered.isoformat() if alert.last_triggered else None
        }
    
    # Decorator for timing functions
    def time_function(self, metric_name: str, labels: Dict[str, str] = None):
        """Decorator to time function execution"""
        def decorator(func: Callable) -> Callable:
            @wraps(func)
            def wrapper(*args, **kwargs):
                start_time = time.time()
                try:
                    result = func(*args, **kwargs)
                    status = 'success'
                    return result
                except Exception as e:
                    status = 'error'
                    self.system_metrics.errors_total.labels(
                        error_type=type(e).__name__,
                        component=func.__module__
                    ).inc()
                    raise
                finally:
                    duration = time.time() - start_time
                    
                    # Record timing metric
                    if hasattr(self.agent_metrics, metric_name):
                        metric = getattr(self.agent_metrics, metric_name)
                        if labels:
                            metric.labels(**labels).observe(duration)
                        else:
                            metric.observe(duration)
            
            return wrapper
        return decorator


# Global performance monitor instance
performance_monitor = PerformanceMonitor()


def setup_performance_monitoring(app: Flask, redis_client=None) -> PerformanceMonitor:
    """Setup performance monitoring system"""
    global performance_monitor
    
    performance_monitor = PerformanceMonitor(app, redis_client)
    
    # Add default alerts
    performance_monitor.add_alert(
        'cpu_percent', 85, 'gt', 300, 'warning',
        'High CPU usage detected: {value}% > {threshold}%'
    )
    
    performance_monitor.add_alert(
        'memory_percent', 90, 'gt', 300, 'critical',
        'Critical memory usage: {value}% > {threshold}%'
    )
    
    performance_monitor.add_alert(
        'disk_percent', 95, 'gt', 600, 'critical',
        'Critical disk usage: {value}% > {threshold}%'
    )
    
    performance_monitor.add_alert(
        'error_rate', 10, 'gt', 180, 'warning',
        'High error rate detected: {value} errors/5min'
    )
    
    logger.info("✅ Performance monitoring setup complete")
    return performance_monitor


def get_performance_monitor() -> PerformanceMonitor:
    """Get the global performance monitor instance"""
    return performance_monitor


# Integration decorators for agent metrics
def track_agent_execution(agent_type: str, task_type: str):
    """Decorator to track agent execution metrics"""
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        async def wrapper(*args, **kwargs):
            start_time = time.time()
            status = 'success'
            
            try:
                result = await func(*args, **kwargs)
                if hasattr(result, 'success') and not result.success:
                    status = 'failed'
                return result
            except Exception as e:
                status = 'error'
                performance_monitor.system_metrics.exceptions_total.labels(
                    exception_type=type(e).__name__,
                    module=func.__module__
                ).inc()
                raise
            finally:
                duration = time.time() - start_time
                
                # Record metrics
                performance_monitor.agent_metrics.agent_executions_total.labels(
                    agent_type=agent_type,
                    task_type=task_type,
                    status=status
                ).inc()
                
                performance_monitor.agent_metrics.agent_execution_duration.labels(
                    agent_type=agent_type,
                    task_type=task_type
                ).observe(duration)
        
        return wrapper
    return decorator


def track_workflow_execution(workflow_name: str):
    """Decorator to track workflow execution metrics"""
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        async def wrapper(*args, **kwargs):
            start_time = time.time()
            status = 'success'
            
            try:
                result = await func(*args, **kwargs)
                return result
            except Exception as e:
                status = 'failed'
                raise
            finally:
                duration = time.time() - start_time
                
                # Record metrics
                performance_monitor.agent_metrics.workflow_executions_total.labels(
                    workflow_name=workflow_name,
                    status=status
                ).inc()
                
                performance_monitor.agent_metrics.workflow_duration.labels(
                    workflow_name=workflow_name
                ).observe(duration)
        
        return wrapper
    return decorator


if __name__ == "__main__":
    # Test performance monitoring
    import tempfile
    import os
    from flask import Flask
    
    app = Flask(__name__)
    
    # Setup monitoring
    monitor = setup_performance_monitoring(app)
    
    # Test metrics collection
    print("📊 Testing performance monitoring...")
    
    # Simulate some metrics
    monitor.agent_metrics.agent_executions_total.labels(
        agent_type='file_analysis',
        task_type='analyze_file',
        status='success'
    ).inc()
    
    monitor.agent_metrics.workflow_executions_total.labels(
        workflow_name='file_analysis',
        status='success'
    ).inc()
    
    # Get health status
    health = monitor.get_health_status()
    print(f"Health status: {health['overall_status']}")
    
    # Get dashboard data
    dashboard_data = monitor.get_performance_dashboard_data()
    print(f"Dashboard data keys: {list(dashboard_data.keys())}")
    
    print("✅ Performance monitoring test completed")