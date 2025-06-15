#!/usr/bin/env python3
"""
Flask Integration and Monitoring System for Crypto Hunter
=========================================================

Complete integration of the comprehensive extraction system with the Flask web application:
- RESTful API endpoints for comprehensive extraction
- Real-time WebSocket monitoring
- Background task management with Celery
- Progress tracking and notifications
- Storage management and cleanup
- Configuration management
- Error recovery and resilience
- Performance monitoring and alerting

This ties together all the advanced extraction capabilities with the web interface.
"""

import json
import logging
import os
import sys
import threading
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, Any

from celery import Celery, Task
from celery.bin import celery
from celery.result import AsyncResult
# Flask and web components
from flask import Blueprint, request, jsonify, current_app, send_file
from flask_login import login_required, current_user
from flask_socketio import emit, join_room, leave_room

# Add project path
project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
sys.path.append(project_root)

# Import our comprehensive systems
from crypto_hunter_web import db
from crypto_hunter_web.models import AnalysisFile, Finding, ExtractionRelationship

# Import our new systems
try:
    from crypto_hunter_web.services.extraction.comprehensive_extractor_system import ComprehensiveExtractorSystem
    from crypto_hunter_web.services.extraction.performance_optimization_system import OptimizedExtractionOrchestrator
    from crypto_hunter_web.services.extraction.missing_extractors_integration import register_missing_extractors
    from crypto_hunter_web.services.extraction.advanced_steganography_methods import register_advanced_stegano_extractors
except ImportError as e:
    logging.warning(f"Could not import comprehensive systems: {e}")

logger = logging.getLogger(__name__)

# Create blueprint for comprehensive extraction API
comprehensive_bp = Blueprint('comprehensive', __name__, url_prefix='/api/comprehensive')

# Global task registry for monitoring
ACTIVE_EXTRACTIONS = {}
EXTRACTION_LOCK = threading.RLock()

class ComprehensiveExtractionTask(Task):
    """Custom Celery task for comprehensive extraction"""
    
    def on_success(self, retval, task_id, args, kwargs):
        """Called on task success"""
        with EXTRACTION_LOCK:
            if task_id in ACTIVE_EXTRACTIONS:
                ACTIVE_EXTRACTIONS[task_id]['status'] = 'completed'
                ACTIVE_EXTRACTIONS[task_id]['completed_at'] = datetime.now()
                ACTIVE_EXTRACTIONS[task_id]['result'] = retval
        
        # Emit WebSocket notification
        self._emit_status_update(task_id, 'completed', retval)
    
    def on_failure(self, exc, task_id, args, kwargs, einfo):
        """Called on task failure"""
        with EXTRACTION_LOCK:
            if task_id in ACTIVE_EXTRACTIONS:
                ACTIVE_EXTRACTIONS[task_id]['status'] = 'failed'
                ACTIVE_EXTRACTIONS[task_id]['error'] = str(exc)
                ACTIVE_EXTRACTIONS[task_id]['completed_at'] = datetime.now()
        
        # Emit WebSocket notification
        self._emit_status_update(task_id, 'failed', {'error': str(exc)})
    
    def _emit_status_update(self, task_id: str, status: str, data: Any = None):
        """Emit status update via WebSocket"""
        try:
            from crypto_hunter_web import socketio
            socketio.emit('extraction_status', {
                'task_id': task_id,
                'status': status,
                'data': data,
                'timestamp': datetime.now().isoformat()
            }, room=f'extraction_{task_id}')
        except Exception as e:
            logger.warning(f"Failed to emit status update: {e}")

# Initialize Celery with custom task
def make_celery(app):
    """Create Celery instance"""
    celery = Celery(
        app.import_name,
        backend=app.config.get('CELERY_RESULT_BACKEND', 'redis://localhost:6379/0'),
        broker=app.config.get('CELERY_BROKER_URL', 'redis://localhost:6379/0')
    )
    celery.conf.update(app.config)
    
    # Register custom task
    celery.Task = ComprehensiveExtractionTask
    
    return celery

# Configuration management
class ConfigurationManager:
    """Manage configuration for comprehensive extraction"""
    
    def __init__(self, config_file=None):
        self.config_file = config_file or os.path.join(
            os.path.dirname(os.path.abspath(__file__)),
            'config',
            'comprehensive_extraction.json'
        )
    
    def load_config(self) -> Dict[str, Any]:
        """Load configuration from file or use defaults"""
        try:
            if os.path.exists(self.config_file):
                with open(self.config_file, 'r') as f:
                    config = json.load(f)
                logger.info(f"Loaded configuration from {self.config_file}")
                return config
        except Exception as e:
            logger.warning(f"Failed to load configuration: {e}")
        
        # Return default configuration
        return self._get_default_config()
    
    def save_config(self, config: Dict[str, Any]) -> bool:
        """Save configuration to file"""
        try:
            # Create directory if it doesn't exist
            os.makedirs(os.path.dirname(self.config_file), exist_ok=True)
            
            with open(self.config_file, 'w') as f:
                json.dump(config, f, indent=2)
            
            logger.info(f"Saved configuration to {self.config_file}")
            return True
        except Exception as e:
            logger.error(f"Failed to save configuration: {e}")
            return False
    
    def _get_default_config(self) -> Dict[str, Any]:
        """Get default configuration"""
        return {
            'max_workers': 4,
            'max_memory_mb': 1024,
            'extraction_timeout': 3600,  # 1 hour
            'cache_size': 10000,
            'batch_size': 100,
            'enable_deduplication': True,
            'extractors': {
                'steganography': ['zsteg', 'steghide', 'multilayer_stegano', 'frequency_domain_analyzer'],
                'archives': ['zip_password_crack', 'rar5_extractor', '7zip_extractor'],
                'binary': ['binwalk', 'foremost', 'strings'],
                'advanced': ['volatility_analyzer', 'pcap_analyzer', 'sqlite_analyzer']
            }
        }

# Storage management
class StorageManager:
    """Manage storage for extraction results"""
    
    def __init__(self, base_dir=None):
        self.base_dir = base_dir or os.path.join(
            os.path.dirname(os.path.abspath(__file__)),
            'extractions'
        )
        os.makedirs(self.base_dir, exist_ok=True)
    
    def get_storage_stats(self) -> Dict[str, Any]:
        """Get storage statistics"""
        total_size = 0
        file_count = 0
        
        for root, dirs, files in os.walk(self.base_dir):
            for file in files:
                file_path = os.path.join(root, file)
                if os.path.isfile(file_path):
                    total_size += os.path.getsize(file_path)
                    file_count += 1
        
        return {
            'base_dir': self.base_dir,
            'total_size_bytes': total_size,
            'total_size_gb': total_size / (1024 * 1024 * 1024),
            'file_count': file_count,
            'last_updated': datetime.now().isoformat()
        }
    
    def cleanup_old_extractions(self, max_age_days: int = 30) -> Dict[str, Any]:
        """Clean up old extraction results"""
        cutoff_date = datetime.now() - timedelta(days=max_age_days)
        deleted_count = 0
        freed_bytes = 0
        
        for root, dirs, files in os.walk(self.base_dir):
            for file in files:
                file_path = os.path.join(root, file)
                if os.path.isfile(file_path):
                    file_mtime = datetime.fromtimestamp(os.path.getmtime(file_path))
                    if file_mtime < cutoff_date:
                        file_size = os.path.getsize(file_path)
                        try:
                            os.remove(file_path)
                            deleted_count += 1
                            freed_bytes += file_size
                        except Exception as e:
                            logger.warning(f"Failed to delete {file_path}: {e}")
        
        # Clean up empty directories
        for root, dirs, files in os.walk(self.base_dir, topdown=False):
            for dir_name in dirs:
                dir_path = os.path.join(root, dir_name)
                if not os.listdir(dir_path):
                    try:
                        os.rmdir(dir_path)
                    except Exception as e:
                        logger.warning(f"Failed to remove empty directory {dir_path}: {e}")
        
        return {
            'deleted_count': deleted_count,
            'freed_bytes': freed_bytes,
            'freed_gb': freed_bytes / (1024 * 1024 * 1024),
            'max_age_days': max_age_days,
            'cutoff_date': cutoff_date.isoformat()
        }
    
    def get_extraction_path(self, task_id: str) -> str:
        """Get path for extraction results"""
        extraction_dir = os.path.join(self.base_dir, task_id)
        os.makedirs(extraction_dir, exist_ok=True)
        return extraction_dir

# System monitoring
class SystemMonitor:
    """Monitor system performance and health"""
    
    def __init__(self):
        self.alerts = []
        self.metrics = {
            'cpu_usage': [],
            'memory_usage': [],
            'disk_usage': [],
            'extraction_times': []
        }
        self.start_time = datetime.now()
    
    def add_alert(self, alert_type: str, message: str, severity: str = 'info'):
        """Add system alert"""
        self.alerts.append({
            'type': alert_type,
            'message': message,
            'severity': severity,
            'timestamp': datetime.now()
        })
        
        # Keep only the last 100 alerts
        if len(self.alerts) > 100:
            self.alerts = self.alerts[-100:]
    
    def record_metric(self, metric_type: str, value: float):
        """Record system metric"""
        if metric_type in self.metrics:
            self.metrics[metric_type].append({
                'value': value,
                'timestamp': datetime.now()
            })
            
            # Keep only the last 1000 metrics of each type
            if len(self.metrics[metric_type]) > 1000:
                self.metrics[metric_type] = self.metrics[metric_type][-1000:]
    
    def get_system_health(self) -> Dict[str, Any]:
        """Get system health metrics"""
        try:
            cpu_percent = psutil.cpu_percent(interval=0.1)
            memory = psutil.virtual_memory()
            disk = psutil.disk_usage('/')
            
            # Record metrics
            self.record_metric('cpu_usage', cpu_percent)
            self.record_metric('memory_usage', memory.percent)
            self.record_metric('disk_usage', disk.percent)
            
            # Check for warning conditions
            if cpu_percent > 90:
                self.add_alert('high_cpu', f'High CPU usage: {cpu_percent}%', 'warning')
            
            if memory.percent > 90:
                self.add_alert('high_memory', f'High memory usage: {memory.percent}%', 'warning')
            
            if disk.percent > 90:
                self.add_alert('high_disk', f'High disk usage: {disk.percent}%', 'warning')
            
            return {
                'cpu_percent': cpu_percent,
                'memory_percent': memory.percent,
                'disk_percent': disk.percent,
                'uptime_seconds': (datetime.now() - self.start_time).total_seconds(),
                'active_extractions': len(ACTIVE_EXTRACTIONS),
                'alert_count': len(self.alerts)
            }
        except Exception as e:
            logger.error(f"Failed to get system health: {e}")
            return {
                'error': str(e),
                'active_extractions': len(ACTIVE_EXTRACTIONS),
                'alert_count': len(self.alerts)
            }

# WebSocket event handlers
def register_websocket_events(socketio):
    """Register WebSocket event handlers"""
    
    @socketio.on('connect')
    def handle_connect():
        """Handle client connection"""
        logger.info(f"Client connected: {request.sid}")
    
    @socketio.on('disconnect')
    def handle_disconnect():
        """Handle client disconnection"""
        logger.info(f"Client disconnected: {request.sid}")
    
    @socketio.on('join_extraction')
    def handle_join_extraction(data):
        """Join extraction room to receive updates"""
        task_id = data.get('task_id')
        if task_id:
            room = f'extraction_{task_id}'
            join_room(room)
            logger.info(f"Client {request.sid} joined room {room}")
            
            # Send current status if available
            with EXTRACTION_LOCK:
                if task_id in ACTIVE_EXTRACTIONS:
                    emit('extraction_status', {
                        'task_id': task_id,
                        'status': ACTIVE_EXTRACTIONS[task_id]['status'],
                        'data': ACTIVE_EXTRACTIONS[task_id].get('result', {}),
                        'timestamp': datetime.now().isoformat()
                    })
    
    @socketio.on('leave_extraction')
    def handle_leave_extraction(data):
        """Leave extraction room"""
        task_id = data.get('task_id')
        if task_id:
            room = f'extraction_{task_id}'
            leave_room(room)
            logger.info(f"Client {request.sid} left room {room}")

# API endpoints
@comprehensive_bp.route('/extract', methods=['POST'])
@login_required
def start_extraction():
    """Start comprehensive extraction"""
    try:
        data = request.get_json() or {}
        
        # Get file ID
        file_id = data.get('file_id')
        if not file_id:
            return jsonify({'error': 'file_id is required'}), 400
        
        # Get file record
        file_record = AnalysisFile.query.get(file_id)
        if not file_record:
            return jsonify({'error': f'File not found: {file_id}'}), 404
        
        # Get extraction options
        options = data.get('options', {})
        
        # Create task ID
        task_id = f"extraction_{int(time.time())}_{file_id}"
        
        # Get output directory
        storage_manager = current_app.storage_manager
        output_dir = storage_manager.get_extraction_path(task_id)
        
        # Register task in active extractions
        with EXTRACTION_LOCK:
            ACTIVE_EXTRACTIONS[task_id] = {
                'file_id': file_id,
                'user_id': current_user.id,
                'status': 'pending',
                'created_at': datetime.now(),
                'options': options,
                'output_dir': output_dir
            }
        
        # Load configuration
        config_manager = current_app.config_manager
        config = config_manager.load_config()
        
        # Update config with options
        for key, value in options.items():
            if key in config:
                config[key] = value
        
        # Start extraction task
        from crypto_hunter_web.tasks.extraction_tasks import comprehensive_extraction_task
        task = comprehensive_extraction_task.delay(
            file_record.filepath,
            file_id,
            output_dir,
            config,
            current_user.id
        )
        
        # Update task ID in registry
        with EXTRACTION_LOCK:
            ACTIVE_EXTRACTIONS[task_id]['celery_task_id'] = task.id
        
        return jsonify({
            'task_id': task_id,
            'status': 'pending',
            'file_id': file_id,
            'output_dir': output_dir
        })
        
    except Exception as e:
        logger.error(f"Failed to start extraction: {e}")
        return jsonify({'error': str(e)}), 500

@comprehensive_bp.route('/status/<task_id>')
@login_required
def get_extraction_status(task_id):
    """Get extraction status"""
    try:
        # Check if task is in active extractions
        with EXTRACTION_LOCK:
            if task_id in ACTIVE_EXTRACTIONS:
                status_data = ACTIVE_EXTRACTIONS[task_id].copy()
                
                # Add elapsed time
                if 'created_at' in status_data:
                    elapsed = (datetime.now() - status_data['created_at']).total_seconds()
                    status_data['elapsed_seconds'] = elapsed
                
                return jsonify(status_data)
        
        # Check if task is in Celery
        if 'celery_task_id' in ACTIVE_EXTRACTIONS.get(task_id, {}):
            celery_task_id = ACTIVE_EXTRACTIONS[task_id]['celery_task_id']
            task_result = AsyncResult(celery_task_id)
            
            return jsonify({
                'task_id': task_id,
                'celery_task_id': celery_task_id,
                'status': task_result.status,
                'result': task_result.result if task_result.successful() else None,
                'error': str(task_result.result) if task_result.failed() else None
            })
        
        return jsonify({'error': f'Task not found: {task_id}'}), 404
        
    except Exception as e:
        logger.error(f"Failed to get extraction status: {e}")
        return jsonify({'error': str(e)}), 500

@comprehensive_bp.route('/cancel/<task_id>', methods=['POST'])
@login_required
def cancel_extraction(task_id):
    """Cancel extraction task"""
    try:
        # Check if task is in active extractions
        with EXTRACTION_LOCK:
            if task_id not in ACTIVE_EXTRACTIONS:
                return jsonify({'error': f'Task not found: {task_id}'}), 404
            
            # Get Celery task ID
            celery_task_id = ACTIVE_EXTRACTIONS[task_id].get('celery_task_id')
            if not celery_task_id:
                return jsonify({'error': 'No Celery task ID found'}), 400
            
            # Revoke Celery task
            from celery.task.control import revoke
            revoke(celery_task_id, terminate=True)
            
            # Update status
            ACTIVE_EXTRACTIONS[task_id]['status'] = 'cancelled'
            ACTIVE_EXTRACTIONS[task_id]['completed_at'] = datetime.now()
        
        # Emit WebSocket notification
        try:
            from crypto_hunter_web import socketio
            socketio.emit('extraction_status', {
                'task_id': task_id,
                'status': 'cancelled',
                'timestamp': datetime.now().isoformat()
            }, room=f'extraction_{task_id}')
        except Exception as e:
            logger.warning(f"Failed to emit cancellation notification: {e}")
        
        return jsonify({
            'task_id': task_id,
            'status': 'cancelled',
            'message': 'Extraction cancelled successfully'
        })
        
    except Exception as e:
        logger.error(f"Failed to cancel extraction: {e}")
        return jsonify({'error': str(e)}), 500

@comprehensive_bp.route('/results/<task_id>')
@login_required
def get_extraction_results(task_id):
    """Get extraction results"""
    try:
        # Check if task is in active extractions
        with EXTRACTION_LOCK:
            if task_id not in ACTIVE_EXTRACTIONS:
                return jsonify({'error': f'Task not found: {task_id}'}), 404
            
            # Check if task is completed
            if ACTIVE_EXTRACTIONS[task_id]['status'] != 'completed':
                return jsonify({
                    'task_id': task_id,
                    'status': ACTIVE_EXTRACTIONS[task_id]['status'],
                    'message': 'Extraction not completed yet'
                }), 202
            
            # Get results
            results = ACTIVE_EXTRACTIONS[task_id].get('result', {})
            
            return jsonify({
                'task_id': task_id,
                'status': 'completed',
                'results': results
            })
        
    except Exception as e:
        logger.error(f"Failed to get extraction results: {e}")
        return jsonify({'error': str(e)}), 500

@comprehensive_bp.route('/download/<task_id>/<path:filename>')
@login_required
def download_extraction_file(task_id, filename):
    """Download extraction file"""
    try:
        # Check if task is in active extractions
        with EXTRACTION_LOCK:
            if task_id not in ACTIVE_EXTRACTIONS:
                return jsonify({'error': f'Task not found: {task_id}'}), 404
            
            # Get output directory
            output_dir = ACTIVE_EXTRACTIONS[task_id].get('output_dir')
            if not output_dir:
                return jsonify({'error': 'Output directory not found'}), 404
            
            # Construct file path
            file_path = os.path.join(output_dir, filename)
            
            # Check if file exists
            if not os.path.isfile(file_path):
                return jsonify({'error': f'File not found: {filename}'}), 404
            
            # Send file
            return send_file(file_path, as_attachment=True)
        
    except Exception as e:
        logger.error(f"Failed to download extraction file: {e}")
        return jsonify({'error': str(e)}), 500

@comprehensive_bp.route('/config', methods=['GET', 'PUT'])
@login_required
def manage_config():
    """Get or update configuration"""
    try:
        config_manager = current_app.config_manager
        
        if request.method == 'GET':
            # Get configuration
            config = config_manager.load_config()
            return jsonify(config)
        
        elif request.method == 'PUT':
            # Update configuration
            data = request.get_json()
            if not data:
                return jsonify({'error': 'No data provided'}), 400
            
            # Save configuration
            if config_manager.save_config(data):
                return jsonify({
                    'message': 'Configuration updated successfully',
                    'config': data
                })
            else:
                return jsonify({'error': 'Failed to save configuration'}), 500
        
    except Exception as e:
        logger.error(f"Failed to manage configuration: {e}")
        return jsonify({'error': str(e)}), 500

# Initialize comprehensive extraction system
def initialize_comprehensive_system(app):
    """Initialize comprehensive extraction system"""
    try:
        # Create configuration manager
        config_manager = ConfigurationManager()
        app.config_manager = config_manager
        
        # Create storage manager
        storage_manager = StorageManager()
        app.storage_manager = storage_manager
        
        # Create system monitor
        system_monitor = SystemMonitor()
        app.system_monitor = system_monitor
        
        # Load configuration
        config = config_manager.load_config()
        
        # Initialize Celery
        app.celery = make_celery(app)
        
        # Register comprehensive blueprint
        register_comprehensive_blueprint(app)
        
        logger.info("Comprehensive extraction system initialized")
        
        return {
            'config_manager': config_manager,
            'storage_manager': storage_manager,
            'system_monitor': system_monitor,
            'config': config
        }
    
    except Exception as e:
        logger.error(f"Failed to initialize comprehensive system: {e}")
        raise

# Storage management endpoints
@comprehensive_bp.route('/storage/stats')
@login_required
def get_storage_stats():
    """Get storage statistics"""
    try:
        stats = current_app.storage_manager.get_storage_stats()
        return jsonify(stats)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@comprehensive_bp.route('/storage/cleanup', methods=['POST'])
@login_required
def cleanup_storage():
    """Clean up old extraction results"""
    try:
        data = request.get_json() or {}
        max_age_days = data.get('max_age_days', 30)
        
        result = current_app.storage_manager.cleanup_old_extractions(max_age_days)
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# System monitoring endpoints
@comprehensive_bp.route('/monitoring/alerts')
@login_required
def get_system_alerts():
    """Get system alerts"""
    try:
        alerts = current_app.system_monitor.alerts
        return jsonify({
            'alerts': [
                {
                    'type': alert['type'],
                    'message': alert['message'],
                    'timestamp': alert['timestamp'].isoformat(),
                    'severity': alert['severity']
                }
                for alert in alerts
            ]
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Register with Flask app
def register_comprehensive_blueprint(app):
    """Register comprehensive extraction blueprint with Flask app"""
    app.register_blueprint(comprehensive_bp)
    
    # Initialize WebSocket events if SocketIO is available
    if hasattr(app, 'socketio'):
        register_websocket_events(app.socketio)

if __name__ == '__main__':
    # Test the integration system
    logging.basicConfig(level=logging.INFO)
    
    print("Comprehensive Crypto Hunter Integration System")
    print("=" * 50)
    
    # Test configuration
    config_manager = ConfigurationManager()
    config = config_manager.load_config()
    print(f"Loaded configuration with {len(config)} sections")
    
    # Test storage manager
    storage_manager = StorageManager('./test_extractions')
    stats = storage_manager.get_storage_stats()
    print(f"Storage stats: {stats['file_count']} files, {stats['total_size_gb']:.2f} GB")
    
    print("\nIntegration system ready for deployment!")