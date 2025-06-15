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
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Import our comprehensive systems
from crypto_hunter_web import db
from crypto_hunter_web.models import AnalysisFile, Finding, ExtractionRelationship

# Import our new systems
try:
    from comprehensive_extractor_system import ComprehensiveExtractorSystem
    from performance_optimization_system import OptimizedExtractionOrchestrator
    from missing_extractors_integration import register_missing_extractors
    from advanced_steganography_methods import register_advanced_stegano_extractors
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

@comprehensive_bp.route('/start', methods=['POST'])
@login_required
def start_comprehensive_extraction():
    """Start comprehensive extraction process"""
    try:
        data = request.get_json()
        file_id = data.get('file_id')
        extraction_config = data.get('config', {})
        
        # Validate file
        file_obj = AnalysisFile.query.get(file_id)
        if not file_obj:
            return jsonify({'error': 'File not found'}), 404
        
        if not os.path.exists(file_obj.filepath):
            return jsonify({'error': 'File path not accessible'}), 400
        
        # Create output directory
        output_dir = os.path.join(
            current_app.config.get('EXTRACTION_OUTPUT_DIR', './extractions'),
            f'comprehensive_{file_id}_{int(time.time())}'
        )
        os.makedirs(output_dir, exist_ok=True)
        
        # Start background task
        task = comprehensive_extraction_task.delay(
            file_path=file_obj.filepath,
            file_id=file_id,
            output_dir=output_dir,
            config=extraction_config,
            user_id=current_user.id
        )
        
        # Register task
        with EXTRACTION_LOCK:
            ACTIVE_EXTRACTIONS[task.id] = {
                'task_id': task.id,
                'file_id': file_id,
                'user_id': current_user.id,
                'started_at': datetime.now(),
                'status': 'started',
                'output_dir': output_dir,
                'config': extraction_config
            }
        
        return jsonify({
            'task_id': task.id,
            'status': 'started',
            'output_dir': output_dir,
            'websocket_room': f'extraction_{task.id}'
        })
    
    except Exception as e:
        logger.error(f"Failed to start comprehensive extraction: {e}")
        return jsonify({'error': str(e)}), 500

@comprehensive_bp.route('/status/<task_id>')
@login_required
def get_extraction_status(task_id: str):
    """Get extraction task status"""
    try:
        # Check local registry first
        with EXTRACTION_LOCK:
            if task_id in ACTIVE_EXTRACTIONS:
                local_status = ACTIVE_EXTRACTIONS[task_id].copy()
                
                # Add Celery task info
                task = AsyncResult(task_id)
                local_status['celery_status'] = task.status
                local_status['celery_info'] = task.info if task.info else {}
                
                return jsonify(local_status)
        
        # Check Celery directly
        task = AsyncResult(task_id)
        return jsonify({
            'task_id': task_id,
            'status': task.status,
            'info': task.info if task.info else {},
            'result': task.result if task.successful() else None
        })
    
    except Exception as e:
        logger.error(f"Failed to get extraction status: {e}")
        return jsonify({'error': str(e)}), 500

@comprehensive_bp.route('/cancel/<task_id>', methods=['POST'])
@login_required
def cancel_extraction(task_id: str):
    """Cancel extraction task"""
    try:
        # Check if user owns this task
        with EXTRACTION_LOCK:
            if task_id in ACTIVE_EXTRACTIONS:
                task_info = ACTIVE_EXTRACTIONS[task_id]
                if task_info['user_id'] != current_user.id:
                    return jsonify({'error': 'Permission denied'}), 403
                
                # Mark as cancelled
                task_info['status'] = 'cancelled'
                task_info['completed_at'] = datetime.now()
        
        # Revoke Celery task
        from crypto_hunter_web import celery
        celery.control.revoke(task_id, terminate=True)
        
        return jsonify({'status': 'cancelled'})
    
    except Exception as e:
        logger.error(f"Failed to cancel extraction: {e}")
        return jsonify({'error': str(e)}), 500

@comprehensive_bp.route('/list')
@login_required
def list_extractions():
    """List user's extraction tasks"""
    try:
        user_extractions = []
        
        with EXTRACTION_LOCK:
            for task_id, task_info in ACTIVE_EXTRACTIONS.items():
                if task_info['user_id'] == current_user.id:
                    # Add Celery status
                    task = AsyncResult(task_id)
                    task_info = task_info.copy()
                    task_info['celery_status'] = task.status
                    user_extractions.append(task_info)
        
        return jsonify({
            'extractions': user_extractions,
            'total': len(user_extractions)
        })
    
    except Exception as e:
        logger.error(f"Failed to list extractions: {e}")
        return jsonify({'error': str(e)}), 500

@comprehensive_bp.route('/download/<task_id>')
@login_required
def download_extraction_results(task_id: str):
    """Download extraction results as archive"""
    try:
        # Check if user owns this task
        with EXTRACTION_LOCK:
            if task_id not in ACTIVE_EXTRACTIONS:
                return jsonify({'error': 'Task not found'}), 404
            
            task_info = ACTIVE_EXTRACTIONS[task_id]
            if task_info['user_id'] != current_user.id:
                return jsonify({'error': 'Permission denied'}), 403
            
            output_dir = task_info['output_dir']
        
        # Create archive
        import zipfile
        import tempfile
        
        with tempfile.NamedTemporaryFile(suffix='.zip', delete=False) as tmp_file:
            with zipfile.ZipFile(tmp_file.name, 'w', zipfile.ZIP_DEFLATED) as zip_file:
                for root, dirs, files in os.walk(output_dir):
                    for file in files:
                        file_path = os.path.join(root, file)
                        arc_path = os.path.relpath(file_path, output_dir)
                        zip_file.write(file_path, arc_path)
            
            return send_file(
                tmp_file.name,
                as_attachment=True,
                download_name=f'extraction_{task_id}.zip'
            )
    
    except Exception as e:
        logger.error(f"Failed to download extraction results: {e}")
        return jsonify({'error': str(e)}), 500

@comprehensive_bp.route('/config/defaults')
@login_required
def get_default_config():
    """Get default extraction configuration"""
    return jsonify({
        'max_workers': 8,
        'max_depth': 10,
        'max_memory_mb': 2048,
        'cache_size': 100000,
        'batch_size': 1000,
        'enable_advanced_stegano': True,
        'enable_password_cracking': True,
        'enable_deduplication': True,
        'extractors': {
            'steganography': ['zsteg', 'steghide', 'multilayer_stegano', 'frequency_domain_analyzer'],
            'archives': ['zip_password_crack', 'rar5_extractor', '7zip_extractor'],
            'binary': ['binwalk', 'foremost', 'strings'],
            'advanced': ['volatility_analyzer', 'pcap_analyzer', 'sqlite_analyzer']
        }
    })

# Celery tasks
@celery.task(bind=True, base=ComprehensiveExtractionTask)
def comprehensive_extraction_task(self, file_path: str, file_id: int, output_dir: str, config: Dict[str, Any], user_id: int):
    """Comprehensive extraction Celery task"""
    try:
        # Update task status
        self.update_state(state='PROGRESS', meta={'status': 'initializing'})
        
        # Initialize orchestrator with config
        orchestrator = OptimizedExtractionOrchestrator(
            max_workers=config.get('max_workers', 8),
            max_memory_mb=config.get('max_memory_mb', 2048),
            cache_size=config.get('cache_size', 100000),
            batch_size=config.get('batch_size', 1000)
        )
        
        # Set up progress callback
        def progress_callback(progress_info):
            self.update_state(state='PROGRESS', meta={
                'status': 'processing',
                'progress': progress_info
            })
        
        # Run extraction
        result = orchestrator.start_extraction(file_path, output_dir)
        
        # Store results in database
        _store_extraction_results(file_id, result, output_dir, user_id)
        
        return {
            'status': 'completed',
            'file_id': file_id,
            'output_dir': output_dir,
            'results': result
        }
    
    except Exception as e:
        logger.error(f"Comprehensive extraction task failed: {e}")
        raise

def _store_extraction_results(file_id: int, results: Dict[str, Any], output_dir: str, user_id: int):
    """Store extraction results in database"""
    try:
        # Create extraction relationship records
        for extracted_file_path in results.get('extracted_files', []):
            if os.path.exists(extracted_file_path):
                # Calculate file hash
                import hashlib
                with open(extracted_file_path, 'rb') as f:
                    file_hash = hashlib.sha256(f.read()).hexdigest()
                
                # Create AnalysisFile record for extracted file
                extracted_file = AnalysisFile(
                    filename=os.path.basename(extracted_file_path),
                    filepath=extracted_file_path,
                    file_size=os.path.getsize(extracted_file_path),
                    sha256_hash=file_hash,
                    uploaded_by=user_id,
                    status='complete'
                )
                db.session.add(extracted_file)
                db.session.flush()
                
                # Create extraction relationship
                relationship = ExtractionRelationship(
                    source_file_id=file_id,
                    extracted_file_id=extracted_file.id,
                    extraction_method='comprehensive_extraction',
                    parameters=json.dumps(results.get('config', {})),
                    discovered_by=user_id
                )
                db.session.add(relationship)
        
        # Create findings for interesting discoveries
        for finding_data in results.get('findings', []):
            finding = Finding(
                file_id=file_id,
                finding_type=finding_data.get('type', 'unknown'),
                category=finding_data.get('category', 'general'),
                title=finding_data.get('title', 'Comprehensive Extraction Finding'),
                description=finding_data.get('description', ''),
                confidence_level=finding_data.get('confidence', 5),
                created_by=user_id,
                analysis_method='comprehensive_extraction'
            )
            db.session.add(finding)
        
        db.session.commit()
        
    except Exception as e:
        logger.error(f"Failed to store extraction results: {e}")
        db.session.rollback()

# WebSocket events for real-time monitoring
def register_websocket_events(socketio):
    """Register WebSocket events for real-time monitoring"""
    
    @socketio.on('join_extraction')
    def on_join_extraction(data):
        """Join extraction monitoring room"""
        task_id = data.get('task_id')
        if task_id:
            join_room(f'extraction_{task_id}')
            emit('joined', {'room': f'extraction_{task_id}'})
    
    @socketio.on('leave_extraction')
    def on_leave_extraction(data):
        """Leave extraction monitoring room"""
        task_id = data.get('task_id')
        if task_id:
            leave_room(f'extraction_{task_id}')
            emit('left', {'room': f'extraction_{task_id}'})
    
    @socketio.on('get_system_stats')
    def on_get_system_stats():
        """Get real-time system statistics"""
        try:
            import psutil
            
            stats = {
                'cpu_percent': psutil.cpu_percent(interval=1),
                'memory_percent': psutil.virtual_memory().percent,
                'disk_percent': psutil.disk_usage('/').percent,
                'active_extractions': len(ACTIVE_EXTRACTIONS),
                'timestamp': datetime.now().isoformat()
            }
            
            emit('system_stats', stats)
        
        except Exception as e:
            emit('error', {'message': str(e)})

# Storage management
class StorageManager:
    """Manage extraction output storage"""
    
    def __init__(self, base_dir: str, max_size_gb: float = 100.0):
        self.base_dir = Path(base_dir)
        self.max_size_gb = max_size_gb
        self.max_size_bytes = int(max_size_gb * 1024 * 1024 * 1024)
    
    def get_storage_stats(self) -> Dict[str, Any]:
        """Get storage statistics"""
        total_size = 0
        file_count = 0
        oldest_file = None
        newest_file = None
        
        for root, dirs, files in os.walk(self.base_dir):
            for file in files:
                file_path = Path(root) / file
                try:
                    stat = file_path.stat()
                    total_size += stat.st_size
                    file_count += 1
                    
                    if not oldest_file or stat.st_mtime < oldest_file[1]:
                        oldest_file = (file_path, stat.st_mtime)
                    
                    if not newest_file or stat.st_mtime > newest_file[1]:
                        newest_file = (file_path, stat.st_mtime)
                
                except OSError:
                    continue
        
        return {
            'total_size_bytes': total_size,
            'total_size_gb': total_size / (1024 * 1024 * 1024),
            'file_count': file_count,
            'usage_percent': (total_size / self.max_size_bytes) * 100,
            'oldest_file': str(oldest_file[0]) if oldest_file else None,
            'newest_file': str(newest_file[0]) if newest_file else None,
            'max_size_gb': self.max_size_gb
        }
    
    def cleanup_old_extractions(self, max_age_days: int = 30) -> Dict[str, Any]:
        """Clean up old extraction results"""
        cutoff_time = time.time() - (max_age_days * 24 * 60 * 60)
        
        deleted_files = 0
        deleted_size = 0
        errors = []
        
        for root, dirs, files in os.walk(self.base_dir, topdown=False):
            for file in files:
                file_path = Path(root) / file
                try:
                    stat = file_path.stat()
                    if stat.st_mtime < cutoff_time:
                        deleted_size += stat.st_size
                        file_path.unlink()
                        deleted_files += 1
                
                except OSError as e:
                    errors.append(f"Failed to delete {file_path}: {e}")
            
            # Remove empty directories
            try:
                if not os.listdir(root):
                    os.rmdir(root)
            except OSError:
                pass
        
        return {
            'deleted_files': deleted_files,
            'deleted_size_bytes': deleted_size,
            'deleted_size_gb': deleted_size / (1024 * 1024 * 1024),
            'errors': errors
        }

# Configuration management
class ConfigurationManager:
    """Manage extraction system configuration"""
    
    def __init__(self, config_file: str = 'extraction_config.json'):
        self.config_file = config_file
        self.default_config = {
            'extraction': {
                'max_workers': 8,
                'max_depth': 10,
                'max_memory_mb': 2048,
                'cache_size': 100000,
                'batch_size': 1000,
                'timeout_seconds': 3600
            },
            'storage': {
                'max_size_gb': 100.0,
                'cleanup_age_days': 30,
                'compression_enabled': True
            },
            'extractors': {
                'enabled_categories': [
                    'steganography',
                    'archives',
                    'binary',
                    'documents',
                    'memory',
                    'network'
                ],
                'steganography_advanced': True,
                'password_cracking': True,
                'machine_learning': False
            },
            'monitoring': {
                'progress_update_interval': 1.0,
                'resource_monitoring': True,
                'websocket_enabled': True
            }
        }
    
    def load_config(self) -> Dict[str, Any]:
        """Load configuration from file"""
        try:
            if os.path.exists(self.config_file):
                with open(self.config_file, 'r') as f:
                    config = json.load(f)
                
                # Merge with defaults
                return self._merge_config(self.default_config, config)
            else:
                return self.default_config.copy()
        
        except Exception as e:
            logger.warning(f"Failed to load config: {e}, using defaults")
            return self.default_config.copy()
    
    def save_config(self, config: Dict[str, Any]):
        """Save configuration to file"""
        try:
            with open(self.config_file, 'w') as f:
                json.dump(config, f, indent=2)
        
        except Exception as e:
            logger.error(f"Failed to save config: {e}")
    
    def _merge_config(self, default: Dict[str, Any], user: Dict[str, Any]) -> Dict[str, Any]:
        """Merge user config with defaults"""
        result = default.copy()
        
        for key, value in user.items():
            if key in result and isinstance(result[key], dict) and isinstance(value, dict):
                result[key] = self._merge_config(result[key], value)
            else:
                result[key] = value
        
        return result

# Monitoring and alerting
class SystemMonitor:
    """Monitor system health and performance"""
    
    def __init__(self):
        self.monitoring = False
        self.monitor_thread = None
        self.alerts = []
        self.thresholds = {
            'cpu_percent': 90.0,
            'memory_percent': 85.0,
            'disk_percent': 95.0,
            'error_rate': 10.0  # errors per minute
        }
    
    def start_monitoring(self):
        """Start system monitoring"""
        self.monitoring = True
        self.monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self.monitor_thread.start()
        logger.info("System monitoring started")
    
    def stop_monitoring(self):
        """Stop system monitoring"""
        self.monitoring = False
        if self.monitor_thread:
            self.monitor_thread.join(timeout=5.0)
    
    def _monitor_loop(self):
        """Main monitoring loop"""
        import psutil
        
        while self.monitoring:
            try:
                # Check system resources
                cpu_percent = psutil.cpu_percent(interval=1)
                memory_percent = psutil.virtual_memory().percent
                disk_percent = psutil.disk_usage('/').percent
                
                # Check thresholds
                if cpu_percent > self.thresholds['cpu_percent']:
                    self._create_alert('high_cpu', f'CPU usage: {cpu_percent:.1f}%')
                
                if memory_percent > self.thresholds['memory_percent']:
                    self._create_alert('high_memory', f'Memory usage: {memory_percent:.1f}%')
                
                if disk_percent > self.thresholds['disk_percent']:
                    self._create_alert('high_disk', f'Disk usage: {disk_percent:.1f}%')
                
                # Check extraction task health
                self._check_task_health()
                
                time.sleep(30)  # Check every 30 seconds
            
            except Exception as e:
                logger.error(f"Monitoring error: {e}")
                time.sleep(60)
    
    def _create_alert(self, alert_type: str, message: str):
        """Create system alert"""
        alert = {
            'type': alert_type,
            'message': message,
            'timestamp': datetime.now(),
            'severity': 'warning'
        }
        
        self.alerts.append(alert)
        
        # Keep only recent alerts
        cutoff = datetime.now() - timedelta(hours=24)
        self.alerts = [a for a in self.alerts if a['timestamp'] > cutoff]
        
        logger.warning(f"System alert: {alert_type} - {message}")
        
        # Emit WebSocket alert
        try:
            from crypto_hunter_web import socketio
            socketio.emit('system_alert', alert)
        except:
            pass
    
    def _check_task_health(self):
        """Check health of extraction tasks"""
        with EXTRACTION_LOCK:
            for task_id, task_info in ACTIVE_EXTRACTIONS.items():
                # Check for stuck tasks
                if task_info['status'] == 'started':
                    runtime = datetime.now() - task_info['started_at']
                    if runtime > timedelta(hours=2):  # 2 hour timeout
                        self._create_alert('stuck_task', f'Task {task_id} running for {runtime}')

# Initialize everything
def initialize_comprehensive_system(app):
    """Initialize the comprehensive extraction system"""
    try:
        # Register extractors
        register_missing_extractors()
        register_advanced_stegano_extractors()
        
        # Initialize storage manager
        extraction_dir = app.config.get('EXTRACTION_OUTPUT_DIR', './extractions')
        os.makedirs(extraction_dir, exist_ok=True)
        storage_manager = StorageManager(extraction_dir)
        
        # Initialize configuration manager
        config_manager = ConfigurationManager()
        config = config_manager.load_config()
        
        # Initialize system monitor
        system_monitor = SystemMonitor()
        system_monitor.start_monitoring()
        
        # Store managers in app context
        app.storage_manager = storage_manager
        app.config_manager = config_manager
        app.system_monitor = system_monitor
        app.extraction_config = config
        
        logger.info("Comprehensive extraction system initialized successfully")
        
        return {
            'storage_manager': storage_manager,
            'config_manager': config_manager,
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
