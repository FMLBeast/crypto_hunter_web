#!/usr/bin/env python3
"""
WebSocket Events - Real-time updates for background services and analysis progress
"""

from flask import session, current_app
from flask_socketio import SocketIO, emit, join_room, leave_room, disconnect
from datetime import datetime
import json
import logging

from crypto_hunter_web.services.auth_service import AuthService
from crypto_hunter_web.services.background_service import BackgroundService
from crypto_hunter_web.models import AnalysisFile, Finding

logger = logging.getLogger(__name__)

# Initialize SocketIO (this would be done in your app factory)
socketio = SocketIO(cors_allowed_origins="*", logger=True, engineio_logger=True)

# Store active connections
active_connections = {}

@socketio.on('connect')
def handle_connect():
    """Handle client connection"""
    try:
        # Verify authentication
        user_id = session.get('user_id')
        if not user_id:
            logger.warning("Unauthenticated WebSocket connection attempt")
            disconnect()
            return False
        
        # Store connection info
        active_connections[session.sid] = {
            'user_id': user_id,
            'connected_at': datetime.utcnow(),
            'subscriptions': set()
        }
        
        # Join user-specific room
        join_room(f"user_{user_id}")
        
        # Send connection confirmation
        emit('connected', {
            'status': 'success',
            'user_id': user_id,
            'timestamp': datetime.utcnow().isoformat(),
            'available_channels': [
                'task_updates',
                'file_analysis',
                'findings',
                'system_status'
            ]
        })
        
        logger.info(f"WebSocket connection established for user {user_id}")
        
    except Exception as e:
        logger.error(f"Error handling WebSocket connection: {e}")
        disconnect()

@socketio.on('disconnect')
def handle_disconnect():
    """Handle client disconnection"""
    try:
        if session.sid in active_connections:
            user_id = active_connections[session.sid]['user_id']
            leave_room(f"user_{user_id}")
            del active_connections[session.sid]
            logger.info(f"WebSocket disconnection for user {user_id}")
    except Exception as e:
        logger.error(f"Error handling WebSocket disconnection: {e}")

@socketio.on('subscribe')
def handle_subscribe(data):
    """Subscribe to specific event channels"""
    try:
        if session.sid not in active_connections:
            emit('error', {'message': 'Not authenticated'})
            return
        
        channel = data.get('channel')
        if not channel:
            emit('error', {'message': 'Channel required'})
            return
        
        valid_channels = [
            'task_updates', 'file_analysis', 'findings', 
            'system_status', 'llm_analysis'
        ]
        
        if channel not in valid_channels:
            emit('error', {'message': f'Invalid channel: {channel}'})
            return
        
        # Add to subscriptions
        active_connections[session.sid]['subscriptions'].add(channel)
        
        # Join channel room
        join_room(f"channel_{channel}")
        
        emit('subscribed', {
            'channel': channel,
            'status': 'success',
            'timestamp': datetime.utcnow().isoformat()
        })
        
        # Send initial data for the channel
        send_initial_channel_data(channel)
        
    except Exception as e:
        logger.error(f"Error handling subscription: {e}")
        emit('error', {'message': 'Subscription failed'})

@socketio.on('unsubscribe')
def handle_unsubscribe(data):
    """Unsubscribe from event channels"""
    try:
        if session.sid not in active_connections:
            return
        
        channel = data.get('channel')
        if channel in active_connections[session.sid]['subscriptions']:
            active_connections[session.sid]['subscriptions'].remove(channel)
            leave_room(f"channel_{channel}")
            
            emit('unsubscribed', {
                'channel': channel,
                'status': 'success'
            })
            
    except Exception as e:
        logger.error(f"Error handling unsubscription: {e}")

@socketio.on('get_task_status')
def handle_get_task_status(data):
    """Get real-time status of a specific task"""
    try:
        task_id = data.get('task_id')
        if not task_id:
            emit('error', {'message': 'Task ID required'})
            return
        
        # Get task status
        task_status = BackgroundService.get_task_status(task_id)
        
        # Verify user has access
        user_id = active_connections[session.sid]['user_id']
        if task_status.get('user_id') and task_status['user_id'] != user_id:
            emit('error', {'message': 'Access denied'})
            return
        
        emit('task_status', {
            'task_id': task_id,
            'status': task_status,
            'timestamp': datetime.utcnow().isoformat()
        })
        
    except Exception as e:
        logger.error(f"Error getting task status: {e}")
        emit('error', {'message': 'Failed to get task status'})

@socketio.on('get_live_stats')
def handle_get_live_stats():
    """Get live dashboard statistics"""
    try:
        if session.sid not in active_connections:
            return
        
        user_id = active_connections[session.sid]['user_id']
        
        # Get real-time stats
        from crypto_hunter_web.routes.dashboard import get_user_llm_stats
        stats = {
            'active_tasks': len(BackgroundService.get_user_active_tasks(user_id)),
            'system_status': BackgroundService.get_system_status(),
            'user_stats': BackgroundService.get_analysis_stats(user_id)
        }
        
        emit('live_stats', {
            'stats': stats,
            'timestamp': datetime.utcnow().isoformat()
        })
        
    except Exception as e:
        logger.error(f"Error getting live stats: {e}")
        emit('error', {'message': 'Failed to get live stats'})

def send_initial_channel_data(channel):
    """Send initial data when subscribing to a channel"""
    try:
        user_id = active_connections[session.sid]['user_id']
        
        if channel == 'task_updates':
            # Send current active tasks
            active_tasks = BackgroundService.get_user_active_tasks(user_id)
            emit('initial_data', {
                'channel': channel,
                'data': {'active_tasks': active_tasks}
            })
            
        elif channel == 'system_status':
            # Send current system status
            system_status = BackgroundService.get_system_status()
            emit('initial_data', {
                'channel': channel,
                'data': {'system_status': system_status}
            })
            
        elif channel == 'findings':
            # Send recent findings count
            from crypto_hunter_web.routes.findings_api import get_findings_stats
            findings_stats = get_findings_stats(user_id)
            emit('initial_data', {
                'channel': channel,
                'data': {'findings_stats': findings_stats}
            })
            
    except Exception as e:
        logger.error(f"Error sending initial channel data: {e}")

# Background task event broadcasters (called from Celery tasks)

def broadcast_task_update(task_id, status, user_id=None, room=None):
    """Broadcast task progress update to connected clients"""
    try:
        update_data = {
            'task_id': task_id,
            'status': status,
            'timestamp': datetime.utcnow().isoformat()
        }
        
        if user_id:
            # Send to specific user
            socketio.emit('task_update', update_data, room=f"user_{user_id}")
        elif room:
            # Send to specific room
            socketio.emit('task_update', update_data, room=room)
        else:
            # Send to task_updates channel
            socketio.emit('task_update', update_data, room="channel_task_updates")
            
        logger.debug(f"Broadcasted task update for {task_id}")
        
    except Exception as e:
        logger.error(f"Error broadcasting task update: {e}")

def broadcast_analysis_progress(file_id, progress_data, user_id):
    """Broadcast file analysis progress"""
    try:
        socketio.emit('analysis_progress', {
            'file_id': file_id,
            'progress': progress_data,
            'timestamp': datetime.utcnow().isoformat()
        }, room=f"user_{user_id}")
        
        # Also send to file_analysis channel
        socketio.emit('analysis_progress', {
            'file_id': file_id,
            'progress': progress_data,
            'timestamp': datetime.utcnow().isoformat()
        }, room="channel_file_analysis")
        
    except Exception as e:
        logger.error(f"Error broadcasting analysis progress: {e}")

def broadcast_new_finding(finding_data, user_id):
    """Broadcast new finding discovered"""
    try:
        socketio.emit('new_finding', {
            'finding': finding_data,
            'timestamp': datetime.utcnow().isoformat()
        }, room=f"user_{user_id}")
        
        # Also send to findings channel
        socketio.emit('new_finding', {
            'finding': finding_data,
            'timestamp': datetime.utcnow().isoformat()
        }, room="channel_findings")
        
    except Exception as e:
        logger.error(f"Error broadcasting new finding: {e}")

def broadcast_llm_analysis_update(file_id, llm_data, user_id):
    """Broadcast LLM analysis progress and results"""
    try:
        socketio.emit('llm_analysis_update', {
            'file_id': file_id,
            'llm_data': llm_data,
            'timestamp': datetime.utcnow().isoformat()
        }, room=f"user_{user_id}")
        
        # Also send to LLM analysis channel
        socketio.emit('llm_analysis_update', {
            'file_id': file_id,
            'llm_data': llm_data,
            'timestamp': datetime.utcnow().isoformat()
        }, room="channel_llm_analysis")
        
    except Exception as e:
        logger.error(f"Error broadcasting LLM analysis update: {e}")

def broadcast_system_status_change(status_data):
    """Broadcast system status changes"""
    try:
        socketio.emit('system_status_change', {
            'status': status_data,
            'timestamp': datetime.utcnow().isoformat()
        }, room="channel_system_status")
        
    except Exception as e:
        logger.error(f"Error broadcasting system status change: {e}")

# Integration hooks for Celery tasks

class WebSocketTaskMonitor:
    """Monitor Celery tasks and broadcast updates via WebSocket"""
    
    @staticmethod
    def task_started(task_id, task_info):
        """Called when a task starts"""
        broadcast_task_update(task_id, {
            'state': 'STARTED',
            'stage': 'initializing',
            'progress': 0
        }, user_id=task_info.get('user_id'))
    
    @staticmethod
    def task_progress(task_id, progress_data, user_id=None):
        """Called when task progress is updated"""
        broadcast_task_update(task_id, {
            'state': 'PROGRESS',
            'stage': progress_data.get('stage', 'processing'),
            'progress': progress_data.get('progress', 0),
            'meta': progress_data
        }, user_id=user_id)
        
        # If it's file analysis, also broadcast to analysis channel
        if progress_data.get('file_id'):
            broadcast_analysis_progress(
                progress_data['file_id'], 
                progress_data, 
                user_id
            )
    
    @staticmethod
    def task_completed(task_id, result, user_id=None):
        """Called when a task completes"""
        broadcast_task_update(task_id, {
            'state': 'SUCCESS',
            'stage': 'completed',
            'progress': 100,
            'result': result
        }, user_id=user_id)
        
        # Check if this was an LLM analysis
        if result and result.get('analysis_type') == 'llm':
            broadcast_llm_analysis_update(
                result.get('file_id'),
                result,
                user_id
            )
    
    @staticmethod
    def task_failed(task_id, error_info, user_id=None):
        """Called when a task fails"""
        broadcast_task_update(task_id, {
            'state': 'FAILURE',
            'stage': 'failed',
            'progress': 0,
            'error': str(error_info)
        }, user_id=user_id)
    
    @staticmethod
    def finding_discovered(finding_data, user_id):
        """Called when a new finding is discovered"""
        broadcast_new_finding(finding_data, user_id)

# Utility functions for real-time dashboard updates

def get_connected_users():
    """Get list of currently connected users"""
    return list(set(
        conn_info['user_id'] 
        for conn_info in active_connections.values()
    ))

def broadcast_to_all_users(event, data):
    """Broadcast an event to all connected users"""
    try:
        socketio.emit(event, data)
    except Exception as e:
        logger.error(f"Error broadcasting to all users: {e}")

def send_notification_to_user(user_id, notification):
    """Send a notification to a specific user"""
    try:
        socketio.emit('notification', {
            'type': notification.get('type', 'info'),
            'title': notification.get('title', ''),
            'message': notification.get('message', ''),
            'timestamp': datetime.utcnow().isoformat()
        }, room=f"user_{user_id}")
    except Exception as e:
        logger.error(f"Error sending notification to user {user_id}: {e}")

# Integration with Celery task decorator

def websocket_aware_task(task_func):
    """Decorator to make Celery tasks WebSocket-aware"""
    def wrapper(self, *args, **kwargs):
        task_id = self.request.id
        user_id = kwargs.get('user_id')
        
        try:
            # Notify task started
            WebSocketTaskMonitor.task_started(task_id, {
                'user_id': user_id,
                'task_type': task_func.__name__
            })
            
            # Execute the task
            result = task_func(self, *args, **kwargs)
            
            # Notify task completed
            WebSocketTaskMonitor.task_completed(task_id, result, user_id)
            
            return result
            
        except Exception as e:
            # Notify task failed
            WebSocketTaskMonitor.task_failed(task_id, e, user_id)
            raise
    
    return wrapper

# Example usage in templates (JavaScript client code)

WEBSOCKET_CLIENT_CODE = """
// WebSocket client integration for real-time updates

class CryptoHunterWebSocket {
    constructor() {
        this.socket = null;
        this.subscriptions = new Set();
        this.connect();
    }
    
    connect() {
        this.socket = io({
            transports: ['websocket', 'polling']
        });
        
        this.socket.on('connect', (data) => {
            console.log('WebSocket connected:', data);
            this.onConnected(data);
        });
        
        this.socket.on('disconnect', () => {
            console.log('WebSocket disconnected');
            this.onDisconnected();
        });
        
        this.socket.on('task_update', (data) => {
            this.onTaskUpdate(data);
        });
        
        this.socket.on('analysis_progress', (data) => {
            this.onAnalysisProgress(data);
        });
        
        this.socket.on('new_finding', (data) => {
            this.onNewFinding(data);
        });
        
        this.socket.on('llm_analysis_update', (data) => {
            this.onLLMUpdate(data);
        });
        
        this.socket.on('notification', (data) => {
            this.onNotification(data);
        });
    }
    
    subscribe(channel) {
        if (!this.subscriptions.has(channel)) {
            this.socket.emit('subscribe', { channel: channel });
            this.subscriptions.add(channel);
        }
    }
    
    unsubscribe(channel) {
        if (this.subscriptions.has(channel)) {
            this.socket.emit('unsubscribe', { channel: channel });
            this.subscriptions.delete(channel);
        }
    }
    
    getTaskStatus(taskId) {
        this.socket.emit('get_task_status', { task_id: taskId });
    }
    
    getLiveStats() {
        this.socket.emit('get_live_stats');
    }
    
    // Event handlers (override these in your implementation)
    onConnected(data) {
        // Subscribe to relevant channels
        this.subscribe('task_updates');
        this.subscribe('findings');
    }
    
    onDisconnected() {
        // Handle disconnect
    }
    
    onTaskUpdate(data) {
        // Update task progress in UI
        console.log('Task update:', data);
    }
    
    onAnalysisProgress(data) {
        // Update analysis progress bars
        console.log('Analysis progress:', data);
    }
    
    onNewFinding(data) {
        // Show new finding notification
        console.log('New finding:', data);
    }
    
    onLLMUpdate(data) {
        // Update LLM analysis status
        console.log('LLM update:', data);
    }
    
    onNotification(data) {
        // Show user notification
        this.showNotification(data.title, data.message, data.type);
    }
    
    showNotification(title, message, type = 'info') {
        // Implement your notification UI
        console.log(`${type.toUpperCase()}: ${title} - ${message}`);
    }
}

// Initialize WebSocket connection
window.cryptoWebSocket = new CryptoHunterWebSocket();
"""