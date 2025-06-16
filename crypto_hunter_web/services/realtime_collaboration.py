"""
crypto_hunter_web/services/realtime_collaboration.py
Real-time collaboration system for Crypto Hunter with WebSockets
"""

import json
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Set, Any, Optional
from dataclasses import dataclass, asdict
from flask import request
from flask_socketio import SocketIO, emit, join_room, leave_room, disconnect
from flask_login import current_user

from crypto_hunter_web.models import db, PuzzleSession, PuzzleCollaborator, User

logger = logging.getLogger(__name__)


@dataclass
class CollaboratorPresence:
    """Real-time presence information for collaborators"""
    user_id: int
    username: str
    session_id: str
    socket_id: str
    last_seen: datetime
    current_activity: str = "viewing"
    cursor_position: Optional[Dict[str, Any]] = None
    active_file_id: Optional[int] = None


@dataclass
class SessionActivity:
    """Activity event in a puzzle session"""
    activity_id: str
    session_id: str
    user_id: int
    username: str
    activity_type: str  # 'file_upload', 'analysis_start', 'finding_added', 'breakthrough'
    description: str
    metadata: Dict[str, Any]
    timestamp: datetime


class RealtimeCollaborationService:
    """Service for managing real-time collaboration features"""
    
    def __init__(self, socketio: SocketIO):
        self.socketio = socketio
        self.active_sessions: Dict[str, Set[str]] = {}  # session_id -> set of socket_ids
        self.user_presence: Dict[str, CollaboratorPresence] = {}  # socket_id -> presence
        self.session_activities: Dict[str, List[SessionActivity]] = {}  # session_id -> activities
        
        # Register WebSocket event handlers
        self._register_socket_handlers()
    
    def _register_socket_handlers(self):
        """Register WebSocket event handlers"""
        
        @self.socketio.on('connect')
        def handle_connect():
            logger.info(f"Client connected: {request.sid}")
            if current_user.is_authenticated:
                emit('connection_confirmed', {
                    'user_id': current_user.id,
                    'username': current_user.username,
                    'socket_id': request.sid
                })
        
        @self.socketio.on('disconnect')
        def handle_disconnect():
            logger.info(f"Client disconnected: {request.sid}")
            self._handle_user_disconnect(request.sid)
        
        @self.socketio.on('join_session')
        def handle_join_session(data):
            session_id = data.get('session_id')
            if session_id and current_user.is_authenticated:
                self._handle_join_session(session_id, request.sid)
        
        @self.socketio.on('leave_session')
        def handle_leave_session(data):
            session_id = data.get('session_id')
            if session_id:
                self._handle_leave_session(session_id, request.sid)
        
        @self.socketio.on('user_activity')
        def handle_user_activity(data):
            if current_user.is_authenticated:
                self._handle_user_activity(data, request.sid)
        
        @self.socketio.on('breakthrough_notification')
        def handle_breakthrough(data):
            if current_user.is_authenticated:
                self._handle_breakthrough_notification(data, request.sid)
        
        @self.socketio.on('share_finding')
        def handle_share_finding(data):
            if current_user.is_authenticated:
                self._handle_share_finding(data, request.sid)
    
    def _handle_join_session(self, session_id: str, socket_id: str):
        """Handle user joining a puzzle session"""
        try:
            # Verify session exists and user has access
            session = PuzzleSession.query.get(session_id)
            if not session:
                emit('error', {'message': 'Session not found'})
                return
            
            # Check if user is a collaborator
            collaborator = PuzzleCollaborator.query.filter_by(
                session_id=session_id,
                user_id=current_user.id
            ).first()
            
            if not collaborator and session.created_by != current_user.id:
                emit('error', {'message': 'Access denied'})
                return
            
            # Join the session room
            join_room(session_id)
            
            # Track session membership
            if session_id not in self.active_sessions:
                self.active_sessions[session_id] = set()
            self.active_sessions[session_id].add(socket_id)
            
            # Update user presence
            self.user_presence[socket_id] = CollaboratorPresence(
                user_id=current_user.id,
                username=current_user.username,
                session_id=session_id,
                socket_id=socket_id,
                last_seen=datetime.utcnow(),
                current_activity="joined_session"
            )
            
            # Notify other users in the session
            self.socketio.emit('user_joined', {
                'user_id': current_user.id,
                'username': current_user.username,
                'timestamp': datetime.utcnow().isoformat()
            }, room=session_id, include_self=False)
            
            # Send current session state to the joining user
            self._send_session_state(session_id, socket_id)
            
            # Log activity
            self._log_session_activity(
                session_id=session_id,
                activity_type='user_joined',
                description=f"{current_user.username} joined the session",
                metadata={'socket_id': socket_id}
            )
            
            logger.info(f"User {current_user.username} joined session {session_id}")
            
        except Exception as e:
            logger.error(f"Error handling join session: {e}")
            emit('error', {'message': 'Failed to join session'})
    
    def _handle_leave_session(self, session_id: str, socket_id: str):
        """Handle user leaving a puzzle session"""
        try:
            leave_room(session_id)
            
            # Remove from session tracking
            if session_id in self.active_sessions:
                self.active_sessions[session_id].discard(socket_id)
                if not self.active_sessions[session_id]:
                    del self.active_sessions[session_id]
            
            # Get user info before removing presence
            presence = self.user_presence.get(socket_id)
            if presence:
                # Notify other users
                self.socketio.emit('user_left', {
                    'user_id': presence.user_id,
                    'username': presence.username,
                    'timestamp': datetime.utcnow().isoformat()
                }, room=session_id, include_self=False)
                
                # Log activity
                self._log_session_activity(
                    session_id=session_id,
                    activity_type='user_left',
                    description=f"{presence.username} left the session",
                    metadata={'socket_id': socket_id}
                )
                
                # Remove presence
                del self.user_presence[socket_id]
            
            logger.info(f"User left session {session_id}")
            
        except Exception as e:
            logger.error(f"Error handling leave session: {e}")
    
    def _handle_user_disconnect(self, socket_id: str):
        """Handle user disconnection"""
        presence = self.user_presence.get(socket_id)
        if presence:
            self._handle_leave_session(presence.session_id, socket_id)
    
    def _handle_user_activity(self, data: Dict[str, Any], socket_id: str):
        """Handle user activity updates"""
        presence = self.user_presence.get(socket_id)
        if not presence:
            return
        
        # Update presence information
        presence.last_seen = datetime.utcnow()
        presence.current_activity = data.get('activity', 'viewing')
        presence.cursor_position = data.get('cursor_position')
        presence.active_file_id = data.get('file_id')
        
        # Broadcast activity to other session members
        self.socketio.emit('user_activity_update', {
            'user_id': presence.user_id,
            'username': presence.username,
            'activity': presence.current_activity,
            'cursor_position': presence.cursor_position,
            'file_id': presence.active_file_id,
            'timestamp': presence.last_seen.isoformat()
        }, room=presence.session_id, include_self=False)
    
    def _handle_breakthrough_notification(self, data: Dict[str, Any], socket_id: str):
        """Handle breakthrough notifications"""
        presence = self.user_presence.get(socket_id)
        if not presence:
            return
        
        breakthrough_data = {
            'user_id': presence.user_id,
            'username': presence.username,
            'breakthrough_type': data.get('type', 'general'),
            'description': data.get('description', ''),
            'file_id': data.get('file_id'),
            'finding_id': data.get('finding_id'),
            'timestamp': datetime.utcnow().isoformat()
        }
        
        # Broadcast breakthrough to all session members
        self.socketio.emit('breakthrough_alert', breakthrough_data, room=presence.session_id)
        
        # Log as high-priority activity
        self._log_session_activity(
            session_id=presence.session_id,
            activity_type='breakthrough',
            description=f"🎉 BREAKTHROUGH: {breakthrough_data['description']}",
            metadata=breakthrough_data
        )
        
        logger.info(f"Breakthrough notification in session {presence.session_id}: {breakthrough_data['description']}")
    
    def _handle_share_finding(self, data: Dict[str, Any], socket_id: str):
        """Handle sharing findings with session members"""
        presence = self.user_presence.get(socket_id)
        if not presence:
            return
        
        finding_data = {
            'user_id': presence.user_id,
            'username': presence.username,
            'finding_id': data.get('finding_id'),
            'file_id': data.get('file_id'),
            'description': data.get('description', ''),
            'category': data.get('category', 'general'),
            'confidence': data.get('confidence', 0.5),
            'timestamp': datetime.utcnow().isoformat()
        }
        
        # Broadcast finding to session members
        self.socketio.emit('new_finding_shared', finding_data, room=presence.session_id, include_self=False)
        
        # Log activity
        self._log_session_activity(
            session_id=presence.session_id,
            activity_type='finding_shared',
            description=f"{presence.username} shared a finding: {finding_data['description']}",
            metadata=finding_data
        )
    
    def _send_session_state(self, session_id: str, socket_id: str):
        """Send current session state to a user"""
        try:
            # Get active collaborators
            active_collaborators = []
            for sid, presence in self.user_presence.items():
                if presence.session_id == session_id and sid != socket_id:
                    active_collaborators.append({
                        'user_id': presence.user_id,
                        'username': presence.username,
                        'activity': presence.current_activity,
                        'last_seen': presence.last_seen.isoformat()
                    })
            
            # Get recent activities
            recent_activities = self.session_activities.get(session_id, [])[-10:]  # Last 10 activities
            
            # Send session state
            emit('session_state', {
                'session_id': session_id,
                'active_collaborators': active_collaborators,
                'recent_activities': [asdict(activity) for activity in recent_activities],
                'timestamp': datetime.utcnow().isoformat()
            })
            
        except Exception as e:
            logger.error(f"Error sending session state: {e}")
    
    def _log_session_activity(self, session_id: str, activity_type: str, description: str, metadata: Dict[str, Any] = None):
        """Log an activity in the session"""
        if session_id not in self.session_activities:
            self.session_activities[session_id] = []
        
        activity = SessionActivity(
            activity_id=f"{session_id}_{datetime.utcnow().timestamp()}",
            session_id=session_id,
            user_id=current_user.id,
            username=current_user.username,
            activity_type=activity_type,
            description=description,
            metadata=metadata or {},
            timestamp=datetime.utcnow()
        )
        
        self.session_activities[session_id].append(activity)
        
        # Keep only last 100 activities per session
        if len(self.session_activities[session_id]) > 100:
            self.session_activities[session_id] = self.session_activities[session_id][-100:]
    
    # Public API methods
    
    def notify_agent_progress(self, session_id: str, task_id: str, progress: Dict[str, Any]):
        """Notify session members of agent task progress"""
        if session_id in self.active_sessions:
            self.socketio.emit('agent_progress', {
                'task_id': task_id,
                'progress': progress,
                'timestamp': datetime.utcnow().isoformat()
            }, room=session_id)
    
    def notify_analysis_complete(self, session_id: str, file_id: int, results: Dict[str, Any]):
        """Notify session members that analysis is complete"""
        if session_id in self.active_sessions:
            self.socketio.emit('analysis_complete', {
                'file_id': file_id,
                'results': results,
                'timestamp': datetime.utcnow().isoformat()
            }, room=session_id)
    
    def notify_new_extraction(self, session_id: str, extraction_data: Dict[str, Any]):
        """Notify session members of new extraction results"""
        if session_id in self.active_sessions:
            self.socketio.emit('new_extraction', {
                'extraction': extraction_data,
                'timestamp': datetime.utcnow().isoformat()
            }, room=session_id)
    
    def get_session_stats(self, session_id: str) -> Dict[str, Any]:
        """Get statistics for a session"""
        active_count = len(self.active_sessions.get(session_id, set()))
        activities_count = len(self.session_activities.get(session_id, []))
        
        return {
            'session_id': session_id,
            'active_collaborators': active_count,
            'total_activities': activities_count,
            'last_activity': self.session_activities.get(session_id, [])[-1].timestamp.isoformat() if activities_count > 0 else None
        }


# Global service instance (to be initialized by the Flask app)
realtime_service: Optional[RealtimeCollaborationService] = None


def setup_realtime_collaboration(app, socketio: SocketIO):
    """Setup real-time collaboration with the Flask app"""
    global realtime_service
    
    try:
        realtime_service = RealtimeCollaborationService(socketio)
        
        # Add API routes for collaboration features
        @app.route('/api/collaboration/session/<session_id>/stats')
        def get_session_stats(session_id):
            if realtime_service:
                return realtime_service.get_session_stats(session_id)
            return {'error': 'Collaboration service not available'}, 503
        
        app.logger.info("✅ Real-time collaboration system initialized")
        return True
        
    except Exception as e:
        app.logger.error(f"❌ Failed to setup real-time collaboration: {e}")
        return False
