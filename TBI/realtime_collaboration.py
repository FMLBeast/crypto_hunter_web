"""
crypto_hunter_web/services/realtime_collaboration.py
Real-time collaboration system for Crypto Hunter agent workflows
"""

import asyncio
import json
import logging
import time
from typing import Dict, List, Set, Optional, Any
from datetime import datetime, timedelta
from dataclasses import dataclass, asdict
from enum import Enum
import uuid

from flask import Flask
from flask_socketio import SocketIO, emit, join_room, leave_room, disconnect
from flask_login import current_user
import redis

from crypto_hunter_web.extensions import db
from crypto_hunter_web.models.puzzle_session import PuzzleSession
from crypto_hunter_web.models.agent_models import AgentExecution, WorkflowExecution
from crypto_hunter_web.services.auth_service import AuthService

logger = logging.getLogger(__name__)


class CollaborationEventType(Enum):
    """Types of collaboration events"""
    USER_JOINED = "user_joined"
    USER_LEFT = "user_left"
    WORKFLOW_STARTED = "workflow_started"
    WORKFLOW_COMPLETED = "workflow_completed"
    AGENT_RESULT = "agent_result"
    BREAKTHROUGH = "breakthrough"
    FILE_UPLOADED = "file_uploaded"
    FINDING_SHARED = "finding_shared"
    HYPOTHESIS_CREATED = "hypothesis_created"
    CHAT_MESSAGE = "chat_message"
    CURSOR_MOVE = "cursor_move"
    PRESENCE_UPDATE = "presence_update"


@dataclass
class CollaborationEvent:
    """Collaboration event data structure"""
    event_type: CollaborationEventType
    session_id: str
    user_id: str
    username: str
    timestamp: datetime
    data: Dict[str, Any]
    event_id: str = None
    
    def __post_init__(self):
        if self.event_id is None:
            self.event_id = str(uuid.uuid4())
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'event_type': self.event_type.value,
            'session_id': self.session_id,
            'user_id': self.user_id,
            'username': self.username,
            'timestamp': self.timestamp.isoformat(),
            'event_id': self.event_id,
            'data': self.data
        }


@dataclass
class UserPresence:
    """User presence information"""
    user_id: str
    username: str
    session_id: str
    last_seen: datetime
    status: str  # 'active', 'idle', 'away'
    current_view: str  # 'dashboard', 'files', 'agents', 'results'
    cursor_position: Optional[Dict[str, Any]] = None
    active_workflow: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class RealtimeCollaborationManager:
    """Manages real-time collaboration features"""
    
    def __init__(self, app: Flask = None, socketio: SocketIO = None, redis_client=None):
        self.app = app
        self.socketio = socketio
        self.redis_client = redis_client or redis.Redis()
        
        # In-memory stores for active sessions
        self.active_sessions: Dict[str, Set[str]] = {}  # session_id -> set of user_ids
        self.user_sessions: Dict[str, str] = {}  # user_id -> session_id
        self.user_presence: Dict[str, UserPresence] = {}  # user_id -> presence
        
        # Event history (Redis-backed)
        self.event_history_key = "crypto_hunter:collaboration:events"
        self.presence_key = "crypto_hunter:collaboration:presence"
        
        if app and socketio:
            self._register_socketio_handlers()
    
    def _register_socketio_handlers(self):
        """Register SocketIO event handlers"""
        
        @self.socketio.on('connect')
        @AuthService.socketio_login_required
        def handle_connect():
            """Handle user connection"""
            user_id = str(current_user.id)
            username = current_user.username
            
            logger.info(f"User {username} connected via WebSocket")
            
            # Update user presence
            self._update_user_presence(user_id, username, status='active')
            
            # Send user their current sessions
            user_sessions = self._get_user_sessions(user_id)
            emit('user_sessions', {'sessions': user_sessions})
        
        @self.socketio.on('disconnect')
        @AuthService.socketio_login_required
        def handle_disconnect():
            """Handle user disconnection"""
            user_id = str(current_user.id)
            username = current_user.username
            
            logger.info(f"User {username} disconnected from WebSocket")
            
            # Leave current session if any
            if user_id in self.user_sessions:
                session_id = self.user_sessions[user_id]
                self._leave_session(user_id, username, session_id)
            
            # Remove user presence
            self._remove_user_presence(user_id)
        
        @self.socketio.on('join_session')
        @AuthService.socketio_login_required
        def handle_join_session(data):
            """Handle user joining a collaboration session"""
            user_id = str(current_user.id)
            username = current_user.username
            session_id = data.get('session_id')
            
            if not session_id:
                emit('error', {'message': 'Session ID required'})
                return
            
            # Validate session access
            if not self._validate_session_access(user_id, session_id):
                emit('error', {'message': 'Access denied to session'})
                return
            
            # Leave previous session if any
            if user_id in self.user_sessions:
                old_session = self.user_sessions[user_id]
                if old_session != session_id:
                    self._leave_session(user_id, username, old_session)
            
            # Join new session
            self._join_session(user_id, username, session_id)
            
            # Send session state
            session_state = self._get_session_state(session_id)
            emit('session_state', session_state)
        
        @self.socketio.on('leave_session')
        @AuthService.socketio_login_required
        def handle_leave_session(data):
            """Handle user leaving a collaboration session"""
            user_id = str(current_user.id)
            username = current_user.username
            session_id = data.get('session_id')
            
            if session_id and user_id in self.user_sessions:
                self._leave_session(user_id, username, session_id)
        
        @self.socketio.on('chat_message')
        @AuthService.socketio_login_required
        def handle_chat_message(data):
            """Handle chat message"""
            user_id = str(current_user.id)
            username = current_user.username
            session_id = self.user_sessions.get(user_id)
            
            if not session_id:
                emit('error', {'message': 'Not in a session'})
                return
            
            message = data.get('message', '').strip()
            if not message:
                return
            
            # Create and broadcast chat event
            event = CollaborationEvent(
                event_type=CollaborationEventType.CHAT_MESSAGE,
                session_id=session_id,
                user_id=user_id,
                username=username,
                timestamp=datetime.utcnow(),
                data={'message': message}
            )
            
            self._broadcast_event(event)
            self._store_event(event)
        
        @self.socketio.on('cursor_move')
        @AuthService.socketio_login_required
        def handle_cursor_move(data):
            """Handle cursor movement for collaborative editing"""
            user_id = str(current_user.id)
            username = current_user.username
            session_id = self.user_sessions.get(user_id)
            
            if not session_id:
                return
            
            cursor_data = {
                'x': data.get('x', 0),
                'y': data.get('y', 0),
                'view': data.get('view', 'unknown'),
                'element': data.get('element')
            }
            
            # Update user presence
            if user_id in self.user_presence:
                self.user_presence[user_id].cursor_position = cursor_data
                self.user_presence[user_id].current_view = cursor_data['view']
            
            # Broadcast cursor position (lightweight, no storage)
            event = CollaborationEvent(
                event_type=CollaborationEventType.CURSOR_MOVE,
                session_id=session_id,
                user_id=user_id,
                username=username,
                timestamp=datetime.utcnow(),
                data=cursor_data
            )
            
            self._broadcast_event(event, exclude_sender=True)
        
        @self.socketio.on('presence_update')
        @AuthService.socketio_login_required
        def handle_presence_update(data):
            """Handle presence status update"""
            user_id = str(current_user.id)
            username = current_user.username
            session_id = self.user_sessions.get(user_id)
            
            if not session_id:
                return
            
            status = data.get('status', 'active')
            current_view = data.get('view', 'dashboard')
            active_workflow = data.get('workflow')
            
            # Update presence
            self._update_user_presence(
                user_id, username, status, current_view, active_workflow
            )
            
            # Broadcast presence update
            event = CollaborationEvent(
                event_type=CollaborationEventType.PRESENCE_UPDATE,
                session_id=session_id,
                user_id=user_id,
                username=username,
                timestamp=datetime.utcnow(),
                data={
                    'status': status,
                    'view': current_view,
                    'workflow': active_workflow
                }
            )
            
            self._broadcast_event(event, exclude_sender=True)
        
        @self.socketio.on('share_finding')
        @AuthService.socketio_login_required
        def handle_share_finding(data):
            """Handle sharing of analysis findings"""
            user_id = str(current_user.id)
            username = current_user.username
            session_id = self.user_sessions.get(user_id)
            
            if not session_id:
                emit('error', {'message': 'Not in a session'})
                return
            
            finding_data = {
                'type': data.get('type'),
                'content': data.get('content'),
                'file_id': data.get('file_id'),
                'confidence': data.get('confidence'),
                'agent_type': data.get('agent_type'),
                'description': data.get('description')
            }
            
            # Create and broadcast finding event
            event = CollaborationEvent(
                event_type=CollaborationEventType.FINDING_SHARED,
                session_id=session_id,
                user_id=user_id,
                username=username,
                timestamp=datetime.utcnow(),
                data=finding_data
            )
            
            self._broadcast_event(event)
            self._store_event(event)
            
            # Check if this could be a breakthrough
            self._check_breakthrough(session_id, finding_data)
    
    def _join_session(self, user_id: str, username: str, session_id: str):
        """Handle user joining a session"""
        # Add to in-memory tracking
        if session_id not in self.active_sessions:
            self.active_sessions[session_id] = set()
        
        self.active_sessions[session_id].add(user_id)
        self.user_sessions[user_id] = session_id
        
        # Join SocketIO room
        join_room(session_id)
        
        # Update presence
        self._update_user_presence(user_id, username, session_id=session_id)
        
        # Create and broadcast join event
        event = CollaborationEvent(
            event_type=CollaborationEventType.USER_JOINED,
            session_id=session_id,
            user_id=user_id,
            username=username,
            timestamp=datetime.utcnow(),
            data={'action': 'joined'}
        )
        
        self._broadcast_event(event)
        self._store_event(event)
        
        logger.info(f"User {username} joined session {session_id}")
    
    def _leave_session(self, user_id: str, username: str, session_id: str):
        """Handle user leaving a session"""
        # Remove from in-memory tracking
        if session_id in self.active_sessions:
            self.active_sessions[session_id].discard(user_id)
            if not self.active_sessions[session_id]:
                del self.active_sessions[session_id]
        
        if user_id in self.user_sessions:
            del self.user_sessions[user_id]
        
        # Leave SocketIO room
        leave_room(session_id)
        
        # Create and broadcast leave event
        event = CollaborationEvent(
            event_type=CollaborationEventType.USER_LEFT,
            session_id=session_id,
            user_id=user_id,
            username=username,
            timestamp=datetime.utcnow(),
            data={'action': 'left'}
        )
        
        self._broadcast_event(event)
        self._store_event(event)
        
        logger.info(f"User {username} left session {session_id}")
    
    def _update_user_presence(self, user_id: str, username: str, 
                            status: str = 'active', current_view: str = 'dashboard',
                            active_workflow: str = None, session_id: str = None):
        """Update user presence information"""
        if session_id is None:
            session_id = self.user_sessions.get(user_id)
        
        presence = UserPresence(
            user_id=user_id,
            username=username,
            session_id=session_id or '',
            last_seen=datetime.utcnow(),
            status=status,
            current_view=current_view,
            active_workflow=active_workflow
        )
        
        self.user_presence[user_id] = presence
        
        # Store in Redis with expiration
        self.redis_client.setex(
            f"{self.presence_key}:{user_id}",
            300,  # 5 minutes TTL
            json.dumps(presence.to_dict(), default=str)
        )
    
    def _remove_user_presence(self, user_id: str):
        """Remove user presence"""
        if user_id in self.user_presence:
            del self.user_presence[user_id]
        
        self.redis_client.delete(f"{self.presence_key}:{user_id}")
    
    def _broadcast_event(self, event: CollaborationEvent, exclude_sender: bool = False):
        """Broadcast event to all users in session"""
        room = event.session_id
        event_data = event.to_dict()
        
        if exclude_sender:
            # Broadcast to room except sender
            self.socketio.emit(
                event.event_type.value,
                event_data,
                room=room,
                skip_sid=self.socketio.server.get_sid()
            )
        else:
            # Broadcast to entire room
            self.socketio.emit(event.event_type.value, event_data, room=room)
    
    def _store_event(self, event: CollaborationEvent):
        """Store event in Redis for history"""
        event_data = json.dumps(event.to_dict(), default=str)
        
        # Store in session-specific list with expiration
        session_key = f"{self.event_history_key}:{event.session_id}"
        
        # Add to list and trim to last 1000 events
        pipe = self.redis_client.pipeline()
        pipe.lpush(session_key, event_data)
        pipe.ltrim(session_key, 0, 999)
        pipe.expire(session_key, 86400 * 7)  # 7 days TTL
        pipe.execute()
    
    def _validate_session_access(self, user_id: str, session_id: str) -> bool:
        """Validate user access to session"""
        try:
            session = PuzzleSession.query.filter_by(session_id=session_id).first()
            if not session:
                return False
            
            # Check if user is creator or collaborator
            if session.created_by == int(user_id):
                return True
            
            # Check collaborators
            from crypto_hunter_web.models.puzzle_session import PuzzleCollaborator
            collaborator = PuzzleCollaborator.query.filter_by(
                session_id=session.id,
                user_id=int(user_id)
            ).first()
            
            return collaborator is not None
        except Exception as e:
            logger.error(f"Error validating session access: {e}")
            return False
    
    def _get_session_state(self, session_id: str) -> Dict[str, Any]:
        """Get current session state"""
        # Get active users
        active_users = []
        if session_id in self.active_sessions:
            for user_id in self.active_sessions[session_id]:
                if user_id in self.user_presence:
                    active_users.append(self.user_presence[user_id].to_dict())
        
        # Get recent events (last 50)
        recent_events = self._get_recent_events(session_id, limit=50)
        
        # Get active workflows
        active_workflows = self._get_active_workflows(session_id)
        
        return {
            'session_id': session_id,
            'active_users': active_users,
            'recent_events': recent_events,
            'active_workflows': active_workflows,
            'timestamp': datetime.utcnow().isoformat()
        }
    
    def _get_recent_events(self, session_id: str, limit: int = 50) -> List[Dict[str, Any]]:
        """Get recent events for session"""
        session_key = f"{self.event_history_key}:{session_id}"
        
        try:
            events = self.redis_client.lrange(session_key, 0, limit - 1)
            return [json.loads(event) for event in events]
        except Exception as e:
            logger.error(f"Error getting recent events: {e}")
            return []
    
    def _get_active_workflows(self, session_id: str) -> List[Dict[str, Any]]:
        """Get active workflows for session"""
        try:
            workflows = WorkflowExecution.query.filter_by(
                session_id=session_id,
                status='running'
            ).all()
            
            return [workflow.to_dict() for workflow in workflows]
        except Exception as e:
            logger.error(f"Error getting active workflows: {e}")
            return []
    
    def _get_user_sessions(self, user_id: str) -> List[Dict[str, Any]]:
        """Get sessions accessible to user"""
        try:
            sessions = []
            
            # Get sessions where user is creator
            user_sessions = PuzzleSession.query.filter_by(
                created_by=int(user_id)
            ).all()
            
            for session in user_sessions:
                sessions.append({
                    'session_id': session.session_id,
                    'name': session.session_name,
                    'role': 'creator',
                    'created_at': session.created_at.isoformat(),
                    'active_users': len(self.active_sessions.get(session.session_id, set()))
                })
            
            # Get sessions where user is collaborator
            from crypto_hunter_web.models.puzzle_session import PuzzleCollaborator
            collaborations = PuzzleCollaborator.query.filter_by(
                user_id=int(user_id)
            ).all()
            
            for collab in collaborations:
                session = collab.session
                sessions.append({
                    'session_id': session.session_id,
                    'name': session.session_name,
                    'role': collab.role,
                    'joined_at': collab.created_at.isoformat(),
                    'active_users': len(self.active_sessions.get(session.session_id, set()))
                })
            
            return sessions
        except Exception as e:
            logger.error(f"Error getting user sessions: {e}")
            return []
    
    def _check_breakthrough(self, session_id: str, finding_data: Dict[str, Any]):
        """Check if finding represents a breakthrough"""
        confidence = finding_data.get('confidence', 0)
        finding_type = finding_data.get('type', '')
        
        # Define breakthrough criteria
        breakthrough_indicators = [
            confidence > 0.9,  # Very high confidence
            finding_type in ['solution', 'key', 'flag', 'password'],
            'solved' in finding_data.get('content', '').lower()
        ]
        
        if any(breakthrough_indicators):
            # Create breakthrough event
            event = CollaborationEvent(
                event_type=CollaborationEventType.BREAKTHROUGH,
                session_id=session_id,
                user_id='system',
                username='System',
                timestamp=datetime.utcnow(),
                data={
                    'finding': finding_data,
                    'breakthrough_type': 'potential_solution',
                    'confidence': confidence
                }
            )
            
            self._broadcast_event(event)
            self._store_event(event)
            
            logger.info(f"Breakthrough detected in session {session_id}")
    
    # Public methods for external integration
    
    def notify_workflow_started(self, session_id: str, workflow_id: str, workflow_name: str):
        """Notify users that a workflow has started"""
        event = CollaborationEvent(
            event_type=CollaborationEventType.WORKFLOW_STARTED,
            session_id=session_id,
            user_id='system',
            username='System',
            timestamp=datetime.utcnow(),
            data={
                'workflow_id': workflow_id,
                'workflow_name': workflow_name
            }
        )
        
        self._broadcast_event(event)
        self._store_event(event)
    
    def notify_workflow_completed(self, session_id: str, workflow_id: str, 
                                success: bool, results: Dict[str, Any]):
        """Notify users that a workflow has completed"""
        event = CollaborationEvent(
            event_type=CollaborationEventType.WORKFLOW_COMPLETED,
            session_id=session_id,
            user_id='system',
            username='System',
            timestamp=datetime.utcnow(),
            data={
                'workflow_id': workflow_id,
                'success': success,
                'results_summary': results
            }
        )
        
        self._broadcast_event(event)
        self._store_event(event)
    
    def notify_agent_result(self, session_id: str, agent_type: str, 
                          task_type: str, success: bool, summary: Dict[str, Any]):
        """Notify users of agent execution results"""
        event = CollaborationEvent(
            event_type=CollaborationEventType.AGENT_RESULT,
            session_id=session_id,
            user_id='system',
            username='System',
            timestamp=datetime.utcnow(),
            data={
                'agent_type': agent_type,
                'task_type': task_type,
                'success': success,
                'summary': summary
            }
        )
        
        self._broadcast_event(event)
        self._store_event(event)
    
    def notify_file_uploaded(self, session_id: str, user_id: str, username: str,
                           filename: str, file_id: int):
        """Notify users that a file has been uploaded"""
        event = CollaborationEvent(
            event_type=CollaborationEventType.FILE_UPLOADED,
            session_id=session_id,
            user_id=user_id,
            username=username,
            timestamp=datetime.utcnow(),
            data={
                'filename': filename,
                'file_id': file_id
            }
        )
        
        self._broadcast_event(event)
        self._store_event(event)
    
    def get_session_analytics(self, session_id: str) -> Dict[str, Any]:
        """Get analytics for a collaboration session"""
        events = self._get_recent_events(session_id, limit=1000)
        
        # Analyze events
        event_counts = {}
        user_activity = {}
        timeline = []
        
        for event in events:
            event_type = event['event_type']
            user_id = event['user_id']
            timestamp = datetime.fromisoformat(event['timestamp'])
            
            # Count event types
            event_counts[event_type] = event_counts.get(event_type, 0) + 1
            
            # Track user activity
            if user_id not in user_activity:
                user_activity[user_id] = {
                    'username': event['username'],
                    'events': 0,
                    'last_active': timestamp
                }
            
            user_activity[user_id]['events'] += 1
            if timestamp > user_activity[user_id]['last_active']:
                user_activity[user_id]['last_active'] = timestamp
            
            # Build timeline
            timeline.append({
                'timestamp': event['timestamp'],
                'type': event_type,
                'user': event['username'],
                'summary': self._get_event_summary(event)
            })
        
        return {
            'session_id': session_id,
            'total_events': len(events),
            'event_counts': event_counts,
            'user_activity': user_activity,
            'timeline': sorted(timeline, key=lambda x: x['timestamp'], reverse=True)[:50],
            'active_users_count': len(self.active_sessions.get(session_id, set())),
            'generated_at': datetime.utcnow().isoformat()
        }
    
    def _get_event_summary(self, event: Dict[str, Any]) -> str:
        """Get human-readable summary of event"""
        event_type = event['event_type']
        username = event['username']
        data = event.get('data', {})
        
        summaries = {
            'user_joined': f"{username} joined the session",
            'user_left': f"{username} left the session",
            'workflow_started': f"Started workflow: {data.get('workflow_name', 'Unknown')}",
            'workflow_completed': f"Completed workflow: {data.get('workflow_id', 'Unknown')}",
            'agent_result': f"{data.get('agent_type', 'Agent')} completed {data.get('task_type', 'task')}",
            'breakthrough': f"Breakthrough detected! {data.get('breakthrough_type', '')}",
            'file_uploaded': f"{username} uploaded {data.get('filename', 'a file')}",
            'finding_shared': f"{username} shared a {data.get('type', 'finding')}",
            'chat_message': f"{username}: {data.get('message', '')[:50]}{'...' if len(data.get('message', '')) > 50 else ''}",
            'hypothesis_created': f"{username} created a hypothesis"
        }
        
        return summaries.get(event_type, f"{username} performed {event_type}")


# Global collaboration manager instance
collaboration_manager = RealtimeCollaborationManager()


def setup_realtime_collaboration(app: Flask, socketio: SocketIO, redis_client=None):
    """Setup real-time collaboration system"""
    global collaboration_manager
    
    collaboration_manager = RealtimeCollaborationManager(app, socketio, redis_client)
    
    # Register Flask routes for collaboration API
    @app.route('/api/collaboration/session/<session_id>/analytics', methods=['GET'])
    @AuthService.login_required
    def get_session_analytics(session_id):
        """Get collaboration analytics for session"""
        try:
            analytics = collaboration_manager.get_session_analytics(session_id)
            return {'success': True, 'analytics': analytics}
        except Exception as e:
            logger.exception(f"Failed to get session analytics: {e}")
            return {'success': False, 'error': str(e)}, 500
    
    @app.route('/api/collaboration/session/<session_id>/events', methods=['GET'])
    @AuthService.login_required
    def get_session_events(session_id):
        """Get recent events for session"""
        try:
            limit = request.args.get('limit', 50, type=int)
            events = collaboration_manager._get_recent_events(session_id, limit)
            return {'success': True, 'events': events}
        except Exception as e:
            logger.exception(f"Failed to get session events: {e}")
            return {'success': False, 'error': str(e)}, 500
    
    @app.route('/api/collaboration/presence', methods=['GET'])
    @AuthService.login_required
    def get_user_presence():
        """Get current user presence information"""
        try:
            presence_data = {}
            for user_id, presence in collaboration_manager.user_presence.items():
                presence_data[user_id] = presence.to_dict()
            
            return {'success': True, 'presence': presence_data}
        except Exception as e:
            logger.exception(f"Failed to get user presence: {e}")
            return {'success': False, 'error': str(e)}, 500
    
    logger.info("✅ Real-time collaboration system setup complete")
    return collaboration_manager


# Integration with agent system
def integrate_with_agent_system(agent_system):
    """Integrate collaboration with agent system for notifications"""
    
    # Monkey patch agent system methods to send notifications
    original_analyze_file = agent_system.analyze_file
    original_analyze_session = agent_system.analyze_session
    
    async def patched_analyze_file(file_id: int, workflow_name: str = "file_analysis", 
                                 session_id: str = None, priority = None) -> str:
        """Patched analyze_file with collaboration notifications"""
        result = await original_analyze_file(file_id, workflow_name, session_id, priority)
        
        if session_id:
            collaboration_manager.notify_workflow_started(
                session_id, result, workflow_name
            )
        
        return result
    
    async def patched_analyze_session(session_id: str, workflow_name: str = "collaborative_puzzle_solving",
                                    priority = None) -> str:
        """Patched analyze_session with collaboration notifications"""
        result = await original_analyze_session(session_id, workflow_name, priority)
        
        collaboration_manager.notify_workflow_started(
            session_id, result, workflow_name
        )
        
        return result
    
    # Apply patches
    agent_system.analyze_file = patched_analyze_file
    agent_system.analyze_session = patched_analyze_session
    
    logger.info("✅ Agent system integrated with collaboration notifications")


if __name__ == "__main__":
    # Test collaboration system
    import tempfile
    import os
    
    app = Flask(__name__)
    app.config['SECRET_KEY'] = 'test_secret'
    
    # Create test collaboration manager
    manager = RealtimeCollaborationManager()
    
    # Test event creation and storage
    test_event = CollaborationEvent(
        event_type=CollaborationEventType.USER_JOINED,
        session_id='test_session',
        user_id='test_user',
        username='Test User',
        timestamp=datetime.utcnow(),
        data={'action': 'joined'}
    )
    
    print("✅ Collaboration system test completed")
    print(f"Test event: {test_event.to_dict()}")