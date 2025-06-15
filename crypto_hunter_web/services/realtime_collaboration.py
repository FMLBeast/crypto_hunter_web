"""
crypto_hunter_web/services/realtime_collaboration.py
Real-time collaboration system for puzzle solving sessions
"""

import asyncio
import json
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Set
from dataclasses import dataclass, field
from enum import Enum
import uuid

from flask import current_app
from flask_socketio import SocketIO, emit, join_room, leave_room, rooms
from sqlalchemy import and_, or_

from crypto_hunter_web.extensions import db
from crypto_hunter_web.models import PuzzleSession, PuzzleStep, PuzzleCollaborator, User, Finding
from crypto_hunter_web.services.auth_service import AuthService

logger = logging.getLogger(__name__)


class CollaborationEventType(Enum):
    """Types of collaboration events"""
    USER_JOINED = "user_joined"
    USER_LEFT = "user_left"
    STEP_CREATED = "step_created"
    STEP_UPDATED = "step_updated"
    FINDING_ADDED = "finding_added"
    FINDING_VALIDATED = "finding_validated"
    BREAKTHROUGH = "breakthrough"
    HYPOTHESIS_SHARED = "hypothesis_shared"
    AGENT_RESULT = "agent_result"
    CURSOR_MOVE = "cursor_move"
    TYPING_INDICATOR = "typing_indicator"
    CHAT_MESSAGE = "chat_message"


@dataclass
class CollaborationEvent:
    """Collaboration event data structure"""
    event_type: CollaborationEventType
    session_id: str
    user_id: int
    username: str
    timestamp: datetime = field(default_factory=datetime.utcnow)
    data: Dict[str, Any] = field(default_factory=dict)
    event_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'event_type': self.event_type.value,
            'session_id': self.session_id,
            'user_id': self.user_id,
            'username': self.username,
            'timestamp': self.timestamp.isoformat(),
            'data': self.data,
            'event_id': self.event_id
        }


class UserPresence:
    """Track user presence in sessions"""
    
    def __init__(self):
        # session_id -> {user_id: {last_seen, cursor_position, current_activity}}
        self.presence_data: Dict[str, Dict[int, Dict[str, Any]]] = {}
        self.typing_indicators: Dict[str, Dict[int, datetime]] = {}
    
    def update_presence(self, session_id: str, user_id: int, activity: str = "active", 
                       cursor_position: Optional[Dict[str, Any]] = None):
        """Update user presence in session"""
        if session_id not in self.presence_data:
            self.presence_data[session_id] = {}
        
        self.presence_data[session_id][user_id] = {
            'last_seen': datetime.utcnow(),
            'activity': activity,
            'cursor_position': cursor_position or {}
        }
    
    def set_typing(self, session_id: str, user_id: int, is_typing: bool):
        """Set typing indicator for user"""
        if session_id not in self.typing_indicators:
            self.typing_indicators[session_id] = {}
        
        if is_typing:
            self.typing_indicators[session_id][user_id] = datetime.utcnow()
        else:
            self.typing_indicators[session_id].pop(user_id, None)
    
    def get_online_users(self, session_id: str, timeout_minutes: int = 5) -> List[int]:
        """Get list of online users in session"""
        if session_id not in self.presence_data:
            return []
        
        cutoff_time = datetime.utcnow() - timedelta(minutes=timeout_minutes)
        online_users = []
        
        for user_id, data in self.presence_data[session_id].items():
            if data['last_seen'] > cutoff_time:
                online_users.append(user_id)
        
        return online_users
    
    def get_typing_users(self, session_id: str, timeout_seconds: int = 10) -> List[int]:
        """Get list of currently typing users"""
        if session_id not in self.typing_indicators:
            return []
        
        cutoff_time = datetime.utcnow() - timedelta(seconds=timeout_seconds)
        typing_users = []
        
        for user_id, last_typing in self.typing_indicators[session_id].items():
            if last_typing > cutoff_time:
                typing_users.append(user_id)
        
        return typing_users
    
    def remove_user(self, session_id: str, user_id: int):
        """Remove user from presence tracking"""
        if session_id in self.presence_data:
            self.presence_data[session_id].pop(user_id, None)
        
        if session_id in self.typing_indicators:
            self.typing_indicators[session_id].pop(user_id, None)


class BreakthroughDetector:
    """Detect potential breakthroughs in puzzle solving"""
    
    def __init__(self):
        self.confidence_threshold = 0.8
        self.pattern_threshold = 3  # Number of related findings
    
    def analyze_finding(self, finding: Finding, session_id: str) -> Optional[Dict[str, Any]]:
        """Analyze if a finding represents a breakthrough"""
        breakthrough_indicators = []
        confidence_score = 0.0
        
        # High confidence finding
        if finding.confidence_score and finding.confidence_score > self.confidence_threshold:
            breakthrough_indicators.append("High confidence score")
            confidence_score += 0.3
        
        # Solved cipher/decoded content
        if any(keyword in finding.title.lower() for keyword in ['solved', 'decoded', 'decrypted', 'plaintext']):
            breakthrough_indicators.append("Content successfully decoded")
            confidence_score += 0.4
        
        # Hidden file extraction
        if 'extracted' in finding.title.lower() or 'hidden file' in finding.description.lower():
            breakthrough_indicators.append("Hidden content extracted")
            confidence_score += 0.3
        
        # Check for related findings pattern
        related_findings = self._find_related_findings(finding, session_id)
        if len(related_findings) >= self.pattern_threshold:
            breakthrough_indicators.append(f"Part of {len(related_findings)} related findings")
            confidence_score += 0.2
        
        # Key or password discovery
        if any(keyword in finding.title.lower() for keyword in ['key', 'password', 'passphrase']):
            breakthrough_indicators.append("Potential key/password found")
            confidence_score += 0.3
        
        if confidence_score > 0.5:  # Breakthrough threshold
            return {
                'breakthrough_type': 'finding_breakthrough',
                'confidence': confidence_score,
                'indicators': breakthrough_indicators,
                'finding_id': finding.id,
                'related_findings': [f.id for f in related_findings]
            }
        
        return None
    
    def _find_related_findings(self, finding: Finding, session_id: str) -> List[Finding]:
        """Find related findings in the same session"""
        # Get session to find related files
        session = PuzzleSession.query.filter_by(public_id=session_id).first()
        if not session:
            return []
        
        # Get all findings from session files
        session_file_ids = []
        for step in session.steps:
            for step_file in step.files:
                session_file_ids.append(step_file.file_id)
        
        # Find related findings
        related = Finding.query.filter(
            and_(
                Finding.file_id.in_(session_file_ids),
                Finding.id != finding.id,
                or_(
                    Finding.title.contains(finding.title.split()[0]) if finding.title else False,
                    Finding.category == finding.category
                )
            )
        ).limit(10).all()
        
        return related


class RealtimeCollaboration:
    """Main real-time collaboration service"""
    
    def __init__(self, socketio: SocketIO):
        self.socketio = socketio
        self.presence = UserPresence()
        self.breakthrough_detector = BreakthroughDetector()
        self.event_history: Dict[str, List[CollaborationEvent]] = {}
        self.max_history_events = 100
        
        # Register socket event handlers
        self._register_socket_handlers()
    
    def _register_socket_handlers(self):
        """Register WebSocket event handlers"""
        
        @self.socketio.on('join_session')
        def handle_join_session(data):
            """Handle user joining a puzzle session"""
            session_id = data.get('session_id')
            user = AuthService.get_current_user()
            
            if not session_id or not user:
                emit('error', {'message': 'Invalid session or user'})
                return
            
            # Verify user has access to session
            if not self._verify_session_access(session_id, user.id):
                emit('error', {'message': 'Access denied to session'})
                return
            
            # Join socket room
            join_room(f'session_{session_id}')
            
            # Update presence
            self.presence.update_presence(session_id, user.id, 'joined')
            
            # Create and broadcast join event
            event = CollaborationEvent(
                event_type=CollaborationEventType.USER_JOINED,
                session_id=session_id,
                user_id=user.id,
                username=user.username,
                data={'display_name': user.display_name}
            )
            self._broadcast_event(event)
            
            # Send current session state to new user
            self._send_session_state(session_id, user.id)
            
            logger.info(f"User {user.username} joined session {session_id}")
        
        @self.socketio.on('leave_session')
        def handle_leave_session(data):
            """Handle user leaving a puzzle session"""
            session_id = data.get('session_id')
            user = AuthService.get_current_user()
            
            if session_id and user:
                # Leave socket room
                leave_room(f'session_{session_id}')
                
                # Remove from presence
                self.presence.remove_user(session_id, user.id)
                
                # Broadcast leave event
                event = CollaborationEvent(
                    event_type=CollaborationEventType.USER_LEFT,
                    session_id=session_id,
                    user_id=user.id,
                    username=user.username
                )
                self._broadcast_event(event)
                
                logger.info(f"User {user.username} left session {session_id}")
        
        @self.socketio.on('cursor_move')
        def handle_cursor_move(data):
            """Handle cursor movement for real-time collaboration"""
            session_id = data.get('session_id')
            cursor_position = data.get('position', {})
            user = AuthService.get_current_user()
            
            if session_id and user:
                # Update presence with cursor position
                self.presence.update_presence(
                    session_id, user.id, 'active', cursor_position
                )
                
                # Broadcast cursor movement
                event = CollaborationEvent(
                    event_type=CollaborationEventType.CURSOR_MOVE,
                    session_id=session_id,
                    user_id=user.id,
                    username=user.username,
                    data={'position': cursor_position}
                )
                self._broadcast_event(event, exclude_user=user.id)
        
        @self.socketio.on('typing_indicator')
        def handle_typing_indicator(data):
            """Handle typing indicators"""
            session_id = data.get('session_id')
            is_typing = data.get('is_typing', False)
            user = AuthService.get_current_user()
            
            if session_id and user:
                # Update typing status
                self.presence.set_typing(session_id, user.id, is_typing)
                
                # Broadcast typing indicator
                event = CollaborationEvent(
                    event_type=CollaborationEventType.TYPING_INDICATOR,
                    session_id=session_id,
                    user_id=user.id,
                    username=user.username,
                    data={'is_typing': is_typing}
                )
                self._broadcast_event(event, exclude_user=user.id)
        
        @self.socketio.on('chat_message')
        def handle_chat_message(data):
            """Handle chat messages in session"""
            session_id = data.get('session_id')
            message = data.get('message', '').strip()
            user = AuthService.get_current_user()
            
            if session_id and user and message:
                # Create chat event
                event = CollaborationEvent(
                    event_type=CollaborationEventType.CHAT_MESSAGE,
                    session_id=session_id,
                    user_id=user.id,
                    username=user.username,
                    data={
                        'message': message,
                        'display_name': user.display_name
                    }
                )
                self._broadcast_event(event)
                
                # Store in event history
                self._add_to_history(event)
        
        @self.socketio.on('share_hypothesis')
        def handle_share_hypothesis(data):
            """Handle hypothesis sharing"""
            session_id = data.get('session_id')
            hypothesis = data.get('hypothesis', {})
            user = AuthService.get_current_user()
            
            if session_id and user and hypothesis:
                event = CollaborationEvent(
                    event_type=CollaborationEventType.HYPOTHESIS_SHARED,
                    session_id=session_id,
                    user_id=user.id,
                    username=user.username,
                    data={'hypothesis': hypothesis}
                )
                self._broadcast_event(event)
                self._add_to_history(event)
        
        @self.socketio.on('get_session_users')
        def handle_get_session_users(data):
            """Get current users in session"""
            session_id = data.get('session_id')
            
            if session_id:
                online_users = self.presence.get_online_users(session_id)
                typing_users = self.presence.get_typing_users(session_id)
                
                # Get user details
                users_data = []
                if online_users:
                    users = User.query.filter(User.id.in_(online_users)).all()
                    for user in users:
                        user_data = {
                            'id': user.id,
                            'username': user.username,
                            'display_name': user.display_name,
                            'is_typing': user.id in typing_users
                        }
                        
                        # Add presence data
                        if session_id in self.presence.presence_data:
                            presence = self.presence.presence_data[session_id].get(user.id, {})
                            user_data['last_seen'] = presence.get('last_seen', '').isoformat() if presence.get('last_seen') else ''
                            user_data['activity'] = presence.get('activity', 'unknown')
                            user_data['cursor_position'] = presence.get('cursor_position', {})
                        
                        users_data.append(user_data)
                
                emit('session_users', {
                    'users': users_data,
                    'total_online': len(online_users)
                })
    
    def _verify_session_access(self, session_id: str, user_id: int) -> bool:
        """Verify user has access to puzzle session"""
        try:
            session = PuzzleSession.query.filter_by(public_id=session_id).first()
            if not session:
                return False
            
            # Check if user is owner
            if session.owner_id == user_id:
                return True
            
            # Check if user is collaborator
            collaborator = PuzzleCollaborator.query.filter_by(
                session_id=session.id,
                user_id=user_id
            ).first()
            
            return collaborator is not None
            
        except Exception as e:
            logger.error(f"Error verifying session access: {e}")
            return False
    
    def _send_session_state(self, session_id: str, user_id: int):
        """Send current session state to user"""
        try:
            # Get session data
            session = PuzzleSession.query.filter_by(public_id=session_id).first()
            if not session:
                return
            
            # Get recent events
            recent_events = self.event_history.get(session_id, [])[-20:]  # Last 20 events
            
            # Get online users
            online_users = self.presence.get_online_users(session_id)
            
            # Send state to specific user
            self.socketio.emit('session_state', {
                'session': {
                    'id': session.public_id,
                    'name': session.name,
                    'status': session.status,
                    'step_count': len(session.steps)
                },
                'online_users': online_users,
                'recent_events': [event.to_dict() for event in recent_events]
            }, room=f'user_{user_id}')
            
        except Exception as e:
            logger.error(f"Error sending session state: {e}")
    
    def _broadcast_event(self, event: CollaborationEvent, exclude_user: Optional[int] = None):
        """Broadcast event to all users in session"""
        room = f'session_{event.session_id}'
        event_data = event.to_dict()
        
        if exclude_user:
            # Send to all users except the excluded one
            # Note: This is a simplified approach; in production, you'd need more sophisticated user filtering
            self.socketio.emit('collaboration_event', event_data, room=room)
        else:
            self.socketio.emit('collaboration_event', event_data, room=room)
        
        # Add to history
        self._add_to_history(event)
    
    def _add_to_history(self, event: CollaborationEvent):
        """Add event to session history"""
        if event.session_id not in self.event_history:
            self.event_history[event.session_id] = []
        
        self.event_history[event.session_id].append(event)
        
        # Limit history size
        if len(self.event_history[event.session_id]) > self.max_history_events:
            self.event_history[event.session_id] = self.event_history[event.session_id][-self.max_history_events:]
    
    def notify_finding_added(self, finding: Finding, session_id: str, user_id: int):
        """Notify session of new finding and check for breakthroughs"""
        user = User.query.get(user_id)
        if not user:
            return
        
        # Create finding event
        event = CollaborationEvent(
            event_type=CollaborationEventType.FINDING_ADDED,
            session_id=session_id,
            user_id=user_id,
            username=user.username,
            data={
                'finding': {
                    'id': finding.id,
                    'title': finding.title,
                    'category': finding.category,
                    'confidence_score': finding.confidence_score
                }
            }
        )
        self._broadcast_event(event)
        
        # Check for breakthrough
        breakthrough = self.breakthrough_detector.analyze_finding(finding, session_id)
        if breakthrough:
            self.notify_breakthrough(breakthrough, session_id, user_id)
    
    def notify_breakthrough(self, breakthrough_data: Dict[str, Any], session_id: str, user_id: int):
        """Notify session of a breakthrough"""
        user = User.query.get(user_id)
        if not user:
            return
        
        event = CollaborationEvent(
            event_type=CollaborationEventType.BREAKTHROUGH,
            session_id=session_id,
            user_id=user_id,
            username=user.username,
            data=breakthrough_data
        )
        self._broadcast_event(event)
        
        # Log breakthrough
        logger.info(f"Breakthrough detected in session {session_id}: {breakthrough_data['breakthrough_type']}")
    
    def notify_agent_result(self, workflow_id: str, result_data: Dict[str, Any], 
                           session_id: str, user_id: int):
        """Notify session of agent analysis result"""
        user = User.query.get(user_id)
        if not user:
            return
        
        event = CollaborationEvent(
            event_type=CollaborationEventType.AGENT_RESULT,
            session_id=session_id,
            user_id=user_id,
            username=user.username,
            data={
                'workflow_id': workflow_id,
                'result': result_data
            }
        )
        self._broadcast_event(event)
    
    def get_session_activity(self, session_id: str, hours: int = 24) -> Dict[str, Any]:
        """Get session activity summary"""
        cutoff_time = datetime.utcnow() - timedelta(hours=hours)
        
        # Get events from history
        session_events = self.event_history.get(session_id, [])
        recent_events = [
            event for event in session_events 
            if event.timestamp > cutoff_time
        ]
        
        # Analyze activity
        activity_summary = {
            'total_events': len(recent_events),
            'unique_users': len(set(event.user_id for event in recent_events)),
            'event_types': {},
            'most_active_user': None,
            'breakthrough_count': 0
        }
        
        # Count event types
        for event in recent_events:
            event_type = event.event_type.value
            if event_type not in activity_summary['event_types']:
                activity_summary['event_types'][event_type] = 0
            activity_summary['event_types'][event_type] += 1
            
            if event.event_type == CollaborationEventType.BREAKTHROUGH:
                activity_summary['breakthrough_count'] += 1
        
        # Find most active user
        user_activity = {}
        for event in recent_events:
            if event.user_id not in user_activity:
                user_activity[event.user_id] = 0
            user_activity[event.user_id] += 1
        
        if user_activity:
            most_active_user_id = max(user_activity, key=user_activity.get)
            user = User.query.get(most_active_user_id)
            if user:
                activity_summary['most_active_user'] = {
                    'id': user.id,
                    'username': user.username,
                    'event_count': user_activity[most_active_user_id]
                }
        
        return activity_summary


# Global collaboration instance
collaboration_service: Optional[RealtimeCollaboration] = None


def init_collaboration(socketio: SocketIO):
    """Initialize real-time collaboration service"""
    global collaboration_service
    collaboration_service = RealtimeCollaboration(socketio)
    logger.info("Real-time collaboration service initialized")


def get_collaboration_service() -> Optional[RealtimeCollaboration]:
    """Get the collaboration service instance"""
    return collaboration_service


# Helper functions for integration
def notify_finding_breakthrough(finding: Finding, session_id: str, user_id: int):
    """Helper to notify about finding breakthroughs"""
    if collaboration_service:
        collaboration_service.notify_finding_added(finding, session_id, user_id)


def notify_agent_completion(workflow_id: str, result_data: Dict[str, Any], 
                           session_id: str, user_id: int):
    """Helper to notify about agent completion"""
    if collaboration_service:
        collaboration_service.notify_agent_result(workflow_id, result_data, session_id, user_id)


# Dashboard API for collaboration insights
def create_collaboration_api():
    """Create API endpoints for collaboration insights"""
    from flask import Blueprint, jsonify, request
    from crypto_hunter_web.services.auth_service import AuthService
    
    collab_api = Blueprint('collaboration', __name__, url_prefix='/api/collaboration')
    
    @collab_api.route('/session/<session_id>/activity', methods=['GET'])
    @AuthService.login_required
    def get_session_activity(session_id):
        """Get session collaboration activity"""
        try:
            hours = request.args.get('hours', 24, type=int)
            
            if not collaboration_service:
                return jsonify({'success': False, 'error': 'Collaboration service not available'})
            
            activity = collaboration_service.get_session_activity(session_id, hours)
            return jsonify({'success': True, 'activity': activity})
            
        except Exception as e:
            logger.exception(f"Error getting session activity: {e}")
            return jsonify({'success': False, 'error': str(e)}), 500
    
    @collab_api.route('/session/<session_id>/users', methods=['GET'])
    @AuthService.login_required
    def get_session_users(session_id):
        """Get current users in session"""
        try:
            if not collaboration_service:
                return jsonify({'success': False, 'error': 'Collaboration service not available'})
            
            online_users = collaboration_service.presence.get_online_users(session_id)
            typing_users = collaboration_service.presence.get_typing_users(session_id)
            
            # Get user details
            users_data = []
            if online_users:
                users = User.query.filter(User.id.in_(online_users)).all()
                for user in users:
                    users_data.append({
                        'id': user.id,
                        'username': user.username,
                        'display_name': user.display_name,
                        'is_typing': user.id in typing_users
                    })
            
            return jsonify({
                'success': True,
                'users': users_data,
                'total_online': len(online_users)
            })
            
        except Exception as e:
            logger.exception(f"Error getting session users: {e}")
            return jsonify({'success': False, 'error': str(e)}), 500
    
    @collab_api.route('/session/<session_id>/events', methods=['GET'])
    @AuthService.login_required
    def get_session_events(session_id):
        """Get recent session events"""
        try:
            if not collaboration_service:
                return jsonify({'success': False, 'error': 'Collaboration service not available'})
            
            limit = request.args.get('limit', 50, type=int)
            events = collaboration_service.event_history.get(session_id, [])[-limit:]
            
            return jsonify({
                'success': True,
                'events': [event.to_dict() for event in events],
                'total_events': len(events)
            })
            
        except Exception as e:
            logger.exception(f"Error getting session events: {e}")
            return jsonify({'success': False, 'error': str(e)}), 500
    
    return collab_api
