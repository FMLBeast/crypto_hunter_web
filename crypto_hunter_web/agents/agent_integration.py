"""
crypto_hunter_web/services/agent_integration.py
Flask integration for the agent-based extraction system
"""

import asyncio
import logging
from typing import Dict, Any, Optional
from flask import Flask, current_app
from celery import Celery

from crypto_hunter_web.agents.base import agent_registry
from crypto_hunter_web.agents.orchestration import orchestration_engine
from crypto_hunter_web.agents.specialized import (
    FileAnalysisAgent, SteganographyAgent, CryptographyAgent, IntelligenceAgent
)
from crypto_hunter_web.services.agent_extraction_service import agent_extraction_service

logger = logging.getLogger(__name__)


class AgentSystemIntegration:
    """Handles integration of agent system with Flask app"""
    
    def __init__(self):
        self.app: Optional[Flask] = None
        self.celery: Optional[Celery] = None
        self.initialized = False
        self.background_task: Optional[asyncio.Task] = None
    
    def init_app(self, app: Flask, celery: Optional[Celery] = None):
        """Initialize agent system with Flask app"""
        self.app = app
        self.celery = celery
        
        # Configure agent system
        self._configure_agent_system(app)
        
        # Register Flask routes
        self._register_routes(app)
        
        # Register Celery tasks if available
        if celery:
            self._register_celery_tasks(celery)
        
        # Start background services
        self._start_background_services(app)
        
        self.initialized = True
        logger.info("Agent system integration initialized successfully")
    
    def _configure_agent_system(self, app: Flask):
        """Configure agent system settings"""
        # Agent system configuration
        app.config.setdefault('AGENT_SYSTEM_ENABLED', True)
        app.config.setdefault('AGENT_MAX_CONCURRENT_WORKFLOWS', 10)
        app.config.setdefault('AGENT_TASK_TIMEOUT', 600)
        app.config.setdefault('AGENT_CLEANUP_INTERVAL', 3600)  # 1 hour
        
        # Database settings for agents
        app.config.setdefault('AGENT_DB_BATCH_SIZE', 100)
        app.config.setdefault('AGENT_RESULT_RETENTION_DAYS', 30)
    
    def _register_routes(self, app: Flask):
        """Register Flask routes for agent system"""
        from crypto_hunter_web.services.agent_extraction_service import create_flask_routes
        create_flask_routes(app)
    
    def _register_celery_tasks(self, celery: Celery):
        """Register Celery tasks for agent system"""
        from crypto_hunter_web.services.agent_extraction_service import create_celery_tasks
        
        tasks = create_celery_tasks(celery)
        
        # Store task references for later use
        self.celery_tasks = tasks
        
        logger.info(f"Registered {len(tasks)} agent Celery tasks")
    
    def _start_background_services(self, app: Flask):
        """Start background services for agent system"""
        def start_services():
            """Start services in app context"""
            with app.app_context():
                try:
                    # Initialize the agent extraction service
                    agent_extraction_service.initialize()
                    
                    # Create event loop for agent system
                    if not hasattr(current_app, '_agent_event_loop'):
                        loop = asyncio.new_event_loop()
                        asyncio.set_event_loop(loop)
                        current_app._agent_event_loop = loop
                        
                        # Start orchestration engine
                        loop.create_task(orchestration_engine.start())
                        
                        logger.info("Agent system background services started")
                    
                except Exception as e:
                    logger.error(f"Failed to start agent background services: {e}")
        
        # Start services in a separate thread to avoid blocking Flask startup
        import threading
        service_thread = threading.Thread(target=start_services, daemon=True)
        service_thread.start()


# Global integration instance
agent_integration = AgentSystemIntegration()


def init_agent_system(app: Flask, celery: Optional[Celery] = None):
    """Initialize agent system with Flask app"""
    agent_integration.init_app(app, celery)


# Enhanced background API routes
def create_enhanced_background_api():
    """Create enhanced background API with agent support"""
    from flask import Blueprint, request, jsonify
    from crypto_hunter_web.services.auth_service import AuthService
    from crypto_hunter_web.models import AnalysisFile
    
    enhanced_bg_api = Blueprint('enhanced_background', __name__, url_prefix='/api/background/v2')
    
    @enhanced_bg_api.route('/analyze', methods=['POST'])
    @AuthService.login_required
    def start_enhanced_analysis():
        """Start enhanced agent-based analysis"""
        try:
            data = request.get_json()
            file_id = data.get('file_id')
            analysis_type = data.get('analysis_type', 'comprehensive')
            session_id = data.get('session_id')
            
            if not file_id:
                return jsonify({'success': False, 'error': 'file_id required'}), 400
            
            # Validate file exists
            file_record = AnalysisFile.query.get(file_id)
            if not file_record:
                return jsonify({'success': False, 'error': 'File not found'}), 404
            
            # Start agent-based analysis
            if agent_integration.celery and 'analyze_file' in agent_integration.celery_tasks:
                # Use Celery for async processing
                task = agent_integration.celery_tasks['analyze_file'].delay(
                    file_id=file_id,
                    user_id=AuthService.get_current_user().id,
                    analysis_type=analysis_type,
                    session_id=session_id
                )
                
                return jsonify({
                    'success': True,
                    'task_id': task.id,
                    'analysis_type': analysis_type,
                    'estimated_duration': _estimate_analysis_duration(analysis_type),
                    'message': f'Started {analysis_type} analysis with agent system'
                })
            else:
                # Direct async execution
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                try:
                    workflow_id = loop.run_until_complete(
                        agent_extraction_service.analyze_file(
                            file_id=file_id,
                            user_id=AuthService.get_current_user().id,
                            analysis_type=analysis_type,
                            session_id=session_id
                        )
                    )
                    
                    return jsonify({
                        'success': True,
                        'workflow_id': workflow_id,
                        'analysis_type': analysis_type,
                        'message': f'Started {analysis_type} analysis'
                    })
                finally:
                    loop.close()
                    
        except Exception as e:
            logger.exception(f"Enhanced analysis failed: {e}")
            return jsonify({'success': False, 'error': str(e)}), 500
    
    @enhanced_bg_api.route('/steganography', methods=['POST'])
    @AuthService.login_required
    def start_steganography_analysis():
        """Start focused steganography analysis"""
        try:
            data = request.get_json()
            file_id = data.get('file_id')
            methods = data.get('methods', ['zsteg', 'steghide', 'binwalk'])
            session_id = data.get('session_id')
            
            if not file_id:
                return jsonify({'success': False, 'error': 'file_id required'}), 400
            
            # Start steganography extraction
            if agent_integration.celery and 'extract_steganography' in agent_integration.celery_tasks:
                task = agent_integration.celery_tasks['extract_steganography'].delay(
                    file_id=file_id,
                    methods=methods,
                    session_id=session_id
                )
                
                return jsonify({
                    'success': True,
                    'task_id': task.id,
                    'methods': methods,
                    'message': 'Started steganography extraction'
                })
            else:
                # Direct execution
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                try:
                    task_id = loop.run_until_complete(
                        agent_extraction_service.extract_steganography(
                            file_id=file_id,
                            methods=methods,
                            session_id=session_id
                        )
                    )
                    
                    return jsonify({
                        'success': True,
                        'task_id': task_id,
                        'methods': methods,
                        'message': 'Started steganography extraction'
                    })
                finally:
                    loop.close()
                    
        except Exception as e:
            logger.exception(f"Steganography analysis failed: {e}")
            return jsonify({'success': False, 'error': str(e)}), 500
    
    @enhanced_bg_api.route('/status/workflow/<workflow_id>', methods=['GET'])
    @AuthService.login_required
    def get_workflow_status(workflow_id):
        """Get workflow status"""
        try:
            status = agent_extraction_service.get_analysis_status(workflow_id)
            if status:
                return jsonify({'success': True, 'status': status})
            else:
                return jsonify({'success': False, 'error': 'Workflow not found'}), 404
                
        except Exception as e:
            logger.exception(f"Failed to get workflow status: {e}")
            return jsonify({'success': False, 'error': str(e)}), 500
    
    @enhanced_bg_api.route('/results/workflow/<workflow_id>', methods=['GET'])
    @AuthService.login_required
    def get_workflow_results(workflow_id):
        """Get comprehensive workflow results"""
        try:
            results = agent_extraction_service.get_analysis_results(workflow_id)
            return jsonify({'success': True, 'results': results})
            
        except Exception as e:
            logger.exception(f"Failed to get workflow results: {e}")
            return jsonify({'success': False, 'error': str(e)}), 500
    
    @enhanced_bg_api.route('/system/status', methods=['GET'])
    @AuthService.login_required
    def get_system_status():
        """Get agent system status"""
        try:
            status = agent_extraction_service.get_agent_status()
            
            # Add system health metrics
            status['system_health'] = _get_system_health()
            
            return jsonify({'success': True, 'status': status})
            
        except Exception as e:
            logger.exception(f"Failed to get system status: {e}")
            return jsonify({'success': False, 'error': str(e)}), 500
    
    @enhanced_bg_api.route('/workflows', methods=['GET'])
    @AuthService.login_required
    def list_workflows():
        """List available workflow templates"""
        try:
            workflows = list(orchestration_engine.workflow_templates.keys())
            
            workflow_info = {}
            for name, template in orchestration_engine.workflow_templates.items():
                workflow_info[name] = {
                    'name': template.name,
                    'description': template.description,
                    'steps': len(template.steps)
                }
            
            return jsonify({
                'success': True,
                'workflows': workflows,
                'workflow_info': workflow_info
            })
            
        except Exception as e:
            logger.exception(f"Failed to list workflows: {e}")
            return jsonify({'success': False, 'error': str(e)}), 500
    
    def _estimate_analysis_duration(analysis_type: str) -> str:
        """Estimate analysis duration based on type"""
        durations = {
            'comprehensive': '5-15 minutes',
            'steganography': '2-8 minutes',
            'crypto': '3-10 minutes',
            'quick': '1-3 minutes',
            'deep': '10-30 minutes'
        }
        return durations.get(analysis_type, '5-10 minutes')
    
    def _get_system_health() -> Dict[str, Any]:
        """Get system health metrics"""
        return {
            'agents_registered': len(agent_registry.agents),
            'orchestration_running': orchestration_engine.running,
            'active_workflows': len(orchestration_engine.active_workflows),
            'agent_system_initialized': agent_integration.initialized
        }
    
    return enhanced_bg_api


# WebSocket support for real-time updates
def create_websocket_handlers(socketio):
    """Create WebSocket handlers for real-time agent updates"""
    
    @socketio.on('subscribe_workflow')
    def handle_workflow_subscription(data):
        """Subscribe to workflow updates"""
        workflow_id = data.get('workflow_id')
        if workflow_id:
            # Join workflow room for updates
            from flask_socketio import join_room
            join_room(f'workflow_{workflow_id}')
            logger.info(f"Client subscribed to workflow {workflow_id}")
    
    @socketio.on('unsubscribe_workflow')
    def handle_workflow_unsubscription(data):
        """Unsubscribe from workflow updates"""
        workflow_id = data.get('workflow_id')
        if workflow_id:
            from flask_socketio import leave_room
            leave_room(f'workflow_{workflow_id}')
            logger.info(f"Client unsubscribed from workflow {workflow_id}")
    
    @socketio.on('get_agent_status')
    def handle_agent_status_request():
        """Get real-time agent status"""
        try:
            status = agent_extraction_service.get_agent_status()
            from flask_socketio import emit
            emit('agent_status', {'success': True, 'status': status})
        except Exception as e:
            from flask_socketio import emit
            emit('agent_status', {'success': False, 'error': str(e)})


# Enhanced CLI commands for agent system
def register_agent_commands(app: Flask):
    """Register CLI commands for agent system management"""
    
    @app.cli.command('agent-status')
    def agent_status():
        """Show agent system status"""
        with app.app_context():
            status = agent_extraction_service.get_agent_status()
            
            print("\n=== Agent System Status ===")
            print(f"Agents registered: {len(status['agents'])}")
            print(f"Task queue: {status['task_queue']}")
            print(f"Orchestration engine running: {status['orchestration_engine']['running']}")
            print(f"Active workflows: {status['orchestration_engine']['active_workflows']}")
            
            print("\n=== Registered Agents ===")
            for agent_id, agent_status in status['agents'].items():
                print(f"  {agent_id}: {agent_status['agent_type']} ({agent_status['status']})")
    
    @app.cli.command('agent-init')
    def init_agents():
        """Initialize agent system"""
        with app.app_context():
            try:
                agent_extraction_service.initialize()
                print("✅ Agent system initialized successfully")
            except Exception as e:
                print(f"❌ Failed to initialize agent system: {e}")
    
    @app.cli.command('agent-cleanup')
    def cleanup_agents():
        """Cleanup old agent executions"""
        with app.app_context():
            try:
                agent_extraction_service.cleanup_old_executions(days_old=7)
                print("✅ Agent cleanup completed")
            except Exception as e:
                print(f"❌ Agent cleanup failed: {e}")
    
    @app.cli.command('agent-test')
    def test_agents():
        """Test agent system with sample data"""
        with app.app_context():
            print("🧪 Testing agent system...")
            
            # Test agent registration
            if len(agent_registry.agents) == 0:
                print("❌ No agents registered")
                return
            
            print(f"✅ {len(agent_registry.agents)} agents registered")
            
            # Test workflow templates
            templates = list(orchestration_engine.workflow_templates.keys())
            print(f"✅ {len(templates)} workflow templates available: {templates}")
            
            print("🎉 Agent system test completed")


# Legacy API compatibility layer
def create_legacy_compatibility_layer():
    """Create compatibility layer for legacy extraction API"""
    from flask import Blueprint, request, jsonify
    from crypto_hunter_web.services.auth_service import AuthService
    
    legacy_bp = Blueprint('legacy_extraction', __name__, url_prefix='/api/legacy')
    
    @legacy_bp.route('/extract', methods=['POST'])
    @AuthService.login_required
    def legacy_extract():
        """Legacy extraction endpoint that routes to agent system"""
        try:
            data = request.get_json()
            file_id = data.get('file_id')
            method = data.get('method', 'comprehensive')
            
            if not file_id:
                return jsonify({'success': False, 'error': 'file_id required'}), 400
            
            # Map legacy methods to new analysis types
            method_mapping = {
                'zsteg': 'steganography',
                'steghide': 'steganography',
                'binwalk': 'comprehensive',
                'crypto': 'crypto',
                'full': 'comprehensive'
            }
            
            analysis_type = method_mapping.get(method, 'comprehensive')
            
            # Route to agent system
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            try:
                workflow_id = loop.run_until_complete(
                    agent_extraction_service.analyze_file(
                        file_id=file_id,
                        user_id=AuthService.get_current_user().id,
                        analysis_type=analysis_type
                    )
                )
                
                return jsonify({
                    'success': True,
                    'workflow_id': workflow_id,
                    'legacy_method': method,
                    'new_analysis_type': analysis_type,
                    'message': 'Analysis started with agent system'
                })
            finally:
                loop.close()
                
        except Exception as e:
            logger.exception(f"Legacy extraction failed: {e}")
            return jsonify({'success': False, 'error': str(e)}), 500
    
    return legacy_bp


# Monitoring and metrics
class AgentMetrics:
    """Collect and track agent system metrics"""
    
    def __init__(self):
        self.reset_metrics()
    
    def reset_metrics(self):
        """Reset all metrics"""
        self.metrics = {
            'workflows_started': 0,
            'workflows_completed': 0,
            'workflows_failed': 0,
            'tasks_executed': 0,
            'tasks_failed': 0,
            'average_workflow_duration': 0.0,
            'agent_errors': {},
            'popular_analysis_types': {}
        }
    
    def record_workflow_started(self, workflow_name: str):
        """Record workflow started"""
        self.metrics['workflows_started'] += 1
        
        if workflow_name not in self.metrics['popular_analysis_types']:
            self.metrics['popular_analysis_types'][workflow_name] = 0
        self.metrics['popular_analysis_types'][workflow_name] += 1
    
    def record_workflow_completed(self, workflow_name: str, duration: float):
        """Record workflow completed"""
        self.metrics['workflows_completed'] += 1
        
        # Update average duration
        current_avg = self.metrics['average_workflow_duration']
        completed = self.metrics['workflows_completed']
        self.metrics['average_workflow_duration'] = ((current_avg * (completed - 1)) + duration) / completed
    
    def record_workflow_failed(self, workflow_name: str):
        """Record workflow failed"""
        self.metrics['workflows_failed'] += 1
    
    def record_task_executed(self, agent_id: str):
        """Record task executed"""
        self.metrics['tasks_executed'] += 1
    
    def record_task_failed(self, agent_id: str, error: str):
        """Record task failed"""
        self.metrics['tasks_failed'] += 1
        
        if agent_id not in self.metrics['agent_errors']:
            self.metrics['agent_errors'][agent_id] = []
        self.metrics['agent_errors'][agent_id].append(error)
    
    def get_metrics(self) -> Dict[str, Any]:
        """Get current metrics"""
        return self.metrics.copy()


# Global metrics instance
agent_metrics = AgentMetrics()


def setup_agent_integration(app: Flask, celery: Optional[Celery] = None, socketio=None):
    """Complete setup of agent system integration"""
    
    # Initialize agent system
    init_agent_system(app, celery)
    
    # Register enhanced API
    enhanced_api = create_enhanced_background_api()
    app.register_blueprint(enhanced_api)
    
    # Register legacy compatibility
    legacy_api = create_legacy_compatibility_layer()
    app.register_blueprint(legacy_api)
    
    # Register CLI commands
    register_agent_commands(app)
    
    # Setup WebSocket handlers if available
    if socketio:
        create_websocket_handlers(socketio)
    
    # Create database tables
    with app.app_context():
        from crypto_hunter_web.models.agent_models import create_agent_tables
        create_agent_tables()
    
    logger.info("Complete agent system integration setup completed")
