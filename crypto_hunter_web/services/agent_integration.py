"""
crypto_hunter_web/services/agent_integration.py
Complete integration of the multi-agent system with Flask app
"""

import asyncio
import logging
from typing import Dict, List, Any, Optional
from datetime import datetime
from flask import current_app, g

from crypto_hunter_web.agents.base import (
    AgentTask, AgentResult, AgentType, TaskPriority, 
    agent_registry, task_queue
)
from crypto_hunter_web.agents.orchestration import orchestration_engine
from crypto_hunter_web.agents.specialized import (
    FileAnalysisAgent, SteganographyAgent, CryptographyAgent, IntelligenceAgent
)
from crypto_hunter_web.models import db, AnalysisFile, Finding, PuzzleSession

logger = logging.getLogger(__name__)


class AgentIntegrationService:
    """Service that integrates the agent system with Flask app"""
    
    def __init__(self):
        self.initialized = False
        self.active_tasks: Dict[str, AgentTask] = {}
        self.completed_tasks: Dict[str, AgentResult] = {}
        
    def initialize(self, app=None):
        """Initialize the agent system"""
        if self.initialized:
            return True
            
        try:
            # Register all specialized agents
            agents = [
                FileAnalysisAgent(),
                SteganographyAgent(),
                CryptographyAgent(),
                IntelligenceAgent()
            ]
            
            for agent in agents:
                agent_registry.register_agent(agent)
            
            self.initialized = True
            logger.info(f"✅ Agent system initialized with {len(agents)} agents")
            return True
            
        except Exception as e:
            logger.error(f"❌ Failed to initialize agent system: {e}")
            return False
    
    async def analyze_file_with_agents(self, file_id: int, workflow_name: str = "file_analysis") -> str:
        """Start agent-based file analysis"""
        try:
            # Get file record
            file_record = AnalysisFile.query.get(file_id)
            if not file_record:
                raise ValueError(f"File not found: {file_id}")
            
            # Create initial task data
            initial_data = {
                'file_id': file_id,
                'file_path': file_record.filepath,
                'file_name': file_record.filename,
                'file_size': file_record.file_size
            }
            
            # Execute workflow
            workflow_id = await orchestration_engine.execute_workflow(
                workflow_name=workflow_name,
                initial_data=initial_data,
                session_id=file_record.session_id
            )
            
            return workflow_id
            
        except Exception as e:
            logger.error(f"Error starting agent analysis: {e}")
            raise
    
    async def execute_single_task(self, task: AgentTask) -> AgentResult:
        """Execute a single agent task"""
        try:
            # Find available agent
            agent = agent_registry.find_available_agent(task)
            if not agent:
                return AgentResult(
                    task_id=task.task_id,
                    agent_id="system",
                    success=False,
                    error="No available agent for task"
                )
            
            # Execute task
            result = await agent.execute_task(task)
            
            # Store result
            self.completed_tasks[task.task_id] = result
            
            # Process next tasks if any
            for next_task in result.next_tasks:
                task_queue.add_task(next_task)
            
            return result
            
        except Exception as e:
            logger.error(f"Error executing task {task.task_id}: {e}")
            return AgentResult(
                task_id=task.task_id,
                agent_id="system",
                success=False,
                error=str(e)
            )
    
    def create_file_analysis_task(self, file_id: int, analysis_type: str = "comprehensive") -> AgentTask:
        """Create a file analysis task"""
        return AgentTask(
            task_type='analyze_file',
            agent_type=AgentType.FILE_ANALYSIS,
            priority=TaskPriority.NORMAL,
            payload={
                'file_id': file_id,
                'analysis_type': analysis_type
            },
            context={
                'created_by': 'agent_integration_service',
                'timestamp': datetime.utcnow().isoformat()
            }
        )
    
    def create_steganography_task(self, file_id: int, methods: List[str] = None) -> AgentTask:
        """Create a steganography analysis task"""
        if methods is None:
            methods = ['zsteg', 'steghide', 'binwalk']
            
        return AgentTask(
            task_type='extract_hidden_data',
            agent_type=AgentType.STEGANOGRAPHY,
            priority=TaskPriority.HIGH,
            payload={
                'file_id': file_id,
                'methods': methods
            }
        )
    
    def create_crypto_analysis_task(self, file_id: int, content: str = None) -> AgentTask:
        """Create a cryptography analysis task"""
        return AgentTask(
            task_type='analyze_crypto_patterns',
            agent_type=AgentType.CRYPTOGRAPHY,
            priority=TaskPriority.NORMAL,
            payload={
                'file_id': file_id,
                'content': content
            }
        )
    
    def get_task_status(self, task_id: str) -> Dict[str, Any]:
        """Get status of a task"""
        if task_id in self.completed_tasks:
            result = self.completed_tasks[task_id]
            return {
                'task_id': task_id,
                'status': 'completed',
                'success': result.success,
                'data': result.data,
                'error': result.error,
                'execution_time': result.execution_time
            }
        elif task_id in self.active_tasks:
            return {
                'task_id': task_id,
                'status': 'running',
                'started_at': self.active_tasks[task_id].created_at.isoformat()
            }
        else:
            return {
                'task_id': task_id,
                'status': 'not_found'
            }
    
    def get_workflow_status(self, workflow_id: str) -> Dict[str, Any]:
        """Get status of a workflow"""
        return orchestration_engine.get_workflow_status(workflow_id)


# Global service instance
agent_integration_service = AgentIntegrationService()


def setup_agent_integration(app, celery=None):
    """Setup agent integration with Flask app"""
    if not agent_integration_service.initialize(app):
        app.logger.error("Failed to initialize agent system")
        return False
    
    # Add agent routes
    @app.route('/api/agent/analyze/<int:file_id>', methods=['POST'])
    def analyze_file_with_agents(file_id):
        """Start agent-based file analysis"""
        try:
            # Create and queue analysis task
            task = agent_integration_service.create_file_analysis_task(file_id)
            task_queue.add_task(task)
            
            return {
                'success': True,
                'task_id': task.task_id,
                'message': 'Analysis started with agent system'
            }
        except Exception as e:
            return {'success': False, 'error': str(e)}, 400
    
    @app.route('/api/agent/task/<task_id>', methods=['GET'])
    def get_task_status(task_id):
        """Get task status"""
        status = agent_integration_service.get_task_status(task_id)
        return status
    
    @app.route('/api/agent/workflow/<workflow_id>', methods=['GET'])
    def get_workflow_status(workflow_id):
        """Get workflow status"""
        status = agent_integration_service.get_workflow_status(workflow_id)
        return status
    
    @app.route('/api/agent/status', methods=['GET'])
    def get_system_status():
        """Get overall agent system status"""
        return {
            'agents_registered': len(agent_registry.agents),
            'tasks_queued': len(task_queue.tasks),
            'tasks_running': len(task_queue.running_tasks),
            'initialized': agent_integration_service.initialized
        }
    
    app.logger.info("✅ Agent integration routes registered")
    return True


def create_agent_tables():
    """Create database tables for agent system"""
    # This will be implemented when we add the agent database models
    pass
