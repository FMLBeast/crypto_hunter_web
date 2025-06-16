"""
crypto_hunter_web/services/complete_agent_system.py
Complete integration of the multi-agent system for Crypto Hunter
"""

import os
import asyncio
import logging
from typing import Dict, Any, List, Optional
from datetime import datetime
import json

from crypto_hunter_web.extensions import db
from crypto_hunter_web.agents.base import AgentType, TaskPriority
from crypto_hunter_web.agents.agent_framework import (
    OrchestrationAgent, AgentRegistry, TaskQueue, orchestrator, 
    agent_registry, task_queue
)
from crypto_hunter_web.agents.specialized_agents import (
    FileAnalysisAgent, SteganographyAgent, CryptographyAgent, IntelligenceAgent
)
from crypto_hunter_web.agents.missing_specialized_agents import (
    RelationshipAgent, PresentationAgent, ValidationAgent
)
from crypto_hunter_web.agents.complete_workflow_templates import (
    register_complete_workflow_templates, get_workflow_recommendations,
    get_workflow_metadata, WorkflowExecutionUtils
)
from crypto_hunter_web.models.agent_models import (
    AgentExecution, WorkflowExecution, PatternFinding, CipherAnalysis,
    FileCorrelation, SessionIntelligence
)

logger = logging.getLogger(__name__)


class CompleteAgentSystem:
    """
    Complete agent system orchestrator that manages all agents and workflows
    """
    
    def __init__(self):
        self.initialized = False
        self.orchestrator = orchestrator
        self.agent_registry = agent_registry
        self.task_queue = task_queue
        self.agents = {}
        self.system_status = "stopped"
        
    def initialize(self, app=None) -> bool:
        """Initialize the complete agent system"""
        try:
            logger.info("🚀 Initializing Complete Agent System...")
            
            # Initialize core components
            self._initialize_agents()
            self._register_workflows()
            self._setup_monitoring()
            
            # Start orchestrator
            self.orchestrator.start()
            
            self.initialized = True
            self.system_status = "running"
            
            logger.info("✅ Complete Agent System initialized successfully")
            logger.info(f"📊 Registered {len(self.agents)} agents")
            logger.info(f"📋 Available workflows: {list(self.orchestrator.workflow_templates.keys())}")
            
            return True
            
        except Exception as e:
            logger.exception(f"❌ Failed to initialize agent system: {e}")
            self.system_status = "error"
            return False
    
    def _initialize_agents(self):
        """Initialize and register all specialized agents"""
        logger.info("🤖 Initializing specialized agents...")
        
        # Core analysis agents
        self.agents['file_analysis'] = FileAnalysisAgent()
        self.agents['steganography'] = SteganographyAgent()
        self.agents['cryptography'] = CryptographyAgent()
        self.agents['intelligence'] = IntelligenceAgent()
        
        # Relationship and validation agents
        self.agents['relationship'] = RelationshipAgent()
        self.agents['presentation'] = PresentationAgent()
        self.agents['validation'] = ValidationAgent()
        
        # Register all agents with the orchestrator
        for agent_name, agent in self.agents.items():
            self.orchestrator.register_agent(agent)
            logger.info(f"  ✓ Registered {agent_name} agent")
    
    def _register_workflows(self):
        """Register all workflow templates"""
        logger.info("📋 Registering workflow templates...")
        register_complete_workflow_templates(self.orchestrator)
        
        workflow_count = len(self.orchestrator.workflow_templates)
        logger.info(f"  ✓ Registered {workflow_count} workflow templates")
    
    def _setup_monitoring(self):
        """Setup system monitoring and health checks"""
        logger.info("📊 Setting up system monitoring...")
        
        # Create database tables if they don't exist
        try:
            db.create_all()
            logger.info("  ✓ Database tables verified")
        except Exception as e:
            logger.warning(f"  ⚠️  Database setup issue: {e}")
    
    async def analyze_file(self, file_id: int, workflow_name: str = "file_analysis", 
                          session_id: str = None, priority: TaskPriority = TaskPriority.NORMAL) -> str:
        """
        Start comprehensive file analysis using the agent system
        
        Args:
            file_id: ID of the file to analyze
            workflow_name: Name of the workflow to execute
            session_id: Optional session ID for grouping
            priority: Task priority level
            
        Returns:
            Workflow ID for tracking execution
        """
        if not self.initialized:
            raise RuntimeError("Agent system not initialized")
        
        logger.info(f"🎯 Starting analysis for file {file_id} with workflow '{workflow_name}'")
        
        # Get file information
        from crypto_hunter_web.models.analysis_file import AnalysisFile
        file_obj = AnalysisFile.query.get(file_id)
        if not file_obj:
            raise ValueError(f"File {file_id} not found")
        
        # Create workflow execution
        workflow_id = await self.orchestrator.start_workflow(
            workflow_name=workflow_name,
            initial_data={
                'file_id': file_id,
                'file_path': file_obj.file_path,
                'session_id': session_id or file_obj.session_id,
                'analysis_mode': 'comprehensive'
            },
            priority=priority
        )
        
        logger.info(f"🚀 Started workflow {workflow_id} for file analysis")
        return workflow_id
    
    async def analyze_session(self, session_id: str, workflow_name: str = "collaborative_puzzle_solving",
                            priority: TaskPriority = TaskPriority.HIGH) -> str:
        """
        Analyze all files in a session using collaborative workflow
        
        Args:
            session_id: Session ID to analyze
            workflow_name: Workflow to use for session analysis
            priority: Task priority
            
        Returns:
            Workflow ID for tracking
        """
        if not self.initialized:
            raise RuntimeError("Agent system not initialized")
        
        logger.info(f"🎯 Starting session analysis for {session_id}")
        
        # Get all files in session
        from crypto_hunter_web.models.analysis_file import AnalysisFile
        files = AnalysisFile.query.filter_by(session_id=session_id).all()
        
        if not files:
            raise ValueError(f"No files found in session {session_id}")
        
        # Prepare session context
        session_context = {
            'session_id': session_id,
            'file_count': len(files),
            'file_types': [f.file_type for f in files if f.file_type],
            'file_ids': [f.id for f in files],
            'total_size': sum(f.file_size or 0 for f in files)
        }
        
        # Start workflow
        workflow_id = await self.orchestrator.start_workflow(
            workflow_name=workflow_name,
            initial_data=session_context,
            priority=priority
        )
        
        logger.info(f"🚀 Started session workflow {workflow_id}")
        return workflow_id
    
    def get_workflow_status(self, workflow_id: str) -> Dict[str, Any]:
        """Get detailed workflow execution status"""
        return self.orchestrator.get_workflow_status(workflow_id)
    
    def get_workflow_results(self, workflow_id: str) -> Dict[str, Any]:
        """Get comprehensive workflow results"""
        status = self.get_workflow_status(workflow_id)
        
        if status['status'] != 'completed':
            return {
                'status': status['status'],
                'progress': status.get('progress', 0),
                'message': 'Workflow still in progress'
            }
        
        # Gather results from all agents
        results = {
            'workflow_id': workflow_id,
            'status': 'completed',
            'completion_time': status.get('completed_at'),
            'execution_time': status.get('execution_time'),
            'agent_results': {},
            'summary': {},
            'findings': [],
            'recommendations': []
        }
        
        # Get agent execution results
        executions = AgentExecution.query.filter_by(workflow_id=workflow_id).all()
        
        for execution in executions:
            agent_type = execution.agent_type
            if agent_type not in results['agent_results']:
                results['agent_results'][agent_type] = []
            
            results['agent_results'][agent_type].append({
                'task_type': execution.task_type,
                'success': execution.success,
                'execution_time': execution.execution_time,
                'output_data': execution.output_data,
                'confidence_score': execution.confidence_score
            })
        
        # Generate summary
        results['summary'] = self._generate_workflow_summary(results['agent_results'])
        
        # Extract findings
        results['findings'] = self._extract_workflow_findings(workflow_id)
        
        # Generate recommendations
        results['recommendations'] = self._generate_workflow_recommendations(results)
        
        return results
    
    def _generate_workflow_summary(self, agent_results: Dict[str, Any]) -> Dict[str, Any]:
        """Generate a summary of workflow results"""
        summary = {
            'agents_executed': len(agent_results),
            'total_tasks': sum(len(tasks) for tasks in agent_results.values()),
            'successful_tasks': 0,
            'failed_tasks': 0,
            'average_confidence': 0.0,
            'key_achievements': []
        }
        
        confidence_scores = []
        
        for agent_type, tasks in agent_results.items():
            for task in tasks:
                if task['success']:
                    summary['successful_tasks'] += 1
                    if task.get('confidence_score'):
                        confidence_scores.append(task['confidence_score'])
                else:
                    summary['failed_tasks'] += 1
        
        if confidence_scores:
            summary['average_confidence'] = sum(confidence_scores) / len(confidence_scores)
        
        # Identify key achievements
        if 'steganography' in agent_results:
            steg_tasks = agent_results['steganography']
            extractions = sum(1 for task in steg_tasks if task['success'] and 'extraction' in task['task_type'])
            if extractions > 0:
                summary['key_achievements'].append(f"Extracted {extractions} hidden element(s)")
        
        if 'cryptography' in agent_results:
            crypto_tasks = agent_results['cryptography']
            solved_ciphers = sum(1 for task in crypto_tasks if task['success'] and task.get('output_data', {}).get('solved'))
            if solved_ciphers > 0:
                summary['key_achievements'].append(f"Solved {solved_ciphers} cryptographic puzzle(s)")
        
        if 'relationship' in agent_results:
            rel_tasks = agent_results['relationship']
            relationships = sum(len(task.get('output_data', {}).get('relationships', [])) for task in rel_tasks if task['success'])
            if relationships > 0:
                summary['key_achievements'].append(f"Mapped {relationships} file relationship(s)")
        
        return summary
    
    def _extract_workflow_findings(self, workflow_id: str) -> List[Dict[str, Any]]:
        """Extract all findings from workflow execution"""
        findings = []
        
        # Get pattern findings
        pattern_findings = PatternFinding.query.join(
            AgentExecution, PatternFinding.agent_execution_id == AgentExecution.id
        ).filter(AgentExecution.workflow_id == workflow_id).all()
        
        for finding in pattern_findings:
            findings.append({
                'type': 'pattern',
                'pattern_type': finding.pattern_type,
                'pattern_name': finding.pattern_name,
                'confidence': finding.confidence_score,
                'file_id': finding.file_id,
                'discovered_by': finding.discovered_by_agent,
                'data': finding.pattern_data
            })
        
        # Get cipher analyses
        cipher_analyses = CipherAnalysis.query.join(
            AgentExecution, CipherAnalysis.agent_execution_id == AgentExecution.id
        ).filter(AgentExecution.workflow_id == workflow_id).all()
        
        for analysis in cipher_analyses:
            findings.append({
                'type': 'cipher',
                'cipher_type': analysis.cipher_type,
                'cipher_name': analysis.cipher_name,
                'confidence': analysis.confidence_score,
                'solved': analysis.is_solved,
                'solution': analysis.solution_text if analysis.is_solved else None,
                'file_id': analysis.file_id,
                'discovered_by': analysis.discovered_by_agent
            })
        
        # Get file correlations
        correlations = FileCorrelation.query.filter_by(
            discovered_by_agent=workflow_id  # This might need adjustment based on your schema
        ).all()
        
        for correlation in correlations:
            findings.append({
                'type': 'correlation',
                'correlation_type': correlation.correlation_type,
                'strength': correlation.correlation_strength,
                'file1_id': correlation.file1_id,
                'file2_id': correlation.file2_id,
                'evidence': correlation.evidence_data
            })
        
        return findings
    
    def _generate_workflow_recommendations(self, results: Dict[str, Any]) -> List[str]:
        """Generate actionable recommendations based on workflow results"""
        recommendations = []
        
        summary = results.get('summary', {})
        findings = results.get('findings', [])
        
        # Check success rate
        total_tasks = summary.get('total_tasks', 0)
        successful_tasks = summary.get('successful_tasks', 0)
        
        if total_tasks > 0:
            success_rate = successful_tasks / total_tasks
            if success_rate < 0.7:
                recommendations.append("Consider manual review due to lower automated success rate")
        
        # Check for unsolved ciphers
        unsolved_ciphers = [f for f in findings if f['type'] == 'cipher' and not f.get('solved', False)]
        if unsolved_ciphers:
            recommendations.append(f"Manual cryptanalysis recommended for {len(unsolved_ciphers)} unsolved cipher(s)")
        
        # Check for weak correlations
        weak_correlations = [f for f in findings if f['type'] == 'correlation' and f.get('strength', 0) < 0.5]
        if weak_correlations:
            recommendations.append("Consider broader relationship analysis for weak correlations")
        
        # Check confidence levels
        avg_confidence = summary.get('average_confidence', 0)
        if avg_confidence < 0.6:
            recommendations.append("Low confidence scores suggest manual verification needed")
        
        # Check for extraction opportunities
        pattern_findings = [f for f in findings if f['type'] == 'pattern']
        if pattern_findings and not any(f['type'] == 'extraction' for f in findings):
            recommendations.append("Pattern detection suggests additional extraction methods may be beneficial")
        
        return recommendations
    
    def get_system_status(self) -> Dict[str, Any]:
        """Get comprehensive system status"""
        return {
            'initialized': self.initialized,
            'status': self.system_status,
            'agents': {
                agent_id: {
                    'agent_type': agent.agent_type.value if hasattr(agent, 'agent_type') else 'unknown',
                    'status': getattr(agent, 'status', 'unknown'),
                    'capabilities': [cap.value for cap in getattr(agent, 'capabilities', [])]
                }
                for agent_id, agent in self.agents.items()
            },
            'orchestrator': {
                'running': self.orchestrator.running,
                'active_workflows': len(self.orchestrator.active_workflows),
                'workflow_templates': list(self.orchestrator.workflow_templates.keys())
            },
            'task_queue': {
                'pending_tasks': len(self.task_queue.tasks),
                'running_tasks': len(getattr(self.task_queue, 'running_tasks', [])),
                'max_concurrent': getattr(self.task_queue, 'max_concurrent_tasks', 5)
            },
            'database': {
                'agent_executions': AgentExecution.query.count(),
                'workflow_executions': WorkflowExecution.query.count(),
                'pattern_findings': PatternFinding.query.count(),
                'cipher_analyses': CipherAnalysis.query.count()
            }
        }
    
    def get_workflow_recommendations(self, session_id: str) -> List[Dict[str, Any]]:
        """Get recommended workflows for a session"""
        # Get session context
        from crypto_hunter_web.models.analysis_file import AnalysisFile
        files = AnalysisFile.query.filter_by(session_id=session_id).all()
        
        if not files:
            return []
        
        file_types = [f.file_type for f in files if f.file_type]
        session_context = {
            'file_count': len(files),
            'file_types': file_types,
            'total_size': sum(f.file_size or 0 for f in files),
            'has_images': any('image' in ft for ft in file_types),
            'has_audio': any('audio' in ft for ft in file_types),
            'has_text': any('text' in ft for ft in file_types)
        }
        
        # Get recommendations
        recommended_workflows = get_workflow_recommendations(file_types, session_context)
        workflow_metadata = get_workflow_metadata()
        
        recommendations = []
        for workflow_name in recommended_workflows:
            if workflow_name in workflow_metadata:
                metadata = workflow_metadata[workflow_name]
                estimated_time = WorkflowExecutionUtils.estimate_execution_time(
                    workflow_name, len(files), [f.file_size or 0 for f in files]
                )
                
                recommendations.append({
                    'workflow_name': workflow_name,
                    'name': metadata['name'],
                    'description': metadata['description'],
                    'estimated_time_seconds': estimated_time,
                    'estimated_time_display': self._format_time(estimated_time),
                    'complexity': metadata['complexity'],
                    'best_for': metadata['best_for'],
                    'agents_used': metadata['agents_used']
                })
        
        return recommendations
    
    def _format_time(self, seconds: int) -> str:
        """Format time in human readable format"""
        if seconds < 60:
            return f"{seconds} seconds"
        elif seconds < 3600:
            minutes = seconds // 60
            return f"{minutes} minute{'s' if minutes != 1 else ''}"
        else:
            hours = seconds // 3600
            minutes = (seconds % 3600) // 60
            return f"{hours}h {minutes}m"
    
    def shutdown(self):
        """Gracefully shutdown the agent system"""
        logger.info("🛑 Shutting down agent system...")
        
        try:
            # Stop orchestrator
            if hasattr(self.orchestrator, 'stop'):
                self.orchestrator.stop()
            
            # Clean up agents
            for agent in self.agents.values():
                if hasattr(agent, 'cleanup'):
                    agent.cleanup()
            
            self.system_status = "stopped"
            logger.info("✅ Agent system shutdown complete")
            
        except Exception as e:
            logger.exception(f"❌ Error during shutdown: {e}")
            self.system_status = "error"


# Global system instance
complete_agent_system = CompleteAgentSystem()


def initialize_complete_system(app=None) -> bool:
    """Initialize the complete agent system"""
    return complete_agent_system.initialize(app)


def get_system_instance() -> CompleteAgentSystem:
    """Get the global system instance"""
    return complete_agent_system


# Flask integration
def setup_complete_agent_routes(app):
    """Setup Flask routes for the complete agent system"""
    from flask import Blueprint, request, jsonify
    from crypto_hunter_web.services.auth_service import AuthService
    
    agent_bp = Blueprint('complete_agents', __name__, url_prefix='/api/agents')
    
    @agent_bp.route('/analyze/file/<int:file_id>', methods=['POST'])
    @AuthService.login_required
    async def analyze_file(file_id):
        """Start file analysis with agent system"""
        try:
            data = request.get_json() or {}
            workflow_name = data.get('workflow', 'file_analysis')
            session_id = data.get('session_id')
            priority_str = data.get('priority', 'normal')
            
            # Convert priority string to enum
            priority_map = {
                'critical': TaskPriority.CRITICAL,
                'high': TaskPriority.HIGH,
                'normal': TaskPriority.NORMAL,
                'low': TaskPriority.LOW,
                'background': TaskPriority.BACKGROUND
            }
            priority = priority_map.get(priority_str.lower(), TaskPriority.NORMAL)
            
            # Start analysis
            workflow_id = await complete_agent_system.analyze_file(
                file_id=file_id,
                workflow_name=workflow_name,
                session_id=session_id,
                priority=priority
            )
            
            return jsonify({
                'success': True,
                'workflow_id': workflow_id,
                'message': f'Analysis started with workflow {workflow_name}'
            })
            
        except Exception as e:
            logger.exception(f"Failed to start file analysis: {e}")
            return jsonify({'success': False, 'error': str(e)}), 500
    
    @agent_bp.route('/analyze/session/<session_id>', methods=['POST'])
    @AuthService.login_required
    async def analyze_session(session_id):
        """Start session analysis with agent system"""
        try:
            data = request.get_json() or {}
            workflow_name = data.get('workflow', 'collaborative_puzzle_solving')
            priority_str = data.get('priority', 'high')
            
            priority_map = {
                'critical': TaskPriority.CRITICAL,
                'high': TaskPriority.HIGH,
                'normal': TaskPriority.NORMAL,
                'low': TaskPriority.LOW,
                'background': TaskPriority.BACKGROUND
            }
            priority = priority_map.get(priority_str.lower(), TaskPriority.HIGH)
            
            # Start session analysis
            workflow_id = await complete_agent_system.analyze_session(
                session_id=session_id,
                workflow_name=workflow_name,
                priority=priority
            )
            
            return jsonify({
                'success': True,
                'workflow_id': workflow_id,
                'message': f'Session analysis started with workflow {workflow_name}'
            })
            
        except Exception as e:
            logger.exception(f"Failed to start session analysis: {e}")
            return jsonify({'success': False, 'error': str(e)}), 500
    
    @agent_bp.route('/workflow/<workflow_id>/status', methods=['GET'])
    @AuthService.login_required
    def get_workflow_status(workflow_id):
        """Get workflow execution status"""
        try:
            status = complete_agent_system.get_workflow_status(workflow_id)
            return jsonify({'success': True, 'status': status})
        except Exception as e:
            logger.exception(f"Failed to get workflow status: {e}")
            return jsonify({'success': False, 'error': str(e)}), 500
    
    @agent_bp.route('/workflow/<workflow_id>/results', methods=['GET'])
    @AuthService.login_required
    def get_workflow_results(workflow_id):
        """Get workflow execution results"""
        try:
            results = complete_agent_system.get_workflow_results(workflow_id)
            return jsonify({'success': True, 'results': results})
        except Exception as e:
            logger.exception(f"Failed to get workflow results: {e}")
            return jsonify({'success': False, 'error': str(e)}), 500
    
    @agent_bp.route('/system/status', methods=['GET'])
    @AuthService.login_required
    def get_system_status():
        """Get complete system status"""
        try:
            status = complete_agent_system.get_system_status()
            return jsonify({'success': True, 'status': status})
        except Exception as e:
            logger.exception(f"Failed to get system status: {e}")
            return jsonify({'success': False, 'error': str(e)}), 500
    
    @agent_bp.route('/workflows/recommendations/<session_id>', methods=['GET'])
    @AuthService.login_required
    def get_workflow_recommendations(session_id):
        """Get workflow recommendations for session"""
        try:
            recommendations = complete_agent_system.get_workflow_recommendations(session_id)
            return jsonify({'success': True, 'recommendations': recommendations})
        except Exception as e:
            logger.exception(f"Failed to get workflow recommendations: {e}")
            return jsonify({'success': False, 'error': str(e)}), 500
    
    @agent_bp.route('/workflows/metadata', methods=['GET'])
    @AuthService.login_required
    def get_all_workflows():
        """Get metadata for all available workflows"""
        try:
            metadata = get_workflow_metadata()
            return jsonify({'success': True, 'workflows': metadata})
        except Exception as e:
            logger.exception(f"Failed to get workflow metadata: {e}")
            return jsonify({'success': False, 'error': str(e)}), 500
    
    app.register_blueprint(agent_bp)
    logger.info("✅ Complete agent system routes registered")


# CLI commands for Flask app
def register_agent_cli_commands(app):
    """Register CLI commands for agent system management"""
    
    @app.cli.command('agent-system-init')
    def init_complete_system():
        """Initialize the complete agent system"""
        with app.app_context():
            if initialize_complete_system(app):
                print("✅ Complete agent system initialized successfully")
            else:
                print("❌ Failed to initialize complete agent system")
    
    @app.cli.command('agent-system-status')
    def system_status():
        """Get complete system status"""
        with app.app_context():
            status = complete_agent_system.get_system_status()
            
            print("\n🤖 Complete Agent System Status")
            print("=" * 50)
            print(f"Status: {status['status']}")
            print(f"Initialized: {status['initialized']}")
            print(f"Agents: {len(status['agents'])}")
            print(f"Active Workflows: {status['orchestrator']['active_workflows']}")
            print(f"Pending Tasks: {status['task_queue']['pending_tasks']}")
            
            print("\n📊 Database Counts:")
            for table, count in status['database'].items():
                print(f"  {table}: {count}")
    
    @app.cli.command('agent-system-shutdown')
    def shutdown_system():
        """Shutdown the agent system"""
        with app.app_context():
            complete_agent_system.shutdown()
            print("🛑 Agent system shutdown complete")
    
    @app.cli.command('agent-cleanup-old')
    @app.cli.option('--days', default=7, help='Delete executions older than N days')
    def cleanup_old_executions(days):
        """Clean up old agent executions"""
        with app.app_context():
            from datetime import timedelta
            
            cutoff_date = datetime.utcnow() - timedelta(days=days)
            
            # Delete old executions
            old_executions = AgentExecution.query.filter(
                AgentExecution.created_at < cutoff_date
            ).delete()
            
            old_workflows = WorkflowExecution.query.filter(
                WorkflowExecution.created_at < cutoff_date
            ).delete()
            
            db.session.commit()
            
            print(f"🧹 Cleaned up {old_executions} old agent executions")
            print(f"🧹 Cleaned up {old_workflows} old workflow executions")
