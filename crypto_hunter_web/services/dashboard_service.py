"""
crypto_hunter_web/services/dashboard_service.py
Interactive dashboard and visualization system for puzzle solving insights
"""

import json
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple
from collections import defaultdict, Counter
from dataclasses import dataclass

from flask import current_app
from sqlalchemy import func, and_, or_, desc
import networkx as nx

from crypto_hunter_web.extensions import db
from crypto_hunter_web.models import (
    AnalysisFile, Finding, PuzzleSession, PuzzleStep, User,
    ExtractionRelationship, FileContent
)
from crypto_hunter_web.models.agent_models import (
    AgentExecution, WorkflowExecution, PatternFinding, 
    CipherAnalysis, FileCorrelation, SessionIntelligence
)

logger = logging.getLogger(__name__)


@dataclass
class DashboardMetrics:
    """Dashboard metrics data structure"""
    total_files: int = 0
    total_findings: int = 0
    total_sessions: int = 0
    active_workflows: int = 0
    solved_puzzles: int = 0
    success_rate: float = 0.0
    avg_analysis_time: float = 0.0
    top_file_types: List[Tuple[str, int]] = None
    recent_breakthroughs: List[Dict[str, Any]] = None
    
    def __post_init__(self):
        if self.top_file_types is None:
            self.top_file_types = []
        if self.recent_breakthroughs is None:
            self.recent_breakthroughs = []


class DashboardService:
    """Service for generating dashboard data and visualizations"""
    
    def __init__(self):
        self.cache_timeout = 300  # 5 minutes
        self._cached_metrics = {}
    
    def get_overview_metrics(self, user_id: Optional[int] = None, 
                           days: int = 30) -> DashboardMetrics:
        """Get overview metrics for dashboard"""
        cache_key = f"overview_metrics_{user_id}_{days}"
        
        # Check cache
        if cache_key in self._cached_metrics:
            cached_data, timestamp = self._cached_metrics[cache_key]
            if (datetime.utcnow() - timestamp).seconds < self.cache_timeout:
                return cached_data
        
        # Calculate metrics
        cutoff_date = datetime.utcnow() - timedelta(days=days)
        
        # Base queries
        file_query = AnalysisFile.query
        finding_query = Finding.query
        session_query = PuzzleSession.query
        
        # Filter by user if specified
        if user_id:
            file_query = file_query.filter_by(discovered_by=user_id)
            session_query = session_query.filter_by(owner_id=user_id)
        
        # Filter by date
        file_query = file_query.filter(AnalysisFile.created_at >= cutoff_date)
        finding_query = finding_query.filter(Finding.created_at >= cutoff_date)
        session_query = session_query.filter(PuzzleSession.created_at >= cutoff_date)
        
        # Calculate metrics
        metrics = DashboardMetrics()
        
        # Basic counts
        metrics.total_files = file_query.count()
        metrics.total_findings = finding_query.count()
        metrics.total_sessions = session_query.count()
        
        # Active workflows
        metrics.active_workflows = WorkflowExecution.query.filter(
            WorkflowExecution.status.in_(['pending', 'running'])
        ).count()
        
        # Solved puzzles (sessions with status 'completed')
        metrics.solved_puzzles = session_query.filter_by(status='completed').count()
        
        # Success rate
        if metrics.total_sessions > 0:
            metrics.success_rate = metrics.solved_puzzles / metrics.total_sessions
        
        # Average analysis time from workflows
        completed_workflows = WorkflowExecution.query.filter(
            and_(
                WorkflowExecution.status == 'completed',
                WorkflowExecution.started_at.isnot(None),
                WorkflowExecution.completed_at.isnot(None),
                WorkflowExecution.created_at >= cutoff_date
            )
        ).all()
        
        if completed_workflows:
            total_time = sum(
                (wf.completed_at - wf.started_at).total_seconds()
                for wf in completed_workflows
            )
            metrics.avg_analysis_time = total_time / len(completed_workflows)
        
        # Top file types
        file_type_counts = db.session.query(
            AnalysisFile.mime_type,
            func.count(AnalysisFile.id)
        ).filter(
            AnalysisFile.created_at >= cutoff_date
        ).group_by(
            AnalysisFile.mime_type
        ).order_by(
            desc(func.count(AnalysisFile.id))
        ).limit(10).all()
        
        metrics.top_file_types = [(ft[0] or 'unknown', ft[1]) for ft in file_type_counts]
        
        # Recent breakthroughs
        metrics.recent_breakthroughs = self._get_recent_breakthroughs(days)
        
        # Cache results
        self._cached_metrics[cache_key] = (metrics, datetime.utcnow())
        
        return metrics
    
    def _get_recent_breakthroughs(self, days: int) -> List[Dict[str, Any]]:
        """Get recent breakthrough findings"""
        cutoff_date = datetime.utcnow() - timedelta(days=days)
        
        # High confidence findings
        breakthroughs = Finding.query.filter(
            and_(
                Finding.created_at >= cutoff_date,
                Finding.confidence_score >= 0.8
            )
        ).order_by(desc(Finding.created_at)).limit(10).all()
        
        # Solved ciphers
        solved_ciphers = CipherAnalysis.query.filter(
            and_(
                CipherAnalysis.created_at >= cutoff_date,
                CipherAnalysis.is_solved == True
            )
        ).order_by(desc(CipherAnalysis.created_at)).limit(5).all()
        
        breakthrough_list = []
        
        # Add high confidence findings
        for finding in breakthroughs:
            breakthrough_list.append({
                'type': 'high_confidence_finding',
                'title': finding.title,
                'confidence': finding.confidence_score,
                'timestamp': finding.created_at.isoformat(),
                'file_id': finding.file_id
            })
        
        # Add solved ciphers
        for cipher in solved_ciphers:
            breakthrough_list.append({
                'type': 'solved_cipher',
                'title': f"Solved {cipher.cipher_type}: {cipher.cipher_name}",
                'confidence': cipher.confidence_score,
                'timestamp': cipher.created_at.isoformat(),
                'solution': cipher.solution_text[:100] + '...' if cipher.solution_text else None
            })
        
        # Sort by timestamp and return top 10
        breakthrough_list.sort(key=lambda x: x['timestamp'], reverse=True)
        return breakthrough_list[:10]
    
    def get_file_relationship_graph(self, session_id: Optional[str] = None, 
                                  user_id: Optional[int] = None) -> Dict[str, Any]:
        """Generate file relationship graph data"""
        # Create NetworkX graph
        G = nx.DiGraph()
        
        # Base query for files
        files_query = AnalysisFile.query
        
        if session_id:
            # Get files from specific session
            session = PuzzleSession.query.filter_by(public_id=session_id).first()
            if session:
                file_ids = []
                for step in session.steps:
                    for step_file in step.files:
                        file_ids.append(step_file.file_id)
                files_query = files_query.filter(AnalysisFile.id.in_(file_ids))
        elif user_id:
            files_query = files_query.filter_by(discovered_by=user_id)
        
        files = files_query.limit(100).all()  # Limit for performance
        
        # Add nodes
        for file in files:
            G.add_node(file.id, 
                      filename=file.filename,
                      file_type=file.mime_type or 'unknown',
                      size=file.filesize,
                      findings_count=len(file.findings))
        
        # Add extraction relationships
        for file in files:
            relationships = ExtractionRelationship.query.filter_by(
                parent_file_id=file.id
            ).all()
            
            for rel in relationships:
                if rel.extracted_file_id in [f.id for f in files]:
                    G.add_edge(file.id, rel.extracted_file_id,
                             relationship_type='extraction',
                             method=rel.extraction_method,
                             tool=rel.extraction_tool)
        
        # Add file correlations from agent analysis
        correlations = FileCorrelation.query.filter(
            or_(
                FileCorrelation.file1_id.in_([f.id for f in files]),
                FileCorrelation.file2_id.in_([f.id for f in files])
            )
        ).all()
        
        for corr in correlations:
            if corr.file1_id in [f.id for f in files] and corr.file2_id in [f.id for f in files]:
                G.add_edge(corr.file1_id, corr.file2_id,
                         relationship_type='correlation',
                         correlation_type=corr.correlation_type,
                         strength=corr.correlation_strength)
        
        # Convert to visualization format
        nodes = []
        edges = []
        
        # Calculate node positions using spring layout
        try:
            pos = nx.spring_layout(G, k=3, iterations=50)
        except:
            pos = {}
        
        for node_id, data in G.nodes(data=True):
            node_pos = pos.get(node_id, [0, 0])
            nodes.append({
                'id': node_id,
                'label': data.get('filename', f'File {node_id}'),
                'type': data.get('file_type', 'unknown'),
                'size': min(max(data.get('size', 1000) / 1000, 10), 50),  # Scale for visualization
                'findings_count': data.get('findings_count', 0),
                'x': float(node_pos[0]) * 300,  # Scale for visualization
                'y': float(node_pos[1]) * 300
            })
        
        for source, target, data in G.edges(data=True):
            edges.append({
                'source': source,
                'target': target,
                'type': data.get('relationship_type', 'unknown'),
                'strength': data.get('strength', 1.0),
                'label': data.get('method', data.get('correlation_type', ''))
            })
        
        return {
            'nodes': nodes,
            'edges': edges,
            'stats': {
                'total_nodes': len(nodes),
                'total_edges': len(edges),
                'connected_components': nx.number_connected_components(G.to_undirected())
            }
        }
    
    def get_analysis_timeline(self, session_id: Optional[str] = None,
                            user_id: Optional[int] = None, days: int = 30) -> Dict[str, Any]:
        """Generate analysis timeline data"""
        cutoff_date = datetime.utcnow() - timedelta(days=days)
        
        # Get workflow executions
        workflow_query = WorkflowExecution.query.filter(
            WorkflowExecution.created_at >= cutoff_date
        )
        
        if session_id:
            workflow_query = workflow_query.filter_by(session_id=session_id)
        
        workflows = workflow_query.order_by(WorkflowExecution.created_at).all()
        
        # Get findings
        finding_query = Finding.query.filter(Finding.created_at >= cutoff_date)
        
        if user_id:
            # Get findings from user's files
            user_files = AnalysisFile.query.filter_by(discovered_by=user_id).all()
            file_ids = [f.id for f in user_files]
            finding_query = finding_query.filter(Finding.file_id.in_(file_ids))
        
        findings = finding_query.order_by(Finding.created_at).all()
        
        # Combine into timeline
        timeline_events = []
        
        # Add workflow events
        for wf in workflows:
            timeline_events.append({
                'timestamp': wf.created_at.isoformat(),
                'type': 'workflow_started',
                'title': f"Started {wf.workflow_name}",
                'description': f"Workflow {wf.workflow_id}",
                'status': wf.status,
                'duration': self._calculate_duration(wf.started_at, wf.completed_at)
            })
            
            if wf.completed_at:
                timeline_events.append({
                    'timestamp': wf.completed_at.isoformat(),
                    'type': 'workflow_completed',
                    'title': f"Completed {wf.workflow_name}",
                    'description': f"Workflow {wf.workflow_id}",
                    'status': wf.status,
                    'success': wf.success
                })
        
        # Add finding events
        for finding in findings:
            timeline_events.append({
                'timestamp': finding.created_at.isoformat(),
                'type': 'finding_discovered',
                'title': finding.title,
                'description': finding.description[:100] + '...' if finding.description else '',
                'category': finding.category,
                'confidence': finding.confidence_score
            })
        
        # Sort by timestamp
        timeline_events.sort(key=lambda x: x['timestamp'])
        
        return {
            'events': timeline_events,
            'stats': {
                'total_events': len(timeline_events),
                'workflows': len(workflows),
                'findings': len(findings),
                'date_range': {
                    'start': cutoff_date.isoformat(),
                    'end': datetime.utcnow().isoformat()
                }
            }
        }
    
    def _calculate_duration(self, start_time: Optional[datetime], 
                          end_time: Optional[datetime]) -> Optional[float]:
        """Calculate duration in seconds"""
        if start_time and end_time:
            return (end_time - start_time).total_seconds()
        return None
    
    def get_finding_analytics(self, session_id: Optional[str] = None,
                            user_id: Optional[int] = None, days: int = 30) -> Dict[str, Any]:
        """Generate finding analytics"""
        cutoff_date = datetime.utcnow() - timedelta(days=days)
        
        # Base query
        finding_query = Finding.query.filter(Finding.created_at >= cutoff_date)
        
        if session_id:
            # Get findings from session files
            session = PuzzleSession.query.filter_by(public_id=session_id).first()
            if session:
                file_ids = []
                for step in session.steps:
                    for step_file in step.files:
                        file_ids.append(step_file.file_id)
                finding_query = finding_query.filter(Finding.file_id.in_(file_ids))
        elif user_id:
            user_files = AnalysisFile.query.filter_by(discovered_by=user_id).all()
            file_ids = [f.id for f in user_files]
            finding_query = finding_query.filter(Finding.file_id.in_(file_ids))
        
        findings = finding_query.all()
        
        # Analyze findings
        analytics = {
            'total_findings': len(findings),
            'category_distribution': {},
            'confidence_distribution': {
                'high': 0,    # > 0.8
                'medium': 0,  # 0.4 - 0.8
                'low': 0      # < 0.4
            },
            'findings_over_time': [],
            'top_categories': [],
            'average_confidence': 0.0
        }
        
        # Category distribution
        categories = [f.category for f in findings if f.category]
        category_counts = Counter(categories)
        analytics['category_distribution'] = dict(category_counts)
        analytics['top_categories'] = category_counts.most_common(10)
        
        # Confidence distribution
        confidences = [f.confidence_score for f in findings if f.confidence_score is not None]
        if confidences:
            analytics['average_confidence'] = sum(confidences) / len(confidences)
            
            for conf in confidences:
                if conf > 0.8:
                    analytics['confidence_distribution']['high'] += 1
                elif conf >= 0.4:
                    analytics['confidence_distribution']['medium'] += 1
                else:
                    analytics['confidence_distribution']['low'] += 1
        
        # Findings over time (daily counts)
        daily_counts = defaultdict(int)
        for finding in findings:
            date_key = finding.created_at.date().isoformat()
            daily_counts[date_key] += 1
        
        analytics['findings_over_time'] = [
            {'date': date, 'count': count}
            for date, count in sorted(daily_counts.items())
        ]
        
        return analytics
    
    def get_agent_performance_metrics(self, days: int = 7) -> Dict[str, Any]:
        """Get agent system performance metrics"""
        cutoff_date = datetime.utcnow() - timedelta(days=days)
        
        # Get agent executions
        executions = AgentExecution.query.filter(
            AgentExecution.created_at >= cutoff_date
        ).all()
        
        # Get workflow executions
        workflows = WorkflowExecution.query.filter(
            WorkflowExecution.created_at >= cutoff_date
        ).all()
        
        metrics = {
            'total_executions': len(executions),
            'successful_executions': len([e for e in executions if e.success]),
            'failed_executions': len([e for e in executions if not e.success]),
            'agent_type_performance': {},
            'workflow_performance': {},
            'average_execution_time': 0.0,
            'execution_timeline': []
        }
        
        # Calculate success rate
        if executions:
            metrics['success_rate'] = metrics['successful_executions'] / len(executions)
        else:
            metrics['success_rate'] = 0.0
        
        # Agent type performance
        agent_types = defaultdict(lambda: {'total': 0, 'successful': 0, 'failed': 0, 'avg_time': 0.0})
        
        for execution in executions:
            agent_type = execution.agent_type
            agent_types[agent_type]['total'] += 1
            
            if execution.success:
                agent_types[agent_type]['successful'] += 1
            else:
                agent_types[agent_type]['failed'] += 1
            
            if execution.execution_time:
                current_avg = agent_types[agent_type]['avg_time']
                total = agent_types[agent_type]['total']
                agent_types[agent_type]['avg_time'] = ((current_avg * (total - 1)) + execution.execution_time) / total
        
        metrics['agent_type_performance'] = dict(agent_types)
        
        # Workflow performance
        workflow_types = defaultdict(lambda: {'total': 0, 'successful': 0, 'failed': 0})
        
        for workflow in workflows:
            wf_name = workflow.workflow_name
            workflow_types[wf_name]['total'] += 1
            
            if workflow.success:
                workflow_types[wf_name]['successful'] += 1
            else:
                workflow_types[wf_name]['failed'] += 1
        
        metrics['workflow_performance'] = dict(workflow_types)
        
        # Average execution time
        execution_times = [e.execution_time for e in executions if e.execution_time]
        if execution_times:
            metrics['average_execution_time'] = sum(execution_times) / len(execution_times)
        
        # Execution timeline (hourly)
        hourly_counts = defaultdict(int)
        for execution in executions:
            hour_key = execution.created_at.strftime('%Y-%m-%d %H:00')
            hourly_counts[hour_key] += 1
        
        metrics['execution_timeline'] = [
            {'timestamp': hour, 'count': count}
            for hour, count in sorted(hourly_counts.items())
        ]
        
        return metrics
    
    def generate_session_report(self, session_id: str) -> Dict[str, Any]:
        """Generate comprehensive session report"""
        session = PuzzleSession.query.filter_by(public_id=session_id).first()
        if not session:
            return {'error': 'Session not found'}
        
        # Get session metrics
        metrics = self.get_overview_metrics(user_id=session.owner_id, days=365)
        
        # Get file graph
        file_graph = self.get_file_relationship_graph(session_id=session_id)
        
        # Get timeline
        timeline = self.get_analysis_timeline(session_id=session_id, days=365)
        
        # Get finding analytics
        finding_analytics = self.get_finding_analytics(session_id=session_id, days=365)
        
        # Session-specific data
        session_data = {
            'id': session.public_id,
            'name': session.name,
            'description': session.description,
            'status': session.status,
            'created_at': session.created_at.isoformat(),
            'updated_at': session.updated_at.isoformat() if session.updated_at else None,
            'owner': {
                'id': session.owner.id,
                'username': session.owner.username,
                'display_name': session.owner.display_name
            },
            'collaborators': [
                {
                    'user_id': c.user_id,
                    'username': c.user.username,
                    'role': c.role
                }
                for c in session.collaborators
            ],
            'steps': [
                {
                    'id': step.id,
                    'title': step.title,
                    'description': step.description,
                    'is_active': step.is_active,
                    'created_at': step.created_at.isoformat(),
                    'files_count': len(step.files),
                    'findings_count': len(step.findings)
                }
                for step in session.steps
            ]
        }
        
        return {
            'session': session_data,
            'metrics': metrics.__dict__,
            'file_graph': file_graph,
            'timeline': timeline,
            'finding_analytics': finding_analytics,
            'generated_at': datetime.utcnow().isoformat()
        }


# Global dashboard service instance
dashboard_service = DashboardService()


def create_dashboard_api():
    """Create dashboard API endpoints"""
    from flask import Blueprint, jsonify, request
    from crypto_hunter_web.services.auth_service import AuthService
    
    dashboard_api = Blueprint('dashboard', __name__, url_prefix='/api/dashboard')
    
    @dashboard_api.route('/overview', methods=['GET'])
    @AuthService.login_required
    def get_overview():
        """Get dashboard overview metrics"""
        try:
            user_id = request.args.get('user_id', type=int)
            days = request.args.get('days', 30, type=int)
            
            # Only allow users to see their own data unless admin
            current_user = AuthService.get_current_user()
            if user_id and user_id != current_user.id and not current_user.is_admin:
                user_id = current_user.id
            
            metrics = dashboard_service.get_overview_metrics(user_id, days)
            
            return jsonify({
                'success': True,
                'metrics': {
                    'total_files': metrics.total_files,
                    'total_findings': metrics.total_findings,
                    'total_sessions': metrics.total_sessions,
                    'active_workflows': metrics.active_workflows,
                    'solved_puzzles': metrics.solved_puzzles,
                    'success_rate': metrics.success_rate,
                    'avg_analysis_time': metrics.avg_analysis_time,
                    'top_file_types': metrics.top_file_types,
                    'recent_breakthroughs': metrics.recent_breakthroughs
                }
            })
            
        except Exception as e:
            logger.exception(f"Error getting overview metrics: {e}")
            return jsonify({'success': False, 'error': str(e)}), 500
    
    @dashboard_api.route('/file-graph', methods=['GET'])
    @AuthService.login_required
    def get_file_graph():
        """Get file relationship graph"""
        try:
            session_id = request.args.get('session_id')
            user_id = request.args.get('user_id', type=int)
            
            current_user = AuthService.get_current_user()
            if user_id and user_id != current_user.id and not current_user.is_admin:
                user_id = current_user.id
            
            graph_data = dashboard_service.get_file_relationship_graph(session_id, user_id)
            
            return jsonify({
                'success': True,
                'graph': graph_data
            })
            
        except Exception as e:
            logger.exception(f"Error getting file graph: {e}")
            return jsonify({'success': False, 'error': str(e)}), 500
    
    @dashboard_api.route('/timeline', methods=['GET'])
    @AuthService.login_required
    def get_timeline():
        """Get analysis timeline"""
        try:
            session_id = request.args.get('session_id')
            user_id = request.args.get('user_id', type=int)
            days = request.args.get('days', 30, type=int)
            
            current_user = AuthService.get_current_user()
            if user_id and user_id != current_user.id and not current_user.is_admin:
                user_id = current_user.id
            
            timeline_data = dashboard_service.get_analysis_timeline(session_id, user_id, days)
            
            return jsonify({
                'success': True,
                'timeline': timeline_data
            })
            
        except Exception as e:
            logger.exception(f"Error getting timeline: {e}")
            return jsonify({'success': False, 'error': str(e)}), 500
    
    @dashboard_api.route('/findings-analytics', methods=['GET'])
    @AuthService.login_required
    def get_findings_analytics():
        """Get finding analytics"""
        try:
            session_id = request.args.get('session_id')
            user_id = request.args.get('user_id', type=int)
            days = request.args.get('days', 30, type=int)
            
            current_user = AuthService.get_current_user()
            if user_id and user_id != current_user.id and not current_user.is_admin:
                user_id = current_user.id
            
            analytics = dashboard_service.get_finding_analytics(session_id, user_id, days)
            
            return jsonify({
                'success': True,
                'analytics': analytics
            })
            
        except Exception as e:
            logger.exception(f"Error getting findings analytics: {e}")
            return jsonify({'success': False, 'error': str(e)}), 500
    
    @dashboard_api.route('/agent-performance', methods=['GET'])
    @AuthService.login_required
    def get_agent_performance():
        """Get agent performance metrics"""
        try:
            days = request.args.get('days', 7, type=int)
            
            metrics = dashboard_service.get_agent_performance_metrics(days)
            
            return jsonify({
                'success': True,
                'performance': metrics
            })
            
        except Exception as e:
            logger.exception(f"Error getting agent performance: {e}")
            return jsonify({'success': False, 'error': str(e)}), 500
    
    @dashboard_api.route('/session/<session_id>/report', methods=['GET'])
    @AuthService.login_required
    def get_session_report(session_id):
        """Get comprehensive session report"""
        try:
            # Verify user has access to session
            session = PuzzleSession.query.filter_by(public_id=session_id).first()
            if not session:
                return jsonify({'success': False, 'error': 'Session not found'}), 404
            
            current_user = AuthService.get_current_user()
            if session.owner_id != current_user.id and not current_user.is_admin:
                # Check if user is collaborator
                collaborator = session.collaborators.filter_by(user_id=current_user.id).first()
                if not collaborator:
                    return jsonify({'success': False, 'error': 'Access denied'}), 403
            
            report = dashboard_service.generate_session_report(session_id)
            
            return jsonify({
                'success': True,
                'report': report
            })
            
        except Exception as e:
            logger.exception(f"Error generating session report: {e}")
            return jsonify({'success': False, 'error': str(e)}), 500
    
    return dashboard_api
