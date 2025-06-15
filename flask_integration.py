#!/usr/bin/env python3
"""
Flask Integration for AI Multi-Agent System
===========================================

This module integrates the new AI orchestrated extraction system
into your existing Crypto Hunter web application.

Add this to your crypto_hunter_web/services/ directory and update your routes.
"""

import os
import asyncio
import uuid
import json
from datetime import datetime
from typing import Dict, Any, Optional, List
from pathlib import Path
import logging

from flask import current_app
from celery import Celery

# Import your existing models and services
from crypto_hunter_web import db
from crypto_hunter_web.models import AnalysisFile, Finding, PuzzleSession
from crypto_hunter_web.services.base_service import BaseService

# Import the new AI system
try:
    from ai_orchestrated_extraction import AIOrchestrator
    from agent_framework import TaskPriority
    AI_AVAILABLE = True
except ImportError:
    AI_AVAILABLE = False

logger = logging.getLogger(__name__)


class AIExtractionService(BaseService):
    """Service that integrates AI orchestrated extraction into Flask app"""
    
    def __init__(self):
        super().__init__()
        self.orchestrator = None
        self.active_sessions: Dict[str, Dict] = {}
        
    def initialize_ai_system(self) -> bool:
        """Initialize the AI orchestration system"""
        if not AI_AVAILABLE:
            logger.error("AI orchestration system not available")
            return False
        
        try:
            # Create output directory in app instance folder
            output_dir = Path(current_app.instance_path) / "ai_extractions"
            output_dir.mkdir(exist_ok=True)
            
            self.orchestrator = AIOrchestrator(output_dir=str(output_dir))
            logger.info("✅ AI orchestration system initialized")
            return True
            
        except Exception as e:
            logger.error(f"Failed to initialize AI system: {e}")
            return False

    def start_ai_extraction(self, file_id: int, analysis_mode: str = "comprehensive", 
                           user_id: int = None) -> Dict[str, Any]:
        """Start AI extraction for a file"""
        try:
            # Get file record
            analysis_file = AnalysisFile.query.get(file_id)
            if not analysis_file:
                return {'success': False, 'error': 'File not found'}
            
            if not os.path.exists(analysis_file.filepath):
                return {'success': False, 'error': 'Physical file not found'}
            
            # Initialize AI system if needed
            if not self.orchestrator:
                if not self.initialize_ai_system():
                    return {'success': False, 'error': 'AI system initialization failed'}
            
            # Create session ID
            session_id = str(uuid.uuid4())
            
            # Store session info
            session_info = {
                'session_id': session_id,
                'file_id': file_id,
                'file_path': analysis_file.filepath,
                'analysis_mode': analysis_mode,
                'user_id': user_id,
                'status': 'starting',
                'started_at': datetime.utcnow(),
                'progress': 0
            }
            
            self.active_sessions[session_id] = session_info
            
            # Start async extraction using Celery
            from crypto_hunter_web.tasks.ai_extraction_tasks import run_ai_extraction_task
            task = run_ai_extraction_task.delay(session_id, analysis_file.filepath, analysis_mode)
            
            session_info['celery_task_id'] = task.id
            session_info['status'] = 'queued'
            
            logger.info(f"🚀 Started AI extraction session {session_id} for file {file_id}")
            
            return {
                'success': True,
                'session_id': session_id,
                'task_id': task.id,
                'status': 'queued'
            }
            
        except Exception as e:
            logger.error(f"Failed to start AI extraction: {e}")
            return {'success': False, 'error': str(e)}

    def get_extraction_status(self, session_id: str) -> Dict[str, Any]:
        """Get status of AI extraction session"""
        if session_id not in self.active_sessions:
            return {'success': False, 'error': 'Session not found'}
        
        session_info = self.active_sessions[session_id]
        
        # Check Celery task status
        if 'celery_task_id' in session_info:
            from crypto_hunter_web.extensions import celery_app
            task = celery_app.AsyncResult(session_info['celery_task_id'])
            
            if task.state == 'PENDING':
                status = 'queued'
            elif task.state == 'PROGRESS':
                status = 'running'
                if hasattr(task, 'info') and task.info:
                    session_info['progress'] = task.info.get('progress', 0)
                    session_info['current_agent'] = task.info.get('current_agent', 'unknown')
            elif task.state == 'SUCCESS':
                status = 'completed'
                session_info['result'] = task.result
                session_info['completed_at'] = datetime.utcnow()
            elif task.state == 'FAILURE':
                status = 'failed'
                session_info['error'] = str(task.info)
            else:
                status = 'unknown'
            
            session_info['status'] = status
        
        return {
            'success': True,
            'session_info': session_info
        }

    def get_extraction_results(self, session_id: str) -> Dict[str, Any]:
        """Get complete results from AI extraction session"""
        status_result = self.get_extraction_status(session_id)
        
        if not status_result['success']:
            return status_result
        
        session_info = status_result['session_info']
        
        if session_info['status'] != 'completed':
            return {
                'success': False, 
                'error': f"Session not completed (status: {session_info['status']})"
            }
        
        # Get full results
        result = session_info.get('result', {})
        
        # Add session metadata
        result['session_metadata'] = {
            'session_id': session_id,
            'file_id': session_info['file_id'],
            'analysis_mode': session_info['analysis_mode'],
            'started_at': session_info['started_at'],
            'completed_at': session_info.get('completed_at'),
            'user_id': session_info.get('user_id')
        }
        
        return {
            'success': True,
            'results': result
        }

    def create_puzzle_session_from_ai_results(self, session_id: str, 
                                            puzzle_name: str = None) -> Dict[str, Any]:
        """Create a PuzzleSession from AI extraction results"""
        try:
            results_response = self.get_extraction_results(session_id)
            if not results_response['success']:
                return results_response
            
            results = results_response['results']
            session_metadata = results['session_metadata']
            
            # Get the original file
            analysis_file = AnalysisFile.query.get(session_metadata['file_id'])
            if not analysis_file:
                return {'success': False, 'error': 'Original file not found'}
            
            # Create puzzle session
            if not puzzle_name:
                puzzle_name = f"AI Analysis: {analysis_file.filename}"
            
            puzzle_session = PuzzleSession(
                name=puzzle_name,
                description=f"Generated from AI orchestrated analysis",
                created_by=session_metadata.get('user_id', 1),
                status='active',
                difficulty_level='unknown',
                metadata={
                    'ai_session_id': session_id,
                    'source_file_id': session_metadata['file_id'],
                    'analysis_mode': session_metadata['analysis_mode'],
                    'ai_recommendations': results.get('intelligence_synthesis', {}).get('recommendations', []),
                    'threat_assessment': results.get('intelligence_synthesis', {}).get('threat_assessment', {}),
                    'key_findings': results.get('intelligence_synthesis', {}).get('key_findings', [])[:5]  # Top 5 findings
                }
            )
            
            db.session.add(puzzle_session)
            db.session.flush()
            
            # Add original file to puzzle
            puzzle_session.add_file(analysis_file)
            
            # Add extracted files to puzzle
            extracted_files = results.get('extracted_files', [])
            for file_path in extracted_files[:20]:  # Limit to 20 files
                if os.path.exists(file_path) and os.path.getsize(file_path) > 0:
                    try:
                        # Create AnalysisFile for extracted file
                        extracted_analysis_file = self._create_analysis_file_from_path(
                            file_path, session_metadata.get('user_id', 1)
                        )
                        if extracted_analysis_file:
                            puzzle_session.add_file(extracted_analysis_file)
                    except Exception as e:
                        logger.warning(f"Failed to add extracted file {file_path}: {e}")
            
            # Create findings from AI results
            self._create_findings_from_ai_results(analysis_file, results, session_metadata.get('user_id', 1))
            
            db.session.commit()
            
            logger.info(f"✅ Created puzzle session {puzzle_session.id} from AI session {session_id}")
            
            return {
                'success': True,
                'puzzle_session_id': puzzle_session.id,
                'puzzle_session': puzzle_session
            }
            
        except Exception as e:
            db.session.rollback()
            logger.error(f"Failed to create puzzle session: {e}")
            return {'success': False, 'error': str(e)}

    def _create_analysis_file_from_path(self, file_path: str, user_id: int) -> Optional[AnalysisFile]:
        """Create AnalysisFile record from file path"""
        try:
            import hashlib
            import magic
            
            # Calculate hashes
            with open(file_path, 'rb') as f:
                content = f.read()
                sha256_hash = hashlib.sha256(content).hexdigest()
                md5_hash = hashlib.md5(content).hexdigest()
            
            # Check if already exists
            existing = AnalysisFile.query.filter_by(sha256_hash=sha256_hash).first()
            if existing:
                return existing
            
            # Detect file type
            file_type = magic.Magic(mime=True).from_file(file_path)
            
            # Create new record
            analysis_file = AnalysisFile(
                filename=os.path.basename(file_path),
                original_filename=os.path.basename(file_path),
                filepath=file_path,
                file_size=len(content),
                sha256_hash=sha256_hash,
                md5_hash=md5_hash,
                file_type=file_type,
                uploaded_by=user_id,
                status='complete',
                analyzed_at=datetime.utcnow()
            )
            
            db.session.add(analysis_file)
            db.session.flush()
            
            return analysis_file
            
        except Exception as e:
            logger.error(f"Failed to create AnalysisFile from {file_path}: {e}")
            return None

    def _create_findings_from_ai_results(self, analysis_file: AnalysisFile, 
                                       results: Dict[str, Any], user_id: int):
        """Create Finding records from AI results"""
        try:
            synthesis = results.get('intelligence_synthesis', {})
            
            # Main extraction finding
            performance = results.get('performance_metrics', {})
            main_finding = Finding(
                file_id=analysis_file.id,
                finding_type='ai_orchestrated_extraction',
                category='extraction',
                title=f"AI Orchestrated Analysis Completed",
                description=f"AI system completed analysis using {performance.get('total_agents', 0)} agents. "
                           f"Found {len(results.get('extracted_files', []))} extracted files with "
                           f"{len(synthesis.get('key_findings', []))} key findings.",
                confidence_level=int(performance.get('average_confidence', 0.5) * 10),
                priority=8,
                severity='medium',
                analysis_method='ai_orchestrated_system',
                created_by=user_id,
                evidence_data={
                    'performance_metrics': performance,
                    'agent_count': performance.get('total_agents', 0),
                    'execution_time': performance.get('total_execution_time', 0),
                    'extracted_files_count': len(results.get('extracted_files', []))
                }
            )
            db.session.add(main_finding)
            
            # Key findings from intelligence synthesis
            key_findings = synthesis.get('key_findings', [])
            for i, finding_data in enumerate(key_findings[:10]):  # Limit to top 10
                finding = Finding(
                    file_id=analysis_file.id,
                    finding_type='ai_intelligence_finding',
                    category='intelligence',
                    title=f"AI Finding #{i+1}: {finding_data.get('type', 'Unknown')}",
                    description=finding_data.get('details', 'No details available'),
                    confidence_level=int(finding_data.get('confidence', 0.5) * 10),
                    priority=7,
                    severity='low',
                    analysis_method=f"ai_agent_{finding_data.get('agent', 'unknown')}",
                    created_by=user_id,
                    evidence_data=finding_data.get('data', {})
                )
                db.session.add(finding)
            
            # Threat assessment finding
            threat_assessment = synthesis.get('threat_assessment', {})
            if threat_assessment and threat_assessment.get('threat_level') != 'low':
                threat_finding = Finding(
                    file_id=analysis_file.id,
                    finding_type='ai_threat_assessment',
                    category='security',
                    title=f"Threat Assessment: {threat_assessment.get('threat_level', 'unknown').upper()}",
                    description=threat_assessment.get('recommendation', 'AI detected potential threats'),
                    confidence_level=8,
                    priority=9 if threat_assessment.get('threat_level') == 'high' else 7,
                    severity='high' if threat_assessment.get('threat_level') == 'high' else 'medium',
                    analysis_method='ai_threat_analyzer',
                    created_by=user_id,
                    evidence_data={
                        'threat_level': threat_assessment.get('threat_level'),
                        'indicators': threat_assessment.get('indicators', [])
                    }
                )
                db.session.add(threat_finding)
                
        except Exception as e:
            logger.error(f"Failed to create findings from AI results: {e}")

    def cleanup_session(self, session_id: str) -> bool:
        """Clean up a completed session"""
        try:
            if session_id in self.active_sessions:
                session_info = self.active_sessions[session_id]
                
                # Cancel Celery task if still running
                if 'celery_task_id' in session_info:
                    from crypto_hunter_web.extensions import celery_app
                    task = celery_app.AsyncResult(session_info['celery_task_id'])
                    if task.state in ['PENDING', 'PROGRESS']:
                        task.revoke(terminate=True)
                
                # Remove from active sessions
                del self.active_sessions[session_id]
                
                logger.info(f"🧹 Cleaned up AI extraction session {session_id}")
                return True
        except Exception as e:
            logger.error(f"Failed to cleanup session {session_id}: {e}")
        
        return False

    def get_active_sessions(self, user_id: int = None) -> List[Dict[str, Any]]:
        """Get list of active sessions, optionally filtered by user"""
        sessions = []
        
        for session_id, session_info in self.active_sessions.items():
            if user_id is None or session_info.get('user_id') == user_id:
                # Get current status
                status_result = self.get_extraction_status(session_id)
                if status_result['success']:
                    sessions.append(status_result['session_info'])
        
        return sessions


# Create global service instance
ai_extraction_service = AIExtractionService()


# Celery task for async AI extraction
def create_ai_extraction_task(celery_app: Celery):
    """Create Celery task for AI extraction"""
    
    @celery_app.task(bind=True, name='ai_extraction.run_extraction')
    def run_ai_extraction_task(self, session_id: str, file_path: str, analysis_mode: str = "comprehensive"):
        """Celery task to run AI extraction"""
        try:
            # Update progress
            self.update_state(
                state='PROGRESS',
                meta={'progress': 0, 'current_agent': 'initializing'}
            )
            
            # Initialize AI orchestrator
            from ai_orchestrated_extraction import AIOrchestrator
            import tempfile
            
            output_dir = tempfile.mkdtemp(prefix=f"ai_session_{session_id[:8]}_")
            orchestrator = AIOrchestrator(output_dir=output_dir)
            
            self.update_state(
                state='PROGRESS',
                meta={'progress': 10, 'current_agent': 'file_analyzer'}
            )
            
            # Run the extraction (this will be sync in the Celery worker)
            import asyncio
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            
            try:
                result = loop.run_until_complete(
                    orchestrator.extract_and_analyze(file_path, analysis_mode)
                )
                
                self.update_state(
                    state='PROGRESS',
                    meta={'progress': 90, 'current_agent': 'finalizing'}
                )
                
                # Update session in service
                if session_id in ai_extraction_service.active_sessions:
                    ai_extraction_service.active_sessions[session_id]['status'] = 'completed'
                    ai_extraction_service.active_sessions[session_id]['result'] = result
                
                return result
                
            finally:
                loop.close()
            
        except Exception as e:
            # Update session with error
            if session_id in ai_extraction_service.active_sessions:
                ai_extraction_service.active_sessions[session_id]['status'] = 'failed'
                ai_extraction_service.active_sessions[session_id]['error'] = str(e)
            
            raise e
    
    return run_ai_extraction_task


# Flask route integration example
def setup_ai_routes(app):
    """Setup AI extraction routes in Flask app"""
    from flask import Blueprint, request, jsonify
    from flask_login import login_required, current_user
    
    ai_bp = Blueprint('ai_extraction', __name__, url_prefix='/api/ai')
    
    @ai_bp.route('/extract/<int:file_id>', methods=['POST'])
    @login_required
    def start_ai_extraction(file_id):
        """Start AI extraction for a file"""
        data = request.get_json() or {}
        analysis_mode = data.get('analysis_mode', 'comprehensive')
        
        result = ai_extraction_service.start_ai_extraction(
            file_id=file_id,
            analysis_mode=analysis_mode,
            user_id=current_user.id
        )
        
        return jsonify(result)
    
    @ai_bp.route('/status/<session_id>')
    @login_required
    def get_extraction_status(session_id):
        """Get AI extraction status"""
        result = ai_extraction_service.get_extraction_status(session_id)
        return jsonify(result)
    
    @ai_bp.route('/results/<session_id>')
    @login_required
    def get_extraction_results(session_id):
        """Get AI extraction results"""
        result = ai_extraction_service.get_extraction_results(session_id)
        return jsonify(result)
    
    @ai_bp.route('/create-puzzle/<session_id>', methods=['POST'])
    @login_required
    def create_puzzle_from_ai(session_id):
        """Create puzzle session from AI results"""
        data = request.get_json() or {}
        puzzle_name = data.get('name')
        
        result = ai_extraction_service.create_puzzle_session_from_ai_results(
            session_id=session_id,
            puzzle_name=puzzle_name
        )
        
        return jsonify(result)
    
    @ai_bp.route('/sessions')
    @login_required
    def get_active_sessions():
        """Get user's active AI sessions"""
        sessions = ai_extraction_service.get_active_sessions(user_id=current_user.id)
        return jsonify({'success': True, 'sessions': sessions})
    
    app.register_blueprint(ai_bp)
    return ai_bp