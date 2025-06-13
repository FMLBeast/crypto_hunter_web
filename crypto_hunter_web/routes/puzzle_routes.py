"""
Routes for puzzle solving sessions
"""
import json
import logging
from datetime import datetime
from typing import Dict, Any, Optional

from flask import Blueprint, render_template, request, jsonify, redirect, url_for, flash, abort
from flask_login import login_required, current_user
from sqlalchemy.exc import SQLAlchemyError

from crypto_hunter_web import db
from crypto_hunter_web.models import (
    PuzzleSession, PuzzleStep, PuzzleCollaborator,
    PuzzleStepFile, PuzzleStepFinding, PuzzleStepRegion
)
from crypto_hunter_web.models import AnalysisFile, Finding, RegionOfInterest, FileContent
from crypto_hunter_web.services.analysis_service import AnalysisService
from crypto_hunter_web.utils.redis_client_util import (
    cache_session_data, get_cached_session_data, invalidate_session_cache
)
from crypto_hunter_web.utils.decorators import admin_required

logger = logging.getLogger(__name__)

# Blueprint definition
puzzle_bp = Blueprint('puzzle', __name__, url_prefix='/puzzle')


@puzzle_bp.route('/')
@login_required
def index():
    """List all puzzle sessions for the current user"""
    # Get sessions owned by the user
    owned_sessions = PuzzleSession.query.filter_by(owner_id=current_user.id).all()
    
    # Get sessions where user is a collaborator
    collaborations = PuzzleCollaborator.query.filter_by(user_id=current_user.id).all()
    collab_sessions = [c.session for c in collaborations]
    
    # Get public sessions
    public_sessions = PuzzleSession.query.filter_by(is_public=True).all()
    
    return render_template(
        'puzzle/index.html',
        owned_sessions=owned_sessions,
        collab_sessions=collab_sessions,
        public_sessions=public_sessions
    )


@puzzle_bp.route('/create', methods=['GET', 'POST'])
@login_required
def create_session():
    """Create a new puzzle session"""
    if request.method == 'POST':
        name = request.form.get('name')
        description = request.form.get('description')
        is_public = request.form.get('is_public') == 'on'
        
        if not name:
            flash('Session name is required', 'error')
            return redirect(url_for('puzzle.create_session'))
        
        try:
            session = PuzzleSession(
                name=name,
                description=description,
                owner_id=current_user.id,
                is_public=is_public
            )
            db.session.add(session)
            db.session.commit()
            
            # Create initial step
            initial_step = PuzzleStep(
                session_id=session.id,
                title="Initial Step",
                description="Starting point for puzzle solving",
                created_by=current_user.id,
                is_active=True
            )
            db.session.add(initial_step)
            db.session.commit()
            
            flash('Puzzle session created successfully', 'success')
            return redirect(url_for('puzzle.view_session', session_id=session.public_id.hex))
        except SQLAlchemyError as e:
            db.session.rollback()
            logger.error(f"Error creating puzzle session: {e}")
            flash('Error creating puzzle session', 'error')
            return redirect(url_for('puzzle.create_session'))
    
    return render_template('puzzle/create.html')


@puzzle_bp.route('/<session_id>')
@login_required
def view_session(session_id):
    """View a puzzle session"""
    session = _get_session_by_id(session_id)
    if not session:
        abort(404)
    
    # Check if user has access
    if not _user_has_access(session):
        abort(403)
    
    # Get active step
    active_step = session.get_active_step()
    
    # Get active file if any
    active_file = None
    if active_step and request.args.get('file_id'):
        file_id = request.args.get('file_id')
        step_file = PuzzleStepFile.query.filter_by(
            step_id=active_step.id, file_id=file_id).first()
        if step_file:
            active_file = _prepare_file_for_display(step_file.file)
    
    # Get all steps
    steps = PuzzleStep.query.filter_by(session_id=session.id).order_by(PuzzleStep.created_at).all()
    
    # Get collaborators
    collaborators = PuzzleCollaborator.query.filter_by(session_id=session.id).all()
    
    # Prepare data for template
    session_data = {
        'id': session.public_id.hex,
        'name': session.name,
        'description': session.description,
        'owner': session.owner.username,
        'is_public': session.is_public,
        'status': session.status,
        'created_at': session.created_at,
        'updated_at': session.updated_at,
        'collaborators': [_prepare_collaborator(c) for c in collaborators]
    }
    
    steps_data = []
    for step in steps:
        step_data = {
            'id': step.public_id.hex,
            'title': step.title,
            'description': step.description,
            'is_active': step.is_active,
            'created_at': step.created_at,
            'timestamp': step.created_at.strftime('%H:%M'),
            'creator': step.creator.username,
            'files': [_prepare_file_reference(f.file) for f in step.files.all()],
            'findings': [_prepare_finding_reference(f.finding) for f in step.findings.all()],
            'regions': [_prepare_region_reference(r.region) for r in step.regions.all()],
            'tags': step.tags
        }
        steps_data.append(step_data)
    
    # Cache session data for real-time updates
    cache_session_data(session.public_id.hex, {
        'session': session_data,
        'steps': steps_data,
        'active_file': active_file.to_dict() if active_file else None
    })
    
    return render_template(
        'puzzle/session.html',
        session=session_data,
        steps=steps_data,
        active_step=active_step,
        active_file=active_file
    )


@puzzle_bp.route('/<session_id>/step', methods=['POST'])
@login_required
def add_step(session_id):
    """Add a step to a puzzle session"""
    session = _get_session_by_id(session_id)
    if not session:
        abort(404)
    
    # Check if user has edit access
    if not _user_has_edit_access(session):
        abort(403)
    
    title = request.form.get('title')
    description = request.form.get('description')
    
    if not title:
        flash('Step title is required', 'error')
        return redirect(url_for('puzzle.view_session', session_id=session_id))
    
    try:
        # Deactivate current active step
        active_step = session.get_active_step()
        if active_step:
            active_step.is_active = False
            db.session.commit()
        
        # Create new step
        step = PuzzleStep(
            session_id=session.id,
            title=title,
            description=description,
            created_by=current_user.id,
            is_active=True
        )
        db.session.add(step)
        db.session.commit()
        
        # Invalidate cache
        invalidate_session_cache(session_id)
        
        flash('Step added successfully', 'success')
        return redirect(url_for('puzzle.view_session', session_id=session_id))
    except SQLAlchemyError as e:
        db.session.rollback()
        logger.error(f"Error adding step: {e}")
        flash('Error adding step', 'error')
        return redirect(url_for('puzzle.view_session', session_id=session_id))


@puzzle_bp.route('/<session_id>/step/<step_id>/activate', methods=['POST'])
@login_required
def activate_step(session_id, step_id):
    """Activate a step in a puzzle session"""
    session = _get_session_by_id(session_id)
    if not session:
        abort(404)
    
    # Check if user has access
    if not _user_has_access(session):
        abort(403)
    
    step = PuzzleStep.query.filter_by(public_id=step_id, session_id=session.id).first()
    if not step:
        abort(404)
    
    try:
        # Deactivate all steps
        PuzzleStep.query.filter_by(session_id=session.id).update({'is_active': False})
        
        # Activate selected step
        step.is_active = True
        db.session.commit()
        
        # Invalidate cache
        invalidate_session_cache(session_id)
        
        return jsonify({'success': True})
    except SQLAlchemyError as e:
        db.session.rollback()
        logger.error(f"Error activating step: {e}")
        return jsonify({'success': False, 'error': str(e)})


@puzzle_bp.route('/<session_id>/step/<step_id>/file', methods=['POST'])
@login_required
def add_file_to_step(session_id, step_id):
    """Add a file to a step"""
    session = _get_session_by_id(session_id)
    if not session:
        abort(404)
    
    # Check if user has edit access
    if not _user_has_edit_access(session):
        abort(403)
    
    step = PuzzleStep.query.filter_by(public_id=step_id, session_id=session.id).first()
    if not step:
        abort(404)
    
    file_id = request.form.get('file_id')
    note = request.form.get('note')
    
    if not file_id:
        return jsonify({'success': False, 'error': 'File ID is required'})
    
    try:
        file = AnalysisFile.query.get(file_id)
        if not file:
            return jsonify({'success': False, 'error': 'File not found'})
        
        step_file = step.add_file(file.id, note)
        
        # Invalidate cache
        invalidate_session_cache(session_id)
        
        return jsonify({
            'success': True, 
            'file': _prepare_file_reference(file)
        })
    except SQLAlchemyError as e:
        db.session.rollback()
        logger.error(f"Error adding file to step: {e}")
        return jsonify({'success': False, 'error': str(e)})


@puzzle_bp.route('/<session_id>/step/<step_id>/finding', methods=['POST'])
@login_required
def add_finding_to_step(session_id, step_id):
    """Add a finding to a step"""
    session = _get_session_by_id(session_id)
    if not session:
        abort(404)
    
    # Check if user has edit access
    if not _user_has_edit_access(session):
        abort(403)
    
    step = PuzzleStep.query.filter_by(public_id=step_id, session_id=session.id).first()
    if not step:
        abort(404)
    
    finding_id = request.form.get('finding_id')
    note = request.form.get('note')
    
    if not finding_id:
        return jsonify({'success': False, 'error': 'Finding ID is required'})
    
    try:
        finding = Finding.query.get(finding_id)
        if not finding:
            return jsonify({'success': False, 'error': 'Finding not found'})
        
        step_finding = step.add_finding(finding.id, note)
        
        # Invalidate cache
        invalidate_session_cache(session_id)
        
        return jsonify({
            'success': True, 
            'finding': _prepare_finding_reference(finding)
        })
    except SQLAlchemyError as e:
        db.session.rollback()
        logger.error(f"Error adding finding to step: {e}")
        return jsonify({'success': False, 'error': str(e)})


@puzzle_bp.route('/<session_id>/region', methods=['POST'])
@login_required
def add_region(session_id):
    """Add a region of interest"""
    session = _get_session_by_id(session_id)
    if not session:
        abort(404)
    
    # Check if user has edit access
    if not _user_has_edit_access(session):
        abort(403)
    
    # Get active step
    active_step = session.get_active_step()
    if not active_step:
        return jsonify({'success': False, 'error': 'No active step'})
    
    # Get request data
    data = request.json
    if not data:
        return jsonify({'success': False, 'error': 'No data provided'})
    
    file_content_id = data.get('file_content_id')
    start_offset = data.get('start_offset')
    end_offset = data.get('end_offset')
    title = data.get('title', 'Region of Interest')
    description = data.get('description', '')
    region_type = data.get('region_type', 'text')
    color = data.get('color', '#yellow')
    highlight_style = data.get('highlight_style', 'background')
    
    if not file_content_id or start_offset is None or end_offset is None:
        return jsonify({'success': False, 'error': 'Missing required fields'})
    
    try:
        # Create region of interest
        region = AnalysisService.tag_region_of_interest(
            file_content_id=file_content_id,
            start_offset=start_offset,
            end_offset=end_offset,
            title=title,
            description=description,
            region_type=region_type,
            user_id=current_user.id,
            color=color,
            highlight_style=highlight_style
        )
        
        if not region:
            return jsonify({'success': False, 'error': 'Failed to create region'})
        
        # Add region to step
        step_region = active_step.add_region(region.id)
        
        # Invalidate cache
        invalidate_session_cache(session_id)
        
        return jsonify({
            'success': True,
            'region': {
                'id': region.id,
                'title': region.title,
                'description': region.description,
                'start_offset': region.start_offset,
                'end_offset': region.end_offset,
                'color': region.color,
                'highlight_style': region.highlight_style
            }
        })
    except SQLAlchemyError as e:
        db.session.rollback()
        logger.error(f"Error adding region: {e}")
        return jsonify({'success': False, 'error': str(e)})


@puzzle_bp.route('/<session_id>/collaborator', methods=['POST'])
@login_required
def add_collaborator(session_id):
    """Add a collaborator to a puzzle session"""
    session = _get_session_by_id(session_id)
    if not session:
        abort(404)
    
    # Check if user is owner or admin
    if session.owner_id != current_user.id and not current_user.is_admin:
        abort(403)
    
    username = request.form.get('username')
    role = request.form.get('role', 'viewer')
    
    if not username:
        flash('Username is required', 'error')
        return redirect(url_for('puzzle.view_session', session_id=session_id))
    
    try:
        from crypto_hunter_web.models import User
        user = User.query.filter_by(username=username).first()
        if not user:
            flash(f'User {username} not found', 'error')
            return redirect(url_for('puzzle.view_session', session_id=session_id))
        
        # Add collaborator
        collaborator = session.add_collaborator(user.id, role)
        
        # Invalidate cache
        invalidate_session_cache(session_id)
        
        flash(f'Added {username} as {role}', 'success')
        return redirect(url_for('puzzle.view_session', session_id=session_id))
    except SQLAlchemyError as e:
        db.session.rollback()
        logger.error(f"Error adding collaborator: {e}")
        flash('Error adding collaborator', 'error')
        return redirect(url_for('puzzle.view_session', session_id=session_id))


@puzzle_bp.route('/<session_id>/collaborator/<collaborator_id>', methods=['DELETE'])
@login_required
def remove_collaborator(session_id, collaborator_id):
    """Remove a collaborator from a puzzle session"""
    session = _get_session_by_id(session_id)
    if not session:
        abort(404)
    
    # Check if user is owner or admin
    if session.owner_id != current_user.id and not current_user.is_admin:
        abort(403)
    
    try:
        collaborator = PuzzleCollaborator.query.get(collaborator_id)
        if not collaborator or collaborator.session_id != session.id:
            return jsonify({'success': False, 'error': 'Collaborator not found'})
        
        db.session.delete(collaborator)
        db.session.commit()
        
        # Invalidate cache
        invalidate_session_cache(session_id)
        
        return jsonify({'success': True})
    except SQLAlchemyError as e:
        db.session.rollback()
        logger.error(f"Error removing collaborator: {e}")
        return jsonify({'success': False, 'error': str(e)})


# Helper functions
def _get_session_by_id(session_id: str) -> Optional[PuzzleSession]:
    """Get puzzle session by ID"""
    try:
        return PuzzleSession.query.filter_by(public_id=session_id).first()
    except Exception:
        return None


def _user_has_access(session: PuzzleSession) -> bool:
    """Check if current user has access to the session"""
    # Owner always has access
    if session.owner_id == current_user.id:
        return True
    
    # Admin always has access
    if current_user.is_admin:
        return True
    
    # Public sessions are accessible to all
    if session.is_public:
        return True
    
    # Check if user is a collaborator
    collaborator = PuzzleCollaborator.query.filter_by(
        session_id=session.id, user_id=current_user.id).first()
    return collaborator is not None


def _user_has_edit_access(session: PuzzleSession) -> bool:
    """Check if current user has edit access to the session"""
    # Owner always has edit access
    if session.owner_id == current_user.id:
        return True
    
    # Admin always has edit access
    if current_user.is_admin:
        return True
    
    # Check if user is a collaborator with edit or admin role
    collaborator = PuzzleCollaborator.query.filter_by(
        session_id=session.id, user_id=current_user.id).first()
    return collaborator is not None and collaborator.role in ['editor', 'admin']


def _prepare_collaborator(collaborator: PuzzleCollaborator) -> Dict[str, Any]:
    """Prepare collaborator data for template"""
    return {
        'id': collaborator.id,
        'username': collaborator.user.username,
        'role': collaborator.role,
        'online': collaborator.is_online
    }


def _prepare_file_reference(file: AnalysisFile) -> Dict[str, Any]:
    """Prepare file reference for template"""
    return {
        'id': file.id,
        'filename': file.filename,
        'file_type': file.file_type,
        'file_size': file.file_size,
        'file_size_human': _human_readable_size(file.file_size)
    }


def _prepare_finding_reference(finding: Finding) -> Dict[str, Any]:
    """Prepare finding reference for template"""
    return {
        'id': finding.id,
        'title': finding.title,
        'finding_type': finding.finding_type,
        'confidence_level': finding.confidence_level
    }


def _prepare_region_reference(region: RegionOfInterest) -> Dict[str, Any]:
    """Prepare region reference for template"""
    return {
        'id': region.id,
        'title': region.title,
        'region_type': region.region_type,
        'color': region.color
    }


def _prepare_file_for_display(file: AnalysisFile) -> AnalysisFile:
    """Prepare file for display in template"""
    # Get file content
    content_entry = FileContent.query.filter_by(file_id=file.id).first()
    
    if content_entry:
        # Determine content type for display
        if content_entry.content_format == 'text':
            file.content_type = 'text'
            file.content = content_entry.get_content()
        elif content_entry.content_format == 'binary':
            if file.file_type and file.file_type.startswith('image/'):
                file.content_type = 'image'
                file.content_url = url_for('files.file_content_raw', file_id=file.id)
            else:
                file.content_type = 'binary'
        else:
            file.content_type = 'unknown'
    else:
        file.content_type = 'unknown'
    
    # Get findings
    file.findings = Finding.query.filter_by(file_id=file.id).all()
    
    # Add human readable size
    file.file_size_human = _human_readable_size(file.file_size)
    
    return file


def _human_readable_size(size_bytes: int) -> str:
    """Convert bytes to human readable format"""
    if size_bytes == 0:
        return "0B"
    
    size_name = ("B", "KB", "MB", "GB", "TB", "PB", "EB", "ZB", "YB")
    i = 0
    while size_bytes >= 1024 and i < len(size_name) - 1:
        size_bytes /= 1024
        i += 1
    
    return f"{size_bytes:.2f} {size_name[i]}"