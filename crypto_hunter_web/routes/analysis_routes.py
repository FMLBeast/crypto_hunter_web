#!/usr/bin/env python3
"""
Analysis routes - Real implementation for viewing analysis results
"""

from flask import Blueprint, render_template, request, jsonify, session
from sqlalchemy import desc, func

from crypto_hunter_web.models import db, AnalysisFile, Finding, User, FileStatus, FindingStatus
from crypto_hunter_web.services.auth_service import AuthService
from crypto_hunter_web.services.background_service import BackgroundService
from crypto_hunter_web.services.llm_crypto_orchestrator import llm_orchestrated_analysis
from crypto_hunter_web.utils.validators import validate_sha256

analysis_bp = Blueprint('analysis', __name__)

@analysis_bp.route('/files/<sha>/results')
@AuthService.login_required
def file_results(sha):
    """Display comprehensive analysis results for a file"""
    if not validate_sha256(sha):
        return "Invalid SHA256 hash", 400

    file = AnalysisFile.query.filter_by(sha256_hash=sha).first_or_404()

    # Update last accessed
    file.last_accessed = db.session.execute('SELECT NOW()').scalar()
    db.session.commit()

    # Log the view
    AuthService.log_action('analysis_viewed', f'Viewed analysis: {file.filename}', file_id=file.id)

    return render_template('analysis/file_results.html', file=file)

@analysis_bp.route('/files/<sha>/analyze', methods=['POST'])
@AuthService.login_required  
def start_analysis(sha):
    """Start or restart comprehensive analysis"""
    if not validate_sha256(sha):
        return jsonify({'error': 'Invalid SHA256'}), 400

    file = AnalysisFile.query.filter_by(sha256_hash=sha).first_or_404()

    # Get analysis options
    data = request.get_json() or {}
    analysis_types = data.get('analysis_types', ['crypto', 'strings', 'metadata'])
    include_llm = data.get('include_llm', False)
    priority = data.get('priority', 5)

    try:
        # Update file status
        file.status = FileStatus.PROCESSING
        db.session.commit()

        # Start background analysis
        from crypto_hunter_web.services.background_service import analyze_file_comprehensive
        task = analyze_file_comprehensive.delay(
            file_id=file.id,
            analysis_types=analysis_types,
            user_id=session['user_id'],
            priority=priority
        )

        # Start LLM analysis if requested
        llm_task_id = None
        if include_llm:
            user = User.query.get(session['user_id'])
            if user and user.can_verify_findings():  # Check permissions
                llm_task = llm_orchestrated_analysis.delay(file.id)
                llm_task_id = llm_task.id

        # Track the tasks
        BackgroundService.track_task(task.id, 'comprehensive_analysis', file.id, session['user_id'])
        if llm_task_id:
            BackgroundService.track_task(llm_task_id, 'llm_analysis', file.id, session['user_id'])

        return jsonify({
            'success': True,
            'task_id': task.id,
            'llm_task_id': llm_task_id,
            'message': 'Analysis started',
            'estimated_duration': '2-10 minutes'
        })

    except Exception as e:
        return jsonify({'error': str(e)}), 500

@analysis_bp.route('/findings')
@AuthService.login_required
def findings_list():
    """List all findings with filtering and pagination"""
    page = request.args.get('page', 1, type=int)
    per_page = 25

    # Filters
    file_id = request.args.get('file_id', type=int)
    category = request.args.get('category')
    finding_type = request.args.get('type')
    status = request.args.get('status')
    min_confidence = request.args.get('min_confidence', 0, type=int)

    # Build query
    query = Finding.query

    if file_id:
        query = query.filter_by(file_id=file_id)
    if category:
        query = query.filter_by(category=category)  
    if finding_type:
        query = query.filter_by(finding_type=finding_type)
    if status:
        query = query.filter_by(status=status)
    if min_confidence > 0:
        query = query.filter(Finding.confidence_level >= min_confidence)

    # Order by confidence and recency
    query = query.order_by(desc(Finding.confidence_level), desc(Finding.created_at))

    findings = query.paginate(
        page=page, per_page=per_page, error_out=False
    )

    # Get filter statistics
    stats = {
        'total_findings': Finding.query.count(),
        'crypto_findings': Finding.query.filter_by(category='crypto').count(),
        'high_confidence': Finding.query.filter(Finding.confidence_level >= 8).count(),
        'unverified': Finding.query.filter_by(status=FindingStatus.UNVERIFIED).count()
    }

    return render_template('analysis/findings_list.html', 
                         findings=findings, 
                         stats=stats,
                         filters={
                             'file_id': file_id,
                             'category': category,
                             'finding_type': finding_type,
                             'status': status,
                             'min_confidence': min_confidence
                         })

@analysis_bp.route('/findings/<uuid:finding_id>')
@AuthService.login_required
def finding_detail(finding_id):
    """View detailed information about a specific finding"""
    finding = Finding.query.filter_by(public_id=finding_id).first_or_404()

    # Get related findings (same file, similar type)
    related_findings = Finding.query.filter(
        Finding.file_id == finding.file_id,
        Finding.finding_type == finding.finding_type,
        Finding.id != finding.id
    ).limit(5).all()

    return render_template('analysis/finding_detail.html', 
                         finding=finding, 
                         related_findings=related_findings)

@analysis_bp.route('/dashboard')
@AuthService.login_required
def analysis_dashboard():
    """Analysis dashboard with overview and recent activity"""

    # Get user's files and findings
    user_id = session['user_id']

    # Recent analysis activity
    recent_files = AnalysisFile.query.filter_by(created_by=user_id).order_by(
        desc(AnalysisFile.analyzed_at)
    ).limit(10).all()

    recent_findings = Finding.query.join(AnalysisFile).filter(
        AnalysisFile.created_by == user_id
    ).order_by(desc(Finding.created_at)).limit(10).all()

    # Statistics
    stats = {
        'total_files': AnalysisFile.query.filter_by(created_by=user_id).count(),
        'completed_analyses': AnalysisFile.query.filter_by(
            created_by=user_id, status=FileStatus.COMPLETE
        ).count(),
        'total_findings': db.session.query(func.count(Finding.id)).join(AnalysisFile).filter(
            AnalysisFile.created_by == user_id
        ).scalar(),
        'crypto_findings': db.session.query(func.count(Finding.id)).join(AnalysisFile).filter(
            AnalysisFile.created_by == user_id,
            Finding.category == 'crypto'
        ).scalar(),
        'high_priority_files': AnalysisFile.query.filter_by(
            created_by=user_id
        ).filter(AnalysisFile.priority >= 8).count()
    }

    # Analysis progress over time (last 30 days)
    from datetime import datetime, timedelta
    thirty_days_ago = datetime.utcnow() - timedelta(days=30)

    daily_analysis = db.session.query(
        func.date(AnalysisFile.analyzed_at).label('date'),
        func.count(AnalysisFile.id).label('count')
    ).filter(
        AnalysisFile.created_by == user_id,
        AnalysisFile.analyzed_at >= thirty_days_ago
    ).group_by(func.date(AnalysisFile.analyzed_at)).all()

    # Background task status
    active_tasks = BackgroundService.get_user_active_tasks(user_id)

    return render_template('analysis/dashboard.html',
                         recent_files=recent_files,
                         recent_findings=recent_findings,
                         stats=stats,
                         daily_analysis=daily_analysis,
                         active_tasks=active_tasks)

# API Endpoints for AJAX functionality

@analysis_bp.route('/api/findings/<uuid:finding_id>/verify', methods=['POST'])
@AuthService.login_required
def verify_finding(finding_id):
    """Verify a finding"""
    finding = Finding.query.filter_by(public_id=finding_id).first_or_404()

    # Update finding status
    finding.status = FindingStatus.CONFIRMED
    finding.verified_by = session['user_id']
    finding.verified_at = db.session.execute('SELECT NOW()').scalar()

    db.session.commit()

    AuthService.log_action('finding_verified', f'Verified finding: {finding.title}', 
                          finding_id=finding.id)

    return jsonify({'success': True, 'message': 'Finding verified'})

@analysis_bp.route('/api/findings/<uuid:finding_id>/collect', methods=['POST'])
@AuthService.login_required
def collect_finding(finding_id):
    """Add finding to user's collection"""
    finding = Finding.query.filter_by(public_id=finding_id).first_or_404()

    # Add to collections (implementation depends on your collection system)
    # For now, just mark as important
    finding.is_bookmarked = True
    finding.bookmarked_by = session['user_id']

    db.session.commit()

    return jsonify({'success': True, 'message': 'Finding collected'})

@analysis_bp.route('/api/files/<sha>/export')
@AuthService.login_required
def export_file_analysis(sha):
    """Export comprehensive analysis results"""
    if not validate_sha256(sha):
        return jsonify({'error': 'Invalid SHA256'}), 400

    file = AnalysisFile.query.filter_by(sha256_hash=sha).first_or_404()

    # Build comprehensive export data
    export_data = {
        'file_info': {
            'filename': file.filename,
            'sha256': file.sha256_hash,
            'size': file.file_size,
            'type': file.file_type,
            'analyzed_at': file.analyzed_at.isoformat() if file.analyzed_at else None,
            'confidence_score': file.confidence_score
        },
        'findings': [],
        'llm_analysis': None,
        'technical_details': {},
        'export_metadata': {
            'exported_at': db.session.execute('SELECT NOW()').scalar().isoformat(),
            'exported_by': session.get('username'),
            'version': '1.0'
        }
    }

    # Add findings
    for finding in file.findings.all():
        export_data['findings'].append({
            'id': finding.public_id.hex,
            'title': finding.title,
            'description': finding.description,
            'category': finding.category,
            'finding_type': finding.finding_type,
            'confidence_level': finding.confidence_level,
            'status': finding.status.value if hasattr(finding.status, 'value') else finding.status,
            'raw_data': finding.raw_data,
            'byte_offset': finding.byte_offset,
            'line_number': finding.line_number,
            'context': finding.context,
            'analysis_method': finding.analysis_method,
            'created_at': finding.created_at.isoformat()
        })

    # Add LLM analysis if available
    llm_content = file.content_entries.filter_by(content_type='llm_analysis_complete').first()
    if llm_content and llm_content.content_json:
        export_data['llm_analysis'] = llm_content.content_json

    # Add technical details
    content = file.content_entries.first()
    if content:
        export_data['technical_details'] = {
            'content_type': content.content_type,
            'content_size': content.content_size,
            'strings_extracted': getattr(content, 'strings_extracted', False),
            'hex_analyzed': getattr(content, 'hex_analyzed', False)
        }

    return jsonify({
        'success': True,
        'export_data': export_data,
        'export_filename': f"{file.filename}_analysis_{file.sha256_hash[:8]}.json"
    })

@analysis_bp.route('/api/background/tasks')
@AuthService.login_required
def get_background_tasks():
    """Get background tasks for user or specific file"""
    user_id = session['user_id']
    file_id = request.args.get('file_id', type=int)

    try:
        if file_id:
            tasks = BackgroundService.get_file_tasks(file_id)
        else:
            tasks = BackgroundService.get_user_active_tasks(user_id)

        return jsonify({
            'success': True,
            'tasks': tasks
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@analysis_bp.route('/api/background/status/<task_id>')
@AuthService.login_required
def get_task_status(task_id):
    """Get detailed status of a specific background task"""
    try:
        status = BackgroundService.get_task_status(task_id)
        return jsonify({
            'success': True,
            'status': status
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500
