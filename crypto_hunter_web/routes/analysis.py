"""
Analysis and findings routes
"""

from flask import Blueprint, render_template, request, redirect, url_for, flash, session

from crypto_hunter_web.models import db
from crypto_hunter_web.models import Finding, Vector
from crypto_hunter_web.models import AnalysisFile
from crypto_hunter_web.models import User
from crypto_hunter_web.services.auth_service import AuthService

analysis_bp = Blueprint('analysis', __name__)

@analysis_bp.route('/findings')
@AuthService.login_required
def findings_list():
    """List all findings with filters"""
    page = request.args.get('page', 1, type=int)
    vector_filter = request.args.get('vector')
    status_filter = request.args.get('status')
    confidence_filter = request.args.get('confidence', type=int)
    
    query = Finding.query
    
    # Apply filters
    if vector_filter:
        query = query.filter_by(vector_id=vector_filter)
    if status_filter:
        query = query.filter_by(status=status_filter)
    if confidence_filter:
        query = query.filter(Finding.confidence_level >= confidence_filter)
    
    findings = query.order_by(Finding.created_at.desc()).paginate(
        page=page, per_page=20, error_out=False
    )
    
    vectors = Vector.query.all()
    
    return render_template('analysis/findings_list.html',
                         findings=findings,
                         vectors=vectors,
                         vector_filter=vector_filter,
                         status_filter=status_filter,
                         confidence_filter=confidence_filter)

@analysis_bp.route('/findings/<int:finding_id>')
@AuthService.login_required
def finding_detail(finding_id):
    """Finding detail view"""
    finding = Finding.query.get_or_404(finding_id)
    
    AuthService.log_action('finding_viewed', f'Viewed finding: {finding.title}', file_id=finding.file_id)
    
    return render_template('analysis/finding_detail.html', finding=finding)

@analysis_bp.route('/findings/new', methods=['GET', 'POST'])
@AuthService.login_required
def create_finding():
    """Create new finding"""
    if request.method == 'POST':
        file_id = request.form.get('file_id', type=int)
        vector_id = request.form.get('vector_id', type=int)
        
        if not file_id or not vector_id:
            flash('File and vector are required', 'error')
            return redirect(request.url)
        
        finding = Finding(
            file_id=file_id,
            vector_id=vector_id,
            analyst_id=session['user_id'],
            title=request.form.get('title'),
            description=request.form.get('description'),
            finding_type=request.form.get('finding_type'),
            confidence_level=request.form.get('confidence_level', 5, type=int),
            technical_details=request.form.get('technical_details'),
            extracted_data=request.form.get('extracted_data'),
            next_steps=request.form.get('next_steps'),
            impact_level=request.form.get('impact_level', 'low'),
            is_breakthrough=request.form.get('is_breakthrough') == 'on'
        )
        
        db.session.add(finding)
        db.session.commit()
        
        # Award points
        user = User.query.get(session['user_id'])
        points = 50 if finding.is_breakthrough else 25
        user.award_points(points, 'finding_created')
        db.session.commit()
        
        AuthService.log_action('finding_created', f'Created finding: {finding.title}', file_id=file_id)
        flash('Finding created successfully!', 'success')
        return redirect(url_for('analysis.finding_detail', finding_id=finding.id))
    
    # Get file and vector for pre-population
    file_id = request.args.get('file_id', type=int)
    file = AnalysisFile.query.get(file_id) if file_id else None
    vectors = Vector.query.all()
    
    return render_template('analysis/create_finding.html', file=file, vectors=vectors)

@analysis_bp.route('/vectors')
@AuthService.login_required
def vectors_list():
    """List analysis vectors"""
    vectors = Vector.query.all()
    
    return render_template('analysis/vectors_list.html', vectors=vectors)

@analysis_bp.route('/stats')
@AuthService.login_required
def analysis_stats():
    """Analysis statistics and metrics"""
    # Basic stats
    total_findings = Finding.query.count()
    verified_findings = Finding.query.filter_by(status='verified').count()
    breakthrough_findings = Finding.query.filter_by(is_breakthrough=True).count()
    
    # Vector stats
    vector_stats = []
    for vector in Vector.query.all():
        vector_findings = Finding.query.filter_by(vector_id=vector.id).count()
        vector_stats.append({
            'vector': vector,
            'findings_count': vector_findings,
            'verified_count': Finding.query.filter_by(vector_id=vector.id, status='verified').count()
        })
    
    # Top analysts
    top_analysts = db.session.query(User, db.func.count(Finding.id).label('finding_count'))\
        .join(Finding, User.id == Finding.analyst_id)\
        .group_by(User.id)\
        .order_by(db.func.count(Finding.id).desc())\
        .limit(10).all()
    
    return render_template('analysis/stats.html',
                         total_findings=total_findings,
                         verified_findings=verified_findings,
                         breakthrough_findings=breakthrough_findings,
                         vector_stats=vector_stats,
                         top_analysts=top_analysts)
