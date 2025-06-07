# crypto_hunter_web/routes/analysis.py - COMPLETE FIXED VERSION

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
    
    try:
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
    except Exception as e:
        flash(f'Error loading findings: {str(e)}', 'error')
        return redirect(url_for('files.dashboard'))

@analysis_bp.route('/findings/<int:finding_id>')
@AuthService.login_required
def finding_detail(finding_id):
    """Finding detail view"""
    try:
        finding = Finding.query.get_or_404(finding_id)
        
        AuthService.log_action('finding_viewed', f'Viewed finding: {finding.title}', file_id=finding.file_id)
        
        return render_template('analysis/finding_detail.html', finding=finding)
    except Exception as e:
        flash(f'Error loading finding: {str(e)}', 'error')
        return redirect(url_for('analysis.findings_list'))

@analysis_bp.route('/findings/new', methods=['GET', 'POST'])
@AuthService.login_required
def create_finding():
    """Create new finding"""
    if request.method == 'POST':
        try:
            file_id = request.form.get('file_id', type=int)
            vector_id = request.form.get('vector_id', type=int)
            
            if not file_id or not vector_id:
                flash('File and vector are required', 'error')
                return redirect(request.url)
            
            # FIXED: Proper Finding creation with all required fields
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
            
            # FIXED: Safe award_points call with error handling
            try:
                user = User.query.get(session['user_id'])
                if user and hasattr(user, 'award_points'):
                    points = 50 if finding.is_breakthrough else 25
                    user.award_points(points, 'finding_created')
                    db.session.commit()
            except Exception as e:
                print(f"Warning: Could not award points: {e}")
            
            AuthService.log_action('finding_created', f'Created finding: {finding.title}', file_id=file_id)
            flash('Finding created successfully!', 'success')
            return redirect(url_for('analysis.finding_detail', finding_id=finding.id))
            
        except Exception as e:
            db.session.rollback()
            flash(f'Error creating finding: {str(e)}', 'error')
    
    # Get file and vector for pre-population
    file_id = request.args.get('file_id', type=int)
    file = AnalysisFile.query.get(file_id) if file_id else None
    vectors = Vector.query.all()
    
    return render_template('analysis/create_finding.html', file=file, vectors=vectors)

@analysis_bp.route('/vectors')
@AuthService.login_required
def vectors_list():
    """List analysis vectors"""
    try:
        vectors = Vector.query.all()
        return render_template('analysis/vectors_list.html', vectors=vectors)
    except Exception as e:
        flash(f'Error loading vectors: {str(e)}', 'error')
        return redirect(url_for('files.dashboard'))

@analysis_bp.route('/stats')
@AuthService.login_required
def analysis_stats():
    """FIXED: Analysis statistics and metrics with comprehensive error handling"""
    try:
        # Basic stats - with error handling for missing models
        total_findings = 0
        verified_findings = 0
        breakthrough_findings = 0
        
        try:
            total_findings = Finding.query.count()
            if hasattr(Finding, 'status'):
                verified_findings = Finding.query.filter_by(status='verified').count()
            if hasattr(Finding, 'is_breakthrough'):
                breakthrough_findings = Finding.query.filter_by(is_breakthrough=True).count()
        except Exception as e:
            print(f"Error getting finding stats: {e}")
        
        # Vector stats - with error handling
        vector_stats = []
        try:
            vectors = Vector.query.all()
            for vector in vectors:
                try:
                    vector_findings = Finding.query.filter_by(vector_id=vector.id).count()
                    verified_count = 0
                    if hasattr(Finding, 'status'):
                        verified_count = Finding.query.filter_by(vector_id=vector.id, status='verified').count()
                    
                    vector_stats.append({
                        'vector': vector,
                        'findings_count': vector_findings,
                        'verified_count': verified_count
                    })
                except Exception as e:
                    print(f"Error processing vector {vector.id}: {e}")
                    vector_stats.append({
                        'vector': vector,
                        'findings_count': 0,
                        'verified_count': 0
                    })
        except Exception as e:
            print(f"Error getting vector stats: {e}")
        
        # Top analysts - with error handling
        top_analysts = []
        try:
            if hasattr(Finding, 'analyst_id'):
                top_analysts = db.session.query(User, db.func.count(Finding.id).label('finding_count'))\
                    .join(Finding, User.id == Finding.analyst_id)\
                    .group_by(User.id)\
                    .order_by(db.func.count(Finding.id).desc())\
                    .limit(10).all()
        except Exception as e:
            print(f"Error getting top analysts: {e}")
        
        # File analysis stats
        file_stats = {}
        try:
            file_stats = {
                'total_files': AnalysisFile.query.count(),
                'analyzed_files': AnalysisFile.query.filter_by(status='complete').count(),
                'pending_files': AnalysisFile.query.filter_by(status='pending').count(),
                'root_files': AnalysisFile.query.filter_by(is_root_file=True).count()
            }
        except Exception as e:
            print(f"Error getting file stats: {e}")
            file_stats = {'total_files': 0, 'analyzed_files': 0, 'pending_files': 0, 'root_files': 0}
        
        return render_template('analysis/stats.html',
                             total_findings=total_findings,
                             verified_findings=verified_findings,
                             breakthrough_findings=breakthrough_findings,
                             vector_stats=vector_stats,
                             top_analysts=top_analysts,
                             file_stats=file_stats)
                             
    except Exception as e:
        flash(f'Error loading statistics: {str(e)}', 'error')
        return redirect(url_for('files.dashboard'))

@analysis_bp.route('/findings/<int:finding_id>/verify', methods=['POST'])
@AuthService.login_required
def verify_finding(finding_id):
    """Verify a finding (for expert users)"""
    try:
        # Check user permissions
        user = User.query.get(session['user_id'])
        if not user or not hasattr(user, 'can_verify_findings') or not user.can_verify_findings():
            flash('You do not have permission to verify findings', 'error')
            return redirect(url_for('analysis.finding_detail', finding_id=finding_id))
        
        finding = Finding.query.get_or_404(finding_id)
        
        # Update finding status
        if hasattr(finding, 'status'):
            finding.status = 'verified'
            db.session.commit()
            
            # Award points to original analyst
            if finding.analyst_id:
                analyst = User.query.get(finding.analyst_id)
                if analyst and hasattr(analyst, 'award_points'):
                    analyst.award_points(25, 'finding_verified')
                    db.session.commit()
            
            AuthService.log_action('finding_verified', f'Verified finding: {finding.title}', file_id=finding.file_id)
            flash('Finding verified successfully!', 'success')
        else:
            flash('Finding verification not supported', 'warning')
            
    except Exception as e:
        db.session.rollback()
        flash(f'Error verifying finding: {str(e)}', 'error')
    
    return redirect(url_for('analysis.finding_detail', finding_id=finding_id))

@analysis_bp.route('/reports')
@AuthService.login_required
def reports():
    """Analysis reports dashboard"""
    try:
        # Generate various reports
        reports = {
            'recent_findings': Finding.query.order_by(Finding.created_at.desc()).limit(10).all(),
            'high_confidence_findings': Finding.query.filter(Finding.confidence_level >= 8).all(),
            'breakthrough_findings': []
        }
        
        if hasattr(Finding, 'is_breakthrough'):
            reports['breakthrough_findings'] = Finding.query.filter_by(is_breakthrough=True).all()
        
        return render_template('analysis/reports.html', reports=reports)
        
    except Exception as e:
        flash(f'Error loading reports: {str(e)}', 'error')
        return redirect(url_for('files.dashboard'))