# crypto_hunter_web/routes/analysis.py - COMPLETE ADVANCED IMPLEMENTATION

from flask import Blueprint, render_template, request, redirect, url_for, flash, jsonify, current_app
from flask_login import login_required, current_user
from datetime import datetime, timedelta
from sqlalchemy import func, desc, and_, or_

from crypto_hunter_web.models import db, AnalysisFile, Finding, Vector, User, FileContent
from crypto_hunter_web.services.auth_service import AuthService
from crypto_hunter_web.utils.validators import validate_sha256

analysis_bp = Blueprint('analysis', __name__)


@analysis_bp.route('/findings')
@login_required
def findings_list():
    """Advanced findings list with filtering and search"""
    try:
        page = request.args.get('page', 1, type=int)
        search = request.args.get('search', '').strip()
        severity_filter = request.args.get('severity', '')
        type_filter = request.args.get('type', '')
        verified_filter = request.args.get('verified', '')
        file_id = request.args.get('file_id', '', type=str)
        date_from = request.args.get('date_from', '')
        date_to = request.args.get('date_to', '')
        sort_by = request.args.get('sort', 'created_at')
        sort_order = request.args.get('order', 'desc')
        
        # Build base query
        query = Finding.query
        
        # Apply search
        if search:
            query = query.filter(
                or_(
                    Finding.title.ilike(f'%{search}%'),
                    Finding.description.ilike(f'%{search}%'),
                    Finding.tool_name.ilike(f'%{search}%')
                )
            )
        
        # Apply filters
        if severity_filter:
            query = query.filter(Finding.severity == severity_filter)
        
        if type_filter:
            query = query.filter(Finding.finding_type == type_filter)
        
        if verified_filter:
            if verified_filter == 'verified':
                query = query.filter(Finding.verified == True)
            elif verified_filter == 'unverified':
                query = query.filter(Finding.verified == False)
            elif verified_filter == 'false_positive':
                query = query.filter(Finding.false_positive == True)
        
        if file_id:
            try:
                query = query.filter(Finding.file_id == int(file_id))
            except ValueError:
                pass
        
        # Date range filtering
        if date_from:
            try:
                from_date = datetime.strptime(date_from, '%Y-%m-%d')
                query = query.filter(Finding.created_at >= from_date)
            except ValueError:
                pass
        
        if date_to:
            try:
                to_date = datetime.strptime(date_to, '%Y-%m-%d') + timedelta(days=1)
                query = query.filter(Finding.created_at < to_date)
            except ValueError:
                pass
        
        # Apply sorting
        sort_column = getattr(Finding, sort_by, Finding.created_at)
        if sort_order == 'desc':
            query = query.order_by(sort_column.desc())
        else:
            query = query.order_by(sort_column.asc())
        
        # Secondary sort by ID for consistency
        query = query.order_by(Finding.id.desc())
        
        # Paginate
        findings = query.paginate(page=page, per_page=50, error_out=False)
        
        # Get filter options
        severities = db.session.query(Finding.severity.distinct()).all()
        severities = [s[0] for s in severities if s[0]]
        
        finding_types = db.session.query(Finding.finding_type.distinct()).all()
        finding_types = [ft[0] for ft in finding_types if ft[0]]
        
        # Summary statistics
        total_findings = Finding.query.count()
        verified_count = Finding.query.filter(Finding.verified == True).count()
        high_severity = Finding.query.filter(Finding.severity.in_(['critical', 'high'])).count()
        recent_findings = Finding.query.filter(
            Finding.created_at >= datetime.utcnow() - timedelta(days=7)
        ).count()
        
        # Severity distribution
        severity_stats = db.session.query(
            Finding.severity,
            func.count(Finding.id).label('count')
        ).group_by(Finding.severity).all()
        
        summary_stats = {
            'total_findings': total_findings,
            'verified_count': verified_count,
            'verification_rate': (verified_count / total_findings * 100) if total_findings > 0 else 0,
            'high_severity': high_severity,
            'recent_findings': recent_findings,
            'severity_distribution': {s[0]: s[1] for s in severity_stats}
        }
        
        AuthService.log_action('findings_viewed', 'Viewed findings list', metadata={
            'filters': {
                'search': search,
                'severity': severity_filter,
                'type': type_filter,
                'verified': verified_filter
            }
        })
        
        return render_template('analysis/findings_list.html',
                             findings=findings,
                             search=search,
                             severity_filter=severity_filter,
                             type_filter=type_filter,
                             verified_filter=verified_filter,
                             file_id=file_id,
                             date_from=date_from,
                             date_to=date_to,
                             sort_by=sort_by,
                             sort_order=sort_order,
                             severities=severities,
                             finding_types=finding_types,
                             summary_stats=summary_stats)
                             
    except Exception as e:
        current_app.logger.error(f"Error loading findings: {e}")
        flash(f'Error loading findings: {str(e)}', 'error')
        return redirect(url_for('files.dashboard'))


@analysis_bp.route('/findings/<int:finding_id>')
@login_required
def finding_detail(finding_id):
    """Detailed finding view with context and actions"""
    try:
        finding = Finding.query.get_or_404(finding_id)
        
        # Get associated file
        file = finding.file
        
        # Get related findings (same file, similar type)
        related_findings = Finding.query.filter(
            and_(
                Finding.file_id == finding.file_id,
                Finding.id != finding.id
            )
        ).order_by(Finding.severity.desc(), Finding.created_at.desc()).limit(10).all()
        
        # Get similar findings (same type across files)
        similar_findings = Finding.query.filter(
            and_(
                Finding.finding_type == finding.finding_type,
                Finding.id != finding.id
            )
        ).order_by(Finding.confidence.desc()).limit(5).all()
        
        # Get file content context if location is specified
        content_context = None
        if finding.location and file:
            try:
                # Try to get text content
                text_content = file.get_content_by_type('extracted_text')
                if text_content and text_content.content_text:
                    # Extract context around the location
                    content_context = _extract_content_context(
                        text_content.content_text, 
                        finding.location
                    )
            except Exception as e:
                current_app.logger.warning(f"Could not extract content context: {e}")
        
        # Get verification history (would require audit table)
        verification_history = []
        
        # Get creator and verifier info
        creator = User.query.get(finding.created_by) if finding.created_by else None
        verifier = User.query.get(finding.verified_by) if finding.verified_by else None
        
        finding_detail_data = {
            'finding': finding,
            'file': file,
            'related_findings': related_findings,
            'similar_findings': similar_findings,
            'content_context': content_context,
            'verification_history': verification_history,
            'creator': creator,
            'verifier': verifier,
            'can_verify': True,  # Could implement permission checking here
            'vectors': Vector.query.filter_by(enabled=True).all()
        }
        
        AuthService.log_action('finding_viewed', f'Viewed finding: {finding.title}', 
                             metadata={'finding_id': finding_id})
        
        return render_template('analysis/finding_detail.html', **finding_detail_data)
        
    except Exception as e:
        current_app.logger.error(f"Error loading finding detail: {e}")
        flash(f'Error loading finding: {str(e)}', 'error')
        return redirect(url_for('analysis.findings_list'))


@analysis_bp.route('/findings/new', methods=['GET', 'POST'])
@login_required
def create_finding():
    """Create new finding"""
    if request.method == 'POST':
        try:
            # Get form data
            file_sha = request.form.get('file_sha', '').strip()
            title = request.form.get('title', '').strip()
            description = request.form.get('description', '').strip()
            finding_type = request.form.get('finding_type', 'manual')
            severity = request.form.get('severity', 'info')
            location = request.form.get('location', '').strip()
            context = request.form.get('context', '').strip()
            confidence = request.form.get('confidence', 0.8, type=float)
            
            # Validation
            if not title:
                flash('Title is required', 'error')
                return render_template('analysis/create_finding.html')
            
            if not file_sha or not validate_sha256(file_sha):
                flash('Valid file SHA256 is required', 'error')
                return render_template('analysis/create_finding.html')
            
            # Find file
            file = AnalysisFile.find_by_sha(file_sha)
            if not file:
                flash('File not found', 'error')
                return render_template('analysis/create_finding.html')
            
            # Create finding
            finding = Finding(
                file_id=file.id,
                title=title,
                description=description,
                finding_type=finding_type,
                severity=severity,
                location=location,
                context=context,
                confidence=confidence,
                created_by=current_user.id,
                tool_name='manual',
                created_at=datetime.utcnow()
            )
            
            db.session.add(finding)
            db.session.commit()
            
            # Award points to user for manual finding
            current_user.add_points(10, 'manual_finding_created')
            db.session.commit()
            
            flash(f'Finding created successfully: {title}', 'success')
            AuthService.log_action('finding_created', f'Created manual finding: {title}', 
                                 metadata={'finding_id': finding.id, 'file_id': file.id})
            
            return redirect(url_for('analysis.finding_detail', finding_id=finding.id))
            
        except Exception as e:
            current_app.logger.error(f"Error creating finding: {e}")
            db.session.rollback()
            flash(f'Error creating finding: {str(e)}', 'error')
    
    # GET request - show form
    file_sha = request.args.get('file_sha', '')
    file = None
    if file_sha and validate_sha256(file_sha):
        file = AnalysisFile.find_by_sha(file_sha)
    
    # Get recent files for selection
    recent_files = AnalysisFile.query.order_by(
        AnalysisFile.created_at.desc()
    ).limit(20).all()
    
    return render_template('analysis/create_finding.html', 
                         file=file, 
                         file_sha=file_sha,
                         recent_files=recent_files)


@analysis_bp.route('/findings/<int:finding_id>/verify', methods=['POST'])
@login_required
def verify_finding(finding_id):
    """Verify or mark finding as false positive"""
    try:
        finding = Finding.query.get_or_404(finding_id)
        
        data = request.get_json() or {}
        action = data.get('action', 'verify')  # verify, unverify, false_positive
        notes = data.get('notes', '')
        
        if action == 'verify':
            finding.mark_verified(current_user.id, True)
            message = 'Finding verified successfully'
            # Award points for verification
            current_user.add_points(5, 'finding_verified')
            
        elif action == 'unverify':
            finding.mark_verified(current_user.id, False)
            message = 'Finding marked as unverified'
            
        elif action == 'false_positive':
            finding.mark_false_positive(current_user.id)
            message = 'Finding marked as false positive'
            # Award points for false positive identification
            current_user.add_points(3, 'false_positive_identified')
            
        else:
            return jsonify({'error': 'Invalid action'}), 400
        
        db.session.commit()
        
        AuthService.log_action(f'finding_{action}', 
                             f'{action.title()} finding: {finding.title}',
                             metadata={'finding_id': finding_id, 'notes': notes})
        
        return jsonify({
            'success': True,
            'message': message,
            'finding': finding.to_dict()
        })
        
    except Exception as e:
        current_app.logger.error(f"Error verifying finding: {e}")
        db.session.rollback()
        return jsonify({'error': str(e)}), 500


@analysis_bp.route('/vectors')
@login_required
def vectors_list():
    """List and manage attack vectors"""
    try:
        page = request.args.get('page', 1, type=int)
        search = request.args.get('search', '').strip()
        category_filter = request.args.get('category', '')
        enabled_filter = request.args.get('enabled', '')
        
        # Build query
        query = Vector.query
        
        if search:
            query = query.filter(
                or_(
                    Vector.name.ilike(f'%{search}%'),
                    Vector.description.ilike(f'%{search}%')
                )
            )
        
        if category_filter:
            query = query.filter(Vector.category == category_filter)
        
        if enabled_filter:
            enabled = enabled_filter.lower() == 'true'
            query = query.filter(Vector.enabled == enabled)
        
        # Order by category and name
        query = query.order_by(Vector.category, Vector.name)
        
        # Paginate
        vectors = query.paginate(page=page, per_page=50, error_out=False)
        
        # Get categories for filter
        categories = db.session.query(Vector.category.distinct()).all()
        categories = [c[0] for c in categories if c[0]]
        
        # Vector statistics
        total_vectors = Vector.query.count()
        enabled_vectors = Vector.query.filter(Vector.enabled == True).count()
        category_stats = db.session.query(
            Vector.category,
            func.count(Vector.id).label('count')
        ).group_by(Vector.category).all()
        
        vector_stats = {
            'total': total_vectors,
            'enabled': enabled_vectors,
            'disabled': total_vectors - enabled_vectors,
            'by_category': {c[0]: c[1] for c in category_stats}
        }
        
        AuthService.log_action('vectors_viewed', 'Viewed vectors list')
        
        return render_template('analysis/vectors_list.html',
                             vectors=vectors,
                             search=search,
                             category_filter=category_filter,
                             enabled_filter=enabled_filter,
                             categories=categories,
                             vector_stats=vector_stats)
                             
    except Exception as e:
        current_app.logger.error(f"Error loading vectors: {e}")
        flash(f'Error loading vectors: {str(e)}', 'error')
        return redirect(url_for('files.dashboard'))


@analysis_bp.route('/stats')
@login_required
def analysis_stats():
    """Comprehensive analysis statistics dashboard"""
    try:
        # Time range options
        time_range = request.args.get('range', '7d')
        
        if time_range == '24h':
            start_date = datetime.utcnow() - timedelta(hours=24)
        elif time_range == '7d':
            start_date = datetime.utcnow() - timedelta(days=7)
        elif time_range == '30d':
            start_date = datetime.utcnow() - timedelta(days=30)
        else:
            start_date = datetime.utcnow() - timedelta(days=90)
        
        # File analysis statistics
        total_files = AnalysisFile.query.count()
        analyzed_files = AnalysisFile.query.filter(AnalysisFile.status == 'complete').count()
        pending_files = AnalysisFile.query.filter(AnalysisFile.status == 'pending').count()
        
        # Finding statistics
        total_findings = Finding.query.count()
        recent_findings = Finding.query.filter(Finding.created_at >= start_date).count()
        verified_findings = Finding.query.filter(Finding.verified == True).count()
        false_positives = Finding.query.filter(Finding.false_positive == True).count()
        
        # Severity distribution
        severity_data = db.session.query(
            Finding.severity,
            func.count(Finding.id).label('count')
        ).group_by(Finding.severity).all()
        
        # Finding types distribution
        type_data = db.session.query(
            Finding.finding_type,
            func.count(Finding.id).label('count')
        ).group_by(Finding.finding_type).order_by(func.count(Finding.id).desc()).limit(10).all()
        
        # File type analysis
        file_type_data = db.session.query(
            AnalysisFile.file_type,
            func.count(AnalysisFile.id).label('files'),
            func.count(Finding.id).label('findings')
        ).outerjoin(Finding).group_by(AnalysisFile.file_type).order_by(
            func.count(AnalysisFile.id).desc()
        ).limit(15).all()
        
        # Daily activity over time range
        daily_activity = db.session.query(
            func.date(Finding.created_at).label('date'),
            func.count(Finding.id).label('findings')
        ).filter(Finding.created_at >= start_date).group_by(
            func.date(Finding.created_at)
        ).order_by(func.date(Finding.created_at)).all()
        
        # Tool performance
        tool_performance = db.session.query(
            Finding.tool_name,
            func.count(Finding.id).label('total'),
            func.sum(func.case([(Finding.verified == True, 1)], else_=0)).label('verified'),
            func.sum(func.case([(Finding.false_positive == True, 1)], else_=0)).label('false_positives'),
            func.avg(Finding.confidence).label('avg_confidence')
        ).filter(Finding.tool_name.isnot(None)).group_by(Finding.tool_name).order_by(
            func.count(Finding.id).desc()
        ).limit(10).all()
        
        # User contribution statistics
        user_stats = db.session.query(
            User.username,
            func.count(Finding.id).label('findings_created'),
            func.sum(func.case([(Finding.verified == True, 1)], else_=0)).label('verified_findings')
        ).join(Finding, User.id == Finding.created_by).group_by(
            User.id, User.username
        ).order_by(func.count(Finding.id).desc()).limit(10).all()
        
        # Analysis coverage by file type
        coverage_stats = db.session.query(
            AnalysisFile.file_type,
            func.count(AnalysisFile.id).label('total_files'),
            func.sum(func.case([
                (AnalysisFile.id.in_(
                    db.session.query(FileContent.file_id).filter(
                        FileContent.content_type == 'crypto_background_complete'
                    )
                ), 1)
            ], else_=0)).label('analyzed_files')
        ).group_by(AnalysisFile.file_type).all()
        
        stats_data = {
            'time_range': time_range,
            'overview': {
                'total_files': total_files,
                'analyzed_files': analyzed_files,
                'pending_files': pending_files,
                'analysis_rate': (analyzed_files / total_files * 100) if total_files > 0 else 0,
                'total_findings': total_findings,
                'recent_findings': recent_findings,
                'verified_findings': verified_findings,
                'false_positives': false_positives,
                'verification_rate': (verified_findings / total_findings * 100) if total_findings > 0 else 0
            },
            'distributions': {
                'severity': [{'severity': s[0], 'count': s[1]} for s in severity_data],
                'types': [{'type': t[0], 'count': t[1]} for t in type_data],
                'file_types': [{'type': ft[0] or 'Unknown', 'files': ft[1], 'findings': ft[2] or 0} for ft in file_type_data]
            },
            'timeline': {
                'daily_activity': [{'date': str(d[0]), 'findings': d[1]} for d in daily_activity]
            },
            'performance': {
                'tools': [{
                    'tool': tp[0],
                    'total': tp[1],
                    'verified': tp[2] or 0,
                    'false_positives': tp[3] or 0,
                    'avg_confidence': round(tp[4] or 0, 2),
                    'accuracy': round((tp[2] or 0) / tp[1] * 100, 1) if tp[1] > 0 else 0
                } for tp in tool_performance]
            },
            'users': [{
                'username': us[0],
                'findings_created': us[1],
                'verified_findings': us[2] or 0
            } for us in user_stats],
            'coverage': [{
                'file_type': cs[0] or 'Unknown',
                'total_files': cs[1],
                'analyzed_files': cs[2] or 0,
                'coverage_rate': round((cs[2] or 0) / cs[1] * 100, 1) if cs[1] > 0 else 0
            } for cs in coverage_stats]
        }
        
        AuthService.log_action('stats_viewed', f'Viewed analysis statistics ({time_range})')
        
        return render_template('analysis/stats.html', **stats_data)
        
    except Exception as e:
        current_app.logger.error(f"Error loading statistics: {e}")
        flash(f'Error loading statistics: {str(e)}', 'error')
        return redirect(url_for('files.dashboard'))


@analysis_bp.route('/reports')
@login_required
def reports():
    """Generate and view analysis reports"""
    try:
        report_type = request.args.get('type', 'summary')
        date_from = request.args.get('from', '')
        date_to = request.args.get('to', '')
        
        # Date range handling
        if date_from:
            try:
                from_date = datetime.strptime(date_from, '%Y-%m-%d')
            except ValueError:
                from_date = datetime.utcnow() - timedelta(days=30)
        else:
            from_date = datetime.utcnow() - timedelta(days=30)
        
        if date_to:
            try:
                to_date = datetime.strptime(date_to, '%Y-%m-%d') + timedelta(days=1)
            except ValueError:
                to_date = datetime.utcnow()
        else:
            to_date = datetime.utcnow()
        
        # Generate report based on type
        if report_type == 'security':
            report_data = _generate_security_report(from_date, to_date)
        elif report_type == 'performance':
            report_data = _generate_performance_report(from_date, to_date)
        elif report_type == 'detailed':
            report_data = _generate_detailed_report(from_date, to_date)
        else:
            report_data = _generate_summary_report(from_date, to_date)
        
        report_data.update({
            'report_type': report_type,
            'date_from': from_date.strftime('%Y-%m-%d'),
            'date_to': (to_date - timedelta(days=1)).strftime('%Y-%m-%d'),
            'generated_at': datetime.utcnow(),
            'generated_by': current_user.username
        })
        
        AuthService.log_action('report_generated', f'Generated {report_type} report',
                             metadata={'date_range': f"{date_from} to {date_to}"})
        
        return render_template('analysis/reports.html', **report_data)
        
    except Exception as e:
        current_app.logger.error(f"Error generating report: {e}")
        flash(f'Error generating report: {str(e)}', 'error')
        return redirect(url_for('analysis.analysis_stats'))


def _extract_content_context(content: str, location: str, context_size: int = 200) -> Optional[str]:
    """Extract context around a specific location in content"""
    try:
        # Try to parse location (could be line:column, offset, etc.)
        if ':' in location:
            # Line:column format
            line_num, col_num = map(int, location.split(':'))
            lines = content.split('\n')
            if line_num <= len(lines):
                start_line = max(0, line_num - 3)
                end_line = min(len(lines), line_num + 3)
                context_lines = lines[start_line:end_line]
                return '\n'.join(context_lines)
        
        elif location.isdigit():
            # Byte offset
            offset = int(location)
            start = max(0, offset - context_size)
            end = min(len(content), offset + context_size)
            return content[start:end]
        
        # Default: search for location as string
        index = content.lower().find(location.lower())
        if index >= 0:
            start = max(0, index - context_size)
            end = min(len(content), index + len(location) + context_size)
            return content[start:end]
        
        return None
        
    except Exception:
        return None


def _generate_summary_report(from_date: datetime, to_date: datetime) -> Dict[str, Any]:
    """Generate summary analysis report"""
    # Implementation would include summary statistics and key findings
    return {
        'title': 'Analysis Summary Report',
        'key_metrics': {},
        'summary': 'Report summary would go here'
    }


def _generate_security_report(from_date: datetime, to_date: datetime) -> Dict[str, Any]:
    """Generate security-focused report"""
    return {
        'title': 'Security Analysis Report',
        'security_findings': [],
        'risk_assessment': {}
    }


def _generate_performance_report(from_date: datetime, to_date: datetime) -> Dict[str, Any]:
    """Generate performance analysis report"""
    return {
        'title': 'Performance Analysis Report',
        'performance_metrics': {},
        'recommendations': []
    }


def _generate_detailed_report(from_date: datetime, to_date: datetime) -> Dict[str, Any]:
    """Generate detailed comprehensive report"""
    return {
        'title': 'Detailed Analysis Report',
        'detailed_findings': [],
        'analysis_breakdown': {}
    }