"""
File management routes
"""

from flask import Blueprint, render_template, request, redirect, url_for, flash, session
from werkzeug.utils import secure_filename
from datetime import datetime
import os

from crypto_hunter_web.models import db
from crypto_hunter_web.models import AnalysisFile
from crypto_hunter_web.models import Vector
from crypto_hunter_web.models import User
from crypto_hunter_web.services.auth_service import AuthService
from crypto_hunter_web.services.file_analyzer import FileAnalyzer
from crypto_hunter_web.services.import_service import ImportService
from crypto_hunter_web.utils.validators import validate_filename, validate_file_path

files_bp = Blueprint('files', __name__)

@files_bp.route('/dashboard')
@AuthService.login_required
def dashboard():
    """Main dashboard"""
    # Basic statistics
    total_files = AnalysisFile.query.count()
    analyzed_files = AnalysisFile.query.filter_by(status='complete').count()
    pending_files = AnalysisFile.query.filter_by(status='pending').count()
    root_files = AnalysisFile.query.filter_by(is_root_file=True).count()
    
    # User statistics
    top_users = User.query.filter_by(is_active=True).order_by(User.points.desc()).limit(10).all()
    vectors = Vector.query.all()
    
    # Progress calculation
    progress_percentage = (analyzed_files / total_files * 100) if total_files > 0 else 0
    
    return render_template('files/dashboard.html',
                         total_files=total_files,
                         analyzed_files=analyzed_files,
                         pending_files=pending_files,
                         root_files=root_files,
                         progress_percentage=progress_percentage,
                         top_users=top_users,
                         vectors=vectors)

@files_bp.route('/files')
@AuthService.login_required
def file_list():
    """File listing with search and filters"""
    page = request.args.get('page', 1, type=int)
    search = request.args.get('search', '')
    status_filter = request.args.get('status', '')
    file_type_filter = request.args.get('file_type', '')
    sha_search = request.args.get('sha', '')
    root_only = request.args.get('root_only', False, type=bool)
    
    query = AnalysisFile.query
    
    # Apply filters
    if sha_search:
        query = query.filter(AnalysisFile.sha256_hash.contains(sha_search.lower()))
    elif search:
        query = query.filter(AnalysisFile.filename.contains(search))
    
    if status_filter:
        query = query.filter_by(status=status_filter)
    if file_type_filter:
        query = query.filter(AnalysisFile.file_type.contains(file_type_filter))
    if root_only:
        query = query.filter_by(is_root_file=True)
    
    files = query.order_by(AnalysisFile.priority.desc(), AnalysisFile.created_at.desc()).paginate(
        page=page, per_page=50, error_out=False
    )
    
    # Get filter options
    file_types = db.session.query(AnalysisFile.file_type).distinct().all()
    
    AuthService.log_action('file_search', f'Searched files with filters: {search}, {sha_search}')
    
    return render_template('files/file_list.html',
                         files=files,
                         file_types=[ft[0] for ft in file_types if ft[0]],
                         search=search,
                         sha_search=sha_search,
                         status_filter=status_filter,
                         file_type_filter=file_type_filter,
                         root_only=root_only)


@files_bp.route('/files/<sha>')
@AuthService.login_required
def file_detail(sha):
    """Unified file detail and content view"""
    if not validate_sha256(sha):
        return "Invalid SHA256 hash", 400

    file = AnalysisFile.query.filter_by(sha256_hash=sha).first_or_404()

    # Get or create content analysis
    content = FileContent.query.filter_by(file_id=file.id).first()
    if not content and os.path.exists(file.filepath):
        content = FileAnalyzer.analyze_file_content(file.filepath, file.id)

    # Get relationships
    children = file.get_children()
    parents = file.get_parents()
    similar_files = file.get_similar_files()

    # Get extracted strings
    strings_list = []
    interesting_strings_count = 0
    if content and os.path.exists(file.filepath):
        strings_list = FileAnalyzer.extract_strings(file.filepath)
        interesting_strings_count = len([s for s in strings_list if len(s) > 20])

    vectors = Vector.query.all()
    users = User.query.filter_by(is_active=True).all()

    AuthService.log_action('file_viewed', f'Viewed file: {file.filename}', file_id=file.id)

    return render_template('files/file_unified.html',
                           file=file,
                           content=content,
                           children=children,
                           parents=parents,
                           similar_files=similar_files,
                           strings_list=strings_list,
                           interesting_strings_count=interesting_strings_count,
                           vectors=vectors,
                           users=users)

@files_bp.route('/files/add', methods=['GET', 'POST'])
@AuthService.login_required
def add_file():
    """Add new file"""
    if request.method == 'POST':
        # Handle file upload or path entry
        uploaded_file = request.files.get('file_upload')
        file_path = request.form.get('filepath', '')
        
        if uploaded_file and uploaded_file.filename:
            # Handle uploaded file
            filename = secure_filename(uploaded_file.filename)
            if not validate_filename(filename):
                flash('Invalid filename', 'error')
                return render_template('files/add_file.html')
            
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f"{timestamp}_{filename}"
            filepath = os.path.join('bulk_uploads/discovered_files', filename)
            uploaded_file.save(filepath)
            
        elif file_path:
            # Handle file path
            if not validate_file_path(file_path):
                flash('Invalid or inaccessible file path', 'error')
                return render_template('files/add_file.html')
            filepath = file_path
            filename = os.path.basename(file_path)
        else:
            flash('Please provide a file or file path', 'error')
            return render_template('files/add_file.html')
        
        # Calculate SHA256
        sha256_hash = AnalysisFile.calculate_sha256(filepath)
        if not sha256_hash:
            flash('Could not calculate file hash', 'error')
            return render_template('files/add_file.html')
        
        # Check for duplicates
        existing_file = AnalysisFile.find_by_sha(sha256_hash)
        if existing_file:
            flash(f'File already exists: {existing_file.filename}', 'warning')
            return redirect(url_for('files.file_detail', sha=sha256_hash))
        
        # Create new file record
        analysis_file = AnalysisFile(
            sha256_hash=sha256_hash,
            filename=request.form.get('filename') or filename,
            filepath=filepath,
            file_type=request.form.get('file_type', 'application/octet-stream'),
            file_size=os.path.getsize(filepath) if os.path.exists(filepath) else 0,
            extraction_method='manual',
            discovered_by=session['user_id'],
            is_root_file=request.form.get('is_root_file') == 'on',
            status='pending'
        )
        
        db.session.add(analysis_file)
        db.session.flush()
        
        # Analyze content
        if os.path.exists(filepath):
            FileAnalyzer.analyze_file_content(filepath, analysis_file.id)
        
        db.session.commit()
        
        # Award points
        user = User.query.get(session['user_id'])
        user.award_points(20, 'file_discovered')
        db.session.commit()
        
        AuthService.log_action('file_added', f'Added file: {analysis_file.filename}', file_id=analysis_file.id)
        flash('File added successfully!', 'success')
        return redirect(url_for('files.file_detail', sha=sha256_hash))
    
    existing_files = AnalysisFile.query.order_by(AnalysisFile.filename).all()
    return render_template('files/add_file.html', existing_files=existing_files)

@files_bp.route('/files/bulk-import', methods=['GET', 'POST'])
@AuthService.login_required
def bulk_import():
    """Bulk import files from CSV"""
    if request.method == 'POST':
        if 'csv_file' not in request.files:
            flash('No CSV file uploaded', 'error')
            return redirect(url_for('files.bulk_import'))
        
        csv_file = request.files['csv_file']
        if not csv_file.filename.endswith('.csv'):
            flash('Please upload a CSV file', 'error')
            return redirect(url_for('files.bulk_import'))
        
        # Save uploaded file
        filename = secure_filename(csv_file.filename)
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"{timestamp}_{filename}"
        filepath = os.path.join('bulk_uploads', filename)
        csv_file.save(filepath)
        
        try:
            bulk_import = ImportService.import_from_csv(filepath, session['user_id'])
            flash(f'Import completed! {bulk_import.successful_imports} files imported.', 'success')
        except Exception as e:
            flash(f'Import failed: {str(e)}', 'error')
        
        return redirect(url_for('files.bulk_import'))
    
    # Show import history
    from crypto_hunter_web import BulkImport
    imports = BulkImport.query.filter_by(imported_by=session['user_id']).order_by(BulkImport.started_at.desc()).all()
    
    return render_template('files/bulk_import.html', imports=imports)
