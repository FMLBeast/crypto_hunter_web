# crypto_hunter_web/routes/files.py - COMPLETE FIXED VERSION

from flask import Blueprint, render_template, request, redirect, url_for, flash, session, current_app
from werkzeug.utils import secure_filename
from datetime import datetime
import os

from crypto_hunter_web.models import db
from crypto_hunter_web.models import AnalysisFile
from crypto_hunter_web.models import Vector
from crypto_hunter_web.models import User
from crypto_hunter_web.services.auth_service import AuthService
from crypto_hunter_web.utils.validators import validate_filename, validate_file_path

# Try to import optional services (they might not exist in all setups)
try:
    from crypto_hunter_web.services.file_analyzer import FileAnalyzer
except ImportError:
    FileAnalyzer = None

try:
    from crypto_hunter_web.services.import_service import ImportService
except ImportError:
    ImportService = None

files_bp = Blueprint('files', __name__)

@files_bp.route('/dashboard')
@AuthService.login_required
def dashboard():
    """Main dashboard"""
    try:
        # Basic statistics
        total_files = AnalysisFile.query.count()
        analyzed_files = AnalysisFile.query.filter_by(status='complete').count()
        pending_files = AnalysisFile.query.filter_by(status='pending').count()
        root_files = AnalysisFile.query.filter_by(is_root_file=True).count()
        
        # User statistics - FIXED: Safe access to user attributes
        top_users = []
        try:
            users = User.query.filter_by(is_active=True).all()
            # Sort by points if available, otherwise by contributions_count, otherwise by username
            for user in users:
                user.display_points = getattr(user, 'points', 0)
                user.display_level = getattr(user, 'level', 'Analyst')
                user.display_contributions = getattr(user, 'contributions_count', 0)
            
            top_users = sorted(users, key=lambda u: u.display_points, reverse=True)[:10]
        except Exception as e:
            print(f"Error getting user stats: {e}")
        
        # Vector statistics
        vectors = []
        try:
            vectors = Vector.query.all()
        except Exception as e:
            print(f"Error getting vectors: {e}")
        
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
                             
    except Exception as e:
        flash(f'Error loading dashboard: {str(e)}', 'error')
        return render_template('files/dashboard.html',
                             total_files=0, analyzed_files=0, pending_files=0, root_files=0,
                             progress_percentage=0, top_users=[], vectors=[])

@files_bp.route('/files')
@AuthService.login_required
def file_list():
    """File listing with search and filters"""
    page = request.args.get('page', 1, type=int)
    search = request.args.get('search', '')
    status_filter = request.args.get('status')
    file_type_filter = request.args.get('file_type')
    
    try:
        query = AnalysisFile.query
        
        # Apply search
        if search:
            query = query.filter(
                AnalysisFile.filename.contains(search) |
                AnalysisFile.sha256_hash.contains(search)
            )
        
        # Apply filters
        if status_filter:
            query = query.filter_by(status=status_filter)
        if file_type_filter:
            query = query.filter_by(file_type=file_type_filter)
        
        files = query.order_by(AnalysisFile.created_at.desc()).paginate(
            page=page, per_page=50, error_out=False
        )
        
        # Get filter options
        file_types = db.session.query(AnalysisFile.file_type).distinct().all()
        file_types = [ft[0] for ft in file_types if ft[0]]
        
        return render_template('files/file_list.html',
                             files=files,
                             search=search,
                             status_filter=status_filter,
                             file_type_filter=file_type_filter,
                             file_types=file_types)
                             
    except Exception as e:
        flash(f'Error loading files: {str(e)}', 'error')
        return redirect(url_for('files.dashboard'))

@files_bp.route('/files/<sha>')
@AuthService.login_required
def file_detail(sha):
    """File detail view"""
    try:
        # FIXED: Use the static method properly
        file = AnalysisFile.find_by_sha(sha) if hasattr(AnalysisFile, 'find_by_sha') else AnalysisFile.query.filter_by(sha256_hash=sha).first()
        
        if not file:
            flash('File not found', 'error')
            return redirect(url_for('files.file_list'))
        
        AuthService.log_action('file_viewed', f'Viewed file: {file.filename}', file_id=file.id)
        
        return render_template('files/file_detail.html', file=file)
        
    except Exception as e:
        flash(f'Error loading file: {str(e)}', 'error')
        return redirect(url_for('files.file_list'))

@files_bp.route('/files/add', methods=['GET', 'POST'])
@AuthService.login_required
def add_file():
    """Add new file"""
    if request.method == 'POST':
        try:
            # Handle file upload
            file = request.files.get('file')
            file_path = request.form.get('file_path', '').strip()
            
            if file and file.filename:
                # Handle uploaded file
                filename = secure_filename(file.filename)
                upload_folder = current_app.config.get('UPLOAD_FOLDER', 'uploads')
                os.makedirs(upload_folder, exist_ok=True)
                filepath = os.path.join(upload_folder, filename)
                file.save(filepath)
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
            
            # FIXED: Safe SHA256 calculation
            sha256_hash = None
            if hasattr(AnalysisFile, 'calculate_sha256'):
                sha256_hash = AnalysisFile.calculate_sha256(filepath)
            else:
                # Fallback calculation
                import hashlib
                try:
                    with open(filepath, 'rb') as f:
                        sha256_hash = hashlib.sha256(f.read()).hexdigest()
                except Exception as e:
                    print(f"Error calculating SHA256: {e}")
            
            if not sha256_hash:
                flash('Could not calculate file hash', 'error')
                return render_template('files/add_file.html')
            
            # Check for duplicates - FIXED: Safe duplicate check
            existing_file = None
            if hasattr(AnalysisFile, 'find_by_sha'):
                existing_file = AnalysisFile.find_by_sha(sha256_hash)
            else:
                existing_file = AnalysisFile.query.filter_by(sha256_hash=sha256_hash).first()
            
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
            
            # Analyze content if analyzer is available
            if FileAnalyzer and os.path.exists(filepath):
                try:
                    FileAnalyzer.analyze_file_content(filepath, analysis_file.id)
                except Exception as e:
                    print(f"Content analysis failed: {e}")
            
            db.session.commit()
            
            # FIXED: Safe award_points call
            try:
                user = User.query.get(session['user_id'])
                if user and hasattr(user, 'award_points'):
                    user.award_points(20, 'file_discovered')
                    db.session.commit()
            except Exception as e:
                print(f"Warning: Could not award points: {e}")
            
            AuthService.log_action('file_added', f'Added file: {analysis_file.filename}', file_id=analysis_file.id)
            flash('File added successfully!', 'success')
            return redirect(url_for('files.file_detail', sha=sha256_hash))
            
        except Exception as e:
            db.session.rollback()
            flash(f'Error adding file: {str(e)}', 'error')
    
    return render_template('files/add_file.html')

@files_bp.route('/files/bulk-import', methods=['GET', 'POST'])
@AuthService.login_required
def bulk_import():
    """FIXED: Bulk import files from CSV"""
    if request.method == 'POST':
        try:
            # Handle file upload
            if 'file' not in request.files:
                flash('No file selected', 'error')
                return redirect(request.url)
            
            file = request.files['file']
            if file.filename == '':
                flash('No file selected', 'error')
                return redirect(request.url)
            
            if file and file.filename.endswith('.csv'):
                # Save uploaded file
                filename = secure_filename(file.filename)
                upload_folder = current_app.config.get('UPLOAD_FOLDER', 'uploads')
                os.makedirs(upload_folder, exist_ok=True)
                filepath = os.path.join(upload_folder, filename)
                file.save(filepath)
                
                # Process import
                imported_count = 0
                try:
                    if ImportService:
                        result = ImportService.import_from_csv(filepath, session['user_id'])
                        imported_count = result.get('imported', 0)
                        flash(f'Import completed: {imported_count} files processed', 'success')
                    else:
                        # Simple CSV processing fallback
                        import csv
                        with open(filepath, 'r') as csvfile:
                            reader = csv.DictReader(csvfile)
                            for row in reader:
                                # Basic CSV import logic
                                sha256_hash = row.get('sha256_hash') or row.get('sha256') or row.get('hash')
                                filename = row.get('filename') or row.get('name')
                                
                                if sha256_hash and filename:
                                    # Check if file already exists
                                    existing = AnalysisFile.query.filter_by(sha256_hash=sha256_hash).first()
                                    if not existing:
                                        analysis_file = AnalysisFile(
                                            sha256_hash=sha256_hash,
                                            filename=filename,
                                            file_type=row.get('file_type', 'application/octet-stream'),
                                            file_size=int(row.get('file_size', 0)) if row.get('file_size') else 0,
                                            extraction_method='bulk_import',
                                            discovered_by=session['user_id'],
                                            status='pending'
                                        )
                                        db.session.add(analysis_file)
                                        imported_count += 1
                        
                        db.session.commit()
                        flash(f'Import completed: {imported_count} files imported', 'success')
                        
                except Exception as e:
                    flash(f'Import failed: {str(e)}', 'error')
                    db.session.rollback()
                
                # Clean up uploaded file
                try:
                    os.remove(filepath)
                except:
                    pass
                    
                return redirect(url_for('files.file_list'))
            else:
                flash('Please upload a CSV file', 'error')
                
        except Exception as e:
            flash(f'Upload error: {str(e)}', 'error')
    
    return render_template('files/bulk_import.html')

@files_bp.route('/files/<sha>/analyze', methods=['POST'])
@AuthService.login_required
def analyze_file(sha):
    """Trigger file analysis"""
    try:
        file = AnalysisFile.query.filter_by(sha256_hash=sha).first()
        if not file:
            flash('File not found', 'error')
            return redirect(url_for('files.file_list'))
        
        # Update status
        file.status = 'analyzing'
        db.session.commit()
        
        # Trigger analysis if FileAnalyzer is available
        if FileAnalyzer and file.filepath and os.path.exists(file.filepath):
            try:
                FileAnalyzer.analyze_file_content(file.filepath, file.id)
                file.status = 'complete'
                db.session.commit()
                flash('File analysis completed!', 'success')
            except Exception as e:
                file.status = 'failed'
                db.session.commit()
                flash(f'Analysis failed: {str(e)}', 'error')
        else:
            flash('File analysis not available', 'warning')
            file.status = 'pending'
            db.session.commit()
        
        AuthService.log_action('file_analyzed', f'Analyzed file: {file.filename}', file_id=file.id)
        
    except Exception as e:
        flash(f'Error analyzing file: {str(e)}', 'error')
    
    return redirect(url_for('files.file_detail', sha=sha))

@files_bp.route('/files/<sha>/delete', methods=['POST'])
@AuthService.login_required
def delete_file(sha):
    """Delete file"""
    try:
        # Check if user is admin
        user = User.query.get(session['user_id'])
        if not user or not user.is_admin:
            flash('You do not have permission to delete files', 'error')
            return redirect(url_for('files.file_detail', sha=sha))
        
        file = AnalysisFile.query.filter_by(sha256_hash=sha).first()
        if not file:
            flash('File not found', 'error')
            return redirect(url_for('files.file_list'))
        
        filename = file.filename
        
        # Delete file record
        db.session.delete(file)
        db.session.commit()
        
        AuthService.log_action('file_deleted', f'Deleted file: {filename}')
        flash(f'File "{filename}" deleted successfully', 'success')
        
    except Exception as e:
        db.session.rollback()
        flash(f'Error deleting file: {str(e)}', 'error')
    
    return redirect(url_for('files.file_list'))

@files_bp.route('/files/search')
@AuthService.login_required
def search_files():
    """Advanced file search"""
    query = request.args.get('q', '').strip()
    
    if not query:
        return redirect(url_for('files.file_list'))
    
    try:
        # Search in filename and SHA256
        files = AnalysisFile.query.filter(
            AnalysisFile.filename.contains(query) |
            AnalysisFile.sha256_hash.contains(query)
        ).limit(100).all()
        
        return render_template('files/search_results.html', 
                             files=files, 
                             query=query,
                             result_count=len(files))
                             
    except Exception as e:
        flash(f'Search error: {str(e)}', 'error')
        return redirect(url_for('files.file_list'))