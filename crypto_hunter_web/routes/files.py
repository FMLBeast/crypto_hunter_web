# crypto_hunter_web/routes/files.py - COMPLETE FILE MANAGEMENT ROUTES

from flask import Blueprint, render_template, request, redirect, url_for, flash, session, current_app, jsonify, \
    send_file
from flask_login import login_required, current_user
from werkzeug.utils import secure_filename
from werkzeug.exceptions import RequestEntityTooLarge
from datetime import datetime, timedelta
import os
import json
import hashlib
import mimetypes
from pathlib import Path
import tempfile
import shutil
import uuid

from crypto_hunter_web.models import db, AnalysisFile, FileContent, Finding, Vector, User, AuditLog, FileStatus, FindingStatus, BulkImport
from crypto_hunter_web.services.file_service import FileService
from crypto_hunter_web.services.auth_service import AuthService
from crypto_hunter_web.services.content_analyzer import ContentAnalyzer
from crypto_hunter_web.services.background_service import BackgroundService
from crypto_hunter_web.utils.validators import validate_filename, validate_file_path, validate_sha256
from crypto_hunter_web.utils.decorators import rate_limit, api_endpoint
from crypto_hunter_web.utils.file_utils import calculate_file_hash, detect_file_type, get_file_size_human

files_bp = Blueprint('files', __name__, url_prefix='/files')


@files_bp.route('/dashboard')
@login_required
def dashboard():
    """Enhanced dashboard with comprehensive file analytics"""
    try:
        # Time-based filters
        time_filter = request.args.get('time_filter', '7d')  # 1d, 7d, 30d, all

        if time_filter == '1d':
            since_date = datetime.utcnow() - timedelta(days=1)
        elif time_filter == '30d':
            since_date = datetime.utcnow() - timedelta(days=30)
        elif time_filter == '7d':
            since_date = datetime.utcnow() - timedelta(days=7)
        else:
            since_date = None

        # Basic statistics
        stats = {
            'total_files': AnalysisFile.query.count(),
            'analyzed_files': AnalysisFile.query.filter_by(status=FileStatus.COMPLETE).count(),
            'pending_files': AnalysisFile.query.filter_by(status=FileStatus.PENDING).count(),
            'error_files': AnalysisFile.query.filter_by(status=FileStatus.ERROR).count(),
            'root_files': AnalysisFile.query.filter_by(is_root_file=True).count(),
            'crypto_files': AnalysisFile.query.filter_by(contains_crypto=True).count(),
            'total_findings': Finding.query.count(),
            'confirmed_findings': Finding.query.filter_by(status=FindingStatus.CONFIRMED).count(),
            'total_users': User.query.filter_by(is_active=True).count(),
        }

        # Recent activity (filtered by time)
        recent_query = AnalysisFile.query.order_by(AnalysisFile.created_at.desc())
        if since_date:
            recent_query = recent_query.filter(AnalysisFile.created_at >= since_date)

        recent_files = recent_query.limit(10).all()

        # Recent findings
        findings_query = Finding.query.order_by(Finding.created_at.desc())
        if since_date:
            findings_query = findings_query.filter(Finding.created_at >= since_date)

        recent_findings = findings_query.limit(10).all()

        # File type distribution
        file_type_stats = db.session.query(
            AnalysisFile.file_type,
            db.func.count(AnalysisFile.id).label('count'),
            db.func.sum(AnalysisFile.file_size).label('total_size')
        ).group_by(AnalysisFile.file_type).order_by(db.func.count(AnalysisFile.id).desc()).limit(10).all()

        # Analysis status distribution
        status_stats = db.session.query(
            AnalysisFile.status,
            db.func.count(AnalysisFile.id).label('count')
        ).group_by(AnalysisFile.status).all()

        # Priority distribution
        priority_stats = db.session.query(
            AnalysisFile.priority,
            db.func.count(AnalysisFile.id).label('count')
        ).group_by(AnalysisFile.priority).order_by(AnalysisFile.priority.desc()).all()

        # User activity (top contributors)
        top_contributors = db.session.query(
            User.username,
            User.display_name,
            User.points,
            db.func.count(AnalysisFile.id).label('files_uploaded')
        ).join(AnalysisFile, User.id == AnalysisFile.created_by) \
            .group_by(User.id) \
            .order_by(db.func.count(AnalysisFile.id).desc()) \
            .limit(5).all()

        # Chart data for frontend
        chart_data = {
            'file_types': [{'name': ft[0] or 'Unknown', 'count': ft[1], 'size': ft[2] or 0} for ft in file_type_stats],
            'status_distribution': [{'status': st[0], 'count': st[1]} for st in status_stats],
            'priority_distribution': [{'priority': f'Priority {pt[0]}', 'count': pt[1]} for pt in priority_stats]
        }

        # System health metrics
        health_metrics = {
            'disk_usage': FileService.get_disk_usage(),
            'average_analysis_time': FileService.get_average_analysis_time(),
            'success_rate': FileService.get_analysis_success_rate(),
            'queue_size': FileService.get_queue_size()
        }

        # Calculate additional variables needed by the template
        total_files = stats['total_files']
        complete_files = stats['analyzed_files']
        analyzing_files = stats['pending_files']
        progress_percentage = (complete_files / total_files * 100) if total_files > 0 else 0

        # Get system status and active tasks
        system_status = {}
        active_tasks = []
        try:
            # Get system status which includes worker info, task counts, etc.
            system_status = BackgroundService.get_system_status()

            # Try to get active tasks from the background service
            active_tasks = BackgroundService.get_active_tasks()
        except Exception as e:
            current_app.logger.warning(f"Could not get system status or active tasks: {e}")

        return render_template('dashboard/index.html',
                               stats=stats,
                               total_files=total_files,
                               complete_files=complete_files,
                               analyzing_files=analyzing_files,
                               progress_percentage=progress_percentage,
                               active_tasks=active_tasks,
                               system_status=system_status,
                               recent_files=recent_files,
                               recent_findings=recent_findings,
                               chart_data=json.dumps(chart_data),
                               top_contributors=top_contributors,
                               health_metrics=health_metrics,
                               time_filter=time_filter)

    except Exception as e:
        current_app.logger.error(f"Dashboard error: {e}", exc_info=True)
        flash('Error loading dashboard. Please try again.', 'error')
        # Provide default values for all required template variables
        return render_template('dashboard/index.html', 
                              stats={}, 
                              total_files=0, 
                              complete_files=0, 
                              analyzing_files=0, 
                              progress_percentage=0, 
                              active_tasks=[], 
                              system_status={},
                              recent_files=[], 
                              recent_findings=[])


@files_bp.route('/list')
@login_required
def file_list():
    """Enhanced file listing with advanced filtering and search"""
    # Get filter parameters
    page = request.args.get('page', 1, type=int)
    per_page = min(request.args.get('per_page', 50, type=int), 100)  # Max 100 per page

    # Filters
    status_filter = request.args.get('status', '')
    file_type_filter = request.args.get('file_type', '')
    priority_filter = request.args.get('priority', '', type=int)
    crypto_filter = request.args.get('crypto', '')
    search_query = request.args.get('search', '').strip()
    sort_by = request.args.get('sort', 'created_at')
    sort_order = request.args.get('order', 'desc')

    # Build query
    query = AnalysisFile.query

    # Apply filters
    if status_filter:
        # Convert string status to enum
        try:
            status_enum = FileStatus[status_filter.upper()]
            query = query.filter(AnalysisFile.status == status_enum)
        except (KeyError, AttributeError):
            # If invalid status, ignore filter
            pass

    if file_type_filter:
        query = query.filter(AnalysisFile.file_type == file_type_filter)

    if priority_filter:
        query = query.filter(AnalysisFile.priority == priority_filter)

    if crypto_filter == 'true':
        query = query.filter(AnalysisFile.contains_crypto == True)
    elif crypto_filter == 'false':
        query = query.filter(AnalysisFile.contains_crypto == False)

    # Search functionality
    if search_query:
        search_pattern = f"%{search_query}%"
        query = query.filter(
            db.or_(
                AnalysisFile.filename.ilike(search_pattern),
                AnalysisFile.sha256_hash.ilike(search_pattern),
                AnalysisFile.notes.ilike(search_pattern)
            )
        )

    # Sorting
    if sort_by == 'filename':
        sort_column = AnalysisFile.filename
    elif sort_by == 'file_size':
        sort_column = AnalysisFile.file_size
    elif sort_by == 'priority':
        sort_column = AnalysisFile.priority
    elif sort_by == 'status':
        sort_column = AnalysisFile.status
    else:
        sort_column = AnalysisFile.created_at

    if sort_order == 'asc':
        query = query.order_by(sort_column.asc())
    else:
        query = query.order_by(sort_column.desc())

    # Pagination
    try:
        pagination = query.paginate(
            page=page,
            per_page=per_page,
            error_out=False
        )
        files = pagination.items
    except Exception as e:
        current_app.logger.error(f"Pagination error: {e}")
        flash('Error loading files. Please try again.', 'error')
        files = []
        pagination = None

    # Get filter options for dropdowns
    filter_options = {
        'statuses': db.session.query(AnalysisFile.status).distinct().all(),
        'file_types': db.session.query(AnalysisFile.file_type).distinct().all(),
        'priorities': range(1, 11)
    }

    return render_template('files/file_list.html',
                           files=files,
                           pagination=pagination,
                           filter_options=filter_options,
                           current_filters={
                               'status': status_filter,
                               'file_type': file_type_filter,
                               'priority': priority_filter,
                               'crypto': crypto_filter,
                               'search': search_query,
                               'sort': sort_by,
                               'order': sort_order
                           })


@files_bp.route('/upload', methods=['GET', 'POST'])
@login_required
@rate_limit("20 per hour")
def upload_file():
    """Enhanced file upload with validation and preprocessing"""
    if request.method == 'POST':
        try:
            # Check if files were uploaded
            if 'files' not in request.files:
                flash('No files selected', 'error')
                return redirect(request.url)

            files = request.files.getlist('files')
            if not files or all(f.filename == '' for f in files):
                flash('No files selected', 'error')
                return redirect(request.url)

            # Get upload options
            priority = request.form.get('priority', 5, type=int)
            auto_analyze = request.form.get('auto_analyze', False, type=bool)
            is_root_file = request.form.get('is_root_file', False, type=bool)
            notes = request.form.get('notes', '').strip()
            tags = [tag.strip() for tag in request.form.get('tags', '').split(',') if tag.strip()]

            # Validate priority
            if not 1 <= priority <= 10:
                priority = 5

            uploaded_files = []
            errors = []

            for file in files:
                if file.filename == '':
                    continue

                try:
                    # Validate file
                    if not FileService.validate_upload(file):
                        errors.append(f"{file.filename}: Invalid file type or size")
                        continue

                    # Process upload
                    result = FileService.process_upload(
                        file=file,
                        user_id=current_user.id,
                        priority=priority,
                        is_root_file=is_root_file,
                        notes=notes,
                        tags=tags
                    )

                    if result['success']:
                        uploaded_files.append(result['file'])

                        # Queue for analysis if requested
                        if auto_analyze:
                            BackgroundService.queue_analysis(result['file'].id)
                    else:
                        errors.append(f"{file.filename}: {result['error']}")

                except Exception as e:
                    current_app.logger.error(f"Upload error for {file.filename}: {e}")
                    errors.append(f"{file.filename}: Upload failed")

            # Show results
            if uploaded_files:
                file_names = [f.filename for f in uploaded_files]
                flash(f"Successfully uploaded {len(uploaded_files)} file(s): {', '.join(file_names)}", 'success')

                if auto_analyze:
                    flash(f"Files queued for analysis", 'info')

                # Log successful uploads
                AuditLog.log_action(
                    user_id=current_user.id,
                    action='files_uploaded',
                    description=f'Uploaded {len(uploaded_files)} files',
                    metadata={
                        'file_count': len(uploaded_files),
                        'file_names': file_names,
                        'auto_analyze': auto_analyze
                    }
                )

            if errors:
                for error in errors:
                    flash(error, 'error')

            if uploaded_files:
                return redirect(url_for('files.file_list'))

        except RequestEntityTooLarge:
            flash('File too large. Maximum size allowed is 1GB.', 'error')
        except Exception as e:
            current_app.logger.error(f"Upload error: {e}", exc_info=True)
            flash('Upload failed. Please try again.', 'error')

    # Get upload statistics for display
    upload_stats = {
        'max_file_size': current_app.config.get('MAX_CONTENT_LENGTH', 1073741824),
        'allowed_extensions': list(current_app.config.get('ALLOWED_EXTENSIONS', set())),
        'total_files': current_user.created_files.count(),
        'total_size': db.session.query(db.func.sum(AnalysisFile.file_size)) \
                          .filter(AnalysisFile.created_by == current_user.id).scalar() or 0
    }

    # Get recent uploads for the user
    recent_uploads = db.session.query(AnalysisFile).filter(
        AnalysisFile.created_by == current_user.id
    ).order_by(db.desc(AnalysisFile.created_at)).limit(10).all()

    return render_template('files/upload.html', upload_stats=upload_stats, recent_uploads=recent_uploads)


@files_bp.route('/<sha>/details')
@login_required
def file_details(sha):
    """Comprehensive file details view"""
    if not validate_sha256(sha):
        flash('Invalid file hash format', 'error')
        return redirect(url_for('files.file_list'))

    file = AnalysisFile.find_by_sha(sha)
    if not file:
        flash('File not found', 'error')
        return redirect(url_for('files.file_list'))

    # Get file content entries
    content_entries = FileContent.query.filter_by(file_id=file.id).all()

    # Get findings
    findings = Finding.query.filter_by(file_id=file.id) \
        .order_by(Finding.priority.desc(), Finding.created_at.desc()).all()

    # Get child files (if this is an archive)
    child_files = AnalysisFile.query.filter_by(parent_file_sha=file.sha256_hash).all()

    # Get parent file (if this is extracted from an archive)
    parent_file = None
    if file.parent_file_sha:
        parent_file = AnalysisFile.find_by_sha(file.parent_file_sha)

    # Get analysis progress
    analysis_progress = FileService.get_analysis_progress(file)

    # Get similar files (based on file type and size)
    similar_files = AnalysisFile.query \
        .filter(AnalysisFile.file_type == file.file_type) \
        .filter(AnalysisFile.id != file.id) \
        .filter(AnalysisFile.file_size.between(
        file.file_size * 0.8, file.file_size * 1.2
    )) \
        .limit(5).all()

    # Get file metadata
    file_metadata = {
        'upload_date': file.created_at,
        'last_modified': file.updated_at,
        'analysis_date': file.analyzed_at,
        'file_size_human': get_file_size_human(file.file_size),
        'mime_type': mimetypes.guess_type(file.filename)[0] or 'application/octet-stream',
        'creator': file.creator.username if file.creator else 'Unknown'
    }

    # Track file access
    file.last_accessed = datetime.utcnow()
    db.session.commit()

    return render_template('files/file_details.html',
                           file=file,
                           content_entries=content_entries,
                           findings=findings,
                           child_files=child_files,
                           parent_file=parent_file,
                           similar_files=similar_files,
                           analysis_progress=analysis_progress,
                           file_metadata=file_metadata)


@files_bp.route('/<sha>/analyze', methods=['POST'])
@login_required
@rate_limit("10 per minute")
def analyze_file(sha):
    """Start comprehensive file analysis"""
    if not validate_sha256(sha):
        return jsonify({'error': 'Invalid file hash'}), 400

    file = AnalysisFile.find_by_sha(sha)
    if not file:
        return jsonify({'error': 'File not found'}), 404

    # Check if file is already being analyzed
    if file.status == FileStatus.PROCESSING:
        return jsonify({'error': 'File is already being analyzed'}), 400

    try:
        # Get analysis options
        analysis_types = request.json.get('analysis_types', ['basic', 'strings', 'crypto'])
        force_reanalyze = request.json.get('force_reanalyze', False)

        # Validate analysis types
        valid_types = ['basic', 'strings', 'crypto', 'metadata', 'hex', 'binary', 'archive', 'network']
        analysis_types = [t for t in analysis_types if t in valid_types]

        if not analysis_types:
            return jsonify({'error': 'No valid analysis types specified'}), 400

        # Check if reanalysis is needed
        if file.status == FileStatus.COMPLETE and not force_reanalyze:
            return jsonify({'error': 'File already analyzed. Use force_reanalyze=true to rerun.'}), 400

        # Update file status
        file.status = FileStatus.PROCESSING
        db.session.commit()

        # Queue analysis task
        task_id = BackgroundService.queue_comprehensive_analysis(
            file_id=file.id,
            analysis_types=analysis_types,
            user_id=current_user.id
        )

        # Log action
        AuditLog.log_action(
            user_id=current_user.id,
            action='analysis_started',
            description=f'Started analysis for {file.filename}',
            resource_type='file',
            resource_id=file.sha256_hash,
            metadata={
                'analysis_types': analysis_types,
                'task_id': task_id
            }
        )

        return jsonify({
            'success': True,
            'message': 'Analysis started successfully',
            'task_id': task_id,
            'analysis_types': analysis_types
        })

    except Exception as e:
        current_app.logger.error(f"Analysis start failed: {e}")
        file.status = FileStatus.ERROR
        db.session.commit()
        return jsonify({'error': 'Failed to start analysis'}), 500


@files_bp.route('/<sha>/download')
@login_required
@rate_limit("50 per hour")
def download_file(sha):
    """Download file with security checks"""
    if not validate_sha256(sha):
        flash('Invalid file hash format', 'error')
        return redirect(url_for('files.file_list'))

    file = AnalysisFile.find_by_sha(sha)
    if not file:
        flash('File not found', 'error')
        return redirect(url_for('files.file_list'))

    # Check if file exists on disk
    if not os.path.exists(file.filepath):
        flash('File not available for download', 'error')
        return redirect(url_for('files.file_details', sha=sha))

    # Security check: ensure file is within upload directory
    upload_dir = Path(current_app.config['UPLOAD_FOLDER']).resolve()
    file_path = Path(file.filepath).resolve()

    if not str(file_path).startswith(str(upload_dir)):
        current_app.logger.warning(f"Path traversal attempt: {file.filepath}")
        flash('Access denied', 'error')
        return redirect(url_for('files.file_list'))

    try:
        # Log download
        AuditLog.log_action(
            user_id=current_user.id,
            action='file_downloaded',
            description=f'Downloaded {file.filename}',
            resource_type='file',
            resource_id=file.sha256_hash
        )

        # Update access time
        file.last_accessed = datetime.utcnow()
        db.session.commit()

        return send_file(
            file.filepath,
            as_attachment=True,
            download_name=file.filename,
            mimetype='application/octet-stream'
        )

    except Exception as e:
        current_app.logger.error(f"Download failed for {sha}: {e}")
        flash('Download failed. Please try again.', 'error')
        return redirect(url_for('files.file_details', sha=sha))


@files_bp.route('/<sha>/delete', methods=['POST'])
@login_required
@rate_limit("20 per hour")
def delete_file(sha):
    """Delete file with proper cleanup"""
    if not validate_sha256(sha):
        return jsonify({'error': 'Invalid file hash'}), 400

    file = AnalysisFile.find_by_sha(sha)
    if not file:
        return jsonify({'error': 'File not found'}), 404

    # Check permissions (only creator or admin can delete)
    if file.created_by != current_user.id and not current_user.is_admin:
        return jsonify({'error': 'Permission denied'}), 403

    # Check if file has dependencies (child files)
    child_count = AnalysisFile.query.filter_by(parent_file_sha=file.sha256_hash).count()
    if child_count > 0:
        return jsonify({
            'error': f'Cannot delete file with {child_count} extracted child files'
        }), 400

    try:
        filename = file.filename
        file_id = file.id

        # Delete physical file
        if os.path.exists(file.filepath):
            try:
                os.remove(file.filepath)
            except OSError as e:
                current_app.logger.warning(f"Failed to delete physical file {file.filepath}: {e}")

        # Delete database record (cascades to content and findings)
        db.session.delete(file)
        db.session.commit()

        # Log deletion
        AuditLog.log_action(
            user_id=current_user.id,
            action='file_deleted',
            description=f'Deleted file {filename}',
            metadata={'file_id': file_id, 'filename': filename}
        )

        return jsonify({
            'success': True,
            'message': f'File {filename} deleted successfully'
        })

    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Delete failed for {sha}: {e}")
        return jsonify({'error': 'Failed to delete file'}), 500


@files_bp.route('/<sha>/update', methods=['POST'])
@login_required
def update_file(sha):
    """Update file metadata"""
    if not validate_sha256(sha):
        return jsonify({'error': 'Invalid file hash'}), 400

    file = AnalysisFile.find_by_sha(sha)
    if not file:
        return jsonify({'error': 'File not found'}), 404

    # Check permissions
    if file.created_by != current_user.id and not current_user.is_admin:
        return jsonify({'error': 'Permission denied'}), 403

    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No data provided'}), 400

        # Update allowed fields
        if 'priority' in data:
            priority = int(data['priority'])
            if 1 <= priority <= 10:
                file.priority = priority

        if 'is_root_file' in data:
            file.is_root_file = bool(data['is_root_file'])

        if 'notes' in data:
            file.notes = data['notes'][:1000]  # Limit notes length

        if 'tags' in data:
            tags = data['tags']
            if isinstance(tags, list):
                # Validate and clean tags
                clean_tags = []
                for tag in tags[:10]:  # Max 10 tags
                    if isinstance(tag, str) and len(tag.strip()) <= 50:
                        clean_tags.append(tag.strip().lower())
                file.tags = clean_tags

        db.session.commit()

        # Log update
        AuditLog.log_action(
            user_id=current_user.id,
            action='file_updated',
            description=f'Updated file {file.filename}',
            resource_type='file',
            resource_id=file.sha256_hash,
            metadata=data
        )

        return jsonify({
            'success': True,
            'message': 'File updated successfully',
            'file': file.to_dict()
        })

    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Update failed for {sha}: {e}")
        return jsonify({'error': 'Failed to update file'}), 500


@files_bp.route('/bulk-actions', methods=['POST'])
@login_required
@rate_limit("10 per minute")
def bulk_actions():
    """Perform bulk actions on multiple files"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No data provided'}), 400

        action = data.get('action')
        file_hashes = data.get('file_hashes', [])

        if not action or not file_hashes:
            return jsonify({'error': 'Action and file_hashes required'}), 400

        # Validate file hashes
        if not all(validate_sha256(h) for h in file_hashes):
            return jsonify({'error': 'Invalid file hash format'}), 400

        # Get files
        files = AnalysisFile.query.filter(AnalysisFile.sha256_hash.in_(file_hashes)).all()
        if not files:
            return jsonify({'error': 'No files found'}), 404

        # Check permissions (user can only modify their own files unless admin)
        if not current_user.is_admin:
            user_files = [f for f in files if f.created_by == current_user.id]
            if len(user_files) != len(files):
                return jsonify({'error': 'Permission denied for some files'}), 403

        results = []

        if action == 'delete':
            for file in files:
                try:
                    # Check dependencies
                    child_count = AnalysisFile.query.filter_by(parent_file_sha=file.sha256_hash).count()
                    if child_count > 0:
                        results.append({
                            'hash': file.sha256_hash,
                            'success': False,
                            'error': f'Has {child_count} child files'
                        })
                        continue

                    # Delete file
                    if os.path.exists(file.filepath):
                        os.remove(file.filepath)

                    db.session.delete(file)
                    results.append({
                        'hash': file.sha256_hash,
                        'success': True
                    })
                except Exception as e:
                    results.append({
                        'hash': file.sha256_hash,
                        'success': False,
                        'error': str(e)
                    })

        elif action == 'analyze':
            analysis_types = data.get('analysis_types', ['basic', 'strings', 'crypto'])
            for file in files:
                try:
                    file.status = FileStatus.PROCESSING
                    task_id = BackgroundService.queue_comprehensive_analysis(
                        file_id=file.id,
                        analysis_types=analysis_types,
                        user_id=current_user.id
                    )
                    results.append({
                        'hash': file.sha256_hash,
                        'success': True,
                        'task_id': task_id
                    })
                except Exception as e:
                    results.append({
                        'hash': file.sha256_hash,
                        'success': False,
                        'error': str(e)
                    })

        elif action == 'update_priority':
            priority = data.get('priority', 5)
            if not 1 <= priority <= 10:
                return jsonify({'error': 'Priority must be between 1 and 10'}), 400

            for file in files:
                try:
                    file.priority = priority
                    results.append({
                        'hash': file.sha256_hash,
                        'success': True
                    })
                except Exception as e:
                    results.append({
                        'hash': file.sha256_hash,
                        'success': False,
                        'error': str(e)
                    })

        else:
            return jsonify({'error': 'Invalid action'}), 400

        db.session.commit()

        # Log bulk action
        successful_count = sum(1 for r in results if r['success'])
        AuditLog.log_action(
            user_id=current_user.id,
            action=f'bulk_{action}',
            description=f'Bulk {action} on {successful_count}/{len(files)} files',
            metadata={
                'action': action,
                'total_files': len(files),
                'successful': successful_count,
                'results': results
            }
        )

        return jsonify({
            'success': True,
            'message': f'Bulk {action} completed',
            'results': results
        })

    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Bulk action failed: {e}")
        return jsonify({'error': 'Bulk action failed'}), 500


@files_bp.route('/preview_csv', methods=['POST'])
@login_required
@rate_limit("10 per minute")
def preview_csv():
    """Preview CSV file contents without importing"""
    try:
        # Check if CSV file was uploaded
        if 'csv_file' not in request.files:
            return jsonify({'error': 'No CSV file selected'}), 400

        csv_file = request.files['csv_file']
        if csv_file.filename == '':
            return jsonify({'error': 'No CSV file selected'}), 400

        # Validate file extension
        if not csv_file.filename.lower().endswith('.csv'):
            return jsonify({'error': 'File must be a CSV file'}), 400

        # Read the CSV file
        csv_content = csv_file.read().decode('utf-8')

        # Parse CSV
        import csv
        import io

        # First pass: count total rows and validate format
        csv_reader = csv.reader(io.StringIO(csv_content))

        # Skip header row
        try:
            header = next(csv_reader, None)
        except Exception as e:
            return jsonify({'error': f'Invalid CSV format: {str(e)}'}), 400

        if not header:
            return jsonify({'error': 'Empty CSV file'}), 400

        # Count total rows
        total_rows = sum(1 for _ in csv_reader)

        # Reset for second pass
        io.StringIO(csv_content).seek(0)
        csv_reader = csv.reader(io.StringIO(csv_content))

        # Skip header again
        next(csv_reader, None)

        # Get sample rows (first 100)
        sample_size = min(100, total_rows)
        sample_rows = []

        for i, row in enumerate(csv_reader):
            if i >= sample_size:
                break

            if len(row) < 1 or not row[0]:
                continue

            file_path = row[0]
            file_name = os.path.basename(file_path)

            # Get additional info if available
            file_type = row[1] if len(row) > 1 and row[1] else "Unknown"
            file_size = row[2] if len(row) > 2 and row[2] else "Unknown"

            sample_rows.append({
                'file_path': file_path,
                'file_name': file_name,
                'file_type': file_type,
                'file_size': file_size
            })

        return jsonify({
            'success': True,
            'total_files': total_rows,
            'sample_files': sample_rows,
            'sample_size': len(sample_rows)
        })

    except Exception as e:
        current_app.logger.error(f"CSV preview error: {e}", exc_info=True)
        return jsonify({'error': 'Failed to preview CSV file'}), 500


@files_bp.route('/bulk_import', methods=['GET', 'POST'])
@login_required
@rate_limit("5 per hour")
def bulk_import():
    """Import multiple files from a CSV file"""
    if request.method == 'POST':
        try:
            # Check if CSV file was uploaded
            if 'csv_file' not in request.files:
                flash('No CSV file selected', 'error')
                return redirect(request.url)

            csv_file = request.files['csv_file']
            if csv_file.filename == '':
                flash('No CSV file selected', 'error')
                return redirect(request.url)

            # Validate file extension
            if not csv_file.filename.lower().endswith('.csv'):
                flash('File must be a CSV file', 'error')
                return redirect(request.url)

            # Get import options
            priority = request.form.get('priority', 5, type=int)
            auto_analyze = request.form.get('auto_analyze', False, type=bool)
            notes = request.form.get('notes', '').strip()
            tags = [tag.strip() for tag in request.form.get('tags', '').split(',') if tag.strip()]

            # Validate priority
            if not 1 <= priority <= 10:
                priority = 5

            # Create a bulk import record
            try:
                # Try to create a BulkImport record with minimal fields to avoid issues with missing columns
                bulk_import = BulkImport(
                    import_type='files',
                    status='pending',
                    source_file=csv_file.filename,
                    file_size=0,  # Will be updated later
                    created_by=current_user.id
                )
                db.session.add(bulk_import)
                db.session.commit()
            except Exception as e:
                # If there's an error (like missing columns), log it and try a more explicit approach
                current_app.logger.warning(f"Error creating BulkImport: {e}")
                db.session.rollback()

                # Create a new record with explicit column insertion to avoid missing columns
                stmt = db.text("""
                    INSERT INTO bulk_imports 
                    (public_id, import_type, status, source_file, file_size, created_by, created_at, updated_at) 
                    VALUES (:public_id, :import_type, :status, :source_file, :file_size, :created_by, :created_at, :updated_at)
                    RETURNING id
                """)

                now = datetime.utcnow()
                result = db.session.execute(stmt, {
                    'public_id': str(uuid.uuid4()),
                    'import_type': 'files',
                    'status': 'pending',
                    'source_file': csv_file.filename,
                    'file_size': 0,
                    'created_by': current_user.id,
                    'created_at': now,
                    'updated_at': now
                })

                # Get the ID of the newly created record
                bulk_import_id = result.scalar()

                # Fetch the record using a raw SQL query to avoid including task_id column
                stmt = db.text("""
                    SELECT id, public_id, import_type, status, total_items, processed_items, 
                           successful_items, failed_items, error_message, error_details,
                           source_file, file_size, file_hash, created_by, created_at, updated_at, completed_at
                    FROM bulk_imports
                    WHERE id = :id
                """)
                result = db.session.execute(stmt, {'id': bulk_import_id}).fetchone()

                # Create a BulkImport object manually
                bulk_import = BulkImport(
                    id=result[0],
                    public_id=result[1],
                    import_type=result[2],
                    status=result[3],
                    total_items=result[4],
                    processed_items=result[5],
                    successful_items=result[6],
                    failed_items=result[7],
                    error_message=result[8],
                    error_details=result[9],
                    source_file=result[10],
                    file_size=result[11],
                    file_hash=result[12],
                    created_by=result[13],
                    created_at=result[14],
                    updated_at=result[15],
                    completed_at=result[16]
                )
                db.session.commit()

            # Read the CSV file
            csv_content = csv_file.read().decode('utf-8')

            # Update file size
            bulk_import.file_size = len(csv_content)
            db.session.commit()

            # Prepare options for the background task
            options = {
                'priority': priority,
                'auto_analyze': auto_analyze,
                'notes': notes,
                'tags': tags
            }

            # Queue the CSV processing task
            from crypto_hunter_web.tasks.analysis_tasks import process_csv_bulk_import
            task = process_csv_bulk_import.delay(bulk_import.id, csv_content, options)

            # Track the task
            BackgroundService.track_task(
                task_id=task.id,
                task_type='bulk_import',
                file_id=0,  # No specific file ID for bulk import
                user_id=current_user.id,
                metadata={
                    'bulk_import_id': bulk_import.id,
                    'filename': csv_file.filename,
                    'options': options
                }
            )

            # Update bulk import with task ID if the column exists
            try:
                bulk_import.task_id = task.id
                db.session.commit()
            except Exception as e:
                # If the task_id column doesn't exist, log the error but continue
                current_app.logger.warning(f"Could not update task_id: {e}")
                db.session.rollback()

            # Log action
            AuditLog.log_action(
                user_id=current_user.id,
                action='bulk_import_started',
                description=f'Started bulk import from {csv_file.filename}',
                metadata={
                    'bulk_import_id': bulk_import.id,
                    'task_id': task.id,
                    'options': options
                }
            )

            flash(f"Bulk import from {csv_file.filename} has been queued for processing. You can check the status on this page.", 'info')
            return redirect(url_for('files.bulk_import'))

        except Exception as e:
            current_app.logger.error(f"Bulk import error: {e}", exc_info=True)
            flash('Bulk import failed. Please try again.', 'error')

    # Get upload statistics for display
    upload_stats = {
        'max_file_size': current_app.config.get('MAX_CONTENT_LENGTH', 1073741824),
        'allowed_extensions': list(current_app.config.get('ALLOWED_EXTENSIONS', set()))
    }

    # Use a new session for these queries to avoid PendingRollbackError
    try:
        # Count total files created by user
        total_files = db.session.query(db.func.count(AnalysisFile.id)) \
                        .filter(AnalysisFile.created_by == current_user.id).scalar() or 0

        # Get total size of files created by user
        total_size = db.session.query(db.func.sum(AnalysisFile.file_size)) \
                        .filter(AnalysisFile.created_by == current_user.id).scalar() or 0

        upload_stats['total_files'] = total_files
        upload_stats['total_size'] = total_size
    except Exception as e:
        # If there's an error, log it and set default values
        current_app.logger.warning(f"Error getting upload stats: {e}")
        upload_stats['total_files'] = 0
        upload_stats['total_size'] = 0
        # Ensure session is rolled back
        db.session.rollback()

    # Get recent imports
    # Using specific column selection to avoid querying non-existent columns
    recent_imports = db.session.query(
        BulkImport.id, BulkImport.public_id, BulkImport.import_type, 
        BulkImport.status, BulkImport.total_items, BulkImport.processed_items,
        BulkImport.successful_items, BulkImport.failed_items,
        BulkImport.error_message, BulkImport.error_details,
        BulkImport.source_file, BulkImport.file_size, BulkImport.file_hash,
        BulkImport.created_by, BulkImport.created_at, BulkImport.updated_at,
        BulkImport.completed_at
    ).filter_by(created_by=current_user.id) \
     .order_by(BulkImport.created_at.desc()) \
     .limit(5).all()

    return render_template('files/bulk_import.html', upload_stats=upload_stats, recent_imports=recent_imports)

@files_bp.route('/statistics')
@login_required
def statistics():
    """File statistics and analytics page"""
    try:
        # Time range filter
        days = request.args.get('days', 30, type=int)
        since_date = datetime.utcnow() - timedelta(days=days)

        # Overall statistics
        stats = {
            'total_files': AnalysisFile.query.count(),
            'total_size': db.session.query(db.func.sum(AnalysisFile.file_size)).scalar() or 0,
            'analyzed_files': AnalysisFile.query.filter_by(status=FileStatus.COMPLETE).count(),
            'crypto_files': AnalysisFile.query.filter_by(contains_crypto=True).count(),
            'recent_uploads': AnalysisFile.query.filter(AnalysisFile.created_at >= since_date).count(),
        }

        # File type analysis
        file_type_analysis = db.session.query(
            AnalysisFile.file_type,
            db.func.count(AnalysisFile.id).label('count'),
            db.func.sum(AnalysisFile.file_size).label('total_size'),
            db.func.avg(AnalysisFile.file_size).label('avg_size'),
            db.func.sum(db.case([(AnalysisFile.contains_crypto == True, 1)], else_=0)).label('crypto_count')
        ).group_by(AnalysisFile.file_type).all()

        # Upload trends (daily)
        upload_trends = db.session.query(
            db.func.date(AnalysisFile.created_at).label('date'),
            db.func.count(AnalysisFile.id).label('count'),
            db.func.sum(AnalysisFile.file_size).label('size')
        ).filter(AnalysisFile.created_at >= since_date) \
            .group_by(db.func.date(AnalysisFile.created_at)) \
            .order_by(db.func.date(AnalysisFile.created_at)).all()

        # Analysis performance
        analysis_performance = db.session.query(
            db.func.avg(AnalysisFile.analysis_duration).label('avg_duration'),
            db.func.min(AnalysisFile.analysis_duration).label('min_duration'),
            db.func.max(AnalysisFile.analysis_duration).label('max_duration'),
            db.func.count(AnalysisFile.id).label('analyzed_count')
        ).filter(AnalysisFile.analysis_duration.isnot(None)).first()

        return render_template('files/statistics.html',
                               stats=stats,
                               file_type_analysis=file_type_analysis,
                               upload_trends=upload_trends,
                               analysis_performance=analysis_performance,
                               days=days)

    except Exception as e:
        current_app.logger.error(f"Statistics error: {e}")
        flash('Error loading statistics. Please try again.', 'error')
        return render_template('files/statistics.html')


# Error handlers
@files_bp.errorhandler(413)
def file_too_large(error):
    """Handle file too large errors"""
    flash('File too large. Please select a smaller file.', 'error')
    return redirect(url_for('files.upload_file'))


@files_bp.errorhandler(404)
def file_not_found(error):
    """Handle file not found errors"""
    flash('File not found.', 'error')
    return redirect(url_for('files.file_list'))
