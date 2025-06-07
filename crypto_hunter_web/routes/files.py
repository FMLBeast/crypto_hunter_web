"""
File operation routes with comprehensive crypto intelligence integration
"""

import os
import json
from datetime import datetime
from flask import Blueprint, request, render_template, redirect, url_for, flash, session, jsonify
from werkzeug.utils import secure_filename

from crypto_hunter_web.models import db, AnalysisFile, BulkImport
from crypto_hunter_web.services.import_service import ImportService
from crypto_hunter_web.services.file_analyzer import FileAnalyzer
from crypto_hunter_web.services.auth_service import AuthService

files_bp = Blueprint('files', __name__)


@files_bp.route('/files/bulk-import', methods=['GET', 'POST'])
@AuthService.login_required
def bulk_import():
    """Comprehensive bulk import with crypto intelligence and background processing"""
    if request.method == 'POST':
        try:
            # Validate file upload
            if 'csv_file' not in request.files:
                flash('No CSV file uploaded', 'error')
                return redirect(url_for('files.bulk_import'))

            csv_file = request.files['csv_file']
            if not csv_file.filename:
                flash('No file selected', 'error')
                return redirect(url_for('files.bulk_import'))

            if not csv_file.filename.lower().endswith('.csv'):
                flash('Please upload a CSV file', 'error')
                return redirect(url_for('files.bulk_import'))

            # Ensure upload directory exists
            upload_dir = 'bulk_uploads'
            os.makedirs(upload_dir, exist_ok=True)

            # Save uploaded file with timestamp
            filename = secure_filename(csv_file.filename)
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f"{timestamp}_{filename}"
            filepath = os.path.join(upload_dir, filename)
            csv_file.save(filepath)

            # Validate file was saved properly
            if not os.path.exists(filepath):
                flash('Failed to save uploaded file', 'error')
                return redirect(url_for('files.bulk_import'))

            # Perform import using comprehensive service with crypto intelligence
            try:
                bulk_import_result = ImportService.import_from_csv(filepath, session['user_id'])

                # Create detailed success message with crypto intelligence stats
                success_msg = (f'Import completed with crypto intelligence! '
                               f'{bulk_import_result.successful_imports} files imported, '
                               f'{bulk_import_result.duplicates_found} duplicates found, '
                               f'{bulk_import_result.errors_count} errors')

                if bulk_import_result.errors_count > 0:
                    success_msg += f' (check import history for error details)'

                # Add background processing info
                success_msg += '. Background crypto analysis started for all imported files.'

                flash(success_msg, 'success')

            except Exception as e:
                flash(f'Import failed: {str(e)}', 'error')

            # Clean up uploaded file
            try:
                os.remove(filepath)
            except:
                pass  # File cleanup is not critical

        except Exception as e:
            flash(f'Upload error: {str(e)}', 'error')

        return redirect(url_for('files.bulk_import'))

    # GET request - show import history and form with background processing stats
    try:
        imports = BulkImport.query.filter_by(
            imported_by=session['user_id']
        ).order_by(BulkImport.started_at.desc()).limit(20).all()

        # Get background processing statistics
        try:
            from crypto_hunter_web.services.background_crypto import BackgroundCryptoService
            background_stats = BackgroundCryptoService.get_system_stats()
        except Exception as e:
            background_stats = {'error': str(e)}

        return render_template('files/bulk_import.html',
                               imports=imports,
                               background_stats=background_stats)

    except Exception as e:
        flash(f'Error loading import history: {str(e)}', 'error')
        return render_template('files/bulk_import.html', imports=[], background_stats={})


@files_bp.route('/files/directory-scan', methods=['GET', 'POST'])
@AuthService.login_required
def directory_scan():
    """Directory scanning with crypto intelligence and background processing"""
    if request.method == 'POST':
        try:
            directory_path = request.form.get('directory_path', '').strip()
            recursive = request.form.get('recursive') == 'on'

            if not directory_path:
                flash('Please provide a directory path', 'error')
                return redirect(url_for('files.directory_scan'))

            # Validate directory
            if not os.path.exists(directory_path):
                flash('Directory does not exist', 'error')
                return redirect(url_for('files.directory_scan'))

            if not os.path.isdir(directory_path):
                flash('Path is not a directory', 'error')
                return redirect(url_for('files.directory_scan'))

            if not os.access(directory_path, os.R_OK):
                flash('Cannot read directory', 'error')
                return redirect(url_for('files.directory_scan'))

            # Perform directory scan with crypto intelligence
            try:
                scan_result = ImportService.scan_directory(
                    directory_path, session['user_id'], recursive
                )

                success_msg = (f'Directory scan completed with crypto intelligence! '
                               f'{scan_result.successful_imports} files imported from '
                               f'{scan_result.total_files} files found')

                if scan_result.errors_count > 0:
                    success_msg += f' ({scan_result.errors_count} errors occurred)'

                success_msg += '. Background crypto analysis started for all imported files.'

                flash(success_msg, 'success')

            except Exception as e:
                flash(f'Directory scan failed: {str(e)}', 'error')

        except Exception as e:
            flash(f'Scan error: {str(e)}', 'error')

        return redirect(url_for('files.directory_scan'))

    # GET request - show scan form with background processing info
    try:
        from crypto_hunter_web.services.background_crypto import BackgroundCryptoService
        background_stats = BackgroundCryptoService.get_system_stats()
    except Exception as e:
        background_stats = {'error': str(e)}

    return render_template('files/directory_scan.html', background_stats=background_stats)


@files_bp.route('/files/<sha>/analyze', methods=['POST'])
@AuthService.login_required
def analyze_file(sha):
    """Trigger comprehensive file analysis with crypto intelligence"""
    try:
        # Find file by SHA
        file_record = AnalysisFile.query.filter_by(sha256_hash=sha).first()
        if not file_record:
            flash('File not found', 'error')
            return redirect(url_for('files.file_list'))

        # Check if file exists on disk
        if not file_record.filepath or not os.path.exists(file_record.filepath):
            flash('File not available for analysis (file path not found)', 'warning')
            return redirect(url_for('files.file_detail', sha=sha))

        # Update status to analyzing
        file_record.status = 'analyzing'
        db.session.commit()

        # Perform comprehensive analysis with crypto intelligence
        try:
            analysis_success = FileAnalyzer.analyze_file_content(
                file_record.filepath, file_record.id
            )

            if analysis_success:
                flash('Comprehensive crypto analysis completed successfully!', 'success')

                # Queue for background crypto processing if high intelligence score
                try:
                    from crypto_hunter_web.services.background_crypto import BackgroundCryptoService

                    # Get analysis results to check intelligence score
                    from crypto_hunter_web.models import FileContent
                    content = FileContent.query.filter_by(file_id=file_record.id).first()

                    if content and content.content_text:
                        analysis_data = json.loads(content.content_text)
                        intelligence_score = analysis_data.get('intelligence_score', 0)

                        if intelligence_score > 50:
                            # Queue for comprehensive background analysis
                            task_id = BackgroundCryptoService.queue_priority_analysis(
                                file_record.id,
                                ['ethereum_validation', 'cipher_analysis', 'pattern_analysis'],
                                high_priority=True
                            )

                            if task_id:
                                flash(
                                    f'High-value crypto content detected! Queued for comprehensive background analysis.',
                                    'info')

                except Exception as e:
                    # Don't fail the main analysis if background queueing fails
                    logger.warning(f"Failed to queue background analysis: {e}")
            else:
                flash('File analysis completed with warnings (check analysis results)', 'warning')
                file_record.status = 'analysis_partial'
                db.session.commit()

        except Exception as e:
            file_record.status = 'analysis_failed'
            db.session.commit()
            flash(f'File analysis failed: {str(e)}', 'error')

        return redirect(url_for('files.file_detail', sha=sha))

    except Exception as e:
        flash(f'Analysis error: {str(e)}', 'error')
        return redirect(url_for('files.file_list'))


@files_bp.route('/files/<sha>/background-analyze', methods=['POST'])
@AuthService.login_required
def background_analyze_file(sha):
    """Queue file for comprehensive background crypto analysis"""
    try:
        file_record = AnalysisFile.query.filter_by(sha256_hash=sha).first()
        if not file_record:
            flash('File not found', 'error')
            return redirect(url_for('files.file_list'))

        # Queue for comprehensive background analysis
        try:
            from crypto_hunter_web.services.background_crypto import BackgroundCryptoService

            # Get analysis preferences from form
            analysis_types = request.form.getlist('analysis_types')
            if not analysis_types:
                analysis_types = ['ethereum_validation', 'cipher_analysis', 'pattern_analysis']

            task_id = BackgroundCryptoService.queue_priority_analysis(
                file_record.id,
                analysis_types,
                high_priority=True
            )

            if task_id:
                flash(f'File queued for comprehensive background crypto analysis! Task ID: {task_id}', 'success')
            else:
                flash('Failed to queue background analysis', 'error')

        except Exception as e:
            flash(f'Background analysis queueing failed: {str(e)}', 'error')

        return redirect(url_for('files.file_detail', sha=sha))

    except Exception as e:
        flash(f'Error: {str(e)}', 'error')
        return redirect(url_for('files.file_list'))


@files_bp.route('/files/bulk-import/status/<int:import_id>')
@AuthService.login_required
def import_status(import_id):
    """Get status of bulk import operation with background processing info"""
    try:
        bulk_import = BulkImport.query.filter_by(
            id=import_id,
            imported_by=session['user_id']
        ).first()

        if not bulk_import:
            return jsonify({'error': 'Import not found'}), 404

        status_data = {
            'id': bulk_import.id,
            'status': bulk_import.status,
            'filename': bulk_import.filename,
            'total_files': bulk_import.total_files or 0,
            'processed_files': bulk_import.processed_files or 0,
            'successful_imports': bulk_import.successful_imports or 0,
            'duplicates_found': bulk_import.duplicates_found or 0,
            'errors_count': bulk_import.errors_count or 0,
            'started_at': bulk_import.started_at.isoformat() if bulk_import.started_at else None,
            'completed_at': bulk_import.completed_at.isoformat() if bulk_import.completed_at else None,
            'progress_percentage': 0
        }

        # Calculate progress percentage
        if bulk_import.total_files and bulk_import.total_files > 0:
            status_data['progress_percentage'] = round(
                (bulk_import.processed_files or 0) / bulk_import.total_files * 100, 1
            )

        # Add background processing info
        try:
            from crypto_hunter_web.services.background_crypto import BackgroundCryptoService
            background_stats = BackgroundCryptoService.get_system_stats()
            status_data['background_processing'] = background_stats
        except Exception as e:
            status_data['background_processing'] = {'error': str(e)}

        return jsonify(status_data)

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@files_bp.route('/files/bulk-import/errors/<int:import_id>')
@AuthService.login_required
def import_errors(import_id):
    """Get detailed error log for bulk import"""
    try:
        bulk_import = BulkImport.query.filter_by(
            id=import_id,
            imported_by=session['user_id']
        ).first()

        if not bulk_import:
            return jsonify({'error': 'Import not found'}), 404

        error_data = {
            'import_id': import_id,
            'filename': bulk_import.filename,
            'status': bulk_import.status,
            'errors_count': bulk_import.errors_count or 0,
            'error_log': bulk_import.error_log or 'No errors recorded',
            'total_files': bulk_import.total_files or 0,
            'successful_imports': bulk_import.successful_imports or 0
        }

        return jsonify(error_data)

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@files_bp.route('/files/background-status')
@AuthService.login_required
def background_status():
    """Get comprehensive background processing status"""
    try:
        from crypto_hunter_web.services.background_crypto import BackgroundCryptoService

        stats = BackgroundCryptoService.get_system_stats()

        # Add user-specific stats
        user_files = AnalysisFile.query.filter_by(discovered_by=session['user_id']).all()

        user_stats = {
            'total_files': len(user_files),
            'analyzed_files': len([f for f in user_files if f.status == 'analyzed']),
            'pending_analysis': len(
                [f for f in user_files if f.status in ['pending_analysis', 'basic_analysis_complete']]),
            'high_priority_files': len([f for f in user_files if f.priority and f.priority > 7])
        }

        return jsonify({
            'system_stats': stats,
            'user_stats': user_stats,
            'timestamp': datetime.now().isoformat()
        })

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@files_bp.route('/files/add', methods=['GET', 'POST'])
@AuthService.login_required
def add_file():
    """Single file upload with crypto intelligence"""
    if request.method == 'POST':
        try:
            if 'file' not in request.files:
                flash('No file uploaded', 'error')
                return redirect(url_for('files.add_file'))

            uploaded_file = request.files['file']
            if not uploaded_file.filename:
                flash('No file selected', 'error')
                return redirect(url_for('files.add_file'))

            # Ensure upload directory exists
            upload_dir = 'single_uploads'
            os.makedirs(upload_dir, exist_ok=True)

            # Save file
            filename = secure_filename(uploaded_file.filename)
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f"{timestamp}_{filename}"
            filepath = os.path.join(upload_dir, filename)
            uploaded_file.save(filepath)

            # Create single-file "import" using comprehensive service
            try:
                # Calculate file hash
                file_size = os.path.getsize(filepath)
                sha256_hash = ImportService._calculate_sha256_safe(filepath)

                if not sha256_hash:
                    flash('Failed to process uploaded file', 'error')
                    os.remove(filepath)
                    return redirect(url_for('files.add_file'))

                # Check for duplicates
                existing_file = AnalysisFile.query.filter_by(sha256_hash=sha256_hash).first()
                if existing_file:
                    flash('File already exists in database', 'warning')
                    os.remove(filepath)
                    return redirect(url_for('files.file_detail', sha=sha256_hash))

                # Create file record with crypto intelligence
                file_data = {
                    'sha256_hash': sha256_hash,
                    'filename': uploaded_file.filename,
                    'filepath': filepath,
                    'file_type': 'unknown',
                    'file_size': file_size,
                    'extraction_method': 'manual_upload',
                    'is_root_file': True
                }

                # Create minimal bulk import for consistency
                bulk_import = BulkImport(
                    filename=f"Manual: {uploaded_file.filename}",
                    imported_by=session['user_id'],
                    status='processing',
                    started_at=datetime.utcnow(),
                    total_files=1
                )
                db.session.add(bulk_import)
                db.session.flush()

                # Import the file with crypto intelligence
                result = ImportService._import_single_file(
                    file_data, session['user_id'], bulk_import
                )

                if result == 'imported':
                    bulk_import.successful_imports = 1
                    bulk_import.status = 'completed'
                    bulk_import.completed_at = datetime.utcnow()
                    db.session.commit()

                    flash('File uploaded and imported with crypto intelligence!', 'success')
                    return redirect(url_for('files.file_detail', sha=sha256_hash))
                else:
                    flash('Failed to import uploaded file', 'error')
                    os.remove(filepath)

            except Exception as e:
                flash(f'Import failed: {str(e)}', 'error')
                if os.path.exists(filepath):
                    os.remove(filepath)

        except Exception as e:
            flash(f'Upload error: {str(e)}', 'error')

        return redirect(url_for('files.add_file'))

    # GET request - show upload form with recent files
    try:
        existing_files = AnalysisFile.query.order_by(
            AnalysisFile.created_at.desc()
        ).limit(10).all()

        # Get background processing stats
        try:
            from crypto_hunter_web.services.background_crypto import BackgroundCryptoService
            background_stats = BackgroundCryptoService.get_system_stats()
        except Exception:
            background_stats = {}

        return render_template('files/add_file.html',
                               existing_files=existing_files,
                               background_stats=background_stats)

    except Exception as e:
        flash(f'Error loading file list: {str(e)}', 'error')
        return render_template('files/add_file.html', existing_files=[], background_stats={})


@files_bp.route('/files')
@AuthService.login_required
def file_list():
    """File listing with crypto intelligence filtering"""
    try:
        page = request.args.get('page', 1, type=int)
        per_page = 50

        # Build query with crypto intelligence filters
        query = AnalysisFile.query

        # Status filter
        status_filter = request.args.get('status')
        if status_filter:
            query = query.filter(AnalysisFile.status == status_filter)

        # File type filter
        type_filter = request.args.get('file_type')
        if type_filter:
            query = query.filter(AnalysisFile.file_type == type_filter)

        # Priority filter for crypto intelligence
        priority_filter = request.args.get('priority')
        if priority_filter:
            if priority_filter == 'high':
                query = query.filter(AnalysisFile.priority >= 8)
            elif priority_filter == 'medium':
                query = query.filter(AnalysisFile.priority.between(5, 7))
            elif priority_filter == 'low':
                query = query.filter(AnalysisFile.priority < 5)

        # Search filter
        search = request.args.get('search')
        if search:
            query = query.filter(AnalysisFile.filename.contains(search))

        # Order and paginate
        query = query.order_by(AnalysisFile.priority.desc(), AnalysisFile.created_at.desc())
        files = query.paginate(
            page=page, per_page=per_page, error_out=False
        )

        # Get comprehensive statistics
        stats = {
            'total_files': AnalysisFile.query.count(),
            'analyzed_files': AnalysisFile.query.filter_by(status='analyzed').count(),
            'pending_files': AnalysisFile.query.filter_by(status='pending_analysis').count(),
            'failed_files': AnalysisFile.query.filter_by(status='analysis_failed').count(),
            'high_priority_files': AnalysisFile.query.filter(AnalysisFile.priority >= 8).count(),
            'crypto_files': AnalysisFile.query.filter(AnalysisFile.priority >= 6).count()
        }

        # Get background processing stats
        try:
            from crypto_hunter_web.services.background_crypto import BackgroundCryptoService
            background_stats = BackgroundCryptoService.get_system_stats()
        except Exception:
            background_stats = {}

        return render_template('files/file_list.html',
                               files=files,
                               stats=stats,
                               background_stats=background_stats)

    except Exception as e:
        flash(f'Error loading file list: {str(e)}', 'error')
        return render_template('files/file_list.html', files=None, stats={}, background_stats={})


@files_bp.route('/files/<sha>')
@AuthService.login_required
def file_detail(sha):
    """File detail view with comprehensive crypto intelligence analysis"""
    try:
        file_record = AnalysisFile.query.filter_by(sha256_hash=sha).first()
        if not file_record:
            flash('File not found', 'error')
            return redirect(url_for('files.file_list'))

        # Get comprehensive analysis content
        from crypto_hunter_web.models import FileContent
        content = FileContent.query.filter_by(file_id=file_record.id).first()
        analysis_data = None

        if content and content.content_text:
            try:
                analysis_data = json.loads(content.content_text)
            except json.JSONDecodeError:
                analysis_data = {'error': 'Invalid analysis data format'}

        # Get background processing status for this file
        background_status = None
        try:
            import redis
            redis_client = redis.Redis(host='localhost', port=6379, db=2, decode_responses=True)

            # Check if file has ongoing background tasks
            active_tasks = redis_client.smembers('active_tasks')
            file_tasks = []

            for task_id in active_tasks:
                task_data_str = redis_client.get(f"task:{task_id}")
                if task_data_str:
                    task_data = json.loads(task_data_str)
                    if task_data.get('file_id') == file_record.id:
                        file_tasks.append(task_data)

            background_status = {
                'active_tasks': file_tasks,
                'has_background_tasks': len(file_tasks) > 0
            }

        except Exception as e:
            background_status = {'error': str(e)}

        return render_template('files/file_detail.html',
                               file=file_record,
                               analysis=analysis_data,
                               background_status=background_status)

    except Exception as e:
        flash(f'Error loading file details: {str(e)}', 'error')
        return redirect(url_for('files.file_list'))