#!/usr/bin/env python3
# crypto_hunter_web/routes/admin.py

from flask import Blueprint, render_template, request, jsonify, current_app, flash, redirect, url_for
from flask_login import login_required, current_user
from sqlalchemy import func, desc
import logging
import os
import time
from datetime import datetime, timedelta

from crypto_hunter_web.models import db, User, AnalysisFile, Finding, AuditLog, FileStatus
from crypto_hunter_web.utils.decorators import admin_required

admin_bp = Blueprint('admin', __name__, url_prefix='/admin')
logger = logging.getLogger(__name__)


@admin_bp.route('/')
@login_required
@admin_required
def dashboard():
    """Admin dashboard with system statistics and management options"""
    try:
        # System statistics
        stats = {
            'total_users': User.query.count(),
            'active_users': User.query.filter_by(is_active=True).count(),
            'admin_users': User.query.filter_by(is_admin=True).count(),
            'total_files': AnalysisFile.query.count(),
            'total_findings': Finding.query.count(),
            'disk_usage': _get_disk_usage(),
            'db_size': _get_db_size(),
        }

        # Recent user registrations
        recent_users = User.query.order_by(desc(User.created_at)).limit(10).all()

        # Recent audit logs
        recent_logs = AuditLog.query.order_by(desc(AuditLog.timestamp)).limit(20).all()

        # User activity stats
        user_activity = db.session.query(
            User.username,
            func.count(AnalysisFile.id).label('file_count'),
            func.count(Finding.id).label('finding_count')
        ).outerjoin(AnalysisFile, User.id == AnalysisFile.created_by) \
         .outerjoin(Finding, User.id == Finding.created_by) \
         .group_by(User.id) \
         .order_by(desc('file_count')) \
         .limit(10).all()

        # System health
        health = {
            'cpu_usage': _get_cpu_usage(),
            'memory_usage': _get_memory_usage(),
            'uptime': _get_uptime(),
            'python_version': _get_python_version(),
        }

        return render_template('admin/dashboard.html',
                              stats=stats,
                              recent_users=recent_users,
                              recent_logs=recent_logs,
                              user_activity=user_activity,
                              health=health)

    except Exception as e:
        logger.error(f"Error loading admin dashboard: {e}")
        flash('Error loading admin dashboard', 'error')
        return render_template('admin/dashboard.html')


@admin_bp.route('/logs')
@login_required
@admin_required
def logs():
    """View and filter system logs"""
    try:
        page = request.args.get('page', 1, type=int)
        per_page = min(request.args.get('per_page', 50, type=int), 100)

        # Filters
        action_filter = request.args.get('action', '')
        user_filter = request.args.get('user_id', '', type=int)
        success_filter = request.args.get('success', '')
        date_from = request.args.get('date_from', '')
        date_to = request.args.get('date_to', '')

        # Build query
        query = AuditLog.query

        if action_filter:
            query = query.filter(AuditLog.action.like(f'%{action_filter}%'))

        if user_filter:
            query = query.filter(AuditLog.user_id == user_filter)

        if success_filter:
            success_bool = success_filter.lower() == 'true'
            query = query.filter(AuditLog.success == success_bool)

        if date_from:
            try:
                from_date = datetime.strptime(date_from, '%Y-%m-%d')
                query = query.filter(AuditLog.timestamp >= from_date)
            except ValueError:
                pass

        if date_to:
            try:
                to_date = datetime.strptime(date_to, '%Y-%m-%d')
                to_date = to_date + timedelta(days=1)  # Include the end date
                query = query.filter(AuditLog.timestamp <= to_date)
            except ValueError:
                pass

        # Order by timestamp descending
        query = query.order_by(desc(AuditLog.timestamp))

        # Pagination
        logs_pagination = query.paginate(page=page, per_page=per_page, error_out=False)
        logs = logs_pagination.items

        # Get unique actions for filter dropdown
        unique_actions = db.session.query(AuditLog.action).distinct().all()

        # Get users for filter dropdown
        users = User.query.all()

        return render_template('admin/logs.html',
                              logs=logs,
                              pagination=logs_pagination,
                              unique_actions=unique_actions,
                              users=users,
                              current_filters={
                                  'action': action_filter,
                                  'user_id': user_filter,
                                  'success': success_filter,
                                  'date_from': date_from,
                                  'date_to': date_to
                              })

    except Exception as e:
        logger.error(f"Error loading admin logs: {e}")
        flash('Error loading logs', 'error')
        return render_template('admin/logs.html', logs=[])


@admin_bp.route('/users')
@login_required
@admin_required
def users():
    """User management"""
    try:
        users = User.query.all()
        return render_template('admin/users.html', users=users)
    except Exception as e:
        logger.error(f"Error loading users: {e}")
        flash('Error loading users', 'error')
        return render_template('admin/users.html', users=[])


@admin_bp.route('/user/<int:user_id>/toggle_admin', methods=['POST'])
@login_required
@admin_required
def toggle_admin(user_id):
    """Toggle admin status for a user"""
    try:
        user = User.query.get_or_404(user_id)

        # Prevent removing admin status from yourself
        if user.id == current_user.id:
            flash('You cannot remove your own admin status', 'error')
            return redirect(url_for('admin.users'))

        user.is_admin = not user.is_admin
        db.session.commit()

        flash(f'Admin status for {user.username} {"enabled" if user.is_admin else "disabled"}', 'success')
        return redirect(url_for('admin.users'))

    except Exception as e:
        logger.error(f"Error toggling admin status: {e}")
        flash('Error updating user', 'error')
        return redirect(url_for('admin.users'))


@admin_bp.route('/user/<int:user_id>/toggle_active', methods=['POST'])
@login_required
@admin_required
def toggle_active(user_id):
    """Toggle active status for a user"""
    try:
        user = User.query.get_or_404(user_id)

        # Prevent deactivating yourself
        if user.id == current_user.id:
            flash('You cannot deactivate your own account', 'error')
            return redirect(url_for('admin.users'))

        user.is_active = not user.is_active
        db.session.commit()

        flash(f'Account for {user.username} {"activated" if user.is_active else "deactivated"}', 'success')
        return redirect(url_for('admin.users'))

    except Exception as e:
        logger.error(f"Error toggling active status: {e}")
        flash('Error updating user', 'error')
        return redirect(url_for('admin.users'))


# Helper functions for system stats
def _get_disk_usage():
    """Get disk usage information"""
    try:
        upload_dir = current_app.config.get('UPLOAD_FOLDER', 'uploads')
        total_size = 0
        for dirpath, dirnames, filenames in os.walk(upload_dir):
            for f in filenames:
                fp = os.path.join(dirpath, f)
                if os.path.exists(fp):
                    total_size += os.path.getsize(fp)

        # Convert to human-readable format
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if total_size < 1024.0:
                return f"{total_size:.1f} {unit}"
            total_size /= 1024.0
        return f"{total_size:.1f} PB"
    except Exception as e:
        logger.error(f"Error getting disk usage: {e}")
        return "Unknown"


def _get_db_size():
    """Get database size information"""
    try:
        # This is a simplified approach that works for SQLite
        db_uri = current_app.config.get('SQLALCHEMY_DATABASE_URI', '')
        if db_uri.startswith('sqlite:///'):
            db_path = db_uri.replace('sqlite:///', '')
            if os.path.exists(db_path):
                size_bytes = os.path.getsize(db_path)
                # Convert to human-readable format
                for unit in ['B', 'KB', 'MB', 'GB']:
                    if size_bytes < 1024.0:
                        return f"{size_bytes:.1f} {unit}"
                    size_bytes /= 1024.0
                return f"{size_bytes:.1f} TB"
        return "Unknown"
    except Exception as e:
        logger.error(f"Error getting DB size: {e}")
        return "Unknown"


def _get_cpu_usage():
    """Get CPU usage information"""
    try:
        import psutil
        return f"{psutil.cpu_percent()}%"
    except ImportError:
        return "psutil not installed"
    except Exception as e:
        logger.error(f"Error getting CPU usage: {e}")
        return "Unknown"


def _get_memory_usage():
    """Get memory usage information"""
    try:
        import psutil
        memory = psutil.virtual_memory()
        return f"{memory.percent}% ({memory.used / (1024 * 1024 * 1024):.1f} GB / {memory.total / (1024 * 1024 * 1024):.1f} GB)"
    except ImportError:
        return "psutil not installed"
    except Exception as e:
        logger.error(f"Error getting memory usage: {e}")
        return "Unknown"


def _get_uptime():
    """Get system uptime"""
    try:
        import psutil
        uptime_seconds = int(time.time() - psutil.boot_time())
        days, remainder = divmod(uptime_seconds, 86400)
        hours, remainder = divmod(remainder, 3600)
        minutes, seconds = divmod(remainder, 60)
        return f"{days}d {hours}h {minutes}m {seconds}s"
    except ImportError:
        return "psutil not installed"
    except Exception as e:
        logger.error(f"Error getting uptime: {e}")
        return "Unknown"


def _get_python_version():
    """Get Python version"""
    try:
        import sys
        return sys.version
    except Exception as e:
        logger.error(f"Error getting Python version: {e}")
        return "Unknown"
