#!/usr/bin/env python3
"""
Findings API Routes - Real implementation for managing analysis findings
"""

from flask import Blueprint, request, jsonify, session
from sqlalchemy import desc, func, and_, or_
from datetime import datetime, timedelta
import json
import logging

from crypto_hunter_web.services.auth_service import AuthService
from crypto_hunter_web.models import db, Finding, AnalysisFile, User, FindingStatus
from crypto_hunter_web.utils.decorators import rate_limit
from crypto_hunter_web.utils.validators import validate_uuid

findings_api_bp = Blueprint('findings_api', __name__)
logger = logging.getLogger(__name__)

@findings_api_bp.route('/findings', methods=['GET'])
@AuthService.login_required
def list_findings():
    """Get paginated list of findings with filtering"""
    try:
        user_id = session['user_id']
        page = request.args.get('page', 1, type=int)
        per_page = min(request.args.get('per_page', 25, type=int), 100)

        # Build base query for user's findings
        query = db.session.query(Finding).join(AnalysisFile).filter(
            AnalysisFile.created_by == user_id
        )

        # Apply filters
        category = request.args.get('category')
        if category:
            query = query.filter(Finding.category == category)

        finding_type = request.args.get('type')
        if finding_type:
            query = query.filter(Finding.finding_type == finding_type)

        status = request.args.get('status')
        if status:
            if hasattr(FindingStatus, status.upper()):
                query = query.filter(Finding.status == getattr(FindingStatus, status.upper()))

        min_confidence = request.args.get('min_confidence', type=int)
        if min_confidence is not None:
            query = query.filter(Finding.confidence_level >= min_confidence)

        file_id = request.args.get('file_id', type=int)
        if file_id:
            query = query.filter(Finding.file_id == file_id)

        search = request.args.get('search')
        if search:
            search_term = f'%{search}%'
            query = query.filter(
                or_(
                    Finding.title.ilike(search_term),
                    Finding.description.ilike(search_term),
                    Finding.raw_data.ilike(search_term)
                )
            )

        # Apply sorting
        sort_by = request.args.get('sort', 'created_at')
        sort_order = request.args.get('order', 'desc')

        if hasattr(Finding, sort_by):
            sort_column = getattr(Finding, sort_by)
            if sort_order.lower() == 'asc':
                query = query.order_by(sort_column.asc())
            else:
                query = query.order_by(sort_column.desc())
        else:
            query = query.order_by(desc(Finding.created_at))

        # Execute query with pagination
        paginated_findings = query.paginate(
            page=page, per_page=per_page, error_out=False
        )

        # Format findings data
        findings_data = []
        for finding in paginated_findings.items:
            finding_data = {
                'id': finding.public_id.hex if hasattr(finding, 'public_id') else str(finding.id),
                'title': finding.title,
                'description': finding.description,
                'category': finding.category,
                'finding_type': finding.finding_type,
                'confidence_level': finding.confidence_level,
                'status': finding.status.value if hasattr(finding.status, 'value') else str(finding.status),
                'priority': finding.priority,
                'severity': finding.severity,
                'file_info': {
                    'id': finding.file.id,
                    'filename': finding.file.filename,
                    'sha256': finding.file.sha256_hash
                },
                'location': {
                    'byte_offset': finding.byte_offset,
                    'byte_length': finding.byte_length,
                    'line_number': finding.line_number
                },
                'evidence': {
                    'raw_data': finding.raw_data[:100] + '...' if finding.raw_data and len(finding.raw_data) > 100 else finding.raw_data,
                    'pattern_matched': finding.pattern_matched,
                    'context': finding.context
                },
                'metadata': {
                    'analysis_method': finding.analysis_method,
                    'created_at': finding.created_at.isoformat() if finding.created_at else None,
                    'verified_at': finding.verified_at.isoformat() if hasattr(finding, 'verified_at') and finding.verified_at else None,
                    'verified_by': finding.verified_by if hasattr(finding, 'verified_by') else None
                }
            }
            findings_data.append(finding_data)

        # Get summary statistics
        stats = get_findings_stats(user_id)

        return jsonify({
            'success': True,
            'findings': findings_data,
            'pagination': {
                'page': page,
                'per_page': per_page,
                'total': paginated_findings.total,
                'pages': paginated_findings.pages,
                'has_next': paginated_findings.has_next,
                'has_prev': paginated_findings.has_prev
            },
            'stats': stats,
            'filters_applied': {
                'category': category,
                'type': finding_type,
                'status': status,
                'min_confidence': min_confidence,
                'file_id': file_id,
                'search': search
            }
        })

    except Exception as e:
        logger.error(f"Error listing findings: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@findings_api_bp.route('/findings/<finding_id>', methods=['GET'])
@AuthService.login_required
def get_finding_detail(finding_id):
    """Get detailed information about a specific finding"""
    try:
        user_id = session['user_id']

        # Get finding and verify access
        finding = db.session.query(Finding).join(AnalysisFile).filter(
            and_(
                Finding.public_id == finding_id,
                AnalysisFile.created_by == user_id
            )
        ).first()

        if not finding:
            return jsonify({'success': False, 'error': 'Finding not found or access denied'}), 404

        # Get related findings (same file, similar type)
        related_findings = db.session.query(Finding).filter(
            and_(
                Finding.file_id == finding.file_id,
                Finding.finding_type == finding.finding_type,
                Finding.id != finding.id
            )
        ).limit(5).all()

        # Get verification history if available
        verification_history = []
        if hasattr(finding, 'verification_history'):
            verification_history = finding.verification_history

        detailed_finding = {
            'id': finding.public_id.hex if hasattr(finding, 'public_id') else str(finding.id),
            'title': finding.title,
            'description': finding.description,
            'category': finding.category,
            'finding_type': finding.finding_type,
            'confidence_level': finding.confidence_level,
            'status': finding.status.value if hasattr(finding.status, 'value') else str(finding.status),
            'priority': finding.priority,
            'severity': finding.severity,
            'file_info': {
                'id': finding.file.id,
                'filename': finding.file.filename,
                'sha256': finding.file.sha256_hash,
                'file_type': finding.file.file_type,
                'file_size': finding.file.file_size
            },
            'location': {
                'byte_offset': finding.byte_offset,
                'byte_length': finding.byte_length,
                'line_number': finding.line_number,
                'context': finding.context
            },
            'evidence': {
                'raw_data': finding.raw_data,
                'pattern_matched': finding.pattern_matched,
                'evidence_data': finding.evidence_data if hasattr(finding, 'evidence_data') else {}
            },
            'analysis': {
                'method': finding.analysis_method,
                'created_at': finding.created_at.isoformat() if finding.created_at else None,
                'verified_at': finding.verified_at.isoformat() if hasattr(finding, 'verified_at') and finding.verified_at else None,
                'verified_by': finding.verified_by if hasattr(finding, 'verified_by') else None
            },
            'related_findings': [
                {
                    'id': rf.public_id.hex if hasattr(rf, 'public_id') else str(rf.id),
                    'title': rf.title,
                    'confidence_level': rf.confidence_level,
                    'status': rf.status.value if hasattr(rf.status, 'value') else str(rf.status)
                }
                for rf in related_findings
            ],
            'verification_history': verification_history
        }

        return jsonify({
            'success': True,
            'finding': detailed_finding
        })

    except Exception as e:
        logger.error(f"Error getting finding detail for {finding_id}: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@findings_api_bp.route('/findings/<finding_id>/verify', methods=['POST'])
@AuthService.login_required
@rate_limit(limit="100 per hour")
def verify_finding(finding_id):
    """Verify or update verification status of a finding"""
    try:
        user_id = session['user_id']
        user = User.query.get(user_id)

        # Check if user has verification permissions
        if not (user and hasattr(user, 'can_verify_findings') and user.can_verify_findings()):
            return jsonify({'success': False, 'error': 'Verification permissions required'}), 403

        # Get finding and verify access
        finding = db.session.query(Finding).join(AnalysisFile).filter(
            and_(
                Finding.public_id == finding_id,
                AnalysisFile.created_by == user_id
            )
        ).first()

        if not finding:
            return jsonify({'success': False, 'error': 'Finding not found or access denied'}), 404

        data = request.get_json() or {}
        verification_status = data.get('status', 'verified')
        verification_notes = data.get('notes', '')

        # Update finding verification
        if verification_status == 'verified':
            finding.status = FindingStatus.VERIFIED if hasattr(FindingStatus, 'VERIFIED') else 'verified'
        elif verification_status == 'false_positive':
            finding.status = FindingStatus.FALSE_POSITIVE if hasattr(FindingStatus, 'FALSE_POSITIVE') else 'false_positive'
        elif verification_status == 'needs_review':
            finding.status = FindingStatus.NEEDS_REVIEW if hasattr(FindingStatus, 'NEEDS_REVIEW') else 'needs_review'

        # Add verification metadata
        if hasattr(finding, 'verified_by'):
            finding.verified_by = user_id
        if hasattr(finding, 'verified_at'):
            finding.verified_at = datetime.utcnow()
        if hasattr(finding, 'verification_notes'):
            finding.verification_notes = verification_notes

        db.session.commit()

        # Log the verification
        AuthService.log_action('finding_verified', 
                             f'Verified finding: {finding.title} as {verification_status}',
                             finding_id=finding.id)

        return jsonify({
            'success': True,
            'message': f'Finding marked as {verification_status}',
            'new_status': verification_status
        })

    except Exception as e:
        logger.error(f"Error verifying finding {finding_id}: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@findings_api_bp.route('/findings/<finding_id>/collect', methods=['POST'])
@AuthService.login_required
@rate_limit(limit="50 per hour")
def collect_finding(finding_id):
    """Add finding to user's collection or bookmark it"""
    try:
        user_id = session['user_id']

        # Get finding and verify access
        finding = db.session.query(Finding).join(AnalysisFile).filter(
            and_(
                Finding.public_id == finding_id,
                AnalysisFile.created_by == user_id
            )
        ).first()

        if not finding:
            return jsonify({'success': False, 'error': 'Finding not found or access denied'}), 404

        # Add to bookmarks (assuming you have a bookmarked field)
        if hasattr(finding, 'is_bookmarked'):
            finding.is_bookmarked = True
        if hasattr(finding, 'bookmarked_by'):
            finding.bookmarked_by = user_id
        if hasattr(finding, 'bookmarked_at'):
            finding.bookmarked_at = datetime.utcnow()

        # Increase priority if it's a significant finding
        if finding.confidence_level >= 8:
            finding.priority = min(10, finding.priority + 1)

        db.session.commit()

        # Log the collection
        AuthService.log_action('finding_collected', 
                             f'Collected finding: {finding.title}',
                             finding_id=finding.id)

        return jsonify({
            'success': True,
            'message': 'Finding added to collection',
            'is_collected': True
        })

    except Exception as e:
        logger.error(f"Error collecting finding {finding_id}: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@findings_api_bp.route('/findings/<finding_id>/export', methods=['GET'])
@AuthService.login_required
def export_finding(finding_id):
    """Export detailed finding information"""
    try:
        user_id = session['user_id']

        # Get finding and verify access
        finding = db.session.query(Finding).join(AnalysisFile).filter(
            and_(
                Finding.public_id == finding_id,
                AnalysisFile.created_by == user_id
            )
        ).first()

        if not finding:
            return jsonify({'success': False, 'error': 'Finding not found or access denied'}), 404

        # Build comprehensive export data
        export_data = {
            'finding_info': {
                'id': finding.public_id.hex if hasattr(finding, 'public_id') else str(finding.id),
                'title': finding.title,
                'description': finding.description,
                'category': finding.category,
                'finding_type': finding.finding_type,
                'confidence_level': finding.confidence_level,
                'status': finding.status.value if hasattr(finding.status, 'value') else str(finding.status),
                'priority': finding.priority,
                'severity': finding.severity
            },
            'file_context': {
                'filename': finding.file.filename,
                'sha256': finding.file.sha256_hash,
                'file_type': finding.file.file_type,
                'file_size': finding.file.file_size,
                'analysis_date': finding.file.analyzed_at.isoformat() if finding.file.analyzed_at else None
            },
            'location_data': {
                'byte_offset': finding.byte_offset,
                'byte_length': finding.byte_length,
                'line_number': finding.line_number,
                'context': finding.context
            },
            'evidence': {
                'raw_data': finding.raw_data,
                'pattern_matched': finding.pattern_matched,
                'evidence_data': finding.evidence_data if hasattr(finding, 'evidence_data') else {},
                'analysis_method': finding.analysis_method
            },
            'verification': {
                'verified_at': finding.verified_at.isoformat() if hasattr(finding, 'verified_at') and finding.verified_at else None,
                'verified_by': finding.verified_by if hasattr(finding, 'verified_by') else None,
                'verification_notes': finding.verification_notes if hasattr(finding, 'verification_notes') else None
            },
            'export_metadata': {
                'exported_at': datetime.utcnow().isoformat(),
                'exported_by': user_id,
                'export_version': '1.0'
            }
        }

        return jsonify({
            'success': True,
            'export_data': export_data,
            'filename': f"finding_{finding.id}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.json"
        })

    except Exception as e:
        logger.error(f"Error exporting finding {finding_id}: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@findings_api_bp.route('/findings/bulk-action', methods=['POST'])
@AuthService.login_required
@rate_limit(limit="10 per minute")
def bulk_findings_action():
    """Perform bulk actions on multiple findings"""
    try:
        user_id = session['user_id']
        data = request.get_json()

        finding_ids = data.get('finding_ids', [])
        action = data.get('action')

        if not finding_ids or not action:
            return jsonify({'success': False, 'error': 'finding_ids and action are required'}), 400

        if len(finding_ids) > 50:  # Limit bulk operations
            return jsonify({'success': False, 'error': 'Too many findings (max 50)'}), 400

        # Get findings and verify access
        findings = db.session.query(Finding).join(AnalysisFile).filter(
            and_(
                Finding.public_id.in_(finding_ids),
                AnalysisFile.created_by == user_id
            )
        ).all()

        if len(findings) != len(finding_ids):
            return jsonify({'success': False, 'error': 'Some findings not found or access denied'}), 404

        success_count = 0
        error_count = 0

        if action == 'verify':
            for finding in findings:
                try:
                    finding.status = FindingStatus.VERIFIED if hasattr(FindingStatus, 'VERIFIED') else 'verified'
                    if hasattr(finding, 'verified_by'):
                        finding.verified_by = user_id
                    if hasattr(finding, 'verified_at'):
                        finding.verified_at = datetime.utcnow()
                    success_count += 1
                except Exception:
                    error_count += 1

        elif action == 'mark_false_positive':
            for finding in findings:
                try:
                    finding.status = FindingStatus.FALSE_POSITIVE if hasattr(FindingStatus, 'FALSE_POSITIVE') else 'false_positive'
                    if hasattr(finding, 'verified_by'):
                        finding.verified_by = user_id
                    if hasattr(finding, 'verified_at'):
                        finding.verified_at = datetime.utcnow()
                    success_count += 1
                except Exception:
                    error_count += 1

        elif action == 'collect':
            for finding in findings:
                try:
                    if hasattr(finding, 'is_bookmarked'):
                        finding.is_bookmarked = True
                    if hasattr(finding, 'bookmarked_by'):
                        finding.bookmarked_by = user_id
                    success_count += 1
                except Exception:
                    error_count += 1

        elif action == 'delete':
            # Only allow deletion of false positives or if user is admin
            user = User.query.get(user_id)
            is_admin = user and hasattr(user, 'is_admin') and user.is_admin

            for finding in findings:
                try:
                    if finding.status == 'false_positive' or is_admin:
                        db.session.delete(finding)
                        success_count += 1
                    else:
                        error_count += 1
                except Exception:
                    error_count += 1

        else:
            return jsonify({'success': False, 'error': f'Unknown action: {action}'}), 400

        db.session.commit()

        # Log the bulk action
        AuthService.log_action('bulk_findings_action', 
                             f'Bulk action {action} on {success_count} findings')

        return jsonify({
            'success': True,
            'message': f'Bulk action completed: {success_count} successful, {error_count} failed',
            'results': {
                'success_count': success_count,
                'error_count': error_count,
                'total_processed': len(findings)
            }
        })

    except Exception as e:
        logger.error(f"Error performing bulk action: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@findings_api_bp.route('/findings/stats')
@AuthService.login_required
def get_findings_statistics():
    """Get comprehensive findings statistics for the user"""
    try:
        user_id = session['user_id']
        stats = get_findings_stats(user_id)

        # Add time-based statistics
        time_stats = get_findings_time_stats(user_id)
        stats.update(time_stats)

        return jsonify({
            'success': True,
            'stats': stats,
            'timestamp': datetime.utcnow().isoformat()
        })

    except Exception as e:
        logger.error(f"Error getting findings statistics: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

# Helper functions

def get_findings_stats(user_id: int) -> dict:
    """Get basic findings statistics for a user"""
    try:
        # Get total counts
        total_findings = db.session.query(func.count(Finding.id)).join(AnalysisFile).filter(
            AnalysisFile.created_by == user_id
        ).scalar() or 0

        # Get counts by category
        crypto_findings = db.session.query(func.count(Finding.id)).join(AnalysisFile).filter(
            and_(AnalysisFile.created_by == user_id, Finding.category == 'crypto')
        ).scalar() or 0

        technical_findings = db.session.query(func.count(Finding.id)).join(AnalysisFile).filter(
            and_(AnalysisFile.created_by == user_id, Finding.category == 'technical')
        ).scalar() or 0

        string_findings = db.session.query(func.count(Finding.id)).join(AnalysisFile).filter(
            and_(AnalysisFile.created_by == user_id, Finding.category == 'strings')
        ).scalar() or 0

        # Get counts by confidence level
        high_confidence = db.session.query(func.count(Finding.id)).join(AnalysisFile).filter(
            and_(AnalysisFile.created_by == user_id, Finding.confidence_level >= 8)
        ).scalar() or 0

        medium_confidence = db.session.query(func.count(Finding.id)).join(AnalysisFile).filter(
            and_(
                AnalysisFile.created_by == user_id, 
                Finding.confidence_level >= 6, 
                Finding.confidence_level < 8
            )
        ).scalar() or 0

        # Get counts by status
        verified_findings = db.session.query(func.count(Finding.id)).join(AnalysisFile).filter(
            and_(AnalysisFile.created_by == user_id, Finding.status == 'verified')
        ).scalar() or 0

        unverified_findings = db.session.query(func.count(Finding.id)).join(AnalysisFile).filter(
            and_(AnalysisFile.created_by == user_id, Finding.status == 'unverified')
        ).scalar() or 0

        return {
            'total_findings': total_findings,
            'by_category': {
                'crypto': crypto_findings,
                'technical': technical_findings,
                'strings': string_findings,
                'other': total_findings - crypto_findings - technical_findings - string_findings
            },
            'by_confidence': {
                'high': high_confidence,
                'medium': medium_confidence,
                'low': total_findings - high_confidence - medium_confidence
            },
            'by_status': {
                'verified': verified_findings,
                'unverified': unverified_findings,
                'other': total_findings - verified_findings - unverified_findings
            }
        }

    except Exception as e:
        logger.error(f"Error getting findings stats for user {user_id}: {e}")
        return {
            'total_findings': 0,
            'by_category': {'crypto': 0, 'technical': 0, 'strings': 0, 'other': 0},
            'by_confidence': {'high': 0, 'medium': 0, 'low': 0},
            'by_status': {'verified': 0, 'unverified': 0, 'other': 0}
        }

def get_findings_time_stats(user_id: int) -> dict:
    """Get time-based findings statistics"""
    try:
        # Get findings from last 24 hours
        yesterday = datetime.utcnow() - timedelta(days=1)
        findings_today = db.session.query(func.count(Finding.id)).join(AnalysisFile).filter(
            and_(
                AnalysisFile.created_by == user_id,
                Finding.created_at >= yesterday
            )
        ).scalar() or 0

        # Get findings from last 7 days
        week_ago = datetime.utcnow() - timedelta(days=7)
        findings_week = db.session.query(func.count(Finding.id)).join(AnalysisFile).filter(
            and_(
                AnalysisFile.created_by == user_id,
                Finding.created_at >= week_ago
            )
        ).scalar() or 0

        # Get findings from last 30 days
        month_ago = datetime.utcnow() - timedelta(days=30)
        findings_month = db.session.query(func.count(Finding.id)).join(AnalysisFile).filter(
            and_(
                AnalysisFile.created_by == user_id,
                Finding.created_at >= month_ago
            )
        ).scalar() or 0

        return {
            'time_based': {
                'last_24_hours': findings_today,
                'last_7_days': findings_week,
                'last_30_days': findings_month
            }
        }

    except Exception as e:
        logger.error(f"Error getting time-based findings stats: {e}")
        return {
            'time_based': {
                'last_24_hours': 0,
                'last_7_days': 0,
                'last_30_days': 0
            }
        }
