# crypto_hunter_web/routes/api/crypto.py - COMPLETE CRYPTO ANALYSIS API

import json
from datetime import datetime, timedelta
from typing import Dict

from crypto_hunter_web.services.ai_service import AIService
from crypto_hunter_web.services.crypto_analyzer import CryptoAnalyzer
from flask import Blueprint, request, jsonify, current_app
from flask_login import login_required, current_user

from crypto_hunter_web.models import db, AnalysisFile, FileContent, Finding, AuditLog
from crypto_hunter_web.services.background_service import BackgroundService
from crypto_hunter_web.services.security_service import SecurityService
from crypto_hunter_web.utils.crypto_patterns import CryptoPatterns
from crypto_hunter_web.utils.decorators import rate_limit, api_endpoint
from crypto_hunter_web.utils.validators import validate_sha256

crypto_api_bp = Blueprint('modern_crypto_api', __name__)


@crypto_api_bp.route('/analyze/<sha>', methods=['POST'])
@login_required
@rate_limit("10 per minute")
@api_endpoint(endpoint="analyze_crypto_patterns_endpoint")
def analyze_crypto_patterns(sha):
    """Comprehensive cryptocurrency and cryptographic pattern analysis"""
    if not validate_sha256(sha):
        return jsonify({'error': 'Invalid SHA256 hash format'}), 400

    file_obj = AnalysisFile.find_by_sha(sha)
    if not file_obj:
        return jsonify({'error': 'File not found'}), 404

    # Check permissions
    if not SecurityService.check_permission(current_user, 'analysis', 'write'):
        return jsonify({'error': 'Insufficient permissions'}), 403

    try:
        # Get analysis options
        data = request.get_json() or {}
        analysis_options = {
            'deep_scan': data.get('deep_scan', False),
            'include_blockchain': data.get('include_blockchain', True),
            'include_wallets': data.get('include_wallets', True),
            'include_keys': data.get('include_keys', True),
            'include_certificates': data.get('include_certificates', True),
            'ai_enhancement': data.get('ai_enhancement', False),
            'confidence_threshold': data.get('confidence_threshold', 0.7)
        }

        # Initialize crypto analyzer
        analyzer = CryptoAnalyzer()

        # Perform analysis
        if analysis_options['deep_scan']:
            # Queue for background processing for deep scans
            task_id = BackgroundService.queue_crypto_analysis(
                file_id=file_obj.id,
                analysis_options=analysis_options,
                user_id=current_user.id
            )

            return jsonify({
                'success': True,
                'message': 'Deep crypto analysis queued for background processing',
                'task_id': task_id,
                'estimated_completion': (datetime.utcnow() + timedelta(minutes=5)).isoformat()
            })
        else:
            # Perform immediate analysis
            results = analyzer.analyze_file(file_obj, analysis_options)

            # Save results to database
            content_entry = FileContent(
                file_id=file_obj.id,
                content_type='crypto_analysis',
                content_format='json',
                content_json=results,
                content_size=len(json.dumps(results)),
                extracted_by=current_user.id,
                extraction_method='api_crypto_analysis'
            )

            db.session.add(content_entry)

            # Create findings for significant discoveries
            findings_created = _create_crypto_findings(file_obj, results, current_user.id)

            # Update file crypto flag
            if results.get('has_crypto_content', False):
                file_obj.contains_crypto = True
                file_obj.confidence_score = results.get('confidence_score', 0.5)

            db.session.commit()

            # Log analysis
            AuditLog.log_action(
                user_id=current_user.id,
                action='crypto_analysis_completed',
                description=f'Crypto analysis completed for {file_obj.filename}',
                resource_type='file',
                resource_id=file_obj.sha256_hash,
                metadata={
                    'analysis_options': analysis_options,
                    'findings_created': findings_created,
                    'crypto_content_detected': results.get('has_crypto_content', False)
                }
            )

            return jsonify({
                'success': True,
                'results': results,
                'findings_created': findings_created,
                'analysis_completed_at': datetime.utcnow().isoformat()
            })

    except Exception as e:
        current_app.logger.error(f"Crypto analysis failed for {sha}: {e}", exc_info=True)
        return jsonify({'error': 'Analysis failed', 'details': str(e)}), 500


@crypto_api_bp.route('/patterns/search', methods=['POST'])
@login_required
@rate_limit("20 per minute")
@api_endpoint(endpoint="search_crypto_patterns_endpoint")
def search_crypto_patterns():
    """Search for specific cryptocurrency patterns across all files"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'Request body required'}), 400

        # Validate input
        pattern_types = data.get('pattern_types', [])
        search_text = data.get('search_text', '')
        file_types = data.get('file_types', [])
        confidence_min = data.get('confidence_min', 0.5)
        limit = min(data.get('limit', 100), 1000)  # Max 1000 results

        if not pattern_types and not search_text:
            return jsonify({'error': 'pattern_types or search_text required'}), 400

        # Build search query
        query = db.session.query(Finding).join(AnalysisFile)

        # Filter by pattern types
        if pattern_types:
            query = query.filter(Finding.finding_type.in_(pattern_types))

        # Filter by file types
        if file_types:
            query = query.filter(AnalysisFile.file_type.in_(file_types))

        # Filter by confidence
        query = query.filter(Finding.confidence_level >= confidence_min * 10)

        # Text search in findings
        if search_text:
            search_pattern = f"%{search_text}%"
            query = query.filter(
                db.or_(
                    Finding.title.ilike(search_pattern),
                    Finding.description.ilike(search_pattern),
                    Finding.raw_data.ilike(search_pattern)
                )
            )

        # Execute query
        findings = query.order_by(Finding.confidence_level.desc(), Finding.created_at.desc()) \
            .limit(limit).all()

        # Format results
        results = []
        for finding in findings:
            result = {
                'finding_id': finding.public_id.hex,
                'file_id': finding.file.public_id.hex,
                'filename': finding.file.filename,
                'pattern_type': finding.finding_type,
                'title': finding.title,
                'description': finding.description,
                'confidence': finding.confidence_level / 10.0,
                'evidence': finding.evidence_data,
                'created_at': finding.created_at.isoformat(),
                'file_size': finding.file.file_size,
                'file_type': finding.file.file_type
            }
            results.append(result)

        # Generate search statistics
        stats = {
            'total_results': len(results),
            'pattern_distribution': {},
            'file_type_distribution': {},
            'confidence_distribution': {'high': 0, 'medium': 0, 'low': 0}
        }

        for finding in findings:
            # Pattern distribution
            pattern = finding.finding_type
            stats['pattern_distribution'][pattern] = stats['pattern_distribution'].get(pattern, 0) + 1

            # File type distribution
            file_type = finding.file.file_type
            stats['file_type_distribution'][file_type] = stats['file_type_distribution'].get(file_type, 0) + 1

            # Confidence distribution
            confidence = finding.confidence_level / 10.0
            if confidence >= 0.8:
                stats['confidence_distribution']['high'] += 1
            elif confidence >= 0.5:
                stats['confidence_distribution']['medium'] += 1
            else:
                stats['confidence_distribution']['low'] += 1

        return jsonify({
            'success': True,
            'results': results,
            'statistics': stats,
            'search_parameters': {
                'pattern_types': pattern_types,
                'search_text': search_text,
                'file_types': file_types,
                'confidence_min': confidence_min,
                'limit': limit
            }
        })

    except Exception as e:
        current_app.logger.error(f"Crypto pattern search failed: {e}", exc_info=True)
        return jsonify({'error': 'Search failed', 'details': str(e)}), 500


@crypto_api_bp.route('/wallets/identify', methods=['POST'])
@login_required
@rate_limit("15 per minute")
@api_endpoint(endpoint="identify_wallet_addresses_endpoint")
def identify_wallet_addresses():
    """Identify and analyze cryptocurrency wallet addresses"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'Request body required'}), 400

        addresses = data.get('addresses', [])
        if not addresses:
            return jsonify({'error': 'addresses list required'}), 400

        if len(addresses) > 100:
            return jsonify({'error': 'Maximum 100 addresses per request'}), 400

        # Initialize crypto patterns analyzer
        crypto_patterns = CryptoPatterns()

        results = []
        for address in addresses:
            try:
                analysis = crypto_patterns.analyze_wallet_address(str(address))
                results.append({
                    'address': address,
                    'valid': analysis.get('valid', False),
                    'cryptocurrency': analysis.get('cryptocurrency', 'unknown'),
                    'address_type': analysis.get('address_type', 'unknown'),
                    'network': analysis.get('network', 'unknown'),
                    'confidence': analysis.get('confidence', 0.0),
                    'metadata': analysis.get('metadata', {})
                })
            except Exception as e:
                results.append({
                    'address': address,
                    'valid': False,
                    'error': str(e)
                })

        # Log wallet identification
        AuditLog.log_action(
            user_id=current_user.id,
            action='wallet_identification',
            description=f'Identified {len(addresses)} wallet addresses',
            metadata={
                'address_count': len(addresses),
                'valid_addresses': sum(1 for r in results if r.get('valid', False))
            }
        )

        return jsonify({
            'success': True,
            'results': results,
            'summary': {
                'total_analyzed': len(addresses),
                'valid_addresses': sum(1 for r in results if r.get('valid', False)),
                'cryptocurrencies_found': list(set(r.get('cryptocurrency', 'unknown')
                                                   for r in results if r.get('valid', False)))
            }
        })

    except Exception as e:
        current_app.logger.error(f"Wallet identification failed: {e}", exc_info=True)
        return jsonify({'error': 'Identification failed', 'details': str(e)}), 500


@crypto_api_bp.route('/keys/analyze', methods=['POST'])
@login_required
@rate_limit("10 per minute")
@api_endpoint
def analyze_cryptographic_keys():
    """Analyze cryptographic keys and certificates"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'Request body required'}), 400

        key_data = data.get('key_data', '')
        analysis_type = data.get('analysis_type', 'auto')  # auto, pem, ssh, pgp

        if not key_data:
            return jsonify({'error': 'key_data required'}), 400

        if len(key_data) > 100000:  # 100KB limit
            return jsonify({'error': 'Key data too large (max 100KB)'}), 400

        # Initialize crypto analyzer
        analyzer = CryptoAnalyzer()

        # Analyze the key
        analysis_result = analyzer.analyze_cryptographic_key(key_data, analysis_type)

        # Log key analysis
        AuditLog.log_action(
            user_id=current_user.id,
            action='key_analysis',
            description=f'Analyzed cryptographic key ({analysis_type})',
            metadata={
                'analysis_type': analysis_type,
                'key_type': analysis_result.get('key_type', 'unknown'),
                'valid': analysis_result.get('valid', False)
            }
        )

        return jsonify({
            'success': True,
            'analysis': analysis_result,
            'analyzed_at': datetime.utcnow().isoformat()
        })

    except Exception as e:
        current_app.logger.error(f"Key analysis failed: {e}", exc_info=True)
        return jsonify({'error': 'Analysis failed', 'details': str(e)}), 500


@crypto_api_bp.route('/blockchain/query', methods=['POST'])
@login_required
@rate_limit("5 per minute")
@api_endpoint
def query_blockchain_data():
    """Query blockchain data for addresses found in files"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'Request body required'}), 400

        addresses = data.get('addresses', [])
        blockchain = data.get('blockchain', 'bitcoin')  # bitcoin, ethereum, etc.
        query_type = data.get('query_type', 'balance')  # balance, transactions, info

        if not addresses:
            return jsonify({'error': 'addresses required'}), 400

        if len(addresses) > 10:
            return jsonify({'error': 'Maximum 10 addresses per request'}), 400

        # Note: This would integrate with blockchain APIs
        # For now, return mock data structure
        results = []
        for address in addresses:
            result = {
                'address': address,
                'blockchain': blockchain,
                'query_type': query_type,
                'data': {
                    'balance': '0.00000000',
                    'transaction_count': 0,
                    'first_seen': None,
                    'last_seen': None,
                    'status': 'inactive'
                },
                'queried_at': datetime.utcnow().isoformat(),
                'note': 'Blockchain API integration not implemented - returning mock data'
            }
            results.append(result)

        # Log blockchain query
        AuditLog.log_action(
            user_id=current_user.id,
            action='blockchain_query',
            description=f'Queried {blockchain} blockchain for {len(addresses)} addresses',
            metadata={
                'blockchain': blockchain,
                'query_type': query_type,
                'address_count': len(addresses)
            }
        )

        return jsonify({
            'success': True,
            'results': results,
            'blockchain': blockchain,
            'query_type': query_type
        })

    except Exception as e:
        current_app.logger.error(f"Blockchain query failed: {e}", exc_info=True)
        return jsonify({'error': 'Query failed', 'details': str(e)}), 500


@crypto_api_bp.route('/statistics', methods=['GET'])
@login_required
@rate_limit("30 per minute")
@api_endpoint
def get_crypto_statistics():
    """Get comprehensive cryptocurrency analysis statistics"""
    try:
        # Time range filter
        days = request.args.get('days', 30, type=int)
        if days > 365:
            days = 365  # Limit to 1 year

        since_date = datetime.utcnow() - timedelta(days=days)

        # Overall crypto statistics
        crypto_stats = {
            'total_crypto_files': AnalysisFile.query.filter_by(contains_crypto=True).count(),
            'crypto_findings': Finding.query.filter(Finding.finding_type.like('%crypto%')).count(),
            'wallet_addresses_found': Finding.query.filter_by(finding_type='wallet_address').count(),
            'private_keys_found': Finding.query.filter_by(finding_type='private_key').count(),
            'certificates_found': Finding.query.filter_by(finding_type='certificate').count(),
        }

        # Recent crypto activity
        recent_crypto_files = AnalysisFile.query.filter(
            AnalysisFile.contains_crypto == True,
            AnalysisFile.created_at >= since_date
        ).count()

        recent_crypto_findings = Finding.query.filter(
            Finding.finding_type.like('%crypto%'),
            Finding.created_at >= since_date
        ).count()

        # Crypto pattern distribution
        crypto_patterns = db.session.query(
            Finding.finding_type,
            db.func.count(Finding.id).label('count'),
            db.func.avg(Finding.confidence_level).label('avg_confidence')
        ).filter(Finding.finding_type.like('%crypto%')) \
            .group_by(Finding.finding_type) \
            .order_by(db.func.count(Finding.id).desc()).all()

        # File type crypto distribution
        file_type_crypto = db.session.query(
            AnalysisFile.file_type,
            db.func.count(AnalysisFile.id).label('total_files'),
            db.func.sum(db.case([(AnalysisFile.contains_crypto == True, 1)], else_=0)).label('crypto_files')
        ).group_by(AnalysisFile.file_type) \
            .having(db.func.sum(db.case([(AnalysisFile.contains_crypto == True, 1)], else_=0)) > 0) \
            .order_by(db.func.sum(db.case([(AnalysisFile.contains_crypto == True, 1)], else_=0)).desc()).all()

        # Top crypto indicators
        top_indicators = db.session.query(
            Finding.title,
            Finding.finding_type,
            db.func.count(Finding.id).label('occurrence_count')
        ).filter(Finding.finding_type.like('%crypto%')) \
            .group_by(Finding.title, Finding.finding_type) \
            .order_by(db.func.count(Finding.id).desc()) \
            .limit(20).all()

        return jsonify({
            'success': True,
            'statistics': {
                'overview': crypto_stats,
                'recent_activity': {
                    'crypto_files_added': recent_crypto_files,
                    'crypto_findings_created': recent_crypto_findings,
                    'time_period_days': days
                },
                'pattern_distribution': [
                    {
                        'pattern_type': p[0],
                        'count': p[1],
                        'average_confidence': float(p[2]) / 10.0 if p[2] else 0
                    } for p in crypto_patterns
                ],
                'file_type_distribution': [
                    {
                        'file_type': ft[0],
                        'total_files': ft[1],
                        'crypto_files': ft[2],
                        'crypto_percentage': (ft[2] / ft[1]) * 100 if ft[1] > 0 else 0
                    } for ft in file_type_crypto
                ],
                'top_indicators': [
                    {
                        'title': ti[0],
                        'type': ti[1],
                        'count': ti[2]
                    } for ti in top_indicators
                ]
            },
            'generated_at': datetime.utcnow().isoformat()
        })

    except Exception as e:
        current_app.logger.error(f"Crypto statistics failed: {e}", exc_info=True)
        return jsonify({'error': 'Statistics generation failed', 'details': str(e)}), 500


@crypto_api_bp.route('/export', methods=['POST'])
@login_required
@rate_limit("5 per hour")
@api_endpoint
def export_crypto_findings():
    """Export cryptocurrency findings in various formats"""
    try:
        data = request.get_json() or {}

        # Export parameters
        export_format = data.get('format', 'json')  # json, csv, xml
        finding_types = data.get('finding_types', [])
        confidence_min = data.get('confidence_min', 0.0)
        include_metadata = data.get('include_metadata', True)

        # Build query
        query = Finding.query.join(AnalysisFile)

        if finding_types:
            query = query.filter(Finding.finding_type.in_(finding_types))

        if confidence_min > 0:
            query = query.filter(Finding.confidence_level >= confidence_min * 10)

        findings = query.order_by(Finding.created_at.desc()).all()

        if export_format == 'json':
            export_data = {
                'export_info': {
                    'generated_at': datetime.utcnow().isoformat(),
                    'total_findings': len(findings),
                    'exported_by': current_user.username,
                    'filters': {
                        'finding_types': finding_types,
                        'confidence_min': confidence_min
                    }
                },
                'findings': []
            }

            for finding in findings:
                finding_data = {
                    'id': finding.public_id.hex,
                    'file_id': finding.file.public_id.hex,
                    'filename': finding.file.filename,
                    'finding_type': finding.finding_type,
                    'title': finding.title,
                    'description': finding.description,
                    'confidence': finding.confidence_level / 10.0,
                    'priority': finding.priority,
                    'status': finding.status.value,
                    'created_at': finding.created_at.isoformat(),
                    'evidence': finding.evidence_data if include_metadata else None
                }
                export_data['findings'].append(finding_data)

            # Log export
            AuditLog.log_action(
                user_id=current_user.id,
                action='crypto_export',
                description=f'Exported {len(findings)} crypto findings as {export_format}',
                metadata={
                    'format': export_format,
                    'finding_count': len(findings),
                    'filters': data
                }
            )

            return jsonify({
                'success': True,
                'data': export_data,
                'format': export_format
            })

        else:
            return jsonify({'error': f'Export format {export_format} not supported'}), 400

    except Exception as e:
        current_app.logger.error(f"Crypto export failed: {e}", exc_info=True)
        return jsonify({'error': 'Export failed', 'details': str(e)}), 500


# Helper functions

def _create_crypto_findings(file_obj: AnalysisFile, analysis_results: Dict, user_id: int) -> int:
    """Create findings from crypto analysis results"""
    findings_created = 0

    try:
        for pattern_result in analysis_results.get('patterns_found', []):
            if pattern_result.get('match_count', 0) > 0:
                finding = Finding(
                    file_id=file_obj.id,
                    finding_type='crypto_pattern',
                    category='cryptography',
                    title=f"{pattern_result['pattern_name']} Found",
                    description=f"Found {pattern_result['match_count']} instances of {pattern_result['pattern_name']}",
                    confidence_level=min(pattern_result.get('confidence', 0.8) * 10, 10),
                    priority=7 if pattern_result.get('confidence', 0) > 0.8 else 5,
                    evidence_data=pattern_result,
                    analysis_method='crypto_api_analysis',
                    created_by=user_id
                )

                db.session.add(finding)
                findings_created += 1

        # Create findings for wallet addresses
        for wallet in analysis_results.get('crypto_categories', {}).get('wallets', []):
            finding = Finding(
                file_id=file_obj.id,
                finding_type='wallet_address',
                category='cryptocurrency',
                title=f"Cryptocurrency Wallet Address",
                description=f"Found wallet address: {wallet[:20]}...",
                confidence_level=9,
                priority=8,
                evidence_data={'wallet_address': wallet},
                analysis_method='crypto_api_analysis',
                created_by=user_id
            )

            db.session.add(finding)
            findings_created += 1

        return findings_created

    except Exception as e:
        current_app.logger.error(f"Failed to create crypto findings: {e}")
        return 0


# Error handlers
@crypto_api_bp.errorhandler(429)
def rate_limit_exceeded(error):
    """Handle rate limit exceeded errors"""
    response = jsonify({
        'error': 'Rate limit exceeded',
        'message': 'Maximum 5 requests per hour',
        'retry_after': getattr(error, 'retry_after', 60)
    }), 429
    response[0].headers['Retry-After'] = str(getattr(error, 'retry_after', 60))
    return response
