# crypto_hunter_web/cli/analysis_commands.py
# Analysis management commands

import click
import json
from flask.cli import with_appcontext
from crypto_hunter_web.models import AnalysisFile, FileContent, Finding
from crypto_hunter_web.services.background_service import BackgroundService


@click.group()
def analysis_cli():
    """Analysis management commands"""
    pass


@analysis_cli.command()
@click.argument('file_hash')
@click.option('--type', 'analysis_type', default='comprehensive',
              type=click.Choice(['comprehensive', 'steganography', 'crypto', 'ai']),
              help='Type of analysis to run')
@with_appcontext
def run(file_hash, analysis_type):
    """Run analysis on a file"""
    file_obj = AnalysisFile.query.filter_by(sha256_hash=file_hash).first()
    if not file_obj:
        click.echo(f"❌ File not found: {file_hash}")
        return

    click.echo(f"🔍 Starting {analysis_type} analysis for {file_obj.filename}...")

    try:
        if analysis_type == 'comprehensive':
            task_id = BackgroundService.queue_comprehensive_analysis(
                file_id=file_obj.id,
                analysis_types=['steganography', 'binary_analysis', 'crypto_patterns', 'strings'],
                user_id=1  # System user
            )
        elif analysis_type == 'steganography':
            task_id = BackgroundService.queue_steganography_analysis(
                file_id=file_obj.id,
                user_id=1
            )
        elif analysis_type == 'crypto':
            task_id = BackgroundService.queue_crypto_analysis(
                file_id=file_obj.id,
                analysis_options={'deep_scan': True},
                user_id=1
            )
        elif analysis_type == 'ai':
            task_id = BackgroundService.queue_ai_analysis(
                file_id=file_obj.id,
                user_id=1
            )
        else:
            click.echo(f"❌ Analysis type '{analysis_type}' not implemented")
            return

        click.echo(f"✅ Analysis queued with task ID: {task_id}")
        click.echo(f"💡 Check status with: crypto-hunter analysis status {task_id}")

    except Exception as e:
        click.echo(f"❌ Failed to queue analysis: {e}")


@analysis_cli.command()
@click.argument('task_id')
@with_appcontext
def status(task_id):
    """Check analysis status"""
    try:
        status_info = BackgroundService.get_task_status(task_id)

        if 'error' in status_info:
            click.echo(f"❌ Error: {status_info['error']}")
            return

        state = status_info.get('state', 'UNKNOWN')
        click.echo(f"📊 Task {task_id}: {state}")

        if state == 'PROGRESS':
            meta = status_info.get('meta', {})
            progress = meta.get('progress', 0)
            stage = meta.get('stage', 'Processing...')
            click.echo(f"⏳ Progress: {progress}% - {stage}")
        elif state == 'SUCCESS':
            result = status_info.get('result', {})
            click.echo(f"✅ Analysis complete!")
            if 'findings_count' in result:
                click.echo(f"🔍 Findings: {result['findings_count']}")
            if 'execution_time' in result:
                click.echo(f"⏱️  Time: {result['execution_time']:.2f}s")
        elif state == 'FAILURE':
            meta = status_info.get('meta', {})
            error = meta.get('error', 'Unknown error')
            click.echo(f"❌ Analysis failed: {error}")

    except Exception as e:
        click.echo(f"❌ Error checking status: {e}")


@analysis_cli.command()
@click.option('--limit', default=10, help='Number of recent analyses to show')
@with_appcontext
def list(limit):
    """List recent analyses"""
    files = AnalysisFile.query.order_by(AnalysisFile.created_at.desc()).limit(limit).all()

    if not files:
        click.echo("No analyses found")
        return

    click.echo("Recent analyses:")
    for file in files:
        status_icon = {
            'complete': '✅',
            'processing': '⏳',
            'failed': '❌',
            'pending': '📋'
        }.get(file.status, '❓')

        findings_count = Finding.query.filter_by(file_id=file.id).count()

        click.echo(f"  {status_icon} {file.filename[:50]} - {file.status}")
        click.echo(f"     Hash: {file.sha256_hash}")
        click.echo(f"     Findings: {findings_count}")
        if file.analyzed_at:
            click.echo(f"     Analyzed: {file.analyzed_at}")
        click.echo()


@analysis_cli.command()
@click.argument('file_hash')
@click.option('--format', 'output_format', default='text',
              type=click.Choice(['text', 'json']),
              help='Output format')
@with_appcontext
def results(file_hash, output_format):
    """Show analysis results for a file"""
    file_obj = AnalysisFile.query.filter_by(sha256_hash=file_hash).first()
    if not file_obj:
        click.echo(f"❌ File not found: {file_hash}")
        return

    # Get findings
    findings = Finding.query.filter_by(file_id=file_obj.id).all()

    # Get analysis content
    content_entries = FileContent.query.filter_by(file_id=file_obj.id).all()

    if output_format == 'json':
        results_data = {
            'file': {
                'filename': file_obj.filename,
                'hash': file_obj.sha256_hash,
                'status': file_obj.status,
                'analyzed_at': file_obj.analyzed_at.isoformat() if file_obj.analyzed_at else None
            },
            'findings': [
                {
                    'type': f.finding_type,
                    'confidence': f.confidence,
                    'description': f.description,
                    'created_at': f.created_at.isoformat()
                }
                for f in findings
            ],
            'content_entries': [
                {
                    'type': c.content_type,
                    'method': c.extraction_method,
                    'size': c.content_size
                }
                for c in content_entries
            ]
        }
        click.echo(json.dumps(results_data, indent=2))
    else:
        click.echo(f"📄 Analysis Results for {file_obj.filename}")
        click.echo(f"🆔 Hash: {file_obj.sha256_hash}")
        click.echo(f"📊 Status: {file_obj.status}")

        if findings:
            click.echo(f"\n🔍 Findings ({len(findings)}):")
            for finding in findings:
                confidence_bar = "█" * int(finding.confidence * 10)
                click.echo(f"  • {finding.finding_type}")
                click.echo(f"    Confidence: {confidence_bar} {finding.confidence:.2f}")
                click.echo(f"    {finding.description}")
                click.echo()
        else:
            click.echo("\n🔍 No findings")

        if content_entries:
            click.echo(f"📋 Content Entries ({len(content_entries)}):")
            for content in content_entries:
                click.echo(f"  • {content.content_type} ({content.extraction_method})")
                click.echo(f"    Size: {content.content_size} bytes")
            click.echo()