"""
Enhanced background cryptographic analysis service with improved error handling and monitoring
"""

import os
import time
import json
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
from celery import group, chain, chord
from celery.exceptions import Retry, WorkerLostError
from celery.signals import task_success, task_failure, task_retry
import redis
from sqlalchemy import func
from sqlalchemy.exc import SQLAlchemyError

from app.services.celery_config import celery_app
from app.models import db
from app.models.file import AnalysisFile, FileContent
from app.models.finding import Finding, Vector
from app.services.crypto_intelligence import CryptoIntelligence, EthereumAnalyzer, CipherAnalyzer, AdvancedCryptoAnalyzer

# Configure logging
logger = logging.getLogger(__name__)
redis_client = redis.Redis(host='localhost', port=6379, db=2, decode_responses=True)


class TaskRegistry:
    """Central task registry for monitoring and coordination"""

    @staticmethod
    def register_task(task_id: str, task_type: str, file_id: int, metadata: Dict = None):
        """Register a task for monitoring"""
        task_data = {
            'task_id': task_id,
            'task_type': task_type,
            'file_id': file_id,
            'created_at': datetime.utcnow().isoformat(),
            'status': 'pending',
            'metadata': metadata or {}
        }
        redis_client.setex(f"task:{task_id}", 3600, json.dumps(task_data))
        redis_client.sadd('active_tasks', task_id)

    @staticmethod
    def update_task_status(task_id: str, status: str, progress: int = None, message: str = None):
        """Update task status"""
        task_data_str = redis_client.get(f"task:{task_id}")
        if task_data_str:
            task_data = json.loads(task_data_str)
            task_data['status'] = status
            task_data['updated_at'] = datetime.utcnow().isoformat()
            if progress is not None:
                task_data['progress'] = progress
            if message:
                task_data['message'] = message
            redis_client.setex(f"task:{task_id}", 3600, json.dumps(task_data))

    @staticmethod
    def complete_task(task_id: str, result: Dict = None):
        """Mark task as completed"""
        TaskRegistry.update_task_status(task_id, 'completed', 100)
        redis_client.srem('active_tasks', task_id)
        if result:
            redis_client.setex(f"task_result:{task_id}", 3600, json.dumps(result))


class BackgroundCryptoManager:
    """Enhanced background crypto analysis manager"""

    TASK_PRIORITIES = {
        'ethereum_validation': 10,
        'cipher_analysis': 8,
        'hash_cracking': 6,
        'pattern_analysis': 4,
        'deep_crypto_scan': 2
    }

    @staticmethod
    def start_continuous_analysis(priority_threshold: int = 5, batch_size: int = 50):
        """Start continuous background analysis with improved batching"""
        try:
            # Get unprocessed files with priority-based ordering
            unprocessed_files = db.session.query(AnalysisFile).filter(
                ~AnalysisFile.id.in_(
                    db.session.query(FileContent.file_id).filter(
                        FileContent.content_type == 'crypto_background_complete'
                    )
                ),
                AnalysisFile.priority >= priority_threshold
            ).order_by(AnalysisFile.priority.desc()).limit(batch_size).all()

            if not unprocessed_files:
                logger.info("No unprocessed files found")
                return 0

            # Create task group for parallel processing
            analysis_tasks = []
            for file in unprocessed_files:
                task = analyze_file_comprehensive.delay(file.id)
                TaskRegistry.register_task(
                    task.id,
                    'comprehensive_analysis',
                    file.id,
                    {'filename': file.filename, 'priority': file.priority}
                )
                analysis_tasks.append(task)

            # Start continuous monitoring if not already running
            if not redis_client.get('monitor_running'):
                continuous_crypto_monitor.delay()

            logger.info(f"Started analysis for {len(unprocessed_files)} files")
            return len(unprocessed_files)

        except Exception as e:
            logger.error(f"Error starting continuous analysis: {e}")
            return 0

    @staticmethod
    def queue_priority_analysis(file_id: int, analysis_types: List[str] = None, high_priority: bool = True):
        """Queue high-priority analysis with better orchestration"""
        if analysis_types is None:
            analysis_types = ['ethereum_validation', 'cipher_analysis', 'pattern_analysis']

        try:
            file = AnalysisFile.query.get(file_id)
            if not file:
                return None

            # Create analysis workflow
            workflow_tasks = []

            for analysis_type in analysis_types:
                if analysis_type == 'ethereum_validation':
                    task = ethereum_comprehensive_analysis.delay(file_id)
                elif analysis_type == 'cipher_analysis':
                    task = cipher_comprehensive_analysis.delay(file_id)
                elif analysis_type == 'pattern_analysis':
                    task = crypto_pattern_deep_scan.delay(file_id)
                else:
                    continue

                TaskRegistry.register_task(
                    task.id,
                    analysis_type,
                    file_id,
                    {'filename': file.filename, 'high_priority': high_priority}
                )
                workflow_tasks.append(task)

            # Create a chord to combine results
            if workflow_tasks:
                callback = combine_analysis_results.si(file_id, [t.id for t in workflow_tasks])
                analysis_chord = chord(workflow_tasks)(callback)
                return analysis_chord.id

            return None

        except Exception as e:
            logger.error(f"Error queuing priority analysis: {e}")
            return None

    @staticmethod
    def get_system_stats():
        """Enhanced system statistics"""
        try:
            # Get active tasks from registry
            active_task_ids = redis_client.smembers('active_tasks')
            active_tasks = []

            for task_id in active_task_ids:
                task_data_str = redis_client.get(f"task:{task_id}")
                if task_data_str:
                    active_tasks.append(json.loads(task_data_str))

            # Queue statistics
            queue_stats = {}
            for queue in ['crypto_main', 'ethereum', 'cipher', 'hash_crack', 'crypto_advanced', 'llm_analysis']:
                try:
                    queue_length = redis_client.llen(f'celery.{queue}')
                    queue_stats[queue] = queue_length
                except:
                    queue_stats[queue] = 0

            # Database statistics
            db_stats = {
                'total_files': AnalysisFile.query.count(),
                'analyzed_files': db.session.query(FileContent).filter_by(content_type='crypto_background_complete').count(),
                'pending_analysis': AnalysisFile.query.filter_by(status='pending').count(),
                'high_priority_files': AnalysisFile.query.filter(AnalysisFile.priority >= 8).count()
            }

            return {
                'active_tasks': active_tasks,
                'queue_stats': queue_stats,
                'database_stats': db_stats,
                'system_health': BackgroundCryptoManager._check_system_health(),
                'last_update': datetime.utcnow().isoformat()
            }

        except Exception as e:
            logger.error(f"Error getting system stats: {e}")
            return {'error': str(e)}

    @staticmethod
    def _check_system_health():
        """Check system health indicators"""
        health = {
            'redis_connected': False,
            'database_connected': False,
            'workers_active': False,
            'queue_lengths_normal': True
        }

        try:
            # Redis health
            redis_client.ping()
            health['redis_connected'] = True
        except:
            pass

        try:
            # Database health
            db.session.execute('SELECT 1')
            health['database_connected'] = True
        except:
            pass

        try:
            # Worker health (check if any tasks completed recently)
            recent_completions = redis_client.zcount('completed_tasks',
                                                   int((datetime.utcnow() - timedelta(minutes=10)).timestamp()),
                                                   int(datetime.utcnow().timestamp()))
            health['workers_active'] = recent_completions > 0
        except:
            pass

        return health


# Enhanced Celery Tasks with better error handling

@celery_app.task(bind=True, max_retries=3, default_retry_delay=60)
def analyze_file_comprehensive(self, file_id: int):
    """Enhanced comprehensive file analysis with better error handling"""

    TaskRegistry.update_task_status(self.request.id, 'running', 0, 'Starting comprehensive analysis')

    try:
        file = AnalysisFile.query.get(file_id)
        if not file:
            raise ValueError(f"File with ID {file_id} not found")

        if not os.path.exists(file.filepath):
            raise FileNotFoundError(f"File path does not exist: {file.filepath}")

        results = {
            'file_id': file_id,
            'filename': file.filename,
            'analysis_start': datetime.utcnow().isoformat(),
            'stages_completed': [],
            'task_id': self.request.id
        }

        TaskRegistry.update_task_status(self.request.id, 'running', 10, 'Reading file content')

        # Read file content safely
        try:
            with open(file.filepath, 'rb') as f:
                content = f.read(10 * 1024 * 1024)  # Read up to 10MB
        except Exception as e:
            raise IOError(f"Error reading file: {e}")

        # Stage 1: Basic crypto pattern analysis
        TaskRegistry.update_task_status(self.request.id, 'running', 20, 'Analyzing crypto patterns')

        try:
            crypto_analysis = CryptoIntelligence.analyze_crypto_content(content, file.filename)
            results['crypto_patterns'] = crypto_analysis
            results['stages_completed'].append('pattern_analysis')
        except Exception as e:
            logger.warning(f"Crypto pattern analysis failed for file {file_id}: {e}")
            results['pattern_analysis_error'] = str(e)

        # Stage 2: Ethereum analysis if patterns found
        ethereum_patterns = [p for p in crypto_analysis.get('crypto_patterns', [])
                           if p['type'] in ['eth_private', 'eth_address']]

        if ethereum_patterns:
            TaskRegistry.update_task_status(self.request.id, 'running', 40, 'Analyzing Ethereum patterns')
            try:
                eth_task = ethereum_comprehensive_analysis.delay(file_id)
                eth_results = eth_task.get(timeout=300)  # 5 minute timeout
                results['ethereum_analysis'] = eth_results
                results['stages_completed'].append('ethereum_analysis')
            except Exception as e:
                logger.warning(f"Ethereum analysis failed for file {file_id}: {e}")
                results['ethereum_analysis_error'] = str(e)

        # Stage 3: Cipher analysis for text content
        if crypto_analysis.get('encoding_detection'):
            TaskRegistry.update_task_status(self.request.id, 'running', 60, 'Analyzing ciphers')
            try:
                cipher_task = cipher_comprehensive_analysis.delay(file_id)
                cipher_results = cipher_task.get(timeout=300)
                results['cipher_analysis'] = cipher_results
                results['stages_completed'].append('cipher_analysis')
            except Exception as e:
                logger.warning(f"Cipher analysis failed for file {file_id}: {e}")
                results['cipher_analysis_error'] = str(e)

        # Stage 4: Hash analysis
        hash_patterns = [p for p in crypto_analysis.get('crypto_patterns', [])
                        if p['type'] in ['md5', 'sha1', 'sha256']]

        if hash_patterns:
            TaskRegistry.update_task_status(self.request.id, 'running', 80, 'Analyzing hashes')
            try:
                hash_results = hash_cracking_analysis.delay(file_id, hash_patterns).get(timeout=600)
                results['hash_analysis'] = hash_results
                results['stages_completed'].append('hash_analysis')
            except Exception as e:
                logger.warning(f"Hash analysis failed for file {file_id}: {e}")
                results['hash_analysis_error'] = str(e)

        # Store results
        TaskRegistry.update_task_status(self.request.id, 'running', 90, 'Storing results')
        store_background_results(file_id, results)

        results['analysis_end'] = datetime.utcnow().isoformat()
        TaskRegistry.complete_task(self.request.id, results)

        logger.info(f"Comprehensive analysis completed for file {file_id}")
        return results

    except Exception as exc:
        error_msg = f"Comprehensive analysis failed for file {file_id}: {exc}"
        logger.error(error_msg)
        TaskRegistry.update_task_status(self.request.id, 'failed', 0, str(exc))

        if self.request.retries < self.max_retries:
            logger.info(f"Retrying analysis for file {file_id}, attempt {self.request.retries + 1}")
            raise self.retry(countdown=60 * (2 ** self.request.retries), exc=exc)
        else:
            # Log final failure
            store_error_result(file_id, str(exc), 'comprehensive_analysis')
            raise exc


@celery_app.task(bind=True, max_retries=2, default_retry_delay=30)
def ethereum_comprehensive_analysis(self, file_id: int):
    """Enhanced Ethereum analysis with rate limiting and error handling"""

    TaskRegistry.update_task_status(self.request.id, 'running', 0, 'Starting Ethereum analysis')

    try:
        file = AnalysisFile.query.get(file_id)
        if not file or not os.path.exists(file.filepath):
            raise ValueError(f"File {file_id} not found or inaccessible")

        results = {
            'file_id': file_id,
            'analysis_type': 'ethereum_comprehensive',
            'private_keys_found': [],
            'addresses_found': [],
            'balance_checks': [],
            'high_value_findings': [],
            'task_id': self.request.id
        }

        # Read file content
        with open(file.filepath, 'rb') as f:
            content = f.read(1024 * 1024)  # Read first 1MB

        text_content = content.decode('utf-8', errors='ignore')

        # Find potential private keys with validation
        potential_keys = CryptoIntelligence.CRYPTO_PATTERNS['eth_private'].findall(text_content)

        TaskRegistry.update_task_status(self.request.id, 'running', 20, f'Validating {len(potential_keys)} potential keys')

        for i, key in enumerate(potential_keys[:10]):  # Limit to 10 keys
            try:
                TaskRegistry.update_task_status(self.request.id, 'running',
                                              20 + (i * 40 // min(len(potential_keys), 10)),
                                              f'Validating key {i+1}')

                validation = EthereumAnalyzer.validate_private_key(key)
                if validation['valid']:
                    results['private_keys_found'].append(validation)

                    # Rate limited balance check
                    time.sleep(0.5)  # Respect API limits
                    try:
                        balance = EthereumAnalyzer.check_balance(validation['address'])
                        results['balance_checks'].append(balance)

                        # Check for high-value findings
                        if float(balance.get('balance_eth', 0)) > 0:
                            results['high_value_findings'].append({
                                'type': 'ethereum_balance',
                                'address': validation['address'],
                                'balance': balance['balance_eth'],
                                'private_key': key
                            })

                            # Create immediate finding for high-value discovery
                            create_ethereum_finding.delay(file_id, validation, balance)

                    except Exception as e:
                        logger.warning(f"Balance check failed for {validation['address']}: {e}")

            except Exception as e:
                logger.warning(f"Key validation failed for key {i}: {e}")

        # Find and validate existing addresses
        TaskRegistry.update_task_status(self.request.id, 'running', 70, 'Analyzing existing addresses')

        addresses = CryptoIntelligence.CRYPTO_PATTERNS['eth_address'].findall(text_content)
        for address in addresses[:5]:  # Limit address checks
            if EthereumAnalyzer.validate_address(address):
                results['addresses_found'].append(address)

        TaskRegistry.complete_task(self.request.id, results)
        logger.info(f"Ethereum analysis completed for file {file_id}")
        return results

    except Exception as exc:
        error_msg = f"Ethereum analysis failed for file {file_id}: {exc}"
        logger.error(error_msg)
        TaskRegistry.update_task_status(self.request.id, 'failed', 0, str(exc))

        if self.request.retries < self.max_retries:
            raise self.retry(countdown=30 * (2 ** self.request.retries), exc=exc)
        else:
            store_error_result(file_id, str(exc), 'ethereum_analysis')
            raise exc


@celery_app.task(bind=True, max_retries=2)
def cipher_comprehensive_analysis(self, file_id: int):
    """Enhanced cipher analysis with improved algorithms"""

    TaskRegistry.update_task_status(self.request.id, 'running', 0, 'Starting cipher analysis')

    try:
        file = AnalysisFile.query.get(file_id)
        if not file or not os.path.exists(file.filepath):
            raise ValueError(f"File {file_id} not found or inaccessible")

        with open(file.filepath, 'rb') as f:
            content = f.read(512 * 1024)  # Read up to 512KB

        text_content = content.decode('utf-8', errors='ignore')

        # Only analyze if content looks like text with potential cipher
        if len(text_content) < 20 or not any(c.isalpha() for c in text_content):
            return {'file_id': file_id, 'analysis_type': 'cipher', 'message': 'No suitable text content for cipher analysis'}

        results = {
            'file_id': file_id,
            'analysis_type': 'cipher_comprehensive',
            'successful_decryptions': [],
            'analysis_results': {},
            'task_id': self.request.id
        }

        # Caesar cipher analysis
        TaskRegistry.update_task_status(self.request.id, 'running', 25, 'Analyzing Caesar ciphers')
        caesar_results = CipherAnalyzer.analyze_caesar_cipher(text_content)
        results['analysis_results']['caesar'] = caesar_results

        # Check for high-scoring Caesar results
        for candidate in caesar_results.get('best_candidates', [])[:3]:
            if candidate['score'] > 50:
                results['successful_decryptions'].append({
                    'method': 'caesar',
                    'shift': candidate['shift'],
                    'decrypted_text': candidate['text'][:500],
                    'confidence': candidate['score']
                })

        # Vigenère analysis
        TaskRegistry.update_task_status(self.request.id, 'running', 50, 'Analyzing Vigenère ciphers')
        vigenere_results = CipherAnalyzer.analyze_vigenere_cipher(text_content)
        results['analysis_results']['vigenere'] = vigenere_results

        # Check for successful Vigenère decryptions
        for key_attempt in vigenere_results.get('key_attempts', [])[:2]:
            if key_attempt['score'] > 40:
                results['successful_decryptions'].append({
                    'method': 'vigenere',
                    'key': key_attempt['key'],
                    'decrypted_text': key_attempt['decoded_text'][:500],
                    'confidence': key_attempt['score']
                })

        # Substitution analysis
        TaskRegistry.update_task_status(self.request.id, 'running', 75, 'Analyzing substitution ciphers')
        substitution_results = CipherAnalyzer.analyze_substitution_cipher(text_content)
        results['analysis_results']['substitution'] = substitution_results

        # Create findings for successful decryptions
        if results['successful_decryptions']:
            create_cipher_finding.delay(file_id, results['successful_decryptions'])

        TaskRegistry.complete_task(self.request.id, results)
        logger.info(f"Cipher analysis completed for file {file_id}")
        return results

    except Exception as exc:
        error_msg = f"Cipher analysis failed for file {file_id}: {exc}"
        logger.error(error_msg)
        TaskRegistry.update_task_status(self.request.id, 'failed', 0, str(exc))

        if self.request.retries < self.max_retries:
            raise self.retry(countdown=30, exc=exc)
        else:
            store_error_result(file_id, str(exc), 'cipher_analysis')
            raise exc


@celery_app.task(bind=True)
def hash_cracking_analysis(self, file_id: int, hash_patterns: List[Dict]):
    """Enhanced hash cracking with extended wordlists"""

    TaskRegistry.update_task_status(self.request.id, 'running', 0, 'Starting hash cracking')

    try:
        results = []

        # Extended wordlists for comprehensive cracking
        wordlists = {
            'common': ['password', '123456', 'admin', 'root', 'flag', 'secret', 'key', 'password123'],
            'crypto_themed': ['satoshi', 'bitcoin', 'ethereum', 'blockchain', 'wallet', 'private'],
            'ctf_themed': ['flag', 'ctf', 'challenge', 'puzzle', 'hidden', 'solve'],
            'years': [str(year) for year in range(2008, 2025)],
            'simple_combinations': []
        }

        # Generate simple combinations
        for word in wordlists['common'][:5]:
            for num in ['123', '1', '2024']:
                wordlists['simple_combinations'].extend([f"{word}{num}", f"{num}{word}"])

        # Combine all wordlists
        full_wordlist = []
        for category, words in wordlists.items():
            full_wordlist.extend(words)

        total_patterns = len(hash_patterns)
        for i, pattern in enumerate(hash_patterns):
            TaskRegistry.update_task_status(self.request.id, 'running',
                                          (i * 90) // total_patterns,
                                          f'Cracking {pattern["type"]} hashes')

            for sample_hash in pattern.get('samples', [])[:3]:
                crack_result = AdvancedCryptoAnalyzer.brute_force_hash(
                    sample_hash, pattern['type'], full_wordlist
                )

                if crack_result['found']:
                    results.append(crack_result)
                    # Create finding for successful crack
                    create_hash_crack_finding.delay(file_id, crack_result)

        TaskRegistry.complete_task(self.request.id, {'cracked_hashes': results})
        return results

    except Exception as exc:
        logger.error(f"Hash cracking failed for file {file_id}: {exc}")
        TaskRegistry.update_task_status(self.request.id, 'failed', 0, str(exc))
        return []


@celery_app.task(bind=True)
def crypto_pattern_deep_scan(self, file_id: int):
    """Enhanced deep pattern scanning with advanced detection"""

    TaskRegistry.update_task_status(self.request.id, 'running', 0, 'Starting deep pattern scan')

    try:
        file = AnalysisFile.query.get(file_id)
        if not file or not os.path.exists(file.filepath):
            raise ValueError(f"File {file_id} not found")

        with open(file.filepath, 'rb') as f:
            content = f.read(2 * 1024 * 1024)  # Read up to 2MB

        results = {
            'file_id': file_id,
            'analysis_type': 'deep_pattern_scan',
            'advanced_patterns': [],
            'entropy_analysis': {},
            'certificate_analysis': [],
            'steganography_indicators': [],
            'task_id': self.request.id
        }

        text_content = content.decode('utf-8', errors='ignore')

        # Advanced pattern detection
        TaskRegistry.update_task_status(self.request.id, 'running', 25, 'Detecting advanced patterns')

        # PGP/GPG patterns
        pgp_patterns = re.findall(r'-----BEGIN PGP.*?-----.*?-----END PGP.*?-----', text_content, re.DOTALL)
        for pgp_block in pgp_patterns:
            results['advanced_patterns'].append({
                'type': 'pgp_block',
                'content': pgp_block[:200],  # Truncate for storage
                'size': len(pgp_block)
            })

        # Certificate analysis
        TaskRegistry.update_task_status(self.request.id, 'running', 50, 'Analyzing certificates')
        cert_patterns = re.findall(r'-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----', text_content, re.DOTALL)
        for cert in cert_patterns:
            cert_analysis = analyze_certificate_content(cert)
            results['certificate_analysis'].append(cert_analysis)

        # Entropy analysis for steganography detection
        TaskRegistry.update_task_status(self.request.id, 'running', 75, 'Calculating entropy')
        if len(content) > 1000:
            entropy = calculate_entropy(content)
            results['entropy_analysis'] = {
                'entropy': entropy,
                'likely_compressed': entropy > 7.8,
                'likely_encrypted': entropy > 7.5,
                'suspicious_patterns': 6.0 < entropy < 7.0,
                'steganography_indicators': entropy > 7.9 or (6.0 < entropy < 6.5)
            }

        TaskRegistry.complete_task(self.request.id, results)
        return results

    except Exception as exc:
        logger.error(f"Deep pattern scan failed for file {file_id}: {exc}")
        TaskRegistry.update_task_status(self.request.id, 'failed', 0, str(exc))
        return {'error': str(exc)}


# Coordination and Monitoring Tasks

@celery_app.task(bind=True)
def combine_analysis_results(self, file_id: int, task_ids: List[str]):
    """Combine results from multiple analysis tasks"""

    try:
        combined_results = {
            'file_id': file_id,
            'combination_task_id': self.request.id,
            'source_tasks': task_ids,
            'combined_at': datetime.utcnow().isoformat(),
            'results': {}
        }

        # Collect results from all tasks
        for task_id in task_ids:
            result_data = redis_client.get(f"task_result:{task_id}")
            if result_data:
                task_result = json.loads(result_data)
                analysis_type = task_result.get('analysis_type', 'unknown')
                combined_results['results'][analysis_type] = task_result

        # Store combined results
        store_background_results(file_id, combined_results)

        # Generate summary findings
        generate_summary_findings.delay(file_id, combined_results)

        logger.info(f"Combined analysis results for file {file_id}")
        return combined_results

    except Exception as e:
        logger.error(f"Error combining results for file {file_id}: {e}")
        return {'error': str(e)}


@celery_app.task(bind=True)
def continuous_crypto_monitor(self):
    """Enhanced continuous monitoring with intelligent scheduling"""

    monitor_id = self.request.id
    redis_client.setex('monitor_running', 3600, monitor_id)

    try:
        iteration = 0
        while redis_client.get('monitor_running') == monitor_id:
            iteration += 1
            logger.info(f"Monitor iteration {iteration}")

            # Check for new high-priority files
            new_high_priority = AnalysisFile.query.filter(
                AnalysisFile.priority >= 8,
                AnalysisFile.created_at > datetime.utcnow() - timedelta(minutes=5),
                AnalysisFile.status == 'pending'
            ).limit(5).all()

            for file in new_high_priority:
                logger.info(f"Queuing high-priority analysis for file {file.id}")
                BackgroundCryptoManager.queue_priority_analysis(file.id)

            # Clean up old task records
            if iteration % 10 == 0:  # Every 10th iteration
                cleanup_old_tasks.delay()

            # Health check
            if iteration % 20 == 0:  # Every 20th iteration
                system_health_check.delay()

            time.sleep(30)  # Wait 30 seconds between iterations

    except Exception as e:
        logger.error(f"Monitor error: {e}")
    finally:
        redis_client.delete('monitor_running')


# Utility Tasks

@celery_app.task
def cleanup_old_tasks():
    """Clean up old task records and results"""
    try:
        cutoff_time = datetime.utcnow() - timedelta(hours=24)
        cutoff_timestamp = cutoff_time.timestamp()

        # Clean up old task records
        old_tasks = redis_client.smembers('active_tasks')
        for task_id in old_tasks:
            task_data_str = redis_client.get(f"task:{task_id}")
            if task_data_str:
                task_data = json.loads(task_data_str)
                created_at = datetime.fromisoformat(task_data['created_at'])
                if created_at < cutoff_time:
                    redis_client.srem('active_tasks', task_id)
                    redis_client.delete(f"task:{task_id}")
                    redis_client.delete(f"task_result:{task_id}")

        logger.info("Cleaned up old task records")

    except Exception as e:
        logger.error(f"Error during cleanup: {e}")


@celery_app.task
def system_health_check():
    """Perform system health check and alert on issues"""
    try:
        health = BackgroundCryptoManager._check_system_health()

        # Log health status
        logger.info(f"System health check: {health}")

        # Store health data
        redis_client.setex('system_health', 300, json.dumps({
            'timestamp': datetime.utcnow().isoformat(),
            'health': health
        }))

        # Alert on critical issues
        if not health['redis_connected']:
            logger.critical("Redis connection failed!")
        if not health['database_connected']:
            logger.critical("Database connection failed!")

    except Exception as e:
        logger.error(f"Health check failed: {e}")


@celery_app.task
def manage_priority_queue():
    """Manage priority queue and resource allocation"""
    try:
        # Get queue statistics
        stats = BackgroundCryptoManager.get_system_stats()
        queue_stats = stats.get('queue_stats', {})

        # If main crypto queue is getting full, prioritize it
        if queue_stats.get('crypto_main', 0) > 50:
            # Reduce lower priority queue processing
            logger.info("High load detected, adjusting queue priorities")

        # Check for stuck tasks
        active_task_ids = redis_client.smembers('active_tasks')
        stuck_tasks = []

        for task_id in active_task_ids:
            task_data_str = redis_client.get(f"task:{task_id}")
            if task_data_str:
                task_data = json.loads(task_data_str)
                created_at = datetime.fromisoformat(task_data['created_at'])
                if datetime.utcnow() - created_at > timedelta(hours=2):  # Task running for >2 hours
                    stuck_tasks.append(task_id)

        if stuck_tasks:
            logger.warning(f"Found {len(stuck_tasks)} potentially stuck tasks")

    except Exception as e:
        logger.error(f"Priority queue management error: {e}")


# Utility Functions

def store_background_results(file_id: int, results: Dict):
    """Store background analysis results with error handling"""
    try:
        existing_content = FileContent.query.filter_by(
            file_id=file_id,
            content_type='crypto_background_complete'
        ).first()

        if existing_content:
            existing_results = json.loads(existing_content.content_text or '{}')
            existing_results.update(results)
            existing_content.content_text = json.dumps(existing_results, indent=2)
            existing_content.updated_at = datetime.utcnow()
        else:
            content = FileContent(
                file_id=file_id,
                content_type='crypto_background_complete',
                content_text=json.dumps(results, indent=2),
                content_size=len(json.dumps(results)),
                created_at=datetime.utcnow()
            )
            db.session.add(content)

        db.session.commit()
        logger.info(f"Stored background results for file {file_id}")

    except SQLAlchemyError as e:
        db.session.rollback()
        logger.error(f"Database error storing results for file {file_id}: {e}")
    except Exception as e:
        logger.error(f"Error storing background results for file {file_id}: {e}")


def store_error_result(file_id: int, error_message: str, analysis_type: str):
    """Store error result for failed analysis"""
    try:
        error_result = {
            'file_id': file_id,
            'analysis_type': analysis_type,
            'error': error_message,
            'error_timestamp': datetime.utcnow().isoformat(),
            'status': 'failed'
        }

        content = FileContent(
            file_id=file_id,
            content_type=f'crypto_error_{analysis_type}',
            content_text=json.dumps(error_result, indent=2),
            content_size=len(json.dumps(error_result)),
            created_at=datetime.utcnow()
        )
        db.session.add(content)
        db.session.commit()

    except Exception as e:
        logger.error(f"Error storing error result: {e}")


def calculate_entropy(data: bytes) -> float:
    """Calculate Shannon entropy of data"""
    if len(data) == 0:
        return 0

    byte_counts = [0] * 256
    for byte in data:
        byte_counts[byte] += 1

    entropy = 0
    for count in byte_counts:
        if count > 0:
            frequency = count / len(data)
            entropy -= frequency * math.log2(frequency)

    return entropy


def analyze_certificate_content(cert_pem: str) -> Dict[str, Any]:
    """Analyze certificate content"""
    try:
        lines = cert_pem.split('\n')
        cert_data = ''.join(line for line in lines if not line.startswith('-----'))

        import base64
        cert_bytes = base64.b64decode(cert_data)

        return {
            'type': 'x509_certificate',
            'size': len(cert_bytes),
            'has_extensions': b'\x30\x82' in cert_bytes,
            'potential_key_usage': 'digital_signature' if b'\x03\x02\x05' in cert_bytes else 'unknown'
        }
    except Exception as e:
        return {'type': 'certificate_parse_error', 'error': str(e)}


# Finding Creation Tasks (these would be imported from the existing file)
@celery_app.task
def create_ethereum_finding(file_id: int, validation: Dict, balance: Dict):
    """Create finding for Ethereum discovery"""
    # Implementation from existing file
    pass


@celery_app.task
def create_cipher_finding(file_id: int, successful_decryptions: List[Dict]):
    """Create finding for cipher decryption"""
    # Implementation from existing file
    pass


@celery_app.task
def create_hash_crack_finding(file_id: int, crack_result: Dict):
    """Create finding for hash crack"""
    # Implementation from existing file
    pass


@celery_app.task
def generate_summary_findings(file_id: int, combined_results: Dict):
    """Generate summary findings from combined analysis"""
    try:
        # Analyze combined results and create summary findings
        file = AnalysisFile.query.get(file_id)
        if not file:
            return

        summary = {
            'total_analyses': len(combined_results.get('results', {})),
            'high_value_findings': 0,
            'crypto_patterns_found': 0,
            'recommendations': []
        }

        # Count significant findings
        for analysis_type, result in combined_results.get('results', {}).items():
            if result.get('high_value_findings'):
                summary['high_value_findings'] += len(result['high_value_findings'])
            if result.get('crypto_patterns'):
                summary['crypto_patterns_found'] += len(result['crypto_patterns'])

        # Generate recommendations
        if summary['high_value_findings'] > 0:
            summary['recommendations'].append("Priority: Review high-value findings immediately")
        if summary['crypto_patterns_found'] > 5:
            summary['recommendations'].append("Deep analysis: Multiple crypto patterns detected")

        # Store summary
        store_background_results(file_id, {'analysis_summary': summary})

        logger.info(f"Generated summary findings for file {file_id}")

    except Exception as e:
        logger.error(f"Error generating summary findings: {e}")


# Signal handlers for monitoring
@task_success.connect
def on_task_success(sender=None, task_id=None, result=None, retries=None, einfo=None, **kwargs):
    """Handle successful task completion"""
    redis_client.zadd('completed_tasks', {task_id: int(datetime.utcnow().timestamp())})


@task_failure.connect
def on_task_failure(sender=None, task_id=None, exception=None, traceback=None, einfo=None, **kwargs):
    """Handle task failure"""
    redis_client.zadd('failed_tasks', {task_id: int(datetime.utcnow().timestamp())})


@task_retry.connect
def on_task_retry(sender=None, task_id=None, reason=None, einfo=None, **kwargs):
    """Handle task retry"""
    redis_client.zadd('retried_tasks', {task_id: int(datetime.utcnow().timestamp())})