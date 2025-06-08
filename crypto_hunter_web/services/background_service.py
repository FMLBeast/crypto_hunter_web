#!/usr/bin/env python3
"""
crypto_hunter_web/services/background_service.py - COMPLETE FORENSICS BACKGROUND SERVICE
Best-in-class forensics analysis with comprehensive tool integration
"""

import os
import json
import logging
import traceback
import tempfile
import shutil
import magic
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Union
from celery import Celery, Task, group, chain, chord
from celery.result import AsyncResult
from celery.exceptions import Retry, WorkerLostError
import redis
from concurrent.futures import ThreadPoolExecutor, TimeoutError
import subprocess
import threading
import time
from dataclasses import dataclass

from crypto_hunter_web.models import db, AnalysisFile, FileContent, Finding, AuditLog
from crypto_hunter_web.services.content_analyzer import ContentAnalyzer
from crypto_hunter_web.services.crypto_analyzer import CryptoAnalyzer
from crypto_hunter_web.services.ai_service import AIService

logger = logging.getLogger(__name__)


@dataclass
class ToolResult:
    """Standardized tool result structure"""
    success: bool
    tool_name: str
    data: bytes
    metadata: Dict[str, Any]
    confidence: float
    execution_time: float
    error_message: str = ""
    command_line: str = ""


class CeleryConfig:
    """Celery configuration optimized for forensics workloads"""

    # Broker settings
    broker_url = os.getenv('CELERY_BROKER_URL', 'redis://localhost:6379/2')
    result_backend = os.getenv('CELERY_RESULT_BACKEND', 'redis://localhost:6379/3')

    # Task settings
    task_serializer = 'json'
    accept_content = ['json']
    result_serializer = 'json'
    timezone = 'UTC'
    enable_utc = True

    # Task routing for different workload types
    task_routes = {
        'crypto_hunter_web.services.background_service.analyze_file_comprehensive': {
            'queue': 'forensics_heavy'
        },
        'crypto_hunter_web.services.background_service.steganography_analysis': {
            'queue': 'steganography'
        },
        'crypto_hunter_web.services.background_service.binary_analysis': {
            'queue': 'binary_analysis'
        },
        'crypto_hunter_web.services.background_service.crypto_pattern_analysis': {
            'queue': 'crypto_analysis'
        },
        'crypto_hunter_web.services.background_service.ai_analysis': {
            'queue': 'ai_analysis'
        }
    }

    # Worker settings optimized for CPU-intensive forensics work
    worker_prefetch_multiplier = 1
    task_acks_late = True
    worker_disable_rate_limits = False
    worker_max_tasks_per_child = 10  # Prevent memory leaks from forensics tools

    # Result settings
    result_expires = 3600 * 48  # 48 hours for forensics results
    task_ignore_result = False

    # Retry settings for forensics tools
    task_default_retry_delay = 120  # 2 minutes
    task_max_retries = 2

    # Beat schedule
    beat_schedule = {
        'cleanup-forensics-temp-files': {
            'task': 'crypto_hunter_web.services.background_service.cleanup_temp_files',
            'schedule': 1800.0,  # Every 30 minutes
        },
        'health-check-tools': {
            'task': 'crypto_hunter_web.services.background_service.health_check_tools',
            'schedule': 3600.0,  # Every hour
        },
        'update-statistics': {
            'task': 'crypto_hunter_web.services.background_service.update_statistics',
            'schedule': 1800.0,  # Every 30 minutes
        }
    }


def create_celery_app(app=None):
    """Create Celery app with Flask context"""
    celery = Celery('crypto_hunter_forensics')
    celery.config_from_object(CeleryConfig)

    if app:
        class ContextTask(Task):
            """Task base class with Flask context and comprehensive error handling"""

            def __call__(self, *args, **kwargs):
                with app.app_context():
                    try:
                        return self.run(*args, **kwargs)
                    except Exception as e:
                        logger.error(f"Task {self.name} failed: {e}",
                                     exc_info=True,
                                     extra={
                                         'task_id': self.request.id,
                                         'task_args': args,
                                         'task_kwargs': kwargs
                                     })
                        raise

        celery.Task = ContextTask

    return celery


# Global celery instance
celery = create_celery_app()


class ForensicsToolkit:
    """Comprehensive forensics analysis toolkit"""

    def __init__(self):
        self.temp_dir = tempfile.mkdtemp(prefix="forensics_")
        self.tools = self._initialize_tools()

    def __del__(self):
        """Cleanup temporary directory"""
        try:
            shutil.rmtree(self.temp_dir, ignore_errors=True)
        except:
            pass

    def _initialize_tools(self) -> Dict[str, Dict]:
        """Initialize all forensics tools with their configurations"""
        return {
            # Steganography Tools
            'binwalk': {
                'command': ['binwalk'],
                'description': 'Binary analysis and extraction',
                'file_types': ['*'],
                'timeout': 120,
                'confidence_base': 0.8
            },
            'zsteg': {
                'command': ['zsteg'],
                'description': 'PNG/BMP steganography detection',
                'file_types': ['image/png', 'image/bmp'],
                'timeout': 60,
                'confidence_base': 0.9
            },
            'steghide': {
                'command': ['steghide'],
                'description': 'JPEG/WAV steganography',
                'file_types': ['image/jpeg', 'audio/wav'],
                'timeout': 60,
                'confidence_base': 0.8
            },
            'stegseek': {
                'command': ['stegseek'],
                'description': 'Fast steghide cracker',
                'file_types': ['image/jpeg', 'audio/wav'],
                'timeout': 300,
                'confidence_base': 0.9
            },
            'outguess': {
                'command': ['outguess'],
                'description': 'JPEG steganography tool',
                'file_types': ['image/jpeg'],
                'timeout': 60,
                'confidence_base': 0.7
            },
            'stegsolve': {
                'command': ['java', '-jar', '/opt/stegsolve/stegsolve.jar'],
                'description': 'Image analysis tool',
                'file_types': ['image/*'],
                'timeout': 120,
                'confidence_base': 0.6
            },

            # Binary Analysis Tools
            'foremost': {
                'command': ['foremost'],
                'description': 'File carving tool',
                'file_types': ['*'],
                'timeout': 300,
                'confidence_base': 0.8
            },
            'scalpel': {
                'command': ['scalpel'],
                'description': 'Fast file carver',
                'file_types': ['*'],
                'timeout': 300,
                'confidence_base': 0.8
            },
            'bulk_extractor': {
                'command': ['bulk_extractor'],
                'description': 'Feature extraction tool',
                'file_types': ['*'],
                'timeout': 600,
                'confidence_base': 0.9
            },

            # Reverse Engineering Tools
            'radare2': {
                'command': ['radare2'],
                'description': 'Reverse engineering framework',
                'file_types': ['application/x-executable', 'application/x-sharedlib'],
                'timeout': 300,
                'confidence_base': 0.9
            },
            'objdump': {
                'command': ['objdump'],
                'description': 'Object file analyzer',
                'file_types': ['application/x-executable'],
                'timeout': 60,
                'confidence_base': 0.7
            },
            'readelf': {
                'command': ['readelf'],
                'description': 'ELF file analyzer',
                'file_types': ['application/x-executable'],
                'timeout': 30,
                'confidence_base': 0.8
            },

            # Analysis Tools
            'strings': {
                'command': ['strings'],
                'description': 'String extraction',
                'file_types': ['*'],
                'timeout': 60,
                'confidence_base': 0.6
            },
            'hexdump': {
                'command': ['hexdump'],
                'description': 'Hex dump utility',
                'file_types': ['*'],
                'timeout': 30,
                'confidence_base': 0.5
            },
            'exiftool': {
                'command': ['exiftool'],
                'description': 'Metadata extraction',
                'file_types': ['image/*', 'video/*', 'audio/*'],
                'timeout': 30,
                'confidence_base': 0.8
            },

            # Audio/Video Tools
            'sox': {
                'command': ['sox'],
                'description': 'Audio processing tool',
                'file_types': ['audio/*'],
                'timeout': 120,
                'confidence_base': 0.7
            },
            'ffmpeg': {
                'command': ['ffmpeg'],
                'description': 'Video/audio processing',
                'file_types': ['video/*', 'audio/*'],
                'timeout': 300,
                'confidence_base': 0.8
            },

            # Network Tools
            'wireshark': {
                'command': ['tshark'],
                'description': 'Network protocol analyzer',
                'file_types': ['application/vnd.tcpdump.pcap'],
                'timeout': 300,
                'confidence_base': 0.9
            },

            # Crypto Tools
            'hashcat': {
                'command': ['hashcat'],
                'description': 'Password cracking tool',
                'file_types': ['*'],
                'timeout': 600,
                'confidence_base': 0.8
            },
            'john': {
                'command': ['john'],
                'description': 'Password cracker',
                'file_types': ['*'],
                'timeout': 600,
                'confidence_base': 0.8
            }
        }

    def analyze_file_comprehensive(self, file_path: str, file_type: str = None) -> Dict[str, Any]:
        """Run comprehensive forensics analysis on a file"""
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"File not found: {file_path}")

        # Detect file type if not provided
        if not file_type:
            file_type = magic.from_file(file_path, mime=True)

        start_time = time.time()
        results = {
            'file_path': file_path,
            'file_type': file_type,
            'file_size': os.path.getsize(file_path),
            'analysis_timestamp': start_time,
            'tools_executed': [],
            'findings': [],
            'extracted_files': [],
            'metadata': {},
            'confidence_score': 0.0
        }

        # Get applicable tools for this file type
        applicable_tools = self._get_applicable_tools(file_type)

        # Run tools in parallel for efficiency
        with ThreadPoolExecutor(max_workers=4) as executor:
            future_to_tool = {}

            for tool_name in applicable_tools:
                future = executor.submit(self._run_tool_analysis, tool_name, file_path, file_type)
                future_to_tool[future] = tool_name

            for future in future_to_tool:
                tool_name = future_to_tool[future]
                try:
                    tool_result = future.result(timeout=600)  # 10 minute max per tool
                    if tool_result:
                        results['tools_executed'].append(tool_result)
                        if tool_result.success:
                            results['findings'].extend(self._extract_findings(tool_result))
                except TimeoutError:
                    logger.warning(f"Tool {tool_name} timed out")
                except Exception as e:
                    logger.error(f"Tool {tool_name} failed: {e}")

        # Calculate overall confidence score
        results['confidence_score'] = self._calculate_confidence_score(results)
        results['execution_time'] = time.time() - start_time

        return results

    def _get_applicable_tools(self, file_type: str) -> List[str]:
        """Get list of applicable tools for a file type"""
        applicable = []

        for tool_name, config in self.tools.items():
            if not self._is_tool_available(tool_name):
                continue

            file_types = config.get('file_types', [])
            if '*' in file_types:
                applicable.append(tool_name)
            elif any(ft in file_type for ft in file_types if ft != '*'):
                applicable.append(tool_name)
            elif file_type.startswith('image/') and 'image/*' in file_types:
                applicable.append(tool_name)
            elif file_type.startswith('audio/') and 'audio/*' in file_types:
                applicable.append(tool_name)
            elif file_type.startswith('video/') and 'video/*' in file_types:
                applicable.append(tool_name)

        return applicable

    def _is_tool_available(self, tool_name: str) -> bool:
        """Check if a tool is available on the system"""
        try:
            config = self.tools[tool_name]
            command = config['command'][0]
            subprocess.run([command, '--version'], capture_output=True, timeout=5)
            return True
        except (subprocess.TimeoutExpired, subprocess.CalledProcessError, FileNotFoundError):
            try:
                subprocess.run(['which', command], capture_output=True, timeout=5, check=True)
                return True
            except:
                return False

    def _run_tool_analysis(self, tool_name: str, file_path: str, file_type: str) -> Optional[ToolResult]:
        """Run analysis with a specific tool"""
        config = self.tools[tool_name]
        start_time = time.time()

        try:
            if tool_name == 'binwalk':
                return self._run_binwalk(file_path, config, start_time)
            elif tool_name == 'zsteg':
                return self._run_zsteg(file_path, config, start_time)
            elif tool_name == 'steghide':
                return self._run_steghide(file_path, config, start_time)
            elif tool_name == 'stegseek':
                return self._run_stegseek(file_path, config, start_time)
            elif tool_name == 'strings':
                return self._run_strings(file_path, config, start_time)
            elif tool_name == 'exiftool':
                return self._run_exiftool(file_path, config, start_time)
            else:
                return self._run_generic_tool(tool_name, file_path, config, start_time)

        except Exception as e:
            execution_time = time.time() - start_time
            return ToolResult(
                success=False,
                tool_name=tool_name,
                data=b'',
                metadata={'error': str(e)},
                confidence=0.0,
                execution_time=execution_time,
                error_message=str(e)
            )

    def _run_binwalk(self, file_path: str, config: Dict, start_time: float) -> ToolResult:
        """Run binwalk analysis with comprehensive extraction"""
        output_dir = os.path.join(self.temp_dir, f"binwalk_{int(start_time)}")
        os.makedirs(output_dir, exist_ok=True)

        command = ['binwalk', '-e', '--dd=.*', '-C', output_dir, file_path]

        try:
            result = subprocess.run(command, capture_output=True, timeout=config['timeout'], text=True)

            # Collect extracted files
            extracted_files = []
            extracted_data = b''

            for root, dirs, files in os.walk(output_dir):
                for file in files:
                    file_full_path = os.path.join(root, file)
                    try:
                        with open(file_full_path, 'rb') as f:
                            file_data = f.read()
                            extracted_data += file_data
                            extracted_files.append({
                                'name': file,
                                'size': len(file_data),
                                'path': file_full_path,
                                'type': magic.from_file(file_full_path, mime=True)
                            })
                    except:
                        continue

            confidence = min(0.9, 0.3 + (len(extracted_files) * 0.1))

            return ToolResult(
                success=len(extracted_files) > 0,
                tool_name='binwalk',
                data=extracted_data,
                metadata={
                    'extracted_files': extracted_files,
                    'output_dir': output_dir,
                    'stdout': result.stdout,
                    'stderr': result.stderr
                },
                confidence=confidence,
                execution_time=time.time() - start_time,
                command_line=' '.join(command)
            )

        except subprocess.TimeoutExpired:
            return ToolResult(
                success=False,
                tool_name='binwalk',
                data=b'',
                metadata={},
                confidence=0.0,
                execution_time=time.time() - start_time,
                error_message="Binwalk timed out"
            )

    def _run_zsteg(self, file_path: str, config: Dict, start_time: float) -> ToolResult:
        """Run zsteg steganography analysis"""
        command = ['zsteg', '-a', file_path]

        try:
            result = subprocess.run(command, capture_output=True, timeout=config['timeout'], text=True)

            findings = []
            if result.stdout:
                lines = result.stdout.strip().split('\n')
                for line in lines:
                    if line.strip() and not line.startswith('['):
                        findings.append(line.strip())

            confidence = min(0.9, 0.2 + (len(findings) * 0.1)) if findings else 0.1

            return ToolResult(
                success=len(findings) > 0,
                tool_name='zsteg',
                data=result.stdout.encode(),
                metadata={
                    'findings': findings,
                    'stderr': result.stderr
                },
                confidence=confidence,
                execution_time=time.time() - start_time,
                command_line=' '.join(command)
            )

        except subprocess.TimeoutExpired:
            return ToolResult(
                success=False,
                tool_name='zsteg',
                data=b'',
                metadata={},
                confidence=0.0,
                execution_time=time.time() - start_time,
                error_message="ZSteg timed out"
            )

    def _run_steghide(self, file_path: str, config: Dict, start_time: float) -> ToolResult:
        """Run steghide analysis with common passwords"""
        common_passwords = ['', 'password', '123456', 'admin', 'root', 'steghide']

        for password in common_passwords:
            try:
                output_file = os.path.join(self.temp_dir, f"steghide_output_{int(start_time)}")
                command = ['steghide', 'extract', '-sf', file_path, '-xf', output_file, '-p', password]
                result = subprocess.run(command, capture_output=True, timeout=30, text=True)

                if result.returncode == 0 and os.path.exists(output_file):
                    with open(output_file, 'rb') as f:
                        extracted_data = f.read()

                    return ToolResult(
                        success=True,
                        tool_name='steghide',
                        data=extracted_data,
                        metadata={
                            'password': password,
                            'extracted_file': output_file,
                            'stderr': result.stderr
                        },
                        confidence=0.9,
                        execution_time=time.time() - start_time,
                        command_line=' '.join(command)
                    )
            except subprocess.TimeoutExpired:
                continue
            except Exception:
                continue

        return ToolResult(
            success=False,
            tool_name='steghide',
            data=b'',
            metadata={'passwords_tried': common_passwords},
            confidence=0.0,
            execution_time=time.time() - start_time,
            error_message="No valid steghide data found"
        )

    def _run_stegseek(self, file_path: str, config: Dict, start_time: float) -> ToolResult:
        """Run stegseek for fast steghide cracking"""
        wordlist_paths = [
            '/usr/share/wordlists/rockyou.txt',
            '/opt/wordlists/common.txt',
            '/usr/share/dict/words'
        ]

        wordlist_path = None
        for path in wordlist_paths:
            if os.path.exists(path):
                wordlist_path = path
                break

        if not wordlist_path:
            return ToolResult(
                success=False,
                tool_name='stegseek',
                data=b'',
                metadata={},
                confidence=0.0,
                execution_time=time.time() - start_time,
                error_message="No wordlist available for stegseek"
            )

        output_file = os.path.join(self.temp_dir, f"stegseek_output_{int(start_time)}")
        command = ['stegseek', file_path, wordlist_path, output_file]

        try:
            result = subprocess.run(command, capture_output=True, timeout=config['timeout'], text=True)

            if result.returncode == 0 and "Found passphrase" in result.stdout and os.path.exists(output_file):
                with open(output_file, 'rb') as f:
                    extracted_data = f.read()

                # Extract password from output
                password = "unknown"
                for line in result.stdout.split('\n'):
                    if "Found passphrase" in line:
                        try:
                            password = line.split('"')[1]
                        except:
                            pass
                        break

                return ToolResult(
                    success=True,
                    tool_name='stegseek',
                    data=extracted_data,
                    metadata={
                        'password': password,
                        'extracted_file': output_file,
                        'stdout': result.stdout
                    },
                    confidence=0.95,
                    execution_time=time.time() - start_time,
                    command_line=' '.join(command)
                )

            return ToolResult(
                success=False,
                tool_name='stegseek',
                data=b'',
                metadata={'stdout': result.stdout, 'stderr': result.stderr},
                confidence=0.0,
                execution_time=time.time() - start_time,
                error_message="No steganographic data found"
            )

        except subprocess.TimeoutExpired:
            return ToolResult(
                success=False,
                tool_name='stegseek',
                data=b'',
                metadata={},
                confidence=0.0,
                execution_time=time.time() - start_time,
                error_message="Stegseek timed out"
            )

    def _run_strings(self, file_path: str, config: Dict, start_time: float) -> ToolResult:
        """Run strings analysis with crypto pattern detection"""
        command = ['strings', '-n', '4', file_path]

        try:
            result = subprocess.run(command, capture_output=True, timeout=config['timeout'])

            if result.returncode == 0:
                strings_data = result.stdout.decode('utf-8', errors='ignore')

                # Analyze strings for crypto patterns
                crypto_patterns = self._analyze_crypto_patterns(strings_data)
                interesting_strings = self._find_interesting_strings(strings_data)

                confidence = min(0.8, 0.1 + (len(crypto_patterns) * 0.1) + (len(interesting_strings) * 0.05))

                return ToolResult(
                    success=True,
                    tool_name='strings',
                    data=result.stdout,
                    metadata={
                        'crypto_patterns': crypto_patterns,
                        'interesting_strings': interesting_strings[:50],  # Limit output
                        'total_strings': len(strings_data.split('\n'))
                    },
                    confidence=confidence,
                    execution_time=time.time() - start_time,
                    command_line=' '.join(command)
                )

        except subprocess.TimeoutExpired:
            pass

        return ToolResult(
            success=False,
            tool_name='strings',
            data=b'',
            metadata={},
            confidence=0.0,
            execution_time=time.time() - start_time,
            error_message="Strings extraction failed"
        )

    def _run_exiftool(self, file_path: str, config: Dict, start_time: float) -> ToolResult:
        """Run exiftool metadata extraction"""
        command = ['exiftool', '-json', file_path]

        try:
            result = subprocess.run(command, capture_output=True, timeout=config['timeout'], text=True)

            if result.returncode == 0:
                try:
                    metadata = json.loads(result.stdout)[0]

                    # Look for interesting metadata
                    interesting_fields = []
                    for key, value in metadata.items():
                        if any(keyword in key.lower() for keyword in ['gps', 'location', 'camera', 'software']):
                            interesting_fields.append({key: value})

                    confidence = min(0.8, 0.3 + (len(interesting_fields) * 0.1))

                    return ToolResult(
                        success=True,
                        tool_name='exiftool',
                        data=result.stdout.encode(),
                        metadata={
                            'extracted_metadata': metadata,
                            'interesting_fields': interesting_fields,
                            'field_count': len(metadata)
                        },
                        confidence=confidence,
                        execution_time=time.time() - start_time,
                        command_line=' '.join(command)
                    )
                except json.JSONDecodeError:
                    pass

        except subprocess.TimeoutExpired:
            pass

        return ToolResult(
            success=False,
            tool_name='exiftool',
            data=b'',
            metadata={},
            confidence=0.0,
            execution_time=time.time() - start_time,
            error_message="Exiftool extraction failed"
        )

    def _run_generic_tool(self, tool_name: str, file_path: str, config: Dict, start_time: float) -> ToolResult:
        """Run generic tool analysis"""
        command = config['command'] + [file_path]

        try:
            result = subprocess.run(command, capture_output=True, timeout=config['timeout'])

            success = result.returncode == 0 and len(result.stdout) > 0
            confidence = config.get('confidence_base', 0.5) if success else 0.0

            return ToolResult(
                success=success,
                tool_name=tool_name,
                data=result.stdout,
                metadata={
                    'stdout': result.stdout.decode('utf-8', errors='ignore'),
                    'stderr': result.stderr.decode('utf-8', errors='ignore'),
                    'returncode': result.returncode
                },
                confidence=confidence,
                execution_time=time.time() - start_time,
                command_line=' '.join(command)
            )

        except subprocess.TimeoutExpired:
            return ToolResult(
                success=False,
                tool_name=tool_name,
                data=b'',
                metadata={},
                confidence=0.0,
                execution_time=time.time() - start_time,
                error_message=f"{tool_name} timed out"
            )

    def _analyze_crypto_patterns(self, text: str) -> List[Dict[str, Any]]:
        """Analyze text for cryptocurrency patterns"""
        import re
        patterns = []

        # Bitcoin addresses
        btc_pattern = r'\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b'
        for match in re.finditer(btc_pattern, text):
            patterns.append({
                'type': 'bitcoin_address',
                'value': match.group(),
                'position': match.start()
            })

        # Ethereum addresses
        eth_pattern = r'\b0x[a-fA-F0-9]{40}\b'
        for match in re.finditer(eth_pattern, text):
            patterns.append({
                'type': 'ethereum_address',
                'value': match.group(),
                'position': match.start()
            })

        # Private key patterns
        privkey_pattern = r'\b[5KL][1-9A-HJ-NP-Za-km-z]{50,51}\b'
        for match in re.finditer(privkey_pattern, text):
            patterns.append({
                'type': 'bitcoin_private_key',
                'value': match.group(),
                'position': match.start()
            })

        # Base64 patterns (potential keys)
        b64_pattern = r'\b[A-Za-z0-9+/]{40,}={0,2}\b'
        for match in re.finditer(b64_pattern, text):
            if len(match.group()) >= 40:
                patterns.append({
                    'type': 'base64_candidate',
                    'value': match.group(),
                    'position': match.start()
                })

        return patterns

    def _find_interesting_strings(self, text: str) -> List[str]:
        """Find interesting strings that might contain clues"""
        interesting = []
        lines = text.split('\n')

        keywords = [
            'password', 'passwd', 'key', 'secret', 'token', 'auth',
            'flag', 'FLAG', 'ctf', 'CTF', 'crypto', 'bitcoin', 'wallet',
            'private', 'public', 'certificate', 'ssh', 'rsa', 'aes'
        ]

        for line in lines:
            line = line.strip()
            if len(line) < 4:
                continue

            for keyword in keywords:
                if keyword.lower() in line.lower():
                    interesting.append(line)
                    break

        return interesting[:100]  # Limit to first 100

    def _extract_findings(self, tool_result: ToolResult) -> List[Dict[str, Any]]:
        """Extract structured findings from tool results"""
        findings = []

        if tool_result.tool_name == 'strings':
            crypto_patterns = tool_result.metadata.get('crypto_patterns', [])
            for pattern in crypto_patterns:
                findings.append({
                    'type': 'cryptocurrency_pattern',
                    'subtype': pattern['type'],
                    'value': pattern['value'],
                    'tool': 'strings',
                    'confidence': 0.8
                })

        elif tool_result.tool_name == 'binwalk':
            extracted_files = tool_result.metadata.get('extracted_files', [])
            for file_info in extracted_files:
                findings.append({
                    'type': 'extracted_file',
                    'filename': file_info['name'],
                    'size': file_info['size'],
                    'file_type': file_info['type'],
                    'tool': 'binwalk',
                    'confidence': 0.7
                })

        elif tool_result.tool_name in ['zsteg', 'steghide', 'stegseek']:
            if tool_result.success:
                findings.append({
                    'type': 'steganographic_content',
                    'tool': tool_result.tool_name,
                    'data_size': len(tool_result.data),
                    'confidence': tool_result.confidence
                })

        return findings

    def _calculate_confidence_score(self, results: Dict) -> float:
        """Calculate overall confidence score for analysis"""
        if not results['tools_executed']:
            return 0.0

        total_confidence = sum(tool.confidence for tool in results['tools_executed'] if tool.success)
        successful_tools = sum(1 for tool in results['tools_executed'] if tool.success)

        if successful_tools == 0:
            return 0.0

        base_score = total_confidence / successful_tools

        # Boost confidence if multiple tools found similar things
        if len(results['findings']) > 3:
            base_score = min(0.95, base_score * 1.2)

        return round(base_score, 2)


class BackgroundService:
    """Service for managing background analysis tasks"""

    def __init__(self):
        self.redis_client = None
        self.forensics_toolkit = ForensicsToolkit()

        try:
            self.redis_client = redis.from_url(os.getenv('REDIS_URL', 'redis://localhost:6379/0'))
        except Exception as e:
            logger.warning(f"Redis not available for background service: {e}")

    @classmethod
    def queue_comprehensive_analysis(cls, file_id: int, analysis_types: List[str],
                                     user_id: int, priority: int = 5) -> str:
        """Queue comprehensive file analysis"""
        try:
            task = analyze_file_comprehensive.apply_async(
                args=[file_id, analysis_types, user_id],
                kwargs={'priority': priority},
                queue='forensics_heavy',
                priority=priority
            )

            cls._track_task(task.id, 'comprehensive_analysis', file_id, user_id)

            logger.info(f"Queued comprehensive analysis for file {file_id}: {task.id}")
            return task.id

        except Exception as e:
            logger.error(f"Failed to queue comprehensive analysis: {e}")
            raise

    @classmethod
    def queue_steganography_analysis(cls, file_id: int, user_id: int) -> str:
        """Queue steganography analysis"""
        try:
            task = steganography_analysis.apply_async(
                args=[file_id, user_id],
                queue='steganography'
            )

            cls._track_task(task.id, 'steganography_analysis', file_id, user_id)

            logger.info(f"Queued steganography analysis for file {file_id}: {task.id}")
            return task.id

        except Exception as e:
            logger.error(f"Failed to queue steganography analysis: {e}")
            raise

    @classmethod
    def queue_crypto_analysis(cls, file_id: int, analysis_options: Dict, user_id: int) -> str:
        """Queue cryptocurrency pattern analysis"""
        try:
            task = crypto_pattern_analysis.apply_async(
                args=[file_id, analysis_options, user_id],
                queue='crypto_analysis'
            )

            cls._track_task(task.id, 'crypto_analysis', file_id, user_id)

            logger.info(f"Queued crypto analysis for file {file_id}: {task.id}")
            return task.id

        except Exception as e:
            logger.error(f"Failed to queue crypto analysis: {e}")
            raise

    @classmethod
    def queue_ai_analysis(cls, file_id: int, ai_options: Dict, user_id: int) -> str:
        """Queue AI analysis"""
        try:
            task = ai_analysis.apply_async(
                args=[file_id, ai_options, user_id],
                queue='ai_analysis'
            )

            cls._track_task(task.id, 'ai_analysis', file_id, user_id)

            logger.info(f"Queued AI analysis for file {file_id}: {task.id}")
            return task.id

        except Exception as e:
            logger.error(f"Failed to queue AI analysis: {e}")
            raise

    @classmethod
    def get_task_status(cls, task_id: str) -> Dict[str, Any]:
        """Get status of a background task"""
        try:
            result = AsyncResult(task_id, app=celery)

            status = {
                'task_id': task_id,
                'state': result.state,
                'meta': {},
                'result': None
            }

            if result.state == 'PENDING':
                status['meta'] = {'progress': 0, 'stage': 'Waiting in queue...'}
            elif result.state == 'PROGRESS':
                status['meta'] = result.info
            elif result.state == 'SUCCESS':
                status['result'] = result.result
            elif result.state == 'FAILURE':
                status['meta'] = {'error': str(result.info), 'stage': 'Failed'}

            return status

        except Exception as e:
            logger.error(f"Failed to get task status: {e}")
            return {'error': str(e)}

    @classmethod
    def get_queue_status(cls) -> Dict[str, Any]:
        """Get status of analysis queues"""
        try:
            inspect = celery.control.inspect()

            active = inspect.active() or {}
            scheduled = inspect.scheduled() or {}
            reserved = inspect.reserved() or {}

            queue_status = {
                'active_tasks': active,
                'scheduled_tasks': scheduled,
                'reserved_tasks': reserved,
                'worker_stats': inspect.stats() or {}
            }

            return queue_status

        except Exception as e:
            logger.error(f"Failed to get queue status: {e}")
            return {}

    @classmethod
    def _track_task(cls, task_id: str, task_type: str, file_id: int, user_id: int):
        """Track task in Redis for monitoring"""
        try:
            service = cls()
            if not service.redis_client:
                return

            task_info = {
                'task_id': task_id,
                'task_type': task_type,
                'file_id': file_id,
                'user_id': user_id,
                'created_at': datetime.utcnow().isoformat(),
                'status': 'PENDING'
            }

            # Store task info
            task_key = f"task:{task_id}"
            service.redis_client.setex(task_key, 86400, json.dumps(task_info))  # 24 hour TTL

            # Add to user's task list
            user_tasks_key = f"user_tasks:{user_id}"
            service.redis_client.lpush(user_tasks_key, task_id)
            service.redis_client.ltrim(user_tasks_key, 0, 99)  # Keep last 100 tasks
            service.redis_client.expire(user_tasks_key, 86400 * 7)  # 7 days

        except Exception as e:
            logger.error(f"Failed to track task: {e}")


# Celery Tasks

@celery.task(bind=True, name='crypto_hunter_web.services.background_service.analyze_file_comprehensive')
def analyze_file_comprehensive(self, file_id: int, analysis_types: List[str], user_id: int, priority: int = 5):
    """Comprehensive file analysis task with all forensics tools"""
    try:
        self.update_state(state='PROGRESS', meta={'progress': 0, 'stage': 'Starting comprehensive analysis'})

        # Get file from database
        file_obj = AnalysisFile.query.get(file_id)
        if not file_obj:
            raise ValueError(f"File {file_id} not found")

        # Update file status
        file_obj.status = 'processing'
        db.session.commit()

        # Initialize forensics toolkit
        toolkit = ForensicsToolkit()

        self.update_state(state='PROGRESS', meta={'progress': 10, 'stage': 'Running forensics analysis'})

        # Perform comprehensive analysis
        start_time = datetime.utcnow()
        forensics_results = toolkit.analyze_file_comprehensive(file_obj.filepath, file_obj.file_type)
        end_time = datetime.utcnow()

        duration = (end_time - start_time).total_seconds()

        self.update_state(state='PROGRESS', meta={'progress': 70, 'stage': 'Processing findings'})

        # Process and store findings
        findings = []
        for finding_data in forensics_results.get('findings', []):
            finding = Finding(
                file_id=file_obj.id,
                finding_type=finding_data.get('type', 'forensics_finding'),
                confidence=finding_data.get('confidence', 0.5),
                description=finding_data.get('description', 'Forensics finding'),
                details=json.dumps(finding_data),
                created_by=user_id
            )
            db.session.add(finding)
            findings.append(finding)

        self.update_state(state='PROGRESS', meta={'progress': 85, 'stage': 'Saving results'})

        # Create file content entry
        content_entry = FileContent(
            file_id=file_obj.id,
            content_type='comprehensive_forensics',
            content_format='json',
            content_json=forensics_results,
            content_size=len(json.dumps(forensics_results)),
            extracted_by=user_id,
            extraction_method='comprehensive_forensics'
        )

        db.session.add(content_entry)

        # Update file status
        file_obj.status = 'complete'
        file_obj.analyzed_at = datetime.utcnow()

        db.session.commit()

        # Log completion
        AuditLog.log_action(
            user_id=user_id,
            action='comprehensive_forensics_completed',
            description=f'Comprehensive forensics analysis completed for {file_obj.filename}',
            resource_type='file',
            resource_id=file_obj.sha256_hash,
            metadata={
                'execution_time': duration,
                'tools_executed': len(forensics_results.get('tools_executed', [])),
                'findings_count': len(findings),
                'confidence_score': forensics_results.get('confidence_score', 0.0)
            }
        )

        self.update_state(state='SUCCESS', meta={'progress': 100, 'stage': 'Analysis complete'})

        return {
            'success': True,
            'file_id': file_id,
            'execution_time': duration,
            'tools_executed': len(forensics_results.get('tools_executed', [])),
            'findings_count': len(findings),
            'confidence_score': forensics_results.get('confidence_score', 0.0),
            'forensics_results': forensics_results
        }

    except Exception as e:
        logger.error(f"Comprehensive analysis failed for file {file_id}: {e}", exc_info=True)

        # Update file status on failure
        try:
            file_obj = AnalysisFile.query.get(file_id)
            if file_obj:
                file_obj.status = 'failed'
                db.session.commit()
        except:
            pass

        self.update_state(
            state='FAILURE',
            meta={
                'error': str(e),
                'traceback': traceback.format_exc(),
                'stage': 'Failed'
            }
        )
        raise


@celery.task(bind=True, name='crypto_hunter_web.services.background_service.steganography_analysis')
def steganography_analysis(self, file_id: int, user_id: int):
    """Specialized steganography analysis"""
    try:
        self.update_state(state='PROGRESS', meta={'progress': 0, 'stage': 'Starting steganography analysis'})

        file_obj = AnalysisFile.query.get(file_id)
        if not file_obj:
            raise ValueError(f"File {file_id} not found")

        toolkit = ForensicsToolkit()

        # Focus on steganography tools
        stego_tools = ['zsteg', 'steghide', 'stegseek', 'outguess', 'binwalk']
        applicable_tools = [tool for tool in stego_tools if toolkit._is_tool_available(tool)]

        self.update_state(state='PROGRESS',
                          meta={'progress': 20, 'stage': f'Running {len(applicable_tools)} steganography tools'})

        results = []
        for i, tool in enumerate(applicable_tools):
            tool_result = toolkit._run_tool_analysis(tool, file_obj.filepath, file_obj.file_type)
            if tool_result:
                results.append(tool_result)

            progress = 20 + (60 * (i + 1) / len(applicable_tools))
            self.update_state(state='PROGRESS', meta={'progress': progress, 'stage': f'Completed {tool}'})

        # Process results
        findings = []
        for result in results:
            if result.success:
                findings.extend(toolkit._extract_findings(result))

        self.update_state(state='PROGRESS', meta={'progress': 90, 'stage': 'Saving steganography results'})

        # Store results
        stego_results = {
            'tool_results': [
                {
                    'tool_name': r.tool_name,
                    'success': r.success,
                    'confidence': r.confidence,
                    'metadata': r.metadata
                }
                for r in results
            ],
            'findings': findings,
            'analysis_type': 'steganography',
            'timestamp': datetime.utcnow().isoformat()
        }

        content_entry = FileContent(
            file_id=file_obj.id,
            content_type='steganography_analysis',
            content_format='json',
            content_json=stego_results,
            content_size=len(json.dumps(stego_results)),
            extracted_by=user_id,
            extraction_method='steganography_suite'
        )

        db.session.add(content_entry)
        db.session.commit()

        self.update_state(state='SUCCESS', meta={'progress': 100, 'stage': 'Steganography analysis complete'})

        return stego_results

    except Exception as e:
        logger.error(f"Steganography analysis failed for file {file_id}: {e}", exc_info=True)
        self.update_state(state='FAILURE', meta={'error': str(e), 'stage': 'Failed'})
        raise


@celery.task(bind=True, name='crypto_hunter_web.services.background_service.crypto_pattern_analysis')
def crypto_pattern_analysis(self, file_id: int, analysis_options: Dict, user_id: int):
    """Cryptocurrency pattern analysis task"""
    try:
        self.update_state(state='PROGRESS', meta={'progress': 0, 'stage': 'Starting crypto pattern analysis'})

        file_obj = AnalysisFile.query.get(file_id)
        if not file_obj:
            raise ValueError(f"File {file_id} not found")

        # Use existing crypto analyzer
        crypto_analyzer = CryptoAnalyzer()

        self.update_state(state='PROGRESS', meta={'progress': 30, 'stage': 'Analyzing crypto patterns'})

        # Analyze for crypto patterns
        crypto_results = crypto_analyzer.analyze_file_for_crypto(file_obj)

        self.update_state(state='PROGRESS', meta={'progress': 80, 'stage': 'Saving crypto analysis'})

        # Store results
        content_entry = FileContent(
            file_id=file_obj.id,
            content_type='crypto_pattern_analysis',
            content_format='json',
            content_json=crypto_results,
            content_size=len(json.dumps(crypto_results)),
            extracted_by=user_id,
            extraction_method='crypto_pattern_analysis'
        )

        db.session.add(content_entry)
        db.session.commit()

        self.update_state(state='SUCCESS', meta={'progress': 100, 'stage': 'Crypto analysis complete'})

        return crypto_results

    except Exception as e:
        logger.error(f"Crypto pattern analysis failed for file {file_id}: {e}", exc_info=True)
        self.update_state(state='FAILURE', meta={'error': str(e), 'stage': 'Failed'})
        raise


@celery.task(bind=True, name='crypto_hunter_web.services.background_service.ai_analysis')
def ai_analysis(self, file_id: int, ai_options: Dict, user_id: int):
    """AI analysis task"""
    try:
        self.update_state(state='PROGRESS', meta={'progress': 0, 'stage': 'Starting AI analysis'})

        file_obj = AnalysisFile.query.get(file_id)
        if not file_obj:
            raise ValueError(f"File {file_id} not found")

        # Use existing AI service
        ai_service = AIService()

        self.update_state(state='PROGRESS', meta={'progress': 30, 'stage': 'Running AI analysis'})

        # Read file content for AI analysis
        with open(file_obj.filepath, 'rb') as f:
            content = f.read()[:50000]  # First 50KB for AI analysis

        text_content = content.decode('utf-8', errors='ignore')

        # Run AI analysis
        ai_results = ai_service.analyze_content_comprehensive(text_content, ai_options)

        self.update_state(state='PROGRESS', meta={'progress': 80, 'stage': 'Saving AI results'})

        # Store results
        content_entry = FileContent(
            file_id=file_obj.id,
            content_type='ai_analysis',
            content_format='json',
            content_json=ai_results,
            content_size=len(json.dumps(ai_results)),
            extracted_by=user_id,
            extraction_method='ai_analysis'
        )

        db.session.add(content_entry)
        db.session.commit()

        self.update_state(state='SUCCESS', meta={'progress': 100, 'stage': 'AI analysis complete'})

        return ai_results

    except Exception as e:
        logger.error(f"AI analysis failed for file {file_id}: {e}", exc_info=True)
        self.update_state(state='FAILURE', meta={'error': str(e), 'stage': 'Failed'})
        raise


# Maintenance tasks

@celery.task(name='crypto_hunter_web.services.background_service.cleanup_temp_files')
def cleanup_temp_files():
    """Clean up temporary files created by forensics tools"""
    try:
        temp_dirs = ['/tmp', tempfile.gettempdir()]
        cleaned_files = 0

        for temp_dir in temp_dirs:
            for root, dirs, files in os.walk(temp_dir):
                for file in files:
                    file_path = os.path.join(root, file)
                    try:
                        # Clean up old forensics temp files
                        if any(pattern in file for pattern in ['binwalk_', 'steg_', 'forensics_']):
                            file_age = datetime.utcnow() - datetime.fromtimestamp(os.path.getctime(file_path))
                            if file_age.total_seconds() > 3600:  # 1 hour old
                                os.remove(file_path)
                                cleaned_files += 1
                    except:
                        continue

        logger.info(f"Cleaned up {cleaned_files} temporary forensics files")
        return {'cleaned_files': cleaned_files}

    except Exception as e:
        logger.error(f"Temp file cleanup failed: {e}")
        raise


@celery.task(name='crypto_hunter_web.services.background_service.health_check_tools')
def health_check_tools():
    """Check health of forensics tools"""
    try:
        toolkit = ForensicsToolkit()

        tool_status = {}
        for tool_name in toolkit.tools.keys():
            tool_status[tool_name] = toolkit._is_tool_available(tool_name)

        available_tools = sum(tool_status.values())
        total_tools = len(tool_status)

        health_report = {
            'timestamp': datetime.utcnow().isoformat(),
            'total_tools': total_tools,
            'available_tools': available_tools,
            'availability_rate': available_tools / total_tools * 100,
            'tool_status': tool_status
        }

        # Store in Redis for quick access
        try:
            redis_client = redis.from_url(os.getenv('REDIS_URL', 'redis://localhost:6379/0'))
            redis_client.setex('forensics_tools_health', 3600, json.dumps(health_report))
        except:
            pass

        logger.info(f"Forensics tools health check: {available_tools}/{total_tools} tools available")

        return health_report

    except Exception as e:
        logger.error(f"Tools health check failed: {e}")
        raise


@celery.task(name='crypto_hunter_web.services.background_service.update_statistics')
def update_statistics():
    """Update system statistics"""
    try:
        # Update file statistics
        total_files = AnalysisFile.query.count()
        analyzed_files = AnalysisFile.query.filter_by(status='complete').count()

        # Update finding statistics
        total_findings = Finding.query.count()

        stats = {
            'timestamp': datetime.utcnow().isoformat(),
            'total_files': total_files,
            'analyzed_files': analyzed_files,
            'total_findings': total_findings,
            'analysis_completion_rate': (analyzed_files / total_files * 100) if total_files > 0 else 0
        }

        # Store statistics in Redis for quick access
        redis_client = redis.from_url(os.getenv('REDIS_URL', 'redis://localhost:6379/0'))
        redis_client.setex('system_statistics', 1800, json.dumps(stats))  # 30 minute TTL

        logger.info("System statistics updated successfully")

        return stats

    except Exception as e:
        logger.error(f"Statistics update failed: {e}")
        raise


# Initialize celery with Flask app context
def init_celery(app):
    """Initialize Celery with Flask app"""
    global celery
    celery = create_celery_app(app)
    return celery